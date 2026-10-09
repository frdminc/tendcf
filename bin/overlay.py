#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Maintain tendcf's patch overlay on libntech and cfengine/core.

The overlay is `overlay/overlay.json` (the manifest) plus one directory per
component holding `git format-patch` output, in order. Design and rationale:
`docs/architecture/upstream-overlay.md`; the issue it serves is
frdminc/tendcf#3. The rule it enforces is the one the issue states: a small
set of patches pinned to a specific upstream commit, each load-bearing for
code this repository has actually shipped, each dropped the moment upstream
carries it.

Subcommands, cheapest first:

  lint       the manifest and the patch files agree with each other and
             with themselves (every file listed, every listed file present,
             order, 40-hex ids, `From` line matches the manifest commit).
             No git repository needed; CI runs this on every push.
  status     print the overlay: components, bases, patches, provenance.
  check      prove the patches apply, in order, to a tree — the pinned base
             by default, or `--against REV` (upstream master, a release tag)
             to detect drift. Uses a temporary index, so the repository is
             never touched. Exit 1 and say DRIFT on the first failure.
  retired    find patches upstream already carries (patch-id match over
             base..REV) and ones whose subject reappears (weaker signal).
             `--strict` exits 1 when a retire candidate exists, so CI can
             fail loudly when upstream catches up.
  apply      `git am` the series onto a checkout whose HEAD is the pinned
             base. Refuses any other HEAD unless `--allow-base-mismatch`;
             aborts the `am` cleanly on failure.
  export     regenerate a component's patch files and manifest entries from
             a fork branch (`--repo`, `--base`, `--tip`); provenance fields
             already in the manifest are kept by commit id.
  self-test  build a throwaway repository, export a sample series, and
             prove: it applies; an unrelated upstream change still applies;
             a conflicting upstream change makes `check` and `apply` fail
             loudly and leave the checkout clean; a cherry-picked patch is
             reported by `retired`. CI runs this on every push.

Exit 1 on any finding. No dependencies beyond git: this must run in a bare
checkout and inside a build.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OVERLAY = ROOT / "overlay"
MANIFEST_NAME = "overlay.json"

HEX40 = re.compile(r"^[0-9a-f]{40}$")
PATCH_NAME = re.compile(r"^(\d{4})-.*\.patch$")
FROM_LINE = re.compile(r"^From ([0-9a-f]{40}) ")
SUBJECT_PREFIX = re.compile(r"^\[PATCH[^\]]*\]\s*")

REQUIRED_PATCH_KEYS = ("commit", "file", "subject")
REQUIRED_COMPONENT_KEYS = ("base", "patches", "upstream")


class Finding(Exception):
    """A lint or check failure. The message is the whole report."""


# ---------------------------------------------------------------- git helpers


def git(repo: Path | str, *args: str, env: dict | None = None,
        check: bool = True, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    cmd = ["git", "-C", str(repo), *args]
    merged = dict(os.environ)
    if env:
        merged.update(env)
    return subprocess.run(cmd, env=merged, check=check, capture_output=True,
                          input=input_bytes)


def git_out(repo: Path | str, *args: str, **kw) -> str:
    return git(repo, *args, **kw).stdout.decode().strip()


def git_path(repo: Path | str, name: str) -> Path:
    """Where `$GIT_DIR/<name>` really is. In a linked worktree or a cow
    pasture `.git` is a file and the per-worktree state (rebase-apply,
    rebase-merge) lives under the main repo's `.git/worktrees/<id>/`, so
    `<checkout>/.git/<name>` would silently never exist."""
    p = Path(git_out(repo, "rev-parse", "--git-path", name))
    return p if p.is_absolute() else Path(repo) / p


def identity_args(repo: Path) -> list[str]:
    """`git am`/`commit` need a committer; supply one only if the repo has none."""
    have = git(repo, "config", "user.email", check=False).returncode == 0
    if have:
        return []
    return ["-c", "user.name=tendcf overlay", "-c", "user.email=overlay@tendcf.invalid"]


# ------------------------------------------------------------ manifest access


def load_manifest(overlay: Path) -> dict:
    path = overlay / MANIFEST_NAME
    if not path.is_file():
        raise Finding(f"{path}: missing manifest")
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise Finding(f"{path}: not JSON: {e}") from None
    canonical = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if canonical != text:
        raise Finding(f"{path}: not in canonical form (2-space indent, sorted keys, "
                      f"trailing newline). Rewrite with: bin/overlay.py lint --fix")
    return data


def save_manifest(overlay: Path, data: dict) -> None:
    (overlay / MANIFEST_NAME).write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8")


def component(data: dict, name: str) -> dict:
    comps = data.get("components", {})
    if name not in comps:
        raise Finding(f"no component {name!r}; have {sorted(comps)}")
    return comps[name]


def patch_paths(overlay: Path, name: str, comp: dict) -> list[Path]:
    return [overlay / name / p["file"] for p in comp["patches"]]


def parse_patch_header(path: Path) -> tuple[str, str]:
    """(commit, subject) from a `git format-patch` file."""
    commit = None
    subject_lines: list[str] = []
    in_subject = False
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if commit is None:
                m = FROM_LINE.match(line)
                if not m:
                    raise Finding(f"{path}: first line is not a `From <sha>` line")
                commit = m.group(1)
                continue
            if in_subject:
                if line.startswith((" ", "\t")):
                    subject_lines.append(line.strip())
                    continue
                break
            if line.startswith("Subject: "):
                subject_lines.append(line[len("Subject: "):])
                in_subject = True
            elif line == "":
                break
    if commit is None or not subject_lines:
        raise Finding(f"{path}: no From/Subject header")
    subject = SUBJECT_PREFIX.sub("", " ".join(subject_lines))
    return commit, subject


# ------------------------------------------------------------------- lint


def lint(overlay: Path) -> list[str]:
    data = load_manifest(overlay)
    findings: list[str] = []
    if data.get("schema_version") != 1:
        findings.append(f"{MANIFEST_NAME}: schema_version must be 1")
    comps = data.get("components")
    if not isinstance(comps, dict):
        findings.append(f"{MANIFEST_NAME}: components must be an object")
        return findings
    listed_dirs = set()
    for name, comp in sorted(comps.items()):
        listed_dirs.add(name)
        for key in REQUIRED_COMPONENT_KEYS:
            if key not in comp:
                findings.append(f"{name}: missing {key!r}")
        base = comp.get("base", "")
        if not HEX40.match(base):
            findings.append(f"{name}: base {base!r} is not a 40-hex commit id")
        cdir = overlay / name
        if not cdir.is_dir():
            findings.append(f"{name}: directory {cdir} missing")
            continue
        on_disk = sorted(p.name for p in cdir.iterdir() if p.suffix == ".patch")
        listed = [p.get("file", "") for p in comp.get("patches", [])]
        if listed != sorted(listed):
            findings.append(f"{name}: manifest patch order is not the NNNN order: {listed}")
        if sorted(listed) != on_disk:
            findings.append(f"{name}: manifest lists {sorted(listed)} but disk has {on_disk}")
        seen_numbers: set[str] = set()
        for entry in comp.get("patches", []):
            for key in REQUIRED_PATCH_KEYS:
                if key not in entry:
                    findings.append(f"{name}: patch entry {entry.get('file', '?')} missing {key!r}")
            fname = entry.get("file", "")
            m = PATCH_NAME.match(fname)
            if not m:
                findings.append(f"{name}/{fname}: not named NNNN-<slug>.patch")
            elif m.group(1) in seen_numbers:
                findings.append(f"{name}/{fname}: duplicate sequence number")
            else:
                seen_numbers.add(m.group(1))
            if not HEX40.match(entry.get("commit", "")):
                findings.append(f"{name}/{fname}: commit is not a 40-hex id")
            path = cdir / fname
            if not path.is_file():
                continue
            try:
                commit, subject = parse_patch_header(path)
            except Finding as e:
                findings.append(str(e))
                continue
            if commit != entry.get("commit"):
                findings.append(f"{name}/{fname}: From line {commit} != manifest commit {entry.get('commit')}")
            if subject != entry.get("subject"):
                findings.append(f"{name}/{fname}: subject {subject!r} != manifest {entry.get('subject')!r}")
    for d in overlay.iterdir():
        if d.is_dir() and d.name not in listed_dirs:
            findings.append(f"{d}: directory not listed in the manifest")
    return findings


# ------------------------------------------------------------------ check


def check(overlay: Path, name: str, repo: Path, against: str | None) -> list[str]:
    """Apply the series into a temporary index built from `against` (default:
    the pinned base). Returns the per-patch report; raises Finding on drift."""
    data = load_manifest(overlay)
    comp = component(data, name)
    rev = against or comp["base"]
    try:
        tree = git_out(repo, "rev-parse", "--verify", f"{rev}^{{tree}}")
        resolved = git_out(repo, "rev-parse", "--verify", f"{rev}^{{commit}}")
    except subprocess.CalledProcessError as e:
        raise Finding(f"{name}: cannot resolve {rev!r} in {repo}: {e.stderr.decode().strip()}") from None
    report = [f"{name}: base {comp['base'][:12]}; checking against {rev} = {resolved[:12]}"
              + ("" if resolved == comp["base"] else "  (NOT the pinned base: drift check)")]
    with tempfile.TemporaryDirectory(prefix="tendcf-overlay-") as tmp:
        index = str(Path(tmp) / "index")
        env = {"GIT_INDEX_FILE": index}
        git(repo, "read-tree", tree, env=env)
        for path in patch_paths(overlay, name, comp):
            r = git(repo, "apply", "--cached", "--whitespace=nowarn", str(path),
                    env=env, check=False)
            if r.returncode != 0:
                err = r.stderr.decode().strip()
                raise Finding(
                    "\n".join(report + [
                        f"DRIFT: {name}/{path.name} does not apply to {rev} ({resolved[:12]}):",
                        *("    " + ln for ln in err.splitlines()),
                        f"Rebase the fork branch onto {rev}, re-export with `bin/overlay.py export`, "
                        f"and bump {name}.base in {MANIFEST_NAME} — or retire the patch if upstream carries it.",
                    ]))
            report.append(f"  ok  {path.name}")
    return report


# ---------------------------------------------------------------- retired


def patch_id(repo: Path, patch_bytes: bytes) -> str | None:
    r = git(repo, "patch-id", "--stable", input_bytes=patch_bytes, check=False)
    out = r.stdout.decode().split()
    return out[0] if out else None


def retired(overlay: Path, name: str, repo: Path, against: str) -> tuple[list[str], bool]:
    data = load_manifest(overlay)
    comp = component(data, name)
    base = comp["base"]
    # Every upstream commit between the pinned base and `against`, by patch-id.
    log = git(repo, "log", "-p", "--no-merges", "--format=commit %H%n%s", f"{base}..{against}").stdout
    ids_out = git(repo, "patch-id", "--stable", input_bytes=log, check=False).stdout.decode()
    upstream_ids = {ln.split()[0]: ln.split()[1] for ln in ids_out.splitlines() if ln.strip()}
    subjects = git_out(repo, "log", "--no-merges", "--format=%s", f"{base}..{against}").splitlines()
    count = len(subjects)
    report = [f"{name}: {count} upstream commit(s) in {base[:12]}..{against}"]
    any_retire = False
    for entry, path in zip(comp["patches"], patch_paths(overlay, name, comp)):
        pid = patch_id(repo, path.read_bytes())
        if pid and pid in upstream_ids:
            any_retire = True
            report.append(f"  RETIRE  {path.name}: identical change is upstream as {upstream_ids[pid][:12]}")
        elif entry["subject"] in subjects:
            any_retire = True
            report.append(f"  VERIFY  {path.name}: an upstream commit has the same subject but a different "
                          f"patch-id; check whether it supersedes this patch")
        else:
            report.append(f"  keep    {path.name}")
    return report, any_retire


# ------------------------------------------------------------------ apply


def apply_series(overlay: Path, name: str, checkout: Path, allow_mismatch: bool) -> list[str]:
    data = load_manifest(overlay)
    comp = component(data, name)
    head = git_out(checkout, "rev-parse", "HEAD")
    report = [f"{name}: HEAD {head[:12]}, pinned base {comp['base'][:12]}"]
    if head != comp["base"] and not allow_mismatch:
        raise Finding(f"{name}: {checkout} is at {head[:12]}, not the pinned base {comp['base'][:12]}. "
                      f"Check out the base, or pass --allow-base-mismatch after `check --against` is green.")
    dirty = git_out(checkout, "status", "--porcelain", "--untracked-files=no")
    if dirty:
        raise Finding(f"{name}: {checkout} has uncommitted changes; refusing to `git am` onto them")
    rebase_apply = git_path(checkout, "rebase-apply")
    for busy in (rebase_apply, git_path(checkout, "rebase-merge")):
        if busy.exists():
            raise Finding(f"{name}: {checkout} has a `git am` or rebase in progress ({busy}); resolve or abort it first")
    paths = patch_paths(overlay, name, comp)
    r = git(checkout, *identity_args(checkout), "am", "--whitespace=nowarn", *map(str, paths), check=False)
    if r.returncode != 0:
        err = r.stderr.decode().strip() + "\n" + r.stdout.decode().strip()
        # Abort only the am session this invocation started: rebase-apply was
        # absent above, so if it exists now it is ours, unless our am refused
        # because someone else's session appeared in between ("still exists").
        if not rebase_apply.exists():
            abort_note = f"no am session was left behind; checkout still at {head[:12]}"
        elif "still exists" in err:
            abort_note = f"another `git am` or rebase session ({rebase_apply}) appeared meanwhile; left it alone"
        else:
            ab = git(checkout, *identity_args(checkout), "am", "--abort", check=False)
            abort_note = (f"aborted, checkout restored to {head[:12]}" if ab.returncode == 0 else
                          f"and `git am --abort` ALSO failed ({ab.returncode}): {ab.stderr.decode().strip()} {ab.stdout.decode().strip()}")
        raise Finding("\n".join(report + [
            f"DRIFT: `git am` failed in {checkout}; {abort_note}:",
            *("    " + ln for ln in err.splitlines() if ln.strip()),
        ]))
    new_head = git_out(checkout, "rev-parse", "HEAD")
    report.append(f"  applied {len(paths)} patch(es); HEAD now {new_head[:12]}")
    return report


# ----------------------------------------------------------------- export


def export(overlay: Path, name: str, repo: Path, base: str, tips: list[str]) -> list[str]:
    """One or more series, each `base..tip`, numbered consecutively. Several
    tips are for independent fork branches with no file overlap (issue #3's
    libntech case); `check` proves the combined order still applies."""
    data = load_manifest(overlay) if (overlay / MANIFEST_NAME).is_file() else {"schema_version": 1, "components": {}}
    comps = data.setdefault("components", {})
    comp = comps.setdefault(name, {"upstream": "", "base": base, "patches": []})
    base_full = git_out(repo, "rev-parse", "--verify", f"{base}^{{commit}}")
    tips_full = [git_out(repo, "rev-parse", "--verify", f"{t}^{{commit}}") for t in tips]
    for tip, tip_full in zip(tips, tips_full):
        if git(repo, "merge-base", "--is-ancestor", base_full, tip_full, check=False).returncode != 0:
            raise Finding(f"{name}: {base} is not an ancestor of {tip}")
    old_by_commit = {p["commit"]: p for p in comp.get("patches", [])}
    cdir = overlay / name
    if cdir.is_dir():
        for p in cdir.iterdir():
            if p.suffix == ".patch":
                p.unlink()
    cdir.mkdir(parents=True, exist_ok=True)
    files: list[str] = []
    for tip_full in tips_full:
        out = git_out(repo, "format-patch", "--no-signature", "--no-renames", "--full-index",
                      "--no-stat", f"--start-number={len(files) + 1}", "-o", str(cdir),
                      f"{base_full}..{tip_full}")
        files.extend(Path(ln).name for ln in out.splitlines() if ln.strip())
    patches = []
    for fname in files:
        commit, subject = parse_patch_header(cdir / fname)
        entry = dict(old_by_commit.get(commit, {}))
        entry.update({"file": fname, "commit": commit, "subject": subject})
        patches.append(entry)
    comp["base"] = base_full
    comp["patches"] = patches
    save_manifest(overlay, data)
    return [f"{name}: exported {len(files)} patch(es) from {base_full[:12]}..{{{', '.join(t[:12] for t in tips_full)}}} into {cdir}",
            *(f"  {f}" for f in files)]


# -------------------------------------------------------------- self-test


def self_test() -> list[str]:
    """A synthetic upstream, a fork branch, an overlay exported from it, and
    the four behaviours the overlay must have. Each assertion names itself."""
    report: list[str] = []

    def ok(label: str, cond: bool, detail: str = "") -> None:
        if not cond:
            raise Finding(f"self-test FAILED: {label}" + (f"\n{detail}" if detail else ""))
        report.append(f"  pass  {label}")

    ident = ["-c", "user.name=tendcf overlay self-test", "-c", "user.email=overlay@tendcf.invalid"]

    def commit_file(repo: Path, rel: str, text: str, msg: str) -> str:
        (repo / rel).write_text(text, encoding="utf-8")
        git(repo, "add", rel)
        git(repo, *ident, "commit", "-q", "-m", msg)
        return git_out(repo, "rev-parse", "HEAD")

    with tempfile.TemporaryDirectory(prefix="tendcf-overlay-selftest-") as tmp:
        tmp_path = Path(tmp)
        upstream = tmp_path / "upstream"
        upstream.mkdir()
        git(upstream, "init", "-q", "-b", "master")
        lines = [f"line {i}\n" for i in range(1, 11)]
        base = commit_file(upstream, "json.c", "".join(lines), "Initial")

        # The fork: two stacked fixes, the second touching a second file.
        git(upstream, "checkout", "-q", "-b", "fix/sample")
        fixed = list(lines)
        fixed[4] = "line 5 fixed\n"
        c1 = commit_file(upstream, "json.c", "".join(fixed), "Fixed line five decoding twice")
        c2 = commit_file(upstream, "json_test.c", "test for line five\n", "Added a test for line five")
        git(upstream, "checkout", "-q", "master")

        overlay = tmp_path / "overlay"
        overlay.mkdir()
        save_manifest(overlay, {"schema_version": 1, "components": {}})
        export(overlay, "sample", upstream, base, [c2])
        data = load_manifest(overlay)
        data["components"]["sample"]["upstream"] = "file://" + str(upstream)
        save_manifest(overlay, data)
        ok("export produced two numbered patches", [p["file"][:5] for p in data["components"]["sample"]["patches"]] == ["0001-", "0002-"])
        ok("lint is clean on the exported overlay", lint(overlay) == [])

        # 1. The series applies to the pinned base.
        check(overlay, "sample", upstream, None)
        ok("check: series applies to the pinned base", True)

        # 2. An unrelated upstream change does not count as drift.
        git(upstream, "checkout", "-q", "-b", "unrelated", base)
        unrelated = commit_file(upstream, "README", "unrelated\n", "Unrelated upstream change")
        check(overlay, "sample", upstream, unrelated)
        ok("check --against: unrelated upstream change still applies", True)

        # 3. A conflicting upstream change fails loudly, in check and in apply.
        git(upstream, "checkout", "-q", "-b", "drifted", base)
        drifted_lines = list(lines)
        drifted_lines[4] = "line 5 rewritten upstream\n"
        drifted = commit_file(upstream, "json.c", "".join(drifted_lines), "Rewrote line five differently")
        try:
            check(overlay, "sample", upstream, drifted)
        except Finding as e:
            ok("check --against: conflicting upstream change reports DRIFT", "DRIFT" in str(e) and "0001-" in str(e), str(e))
        else:
            ok("check --against: conflicting upstream change reports DRIFT", False)

        clone = tmp_path / "clone"
        git(tmp_path, "clone", "-q", str(upstream), str(clone))
        git(clone, "checkout", "-q", drifted)
        try:
            apply_series(overlay, "sample", clone, allow_mismatch=False)
        except Finding as e:
            ok("apply: refuses a checkout whose HEAD is not the pinned base", "not the pinned base" in str(e), str(e))
        else:
            ok("apply: refuses a checkout whose HEAD is not the pinned base", False)
        try:
            apply_series(overlay, "sample", clone, allow_mismatch=True)
        except Finding as e:
            status = git_out(clone, "status", "--porcelain")
            in_progress = git_path(clone, "rebase-apply").exists()
            head_now = git_out(clone, "rev-parse", "HEAD")
            ok("apply --allow-base-mismatch: `git am` conflict fails loudly and leaves the checkout clean",
               "DRIFT" in str(e) and status == "" and not in_progress and head_now == drifted,
               f"status={status!r} rebase-apply={in_progress} HEAD={head_now[:12]} expected={drifted[:12]}\n{e}")
        else:
            ok("apply --allow-base-mismatch: `git am` conflict fails loudly", False)

        # 3b. A user's own `git am`, stopped in a linked worktree (where `.git`
        # is a file), is refused and left alone, never aborted by us.
        wt = tmp_path / "linked-worktree"
        git(clone, "worktree", "add", "-q", "--detach", str(wt), drifted)
        first_patch = overlay / "sample" / data["components"]["sample"]["patches"][0]["file"]
        user_am = git(wt, *ident, "am", str(first_patch), check=False)
        user_session = git_path(wt, "rebase-apply")
        ok("linked worktree: the user's own `git am` stopped, its session outside <worktree>/.git/",
           user_am.returncode != 0 and user_session.exists() and (wt / ".git").is_file()
           and not (wt / ".git" / "rebase-apply").exists(),
           f"am rc={user_am.returncode} session={user_session} exists={user_session.exists()}")
        try:
            apply_series(overlay, "sample", wt, allow_mismatch=True)
        except Finding as e:
            ok("apply: refuses a linked worktree with a `git am` in progress and leaves that session intact",
               "in progress" in str(e) and user_session.exists() and git_out(wt, "rev-parse", "HEAD") == drifted,
               f"session exists={user_session.exists()}\n{e}")
        else:
            ok("apply: refuses a linked worktree with a `git am` in progress", False)
        git(wt, *ident, "am", "--abort")
        git(clone, "worktree", "remove", "--force", str(wt))

        # 4. The series applies for real, with `git am`, onto the base.
        git(clone, "checkout", "-q", base)
        apply_series(overlay, "sample", clone, allow_mismatch=False)
        subjects = git_out(clone, "log", "--format=%s", f"{base}..HEAD").splitlines()
        ok("apply: `git am` lands both commits in order",
           subjects == ["Added a test for line five", "Fixed line five decoding twice"], str(subjects))
        ok("apply: the applied tree matches the fork tip's tree",
           git_out(clone, "rev-parse", "HEAD^{tree}") == git_out(upstream, "rev-parse", f"{c2}^{{tree}}"))

        # 5. Retirement: upstream cherry-picks the first fix.
        git(upstream, "checkout", "-q", "-b", "caught-up", base)
        git(upstream, *ident, "cherry-pick", c1)
        caught_up = git_out(upstream, "rev-parse", "HEAD")
        rep, any_retire = retired(overlay, "sample", upstream, caught_up)
        ok("retired: a cherry-picked patch is reported RETIRE, the other kept",
           any_retire and any("RETIRE" in ln and "0001-" in ln for ln in rep) and any("keep" in ln and "0002-" in ln for ln in rep),
           "\n".join(rep))
        rep, any_retire = retired(overlay, "sample", upstream, unrelated)
        ok("retired: nothing to retire against an unrelated change", not any_retire, "\n".join(rep))

        # 6. Lint catches a manifest that disagrees with the files.
        data = load_manifest(overlay)
        data["components"]["sample"]["patches"][0]["commit"] = "0" * 40
        save_manifest(overlay, data)
        ok("lint: a manifest commit that disagrees with the patch's From line is a finding",
           any("From line" in f for f in lint(overlay)))
        stray = overlay / "sample" / "0003-stray.patch"
        stray.write_text("From " + "1" * 40 + " Mon Sep 17 00:00:00 2001\nSubject: [PATCH] stray\n\n", encoding="utf-8")
        ok("lint: a patch file the manifest does not list is a finding",
           any("disk has" in f for f in lint(overlay)))
    return report


# -------------------------------------------------------------------- main


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--overlay", type=Path, default=DEFAULT_OVERLAY,
                        help=f"overlay directory (default {DEFAULT_OVERLAY})")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("lint", help="manifest and patch files agree").add_argument(
        "--fix", action="store_true", help="rewrite the manifest in canonical form")
    sub.add_parser("status", help="print the overlay")

    p = sub.add_parser("check", help="patches apply to a tree (temporary index; repo untouched)")
    p.add_argument("component")
    p.add_argument("--repo", type=Path, required=True, help="any git repository holding the upstream objects")
    p.add_argument("--against", help="rev to apply onto (default: the pinned base)")

    p = sub.add_parser("retired", help="patches upstream already carries")
    p.add_argument("component")
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--against", required=True, help="upstream rev to compare with, e.g. upstream/master")
    p.add_argument("--strict", action="store_true", help="exit 1 if any patch should be retired")

    p = sub.add_parser("apply", help="`git am` the series onto a checkout at the pinned base")
    p.add_argument("component")
    p.add_argument("--checkout", type=Path, required=True)
    p.add_argument("--allow-base-mismatch", action="store_true")

    p = sub.add_parser("export", help="regenerate a component's patches from a fork branch")
    p.add_argument("component")
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--base", required=True, help="upstream commit the series sits on")
    p.add_argument("--tip", required=True, action="append",
                   help="fork branch tip; repeat for independent series on the same base")

    sub.add_parser("self-test", help="prove the mechanism on a synthetic repository")

    args = parser.parse_args()
    overlay: Path = args.overlay.resolve()
    try:
        if args.cmd == "lint":
            if args.fix:
                path = overlay / MANIFEST_NAME
                save_manifest(overlay, json.loads(path.read_text(encoding="utf-8")))
            findings = lint(overlay)
            for f in findings:
                print(f)
            print(f"overlay lint: {len(findings)} finding(s)")
            return 1 if findings else 0
        if args.cmd == "status":
            data = load_manifest(overlay)
            for name, comp in sorted(data["components"].items()):
                print(f"{name}: upstream {comp.get('upstream', '?')} base {comp['base'][:12]}"
                      f"{'  ' + comp['base_described'] if comp.get('base_described') else ''}")
                for e in comp["patches"]:
                    extra = ", ".join(f"{k}={e[k]}" for k in ("register", "role", "upstream_pr_state") if k in e)
                    print(f"  {e['file']}  {e['commit'][:12]}  {e['subject']}" + (f"  [{extra}]" if extra else ""))
            return 0
        if args.cmd == "check":
            print("\n".join(check(overlay, args.component, args.repo.resolve(), args.against)))
            return 0
        if args.cmd == "retired":
            rep, any_retire = retired(overlay, args.component, args.repo.resolve(), args.against)
            print("\n".join(rep))
            return 1 if (args.strict and any_retire) else 0
        if args.cmd == "apply":
            print("\n".join(apply_series(overlay, args.component, args.checkout.resolve(), args.allow_base_mismatch)))
            return 0
        if args.cmd == "export":
            print("\n".join(export(overlay, args.component, args.repo.resolve(), args.base, args.tip)))
            return 0
        if args.cmd == "self-test":
            rep = self_test()
            print("\n".join(rep))
            print(f"overlay self-test: {len(rep)} assertion(s) passed")
            return 0
    except Finding as e:
        print(str(e), file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as e:
        print(f"{' '.join(e.cmd)} failed ({e.returncode}):\n{e.stderr.decode(errors='replace')}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
