#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml", "jsonschema>=4.21", "rfc3339-validator", "rfc8785"]
# ///
"""Hold the darwin canary goal files, projections, and committed plist goldens to the same rails as deploy/linux/canary/.

The darwin canary (`com.tendcf.canary.main`) is enforced in both the system
LaunchDaemon domain (`domain: "system"`, state-1 macOS VM, issue #70) and the
unprivileged user LaunchAgent domain (`domain: "user"`, issue #94). Each
goal file (`schema_version: 8`, declaring `org.tendcf.execd` under
`writer: "tendcf-install"`, issue #99) is canonical JCS bytes that validates
against `goal-file.schema.json` and passes cross-file lint, with CMDB data
byte-identical to `project(goal-file*.json)`.

Both committed per-domain goldens
(`tests/policy/golden/launchd/system/com.tendcf.canary.main.plist` and
`tests/policy/golden/launchd/user/com.tendcf.canary.main.plist`) are
byte-compared against rendered `policy/templates/launchd.plist.mustache`,
parsed with `plistlib`, verified to differ ONLY in `UserName` (present in
`system`, omitted in `user`), and checked with `plutil -lint` when available
(explicit SKIP on Linux where `plutil` is absent).

Pass `--user-render [--bindir DIR]` on macOS to additionally execute a real
unprivileged `cf-agent` render (not `-n`) into a scratch LaunchAgents directory
and byte-compare the rendered plist against the committed `user` golden.

Run from anywhere:
  deploy/darwin/canary/check.py                          (exit 0 clean, 1 findings)
  deploy/darwin/canary/check.py --user-render [--bindir DIR]
"""

from __future__ import annotations

import argparse
import html
import importlib.util
import json
import os
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CANARY_LABEL = "com.tendcf.canary.main"
GOLDEN_SYSTEM_PLIST = REPO / "tests" / "policy" / "golden" / "launchd" / "system" / f"{CANARY_LABEL}.plist"
GOLDEN_USER_PLIST = REPO / "tests" / "policy" / "golden" / "launchd" / "user" / f"{CANARY_LABEL}.plist"
MUSTACHE_TEMPLATE = REPO / "policy" / "templates" / "launchd.plist.mustache"

PAIRS = (
    (HERE / "goal-file.json", HERE / "host_specific.json"),
    (HERE / "goal-file-absent.json", HERE / "host_specific-absent.json"),
    (HERE / "goal-file-user.json", HERE / "host_specific-user.json"),
)


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def render_launchd_mustache(template_text: str, service_id: str, svc: dict) -> bytes:
    """Render `policy/templates/launchd.plist.mustache` identically to CFEngine mustache."""
    launchd = svc["unit"]["launchd"]
    include_username = launchd["domain"] == "system"
    out = template_text
    out = re.sub(
        r"\{\{#launchd_include_username\}\}\n(.*?)\{\{/launchd_include_username\}\}\n",
        lambda m: m.group(1) if include_username else "",
        out,
        flags=re.DOTALL,
    )
    out = out.replace("{{id}}", html.escape(service_id, quote=True))
    out = out.replace("{{run_as}}", html.escape(svc["run_as"], quote=True))
    out = out.replace("{{working_dir}}", html.escape(svc["working_dir"], quote=True))

    def repl_cmd(m: re.Match[str]) -> str:
        inner = m.group(1)
        return "".join(inner.replace("{{.}}", html.escape(arg, quote=True)) for arg in svc["command"])

    out = re.sub(r"\{\{#command\}\}\n(.*?)\{\{/command\}\}\n", repl_cmd, out, flags=re.DOTALL)

    for key in ("run_at_load", "keep_alive"):
        val = bool(launchd[key])
        out = re.sub(
            rf"\{{\{{#unit\.launchd\.{key}\}}\}}\n(.*?)\{{\{{/unit\.launchd\.{key}\}}\}}\n",
            lambda m, v=val: m.group(1) if v else "",
            out,
            flags=re.DOTALL,
        )
        out = re.sub(
            rf"\{{\{{\^unit\.launchd\.{key}\}}\}}\n(.*?)\{{\{{/unit\.launchd\.{key}\}}\}}\n",
            lambda m, v=val: "" if v else m.group(1),
            out,
            flags=re.DOTALL,
        )

    if "{{" in out or "}}" in out:
        raise ValueError(f"unexpanded mustache tags remain in rendered plist:\n{out}")
    return out.encode("utf-8")


def run_user_render_check(bindir: str | None) -> list[str]:
    """Execute a real unprivileged `cf-agent` render (not `-n`) into a scratch
    LaunchAgents dir and byte-compare against the committed user-domain golden."""
    problems: list[str] = []
    if sys.platform != "darwin":
        return ["`--user-render` requires macOS (darwin)"]
    if os.geteuid() == 0:
        return ["`--user-render` must run unprivileged (non-root)"]

    if bindir:
        bdir = Path(bindir).expanduser().resolve()
    else:
        dev_bin = Path.home() / "opt" / "cfengine-dev" / "bin"
        if (dev_bin / "cf-agent").is_file():
            bdir = dev_bin
        else:
            found = shutil.which("cf-agent")
            if not found:
                return ["cf-agent not found; pass --bindir DIR"]
            bdir = Path(found).resolve().parent

    cf_agent = bdir / "cf-agent"
    cf_promises = bdir / "cf-promises"
    cf_key = bdir / "cf-key"
    for tool in (cf_agent, cf_promises, cf_key):
        if not tool.is_file():
            return [f"missing CFEngine binary: {tool}"]

    user = pwd.getpwuid(os.getuid()).pw_name
    uid = str(os.getuid())
    gid = str(os.getgid())

    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="tendcf-user-render.") as td:
            work = Path(td)
            for sub in ("data", "inputs", "state", "ppkeys", "tmp", "bin", "agents", "loaded"):
                (work / sub).mkdir()
            (work / "ppkeys").chmod(0o700)
            for src in bdir.glob("cf-*"):
                (work / "bin" / src.name).symlink_to(src)

            env = dict(os.environ, CFENGINE_TEST_OVERRIDE_WORKDIR=str(work))
            subprocess.run([str(cf_key)], env=env, capture_output=True, check=False)

            stub_log = work / "launchctl.log"
            stub_log.write_text("", encoding="utf-8")
            stub = work / "launchctl-stub"
            stub.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                f"log={str(stub_log)!r}\n"
                f"state={str(work / 'loaded')!r}\n"
                'printf "%s" "$1" >> "$log"\n'
                'for a in "${@:2}"; do printf "\\t%s" "$a" >> "$log"; done\n'
                'printf "\\n" >> "$log"\n'
                'case "${1:-}" in\n'
                f'  print) [ "${{2:-}}" = "gui/{uid}/{CANARY_LABEL}" ] || exit 64; '
                f'[ -f "$state/{CANARY_LABEL}" ] && exit 0 || exit 113 ;;\n'
                f'  bootstrap) [ "${{2:-}}" = "gui/{uid}" ] && [ -f "${{3:-}}" ] || exit 64; '
                f': > "$state/{CANARY_LABEL}"; exit 0 ;;\n'
                '  *) exit 64 ;;\n'
                'esac\n',
                encoding="utf-8",
            )
            stub.chmod(0o700)

            # Copy committed user-domain projection with run_as set to the running user.
            user_data = json.loads((HERE / "host_specific-user.json").read_text(encoding="utf-8"))
            user_data["vars"]["tendcf_service"][CANARY_LABEL]["run_as"] = user
            (work / "data" / "host_specific.json").write_text(
                json.dumps(user_data, separators=(",", ":"), sort_keys=True), encoding="utf-8"
            )

            harness = work / "inputs" / "user-render.cf"
            harness.write_text(
                "body common control\n"
                "{\n"
                f'      inputs => {{ "{REPO / "policy" / "tendcf_services.cf"}" }};\n'
                '      bundlesequence => { "tendcf_interlocks", "tendcf_user_render" };\n'
                "}\n"
                "bundle agent tendcf_user_render\n"
                "{\n"
                "  methods:\n"
                '      "run"\n'
                f'        usebundle => tendcf_services_apply("user", "{work / "agents"}", "{stub}", "{user}", "{gid}", "{user}", "{uid}");\n'
                "}\n",
                encoding="utf-8",
            )

            r = subprocess.run(
                [str(cf_agent), "-K", "-I", "-f", str(harness)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            combined_out = r.stdout + r.stderr
            if r.returncode != 0:
                problems.append(
                    f"user-render: cf-agent exited {r.returncode}: {combined_out.strip()}"
                )
            if "failed:" in combined_out or "refused:" in combined_out:
                problems.append(
                    f"user-render: unexpected refusal/failure in cf-agent output: {combined_out.strip()}"
                )
            rendered = work / "agents" / f"{CANARY_LABEL}.plist"
            if not rendered.is_file():
                problems.append(
                    f"user-render: cf-agent did not render {rendered.name} "
                    f"(rc={r.returncode}): {combined_out.strip()}"
                )
                return problems
            if not (work / "loaded" / CANARY_LABEL).is_file():
                problems.append(
                    f"user-render: launchctl stub did not record loaded state for {CANARY_LABEL}"
                )

            rendered_bytes = rendered.read_bytes()
            golden_bytes = GOLDEN_USER_PLIST.read_bytes()
            if rendered_bytes != golden_bytes:
                problems.append(
                    f"user-render: rendered {rendered.name} ({len(rendered_bytes)} bytes) "
                    f"is not byte-identical to {GOLDEN_USER_PLIST.relative_to(REPO)} ({len(golden_bytes)} bytes)"
                )

            mode = stat.S_IMODE(rendered.stat().st_mode)
            if mode != 0o644:
                problems.append(f"user-render: rendered plist mode is {oct(mode)}, expected 0o644")

            backups = list((work / "agents").glob("*.cf-*-edit"))
            if backups:
                problems.append(f"user-render: unexpected backup files left behind: {backups}")

            log_lines = stub_log.read_text(encoding="utf-8").splitlines()
            want_print = f"print\tgui/{uid}/{CANARY_LABEL}"
            want_boot = f"bootstrap\tgui/{uid}\t{rendered}"
            if want_print not in log_lines or want_boot not in log_lines:
                problems.append(
                    f"user-render: expected {want_print!r} and {want_boot!r} in launchctl log, got {log_lines!r}"
                )

            plutil = shutil.which("plutil")
            if plutil:
                pr = subprocess.run([plutil, "-lint", str(rendered)], capture_output=True, text=True)
                if pr.returncode != 0:
                    problems.append(
                        f"user-render: plutil -lint failed: {(pr.stderr or pr.stdout).strip()}"
                    )

            if not problems:
                ver = subprocess.run([str(cf_agent), "--version"], capture_output=True, text=True).stdout.splitlines()[0]
                print(
                    f"darwin-canary-user-render: OK ({ver}, user={user} uid={uid}, "
                    f"rendered byte-identical to {GOLDEN_USER_PLIST.relative_to(REPO)}, "
                    f"mode=0644, gui/{uid} bootstrap verified, plutil -lint OK)"
                )
    finally:
        os.umask(old_umask)
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--user-render",
        action="store_true",
        help="run a real unprivileged cf-agent user-domain render into a scratch dir and compare to user golden",
    )
    parser.add_argument(
        "--bindir",
        help="directory containing cf-agent/cf-promises/cf-key for --user-render (default: ~/opt/cfengine-dev/bin or PATH)",
    )
    args = parser.parse_args()

    lint = load("schema_lint", REPO / "bin" / "schema_lint.py")
    projector = load("projector", REPO / "bin" / "projector.py")
    schemas, registry = lint.load_schemas()
    problems: list[str] = []

    docs_by_name: dict[str, dict] = {}
    for goal_path, data_path in PAIRS:
        goal_name = goal_path.relative_to(HERE.parent)
        data_name = data_path.relative_to(HERE.parent)
        raw = goal_path.read_bytes()
        lint.check_canonical_bytes(raw, f"deploy/darwin/{goal_name}")
        doc = json.loads(raw)
        docs_by_name[goal_path.name] = doc
        loaded = {"goal-file.json": doc}
        lint.validate_loaded(loaded, schemas, registry, label_prefix=f"deploy/darwin/{goal_name}")
        lint.check_goal_file_cross_file(loaded, "goal-file.json")
        projected = projector.project(doc)
        if data_path.read_bytes() != projected:
            problems.append(f"deploy/darwin/{data_name} is not project(deploy/darwin/{goal_name})")

    parsed_goldens: dict[str, dict] = {}
    for domain, goal_key, golden_path in (
        ("system", "goal-file.json", GOLDEN_SYSTEM_PLIST),
        ("user", "goal-file-user.json", GOLDEN_USER_PLIST),
    ):
        if not golden_path.is_file():
            problems.append(f"missing committed golden: {golden_path.relative_to(REPO)}")
            continue
        goal_doc = docs_by_name.get(goal_key)
        if goal_doc is None:
            continue
        golden_bytes = golden_path.read_bytes()
        svc = goal_doc["domains"]["supervision"]["entries"]["service"][CANARY_LABEL]

        if not MUSTACHE_TEMPLATE.is_file():
            problems.append(f"missing template: {MUSTACHE_TEMPLATE.relative_to(REPO)}")
        else:
            expected_bytes = render_launchd_mustache(
                MUSTACHE_TEMPLATE.read_text(encoding="utf-8"), CANARY_LABEL, svc
            )
            if golden_bytes != expected_bytes:
                problems.append(
                    f"{golden_path.relative_to(REPO)} is not byte-identical to "
                    f"rendered {MUSTACHE_TEMPLATE.relative_to(REPO)}"
                )

        try:
            parsed = plistlib.loads(golden_bytes)
        except Exception as exc:
            problems.append(f"{golden_path.relative_to(REPO)}: invalid plist: {exc}")
        else:
            parsed_goldens[domain] = parsed
            expected = {
                "Label": CANARY_LABEL,
                "ProgramArguments": svc["command"],
                "WorkingDirectory": svc["working_dir"],
                "RunAtLoad": svc["unit"]["launchd"]["run_at_load"],
                "KeepAlive": svc["unit"]["launchd"]["keep_alive"],
            }
            if domain == "system":
                expected["UserName"] = svc["run_as"]
            if parsed != expected:
                problems.append(
                    f"{golden_path.relative_to(REPO)} does not match deploy/darwin/canary/{goal_key} "
                    f"(got {parsed!r}, expected {expected!r})"
                )

        plutil = shutil.which("plutil")
        if plutil:
            r = subprocess.run([plutil, "-lint", str(golden_path)], capture_output=True, text=True)
            if r.returncode != 0:
                problems.append(
                    f"plutil -lint failed on {golden_path.relative_to(REPO)}: "
                    f"{(r.stderr or r.stdout).strip()}"
                )
        else:
            print(f"SKIP (plutil not available): plutil -lint {golden_path.relative_to(REPO)}")

    if "system" in parsed_goldens and "user" in parsed_goldens:
        sys_p, usr_p = parsed_goldens["system"], parsed_goldens["user"]
        if "UserName" not in sys_p or "UserName" in usr_p:
            problems.append("system golden must carry UserName and user golden must omit UserName")
        else:
            sys_without_user = {k: v for k, v in sys_p.items() if k != "UserName"}
            if sys_without_user != usr_p:
                problems.append(
                    f"system and user goldens differ beyond UserName: {sys_without_user!r} != {usr_p!r}"
                )

    if args.user_render:
        problems.extend(run_user_render_check(args.bindir))

    for finding in lint.findings:
        problems.append(str(finding))
    if problems:
        for problem in problems:
            print(f"darwin-canary-check: FAIL: {problem}")
        return 1
    print(f"darwin-canary-check: OK ({len(PAIRS)} goal files, projections byte-identical, system+user goldens byte-identical)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
