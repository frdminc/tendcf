#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml", "jsonschema>=4.21", "rfc3339-validator", "rfc8785"]
# ///
"""Hold the darwin canary goal files, projections, and committed plist golden to the same rails as deploy/linux/canary/.

The darwin canary (`com.tendcf.canary.main`) is the service enforced on the
state-1 macOS VM (issue 70). Its CMDB data is `project(goal-file.json)`, its
goal files are canonical JCS bytes that validate against goal-file.schema.json
and pass cross-file lint, and its committed per-domain golden
(`tests/policy/golden/launchd/system/com.tendcf.canary.main.plist`) is
byte-compared against the rendered `policy/templates/launchd.plist.mustache`
template, parsed with `plistlib`, and checked with `plutil -lint` when
available (explicit SKIP on Linux where `plutil` is absent).

Note on `org.tendcf.execd`: `schema_version: 7` restricts `writer:
"tendcf-install"` to systemd hosts and requires `.*` prefixes on launchd
(`schema/goal-file.schema.json:154-161`), so `goal-file*.json` here omits a
`unit-writer` entry for `org.tendcf.execd` (schema v8 + launchd-writers
registry ruling tracked separately).

Run from anywhere:  deploy/darwin/canary/check.py   (exit 0 clean, 1 findings)
"""

from __future__ import annotations

import importlib.util
import json
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CANARY_LABEL = "com.tendcf.canary.main"
GOLDEN_PLIST = REPO / "tests" / "policy" / "golden" / "launchd" / "system" / f"{CANARY_LABEL}.plist"
MUSTACHE_TEMPLATE = REPO / "policy" / "templates" / "launchd.plist.mustache"

PAIRS = (
    (HERE / "goal-file.json", HERE / "host_specific.json"),
    (HERE / "goal-file-absent.json", HERE / "host_specific-absent.json"),
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
    out = template_text
    out = out.replace("{{id}}", service_id)
    out = out.replace("{{run_as}}", svc["run_as"])
    out = out.replace("{{working_dir}}", svc["working_dir"])

    def repl_cmd(m: re.Match[str]) -> str:
        inner = m.group(1)
        return "".join(inner.replace("{{.}}", arg) for arg in svc["command"])

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


def main() -> int:
    lint = load("schema_lint", REPO / "bin" / "schema_lint.py")
    projector = load("projector", REPO / "bin" / "projector.py")
    schemas, registry = lint.load_schemas()
    problems: list[str] = []

    present_doc = None
    for goal_path, data_path in PAIRS:
        goal_name = goal_path.relative_to(HERE.parent)
        data_name = data_path.relative_to(HERE.parent)
        raw = goal_path.read_bytes()
        lint.check_canonical_bytes(raw, f"deploy/darwin/{goal_name}")
        doc = json.loads(raw)
        if goal_path.name == "goal-file.json":
            present_doc = doc
        loaded = {"goal-file.json": doc}
        lint.validate_loaded(loaded, schemas, registry, label_prefix=f"deploy/darwin/{goal_name}")
        lint.check_goal_file_cross_file(loaded, "goal-file.json")
        projected = projector.project(doc)
        if data_path.read_bytes() != projected:
            problems.append(f"deploy/darwin/{data_name} is not project(deploy/darwin/{goal_name})")

    if not GOLDEN_PLIST.is_file():
        problems.append(f"missing committed golden: {GOLDEN_PLIST.relative_to(REPO)}")
    elif present_doc is not None:
        golden_bytes = GOLDEN_PLIST.read_bytes()
        svc = present_doc["domains"]["supervision"]["entries"]["service"][CANARY_LABEL]

        # 1. Exact byte-for-byte comparison against rendered mustache template.
        if not MUSTACHE_TEMPLATE.is_file():
            problems.append(f"missing template: {MUSTACHE_TEMPLATE.relative_to(REPO)}")
        else:
            expected_bytes = render_launchd_mustache(
                MUSTACHE_TEMPLATE.read_text(encoding="utf-8"), CANARY_LABEL, svc
            )
            if golden_bytes != expected_bytes:
                problems.append(
                    f"{GOLDEN_PLIST.relative_to(REPO)} is not byte-identical to "
                    f"rendered {MUSTACHE_TEMPLATE.relative_to(REPO)}"
                )

        # 2. Semantic plistlib validation.
        try:
            parsed = plistlib.loads(golden_bytes)
        except Exception as exc:
            problems.append(f"{GOLDEN_PLIST.relative_to(REPO)}: invalid plist: {exc}")
        else:
            expected = {
                "Label": CANARY_LABEL,
                "ProgramArguments": svc["command"],
                "UserName": svc["run_as"],
                "WorkingDirectory": svc["working_dir"],
                "RunAtLoad": svc["unit"]["launchd"]["run_at_load"],
                "KeepAlive": svc["unit"]["launchd"]["keep_alive"],
            }
            if parsed != expected:
                problems.append(
                    f"{GOLDEN_PLIST.relative_to(REPO)} does not match deploy/darwin/canary/goal-file.json "
                    f"(got {parsed!r}, expected {expected!r})"
                )

        # 3. plutil -lint when available (explicit SKIP on Linux where plutil is absent).
        plutil = shutil.which("plutil")
        if plutil:
            r = subprocess.run([plutil, "-lint", str(GOLDEN_PLIST)], capture_output=True, text=True)
            if r.returncode != 0:
                problems.append(
                    f"plutil -lint failed on {GOLDEN_PLIST.relative_to(REPO)}: "
                    f"{(r.stderr or r.stdout).strip()}"
                )
        else:
            print(f"SKIP (plutil not available): plutil -lint {GOLDEN_PLIST.relative_to(REPO)}")

    for finding in lint.findings:
        problems.append(str(finding))
    if problems:
        for problem in problems:
            print(f"darwin-canary-check: FAIL: {problem}")
        return 1
    print(f"darwin-canary-check: OK ({len(PAIRS)} goal files, projections byte-identical, golden byte-identical)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
