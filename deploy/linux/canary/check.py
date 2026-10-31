#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml", "jsonschema>=4.21", "rfc3339-validator", "rfc8785"]
# ///
"""Hold the canary goal files and their projections to the same rails as examples/.

The canary is the first service tendcf enforces on a live Linux host
(linux-targets.md step 7). Its CMDB data is not hand-written: it is
`project(goal-file.json)`, and the goal file is canonical JCS bytes that
validate against goal-file.schema.json and pass the lint's cross-entry rules,
which is where a systemd entry's argv/working_dir alphabet is enforced. This
script runs that, reusing bin/schema_lint.py's own checks, and then requires
each `host_specific*.json` here to be byte-identical to the projection of its
goal file, so the data a host is given cannot drift from the file that was
reviewed.

Run from anywhere:  deploy/linux/canary/check.py   (exit 0 clean, 1 findings)
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]

PAIRS = (
    (HERE / "goal-file.json", HERE / "host_specific.json"),
    (HERE / "goal-file-absent.json", HERE / "host_specific-absent.json"),
    # The NixOS passthrough host (nixos-passthrough-plan.md section 4): the
    # unit namespace is nixos's, no service entries, so the projection is
    # empty and cf-agent has nothing to actuate there.
    (HERE.parent / "passthrough" / "goal-file.json", HERE.parent / "passthrough" / "host_specific.json"),
)


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    lint = load("schema_lint", REPO / "bin" / "schema_lint.py")
    projector = load("projector", REPO / "bin" / "projector.py")
    schemas, registry = lint.load_schemas()
    problems: list[str] = []

    for goal_path, data_path in PAIRS:
        goal_name = goal_path.relative_to(HERE.parent)
        data_name = data_path.relative_to(HERE.parent)
        raw = goal_path.read_bytes()
        lint.check_canonical_bytes(raw, f"deploy/linux/{goal_name}")
        doc = json.loads(raw)
        loaded = {"goal-file.json": doc}
        lint.validate_loaded(loaded, schemas, registry, label_prefix=f"deploy/linux/{goal_name}")
        lint.check_goal_file_cross_file(loaded, "goal-file.json")
        projected = projector.project(doc)
        if data_path.read_bytes() != projected:
            problems.append(f"deploy/linux/{data_name} is not project(deploy/linux/{goal_name})")

    for finding in lint.findings:
        problems.append(str(finding))
    if problems:
        for problem in problems:
            print(f"canary-check: FAIL: {problem}")
        return 1
    print(f"canary-check: OK ({len(PAIRS)} goal files, projections byte-identical)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
