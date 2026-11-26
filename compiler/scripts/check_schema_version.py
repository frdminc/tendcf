"""Fail unless the tendcf compiler renders the goal-file version tendcf's schema requires.

    uv run python scripts/check_schema_version.py TENDCF_DIR

`tendcf.compile.GOAL_FILE_SCHEMA_VERSION` must equal the `const` of
`schema_version` in `TENDCF_DIR/schema/goal-file.schema.json`. A schema bump
that the compiler has not followed otherwise shows up only as a wall of
"/schema_version: N was expected" test failures.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from tendcf.compile import GOAL_FILE_SCHEMA_VERSION


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_schema_version.py TENDCF_DIR", file=sys.stderr)
        return 2
    path = Path(argv[1]) / "schema" / "goal-file.schema.json"
    try:
        const = json.loads(path.read_text())["properties"]["schema_version"]["const"]
    except (OSError, ValueError, KeyError) as exc:
        print(f"check_schema_version: cannot read the schema_version const from {path}: {exc!r}", file=sys.stderr)
        return 2
    if const != GOAL_FILE_SCHEMA_VERSION:
        print(
            f"check_schema_version: FAIL: tendcf compiler renders schema_version {GOAL_FILE_SCHEMA_VERSION} "
            f"but {path} requires {const}",
            file=sys.stderr,
        )
        return 1
    print(f"check_schema_version: ok: both are {const}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
