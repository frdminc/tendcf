"""tendcf — the tendcf compiler tool.

Site Model (YAML/JSON, or a Nix expression evaluated to the same JSON)
-> merge -> conflict check -> render -> one canonical goal file per host.

The contract this consumes lives in tendcf (`schema/`, `examples/`,
`tools/schema_lint.py`, `tools/projector.py`); nothing here redefines it.
Current-design authority: `docs/paper/tendcf-architecture-guide.md`.
"""

__version__ = "0.0.1"
