"""In-tree Linux systemd supervisor renderer stub (`plugins/supervisors/systemd/renderer.py`).

Loaded exclusively through tendcf's static in-tree plugin table
(`compiler/tendcf/plugins.py`).

The systemd unit renderer is planned for `docs/architecture/linux-targets.md`
§3 step 6. Until built, selecting any service for a systemd-supervised host is
a compile error, never a guess.
"""

from __future__ import annotations

from typing import Any

PLUGIN_KIND = "supervisor"
PLUGIN_NAME = "systemd"
SUPERVISOR_NAME = "systemd"
RENDERED = False


def refusal_message(host_name: str, selected_summary: str) -> str:
    return (
        f"host {host_name!r} has supervisor {SUPERVISOR_NAME!r}, whose unit renderer is "
        f"not built (tendcf linux-targets step 6); refusing selected service(s): {selected_summary}"
    )


def render_service_entry(
    record: dict[str, Any],
    *,
    bundle: str,
    where: str,
    schema_version: int,
) -> tuple[str | None, dict[str, Any] | None, list[str]]:
    del bundle, schema_version
    name = record.get("name", "<unnamed>")
    return None, None, [
        f"{where}: supervisor {SUPERVISOR_NAME!r} unit renderer is not built "
        f"(tendcf linux-targets step 6); refusing service {name!r}"
    ]
