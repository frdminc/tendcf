"""In-tree macOS launchd supervisor renderer (`plugins/supervisors/launchd/renderer.py`).

Loaded exclusively through tendcf's static in-tree plugin table
(`compiler/tendcf/plugins.py`).

Renders Site Model service records and `launchd-writers.yml` declarations into
goal-file v9 (`GOAL_FILE_SCHEMA_VERSION`) `supervision` entries, resolving
launchd defaults (`working_dir: "/"`, `run_at_load: false`, `keep_alive: false`,
`domain: "system"`). Never writes plists on a device: the policy bundle under
`policy/` actuates them after approval and projection.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

PLUGIN_KIND = "supervisor"
PLUGIN_NAME = "launchd"
SUPERVISOR_NAME = "launchd"
RENDERED = True

# Per-supervisor default for the REQUIRED `working_dir` (goal-file schema:
# "The compiler resolves the per-supervisor default ('/' for launchd and
# systemd system services, the service directory for runit) and states it").
WORKING_DIR_DEFAULT = "/"

# Site Model `launchd.run_at_load` / `keep_alive` are optional; the goal file
# requires both. Launchd treats omitted RunAtLoad and KeepAlive as false.
LAUNCHD_BOOL_DEFAULTS: dict[str, bool] = {"run_at_load": False, "keep_alive": False}

# Site Model `launchd.domain` is optional (services.schema.json v4); goal file
# v9 requires one of `system` | `user-gui` | `user-background`. Omitted resolves
# to `"system"` (operator rulings 2026-11-23 #94 and 2026-11-24 #103).
LAUNCHD_DOMAIN_DEFAULT = "system"
LAUNCHD_DOMAINS: tuple[str, ...] = ("system", "user-gui", "user-background")

# Installer-owned scheduler LaunchDaemon reserved exclusively for `tendcf-install`
# (issues #99, #102).
RESERVED_LAUNCHD_UNIT = "org.tendcf.execd"


def writer_key(writer: dict[str, Any]) -> str:
    """The unit-writer map key for a launchd-writers.yml entry (`prefix` or exact `label`)."""
    if "prefix" in writer:
        return writer["prefix"]
    return writer["label"]


def writer_matches(writer: dict[str, Any], label: str) -> bool:
    """Prefix `com.tendcf.example.*` matches `com.tendcf.example.x`, not `com.tendcf.examplex`;
    exact `label` matches only itself."""
    has_prefix = "prefix" in writer
    has_label = "label" in writer
    if has_prefix == has_label:
        return False
    if has_prefix:
        prefix = writer["prefix"]
        if not isinstance(prefix, str) or not prefix.endswith(".*"):
            return False
        return label.startswith(prefix[:-1])
    wlabel = writer["label"]
    return isinstance(wlabel, str) and label == wlabel


def keys_overlap(a: str, b: str) -> bool:
    """Do two launchd unit-writer keys overlap by literal text?

    Mirrors `tools/schema_lint.py:unit_keys_overlap`: two prefixes overlap when
    one starts with the other; a prefix and an exact label when the label starts
    with the prefix (including its trailing dot); two exact labels only when
    equal.
    """
    a_star, b_star = a.endswith("*"), b.endswith("*")
    if a_star and b_star:
        return a[:-1].startswith(b[:-1]) or b[:-1].startswith(a[:-1])
    if a_star:
        return b.startswith(a[:-1])
    if b_star:
        return keys_overlap(b, a)
    return a == b


def unit_key_covers(key: str, name: str) -> bool:
    """Does unit-writer `key` (prefix ending in `*` or exact name) cover `name`?"""
    if key.endswith("*"):
        return name.startswith(key[:-1])
    return name == key


def render_service_entry(
    record: dict[str, Any],
    *,
    bundle: str,
    where: str,
    schema_version: int,
) -> tuple[str | None, dict[str, Any] | None, list[str]]:
    """Render one Site Model service record into `(entry_id, entry_doc, errors)`."""
    errors: list[str] = []
    name = record.get("name", "<unnamed>")
    launchd = record["launchd"]
    launchd_domain = launchd.get("domain", LAUNCHD_DOMAIN_DEFAULT)
    if launchd_domain == "user":
        errors.append(
            f"{where}: service {name!r} sets stale v8 launchd.domain='user', "
            f"which schema_version {schema_version} removed. "
            "Resolution: choose 'user-gui' (Aqua GUI/Keychain) or "
            "'user-background' (headless/logout-surviving user/<uid>)"
        )
        return None, None, errors
    if launchd_domain not in LAUNCHD_DOMAINS:
        errors.append(
            f"{where}: service {name!r} sets invalid launchd.domain={launchd_domain!r} "
            f"(expected one of {list(LAUNCHD_DOMAINS)}). "
            "Resolution: set launchd.domain to 'system', 'user-gui', or 'user-background'"
        )
        return None, None, errors
    if launchd_domain in ("user-gui", "user-background") and record.get("runs_as") == "root":
        errors.append(
            f"{where}: service {name!r} sets launchd.domain={launchd_domain!r} "
            "with runs_as='root' — root cf-agent skips user-* domains and non-root "
            "cf-agent refuses run_as='root', so the entry can never converge. "
            "Resolution: use a non-root runs_as for user-* domains, or set launchd.domain='system'"
        )
        return None, None, errors

    launchd_bools = {k: launchd.get(k, default) for k, default in LAUNCHD_BOOL_DEFAULTS.items()}
    launchd_unit: dict[str, Any] = {"domain": launchd_domain, **launchd_bools}
    entry: dict[str, Any] = {
        "state": "present",
        "bundle": bundle,
        "run_as": record["runs_as"],
        "command": list(record["command"]),
        "working_dir": record.get("working_dir", WORKING_DIR_DEFAULT),
        "unit": {
            "launchd": launchd_unit,
        },
    }
    env = record.get("env") or {}
    if env:
        entry["env"] = dict(env)
    return launchd["label"], entry, errors


def render_unit_writers(
    writers: list[dict[str, Any]],
    *,
    where_fn: Callable[[Any], str],
    service_entries: dict[str, Any],
    coverage: str,
    site_domain: str,
    writers_path: Path,
) -> tuple[dict[str, Any], list[str]]:
    """Validate and render `launchd-writers.yml` into goal-file `unit-writer` entries."""
    errors: list[str] = []
    writer_entries: dict[str, Any] = {}
    seen_writers: list[tuple[str, str]] = []  # (key, source location)
    valid_writers: list[dict[str, Any]] = []

    for w in writers:
        where = where_fn(w)
        has_prefix = "prefix" in w
        has_label = "label" in w
        if has_prefix == has_label:
            errors.append(
                f"{where}: launchd unit-writer must declare exactly one of "
                "'prefix' or 'label'. Resolution: keep either `prefix` or `label`, "
                "not both or neither"
            )
            continue
        key = w["prefix"] if has_prefix else w["label"]
        if not isinstance(key, str) or not key:
            errors.append(
                f"{where}: launchd unit-writer key {key!r} must be a non-empty string. "
                "Resolution: provide a valid reverse-DNS prefix or exact label"
            )
            continue
        if unit_key_covers(key.lower(), RESERVED_LAUNCHD_UNIT) and not (
            not has_prefix
            and has_label
            and key == RESERVED_LAUNCHD_UNIT
            and w["writer"] == "tendcf-install"
        ):
            resolution = (
                "narrow the prefix or declare exact "
                f"`label: {RESERVED_LAUNCHD_UNIT}` with `writer: tendcf-install`"
            )
            errors.append(
                f"{where}: launchd unit-writer {key!r} (writer {w['writer']!r}) covers "
                f"reserved installer-owned label {RESERVED_LAUNCHD_UNIT!r} (case-insensitively), "
                f"which is reserved exclusively for exact label {RESERVED_LAUNCHD_UNIT!r} "
                f"with writer 'tendcf-install'. Resolution: {resolution}"
            )
            continue
        if w["writer"] == "tendcf-install":
            if not (not has_prefix and has_label and key == RESERVED_LAUNCHD_UNIT):
                errors.append(
                    f"{where}: launchd unit-writer {key!r} declares writer 'tendcf-install', "
                    f"which is reserved exclusively for exact label {RESERVED_LAUNCHD_UNIT!r}. "
                    f"Resolution: use exact `label: {RESERVED_LAUNCHD_UNIT}` or choose another writer"
                )
                continue
        valid_writers.append(w)
        conflict = False
        for prior_key, prior_where in seen_writers:
            if key == prior_key:
                errors.append(
                    f"launchd unit-writer {key!r} is declared twice: {prior_where} and "
                    f"{where}. Resolution: keep one declaration per unit-writer key"
                )
                conflict = True
                break
            if keys_overlap(key, prior_key):
                errors.append(
                    f"launchd unit-writer {key!r} ({where}) overlaps {prior_key!r} "
                    f"({prior_where}). Resolution: make prefixes and exact labels disjoint"
                )
                conflict = True
                break
        if conflict:
            continue
        seen_writers.append((key, where))
        writer_entries[key] = {"state": "present", "writer": w["writer"]}

    for entry_id in service_entries:
        owners = [w for w in valid_writers if writer_matches(w, entry_id)]
        if not owners:
            errors.append(
                f"service entry {entry_id!r} falls under no prefix or exact label declared in "
                f"{writers_path}. Resolution: declare its prefix or exact label with "
                "writer `cfengine`, or relabel the service"
            )
        elif len(owners) > 1:
            claimed = ", ".join(f"{writer_key(w)!r} ({where_fn(w)})" for w in owners)
            errors.append(
                f"service entry {entry_id!r} matches {len(owners)} launchd unit-writers: "
                f"{claimed}. Resolution: keep unit-writer prefixes and exact labels disjoint"
            )
        elif coverage == "comprehensive" and owners[0]["writer"] != "cfengine":
            owner_key = writer_key(owners[0])
            errors.append(
                f"service entry {entry_id!r} falls under unit-writer "
                f"{owner_key!r} whose writer is {owners[0]['writer']!r}, "
                f"but domain {site_domain!r} is comprehensive and cfengine would be "
                "a second writer. Resolution: change the writer or the label"
            )

    return writer_entries, errors
