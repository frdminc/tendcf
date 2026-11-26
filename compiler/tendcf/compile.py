"""The compile path: Site Model -> merged per-host picture -> conflict check ->
canonical goal file.

What this renders is the per-host **goal file** of guide §7 / paper §2.5,
checked by `schema/goal-file.schema.json` ("compiler output, consent object,
validator input"). It is *not* the CFEngine Augments file: that is produced
device-side, after approval, by tendcf's policy-free projector
(`tools/projector.py`; goal-file reconciliation §9). `tendcf compile --project`
runs that projector over this output as a preview only.

Per `docs/architecture/plugin-layout.md` §4 (D46 Step 4):
  - Renders ONLY the current `GOAL_FILE_SCHEMA_VERSION` (older-version
    rendering is removed until non-operator devices enroll).
  - Loads supervisor renderers (`launchd`, `systemd`, `runit`) strictly through
    the static in-tree plugin table (`tendcf.plugins.load_plugin`).
"""

from __future__ import annotations

import copy
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import rfc8785

from .plugins import PluginError, load_plugin
from .sitemodel import GOAL_FILE_SCHEMA, Schemas, SiteModel
from .workspace import (
    OverrideInput,
    WorkspaceError,
    format_overrides_summary,
    normalize_overrides,
    refuse_release_if_tainted,
)

# Must equal the `const` of `schema/goal-file.schema.json` `schema_version`;
# CI fails when it does not (.github/workflows/check.yml).
# Per D46 §4 ("Current schema version only"), this compiler renders ONLY this version.
GOAL_FILE_SCHEMA_VERSION = 9

# The one state domain the reference projector reads
# (`tools/projector.py:PROJECTING_DOMAIN`).
SUPERVISION_DOMAIN = "supervision"

# Installer-owned scheduler units reserved exclusively for `tendcf-install`
# (issue #102): never emitted as a cfengine service or covered by any other writer.
RESERVED_LAUNCHD_UNIT = "org.tendcf.execd"
RESERVED_SYSTEMD_UNIT = "tendcf-execd.service"
RESERVED_SYSTEMD_SERVICE_IDS = frozenset(
    {
        RESERVED_SYSTEMD_UNIT,
        "tendcf-execd",
        "tendcf-execd.timer",
        "tendcf-execd.socket",
        "tendcf-execd.path",
    }
)

HOST_KEY = re.compile(r"^ed25519:[0-9a-f]{64}\Z")
SUPERVISORS = ("launchd", "systemd", "runit", "nixos")
PLATFORM_SUPERVISORS = {
    "macos": ("launchd",),
    "linux": ("systemd", "runit", "nixos"),
}
NIXOS_REFUSAL = "host is nixos-supervised; its units are the Nix configuration's"

# `common.schema.json#/$defs/interlock` gives these as JSON Schema `default`s;
# the goal file forbids defaults, so the compiler states them.
INTERLOCK_EXPECT_EXIT_DEFAULT = 0
INTERLOCK_TIMEOUT_DEFAULT = 30

TOKEN = re.compile(r"^(service|port|path|class|package|device|network|secret):(.+)\Z")
UNCHECKED_TOKEN_KINDS = frozenset({"path", "secret"})


class CompileError(Exception):
    """The compile is refused. `findings` carries one line per reason."""

    def __init__(self, findings: list[str]) -> None:
        super().__init__("\n".join(findings))
        self.findings = findings


@dataclass(frozen=True)
class HostSpec:
    """Who we are rendering for."""

    name: str
    platform: str
    supervisor: str
    key: str
    device_trust: dict[str, Any]


@dataclass
class Selected:
    """One service record that applies to the host, with why."""

    record: dict[str, Any]
    reason: str  # "hosts" | "role:<name>"
    where: str


@dataclass
class CompileResult:
    goal_file: dict[str, Any]
    canonical: bytes
    diagnostics: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    overrides: tuple[OverrideInput, ...] = ()

    @property
    def tainted(self) -> bool:
        return bool(self.overrides)

    def assert_releasable(self) -> None:
        """Fail closed if any dev-only `--override-input` tainted this compile."""
        refuse_release_if_tainted(self.overrides)


def _is_reserved_systemd_service_id(service_id: str) -> bool:
    """True if `service_id` targets tendcf-execd.service (explicit, suffixless, or companion unit)."""
    return service_id in RESERVED_SYSTEMD_SERVICE_IDS


def _reserved_service_errors(selected: list[Selected]) -> list[str]:
    """Refuse any selected service targeting an installer-owned scheduler unit."""
    errors: list[str] = []
    for sel in selected:
        rec = sel.record
        name = rec.get("name", "<unnamed>")
        launchd_cfg = rec.get("launchd")
        launchd_label = launchd_cfg.get("label") if isinstance(launchd_cfg, dict) else None
        if isinstance(launchd_label, str) and (
            launchd_label.lower() == RESERVED_LAUNCHD_UNIT
            or _is_reserved_systemd_service_id(launchd_label)
        ):
            errors.append(
                f"{sel.where}: service {name!r} targets reserved installer-owned unit "
                f"{launchd_label!r} (owned exclusively by 'tendcf-install'). "
                "Resolution: remove this service or choose a non-reserved launchd label"
            )
        systemd_cfg = rec.get("systemd")
        systemd_unit = systemd_cfg.get("unit") if isinstance(systemd_cfg, dict) else None
        if isinstance(systemd_unit, str) and (
            _is_reserved_systemd_service_id(systemd_unit)
            or systemd_unit.lower() == RESERVED_LAUNCHD_UNIT
        ):
            errors.append(
                f"{sel.where}: service {name!r} targets reserved installer-owned unit "
                f"{systemd_unit!r} (owned exclusively by 'tendcf-install'). "
                "Resolution: remove this service or choose a non-reserved systemd unit name"
            )
    return errors


# --------------------------------------------------------------------------
# Stage 1: merge — which services, with which resolved values, on this host
# --------------------------------------------------------------------------

def select_services(model: SiteModel, host: HostSpec) -> tuple[list[Selected], list[str], list[str]]:
    """Return (selected, diagnostics, errors)."""
    services: list[dict[str, Any]] = model.services.data.get("services", [])
    roles: dict[str, Any] = model.roles.data.get("roles", {})
    selected: list[Selected] = []
    diagnostics: list[str] = []
    errors: list[str] = []

    for record in services:
        name = record.get("name", "<unnamed>")
        where = model.services.where(record)
        reason: str | None = None
        hosts = record.get("hosts") or []
        if host.name in hosts:
            reason = "hosts"
        role = record.get("role")
        if role is not None:
            if role not in roles:
                errors.append(
                    f"{where}: service {name!r} binds role {role!r}, which "
                    f"{model.roles.path} does not declare"
                )
                continue
            if roles[role].get("main") == host.name:
                reason = reason or f"role:{role}"
            elif host.name in (roles[role].get("backups") or []) or host.name in (
                roles[role].get("peers") or []
            ):
                diagnostics.append(
                    f"{where}: service {name!r}: host {host.name!r} is a backup/peer "
                    f"of role {role!r}; not rendered (only `main` receives a "
                    "role-bound service in this version)"
                )
        if reason is None:
            if not hosts and role is None:
                diagnostics.append(
                    f"{where}: service {name!r} has neither `hosts` nor `role`; "
                    "it is declared on no host and is not rendered"
                )
            continue

        platform = record.get("platform")
        if platform not in (host.platform, "any"):
            errors.append(
                f"{where}: service {name!r} is declared on host {host.name!r} "
                f"(via {reason}) but its platform is {platform!r} and the host is "
                f"{host.platform!r}. Resolution: fix `platform:` or `hosts:`/the "
                "role assignment so they agree"
            )
            continue

        managed_by = record.get("managed_by")
        if managed_by != "cfengine":
            diagnostics.append(
                f"{where}: service {name!r} is managed_by {managed_by!r}; only "
                "`cfengine` services render in this version — skipped"
            )
            continue

        selected.append(Selected(record, reason, where))

    return selected, diagnostics, errors


# --------------------------------------------------------------------------
# Stage 2: conflict check over the merged per-host picture
# --------------------------------------------------------------------------

def conflict_check(model: SiteModel, host: HostSpec, selected: list[Selected]) -> tuple[list[str], list[str]]:
    """Return (errors, diagnostics). Errors name resource, writers, values, fix."""
    errors: list[str] = []
    diagnostics: list[str] = []

    seen_names: dict[str, str] = {}
    for record in model.services.data.get("services", []):
        name = record.get("name")
        where = model.services.where(record)
        if name in seen_names:
            errors.append(
                f"service name {name!r} is declared twice: {seen_names[name]} and "
                f"{where}. Resolution: rename one; `name` is the id depends_on refers to"
            )
        else:
            seen_names[name] = where

    errors.extend(_reserved_service_errors(selected))

    by_id: dict[str, Selected] = {}
    for sel in selected:
        launchd = sel.record.get("launchd")
        if not isinstance(launchd, dict) or "label" not in launchd:
            continue
        entry_id = launchd["label"]
        if entry_id in by_id:
            prior = by_id[entry_id]
            errors.append(
                f"entry id {entry_id!r} on host {host.name!r} is claimed by two "
                f"services: {prior.record['name']!r} ({prior.where}) and "
                f"{sel.record['name']!r} ({sel.where}). Resolution: give one a "
                "different launchd label, or move one off this host"
            )
        else:
            by_id[entry_id] = sel

    providers: dict[str, list[Selected]] = {}
    for sel in selected:
        for token in sel.record.get("provides") or []:
            providers.setdefault(token, []).append(sel)
    for token, sels in sorted(providers.items()):
        if len(sels) > 1:
            writers = ", ".join(f"{s.record['name']!r} ({s.where})" for s in sels)
            errors.append(
                f"token {token!r} on host {host.name!r} is provided by {len(sels)} "
                f"services: {writers}. Resolution: only one may provide it — remove "
                "the duplicate `provides` entry, or move one service to another host"
            )

    provided = set(providers)
    for sel in selected:
        provided.add(f"service:{sel.record['name']}")  # auto-provide, guide §10
    roles = model.roles.data.get("roles", {})
    for role in roles.values():
        provided.update(role.get("provides") or [])
    unchecked: dict[str, int] = {}
    for sel in selected:
        for token in sel.record.get("requires") or []:
            if token in provided:
                continue
            m = TOKEN.match(token)
            kind = m.group(1) if m else "?"
            if kind in UNCHECKED_TOKEN_KINDS:
                unchecked[kind] = unchecked.get(kind, 0) + 1
                continue
            near = sorted(t for t in provided if t.startswith(kind + ":"))
            hint = f"; same-kind tokens present: {near}" if near else ""
            diagnostics.append(
                f"{sel.where}: service {sel.record['name']!r} requires {token!r}, "
                f"which nothing on host {host.name!r} provides{hint}"
            )
    for kind, count in sorted(unchecked.items()):
        diagnostics.append(
            f"{count} `requires` of kind {kind!r} on host {host.name!r} not checked: "
            "those tokens are provided by site registries the compiler is not wired to yet"
        )

    return errors, diagnostics


# --------------------------------------------------------------------------
# Stage 4: render (stage 3, inference, is deliberately absent)
# --------------------------------------------------------------------------

def _coverage(domain: dict[str, Any]) -> str:
    """Site Model boolean+reason -> goal file's single enum (reconciliation §4.1)."""
    if domain.get("comprehensive", True):
        return "comprehensive"
    return domain["opt_out_reason"]


def _supplied_supervisor_error(host: HostSpec) -> str | None:
    entries = host.device_trust.get("entries") if isinstance(host.device_trust, dict) else None
    if not isinstance(entries, dict) or "supervisor" not in entries:
        return None
    wanted = {"host": {"name": host.supervisor, "state": "present"}}
    if entries["supervisor"] == wanted:
        return None
    return (
        f"the supplied device-trust document carries supervisor entry "
        f"{entries['supervisor']!r}, but the host input says {host.supervisor!r} "
        f"(expected {wanted!r}). Resolution: make the document and --supervisor agree, "
        "or drop the entry from the document"
    )


def host_errors(host: HostSpec, schema_version: int = GOAL_FILE_SCHEMA_VERSION) -> list[str]:
    """Refusals that depend on the host's own facts, not on the Site Model."""
    errors: list[str] = []
    if not HOST_KEY.match(host.key):
        errors.append(f"host key {host.key!r} is not `ed25519:` + 64 lowercase hex")
    if isinstance(schema_version, bool) or schema_version != GOAL_FILE_SCHEMA_VERSION:
        errors.append(
            f"schema_version {schema_version!r} is not one this compiler renders "
            f"(only current schema_version {GOAL_FILE_SCHEMA_VERSION} is supported)"
        )
    if host.supervisor not in SUPERVISORS:
        errors.append(
            f"host {host.name!r}: supervisor {host.supervisor!r} is not one of "
            f"{list(SUPERVISORS)}. Resolution: state the host's supervisor; there is no default"
        )
    else:
        supplied = _supplied_supervisor_error(host)
        if supplied is not None:
            errors.append(supplied)
        allowed = PLATFORM_SUPERVISORS.get(host.platform)
        if allowed is None:
            errors.append(
                f"host {host.name!r} is {host.platform!r}; no supervisor is decided for "
                f"that platform (known: {sorted(PLATFORM_SUPERVISORS)})"
            )
        elif host.supervisor not in allowed:
            errors.append(
                f"host {host.name!r} is {host.platform!r} with supervisor "
                f"{host.supervisor!r}; a {host.platform} host has one of {list(allowed)}. "
                "Resolution: fix --platform or --supervisor"
            )
    return errors


def supervisor_refusals(
    host: HostSpec,
    selected: list[Selected],
    *,
    tendcf_root: Path | None = None,
) -> list[str]:
    """Selected services this host's supervisor cannot be given a unit for."""
    if not selected:
        return []
    names = ", ".join(f"{s.record['name']!r} ({s.where})" for s in selected)
    if host.supervisor == "nixos":
        return [
            f"host {host.name!r}: {NIXOS_REFUSAL}; refusing selected service(s): {names}. "
            "Resolution: move the service off this host, or declare it in the NixOS configuration"
        ]
    try:
        plugin = load_plugin("supervisor", host.supervisor, tendcf_root=tendcf_root)
    except PluginError as exc:
        return [str(exc)]
    if getattr(plugin, "RENDERED", False):
        return []
    return [plugin.refusal_message(host.name, names)]


def _trust_with_supervisor(host: HostSpec) -> tuple[dict[str, Any], list[str]]:
    """The device-trust domain with the host's `supervisor` entry stated."""
    trust = copy.deepcopy(host.device_trust)
    entries = trust.get("entries") if isinstance(trust, dict) else None
    if not isinstance(entries, dict):
        return trust, ["the supplied device-trust document has no `entries` object"]
    supplied = _supplied_supervisor_error(host)
    if supplied is not None:
        return trust, [supplied]
    entries["supervisor"] = {"host": {"name": host.supervisor, "state": "present"}}
    return trust, []


def render_goal_file(
    model: SiteModel,
    host: HostSpec,
    selected: list[Selected],
    schema_version: int = GOAL_FILE_SCHEMA_VERSION,
    *,
    tendcf_root: Path | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Build the goal-file document. Returns (document, errors)."""
    errors: list[str] = host_errors(host, schema_version)
    if not errors:
        errors = supervisor_refusals(host, selected, tendcf_root=tendcf_root)
    if not errors:
        errors = _reserved_service_errors(selected)
    if errors:
        return {}, errors
    supervisor = host.supervisor

    trust, errs = _trust_with_supervisor(host)
    if errs:
        return {}, errs
    domains: dict[str, Any] = {"device-trust": trust}
    doc: dict[str, Any] = {
        "schema_version": GOAL_FILE_SCHEMA_VERSION,
        "host": host.key,
        "domains": domains,
    }
    if supervisor == "nixos":
        domains[SUPERVISION_DOMAIN] = {"coverage": "deliberately-unmanaged"}
        return doc, errors
    if not selected:
        return doc, errors

    try:
        sup_plugin = load_plugin("supervisor", supervisor, tendcf_root=tendcf_root)
    except PluginError as exc:
        return {}, [str(exc)]

    site_domains: dict[str, Any] = model.services.data.get("domains", {})
    bundles: dict[str, Any] = model.services.data.get("bundles", {})

    used_domains = sorted({s.record["domain"] for s in selected})
    if len(used_domains) > 1:
        errors.append(
            f"host {host.name!r} draws cfengine-managed services from "
            f"{len(used_domains)} Site Model domains {used_domains}; the goal file "
            f"has one actuated domain ({SUPERVISION_DOMAIN!r}) and no decided "
            "mapping for several. Resolution: keep one host's services in one domain"
        )
        return doc, errors
    site_domain = used_domains[0]
    if site_domain not in site_domains:
        errors.append(f"domain {site_domain!r} is not declared under `domains`")
        return doc, errors
    coverage = _coverage(site_domains[site_domain])

    service_entries: dict[str, Any] = {}
    used_bundles: set[str] = set()
    for sel in selected:
        rec = sel.record
        bundle = rec["bundle"]
        if bundle not in bundles:
            errors.append(f"{sel.where}: bundle {bundle!r} is not declared under `bundles`")
            continue
        if bundles[bundle].get("domain") != site_domain:
            errors.append(
                f"{sel.where}: service {rec['name']!r} is in domain {site_domain!r} "
                f"but its bundle {bundle!r} belongs to domain "
                f"{bundles[bundle].get('domain')!r}. Resolution: a bundle and its "
                "members share one domain"
            )
            continue
        used_bundles.add(bundle)
        entry_id, entry, svc_errs = sup_plugin.render_service_entry(
            rec,
            bundle=bundle,
            where=sel.where,
            schema_version=GOAL_FILE_SCHEMA_VERSION,
        )
        if svc_errs:
            errors.extend(svc_errs)
            continue
        assert entry_id is not None and entry is not None
        service_entries[entry_id] = entry

    interlock_entries: dict[str, Any] = {}
    for bundle_id in sorted(used_bundles):
        for interlock in bundles[bundle_id].get("interlocks") or []:
            iid = interlock["id"]
            where = model.services.where(interlock)
            if iid in interlock_entries:
                errors.append(f"{where}: interlock id {iid!r} is declared twice")
                continue
            if iid in service_entries:
                errors.append(
                    f"{where}: interlock id {iid!r} collides with a service entry id; "
                    "the projector keeps one id space across kinds (P-6.7)"
                )
                continue
            if "defines_class" not in interlock:
                errors.append(
                    f"{where}: interlock {iid!r} has no `defines_class`; the goal "
                    "file requires one. Resolution: add `defines_class: <class>`"
                )
                continue
            pre = interlock["pre_action"]
            interlock_entries[iid] = {
                "state": "present",
                "bundle": bundle_id,
                "pre_action": {
                    "command": list(pre["command"]),
                    "expect_exit": pre.get("expect_exit", INTERLOCK_EXPECT_EXIT_DEFAULT),
                    "timeout_seconds": pre.get("timeout_seconds", INTERLOCK_TIMEOUT_DEFAULT),
                },
                "defines_class": interlock["defines_class"],
                "blocks": "enclosing-bundle",
                "report": True,
            }

    writers: list[dict[str, Any]] = model.launchd_writers.data.get("writers", [])
    writer_entries, writer_errs = sup_plugin.render_unit_writers(
        writers,
        where_fn=model.launchd_writers.where,
        service_entries=service_entries,
        coverage=coverage,
        site_domain=site_domain,
        writers_path=model.launchd_writers.path,
    )
    errors.extend(writer_errs)

    entries: dict[str, Any] = {}
    if service_entries:
        entries["service"] = service_entries
    if interlock_entries:
        entries["interlock"] = interlock_entries
    if writer_entries:
        entries["unit-writer"] = writer_entries
    if coverage == "deliberately-unmanaged" and entries:
        errors.append(
            f"domain {site_domain!r} is deliberately-unmanaged but declares "
            f"{len(service_entries)} cfengine-managed service(s); the goal file makes "
            "that unrepresentable. Resolution: change the coverage or the services"
        )
    domain_doc: dict[str, Any] = {"coverage": coverage}
    if entries:
        domain_doc["entries"] = entries
    domains[SUPERVISION_DOMAIN] = domain_doc
    return doc, errors


def _non_nfc(node: Any, path: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and not unicodedata.is_normalized("NFC", k):
                found.append(f"{path}/{k} (key)")
            found.extend(_non_nfc(v, f"{path}/{k}"))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found.extend(_non_nfc(v, f"{path}/{i}"))
    elif isinstance(node, str) and not unicodedata.is_normalized("NFC", node):
        found.append(path or "<root>")
    return found


def canonical_bytes(doc: dict[str, Any]) -> bytes:
    """RFC 8785 bytes, no trailing newline — the bytes are the contract."""
    try:
        return rfc8785.dumps(doc)
    except Exception as exc:  # noqa: BLE001 - rfc8785 raises several types
        raise CompileError([f"goal file carries a value JCS cannot represent: {type(exc).__name__}: {exc}"]) from exc


def compile_host(
    model: SiteModel,
    host: HostSpec,
    schemas: Schemas | None = None,
    schema_version: int = GOAL_FILE_SCHEMA_VERSION,
    overrides: Iterable[OverrideInput] | Mapping[str, Path | str] | None = None,
    *,
    tendcf_root: Path | None = None,
) -> CompileResult:
    """The whole path for one host. Raises CompileError; never emits a wrong file.

    Renders ONLY `GOAL_FILE_SCHEMA_VERSION` (9); any other `schema_version` is
    refused.
    """
    try:
        override_tuple = normalize_overrides(overrides)
    except WorkspaceError as exc:
        raise CompileError([str(exc)]) from exc
    errors: list[str] = host_errors(host, schema_version)
    diagnostics: list[str] = []
    if override_tuple:
        diagnostics.append(
            f"TAINTED (not releasable): dev-only --override-input active "
            f"({format_overrides_summary(override_tuple)}); foreign-input substitution "
            "is not yet wired into compile_host"
        )

    selected, diag, errs = select_services(model, host)
    diagnostics += diag
    errors += errs
    if host.supervisor in SUPERVISORS:
        errors += supervisor_refusals(host, selected, tendcf_root=tendcf_root)
    if errors:
        raise CompileError(errors)

    errs, diag = conflict_check(model, host, selected)
    errors += errs
    diagnostics += diag
    if errors:
        raise CompileError(errors)

    doc, errs = render_goal_file(
        model, host, selected, schema_version, tendcf_root=tendcf_root
    )
    errors += errs
    if errors:
        raise CompileError(errors)

    bad = _non_nfc(doc)
    if bad:
        raise CompileError([f"not NFC-normalized (JCS cannot see this; reconciliation §2.1): {p}" for p in bad])

    if schemas is not None:
        problems = schemas.errors(GOAL_FILE_SCHEMA, doc)
        if problems:
            raise CompileError(
                [f"rendered goal file fails {GOAL_FILE_SCHEMA}: {p}" for p in problems]
            )
    else:
        diagnostics.append(
            "no tendcf schema directory found (not inside a tendcf checkout): the rendered "
            "goal file was NOT validated against goal-file.schema.json (pass --tendcf or set TENDCF_DIR)"
        )

    raw = canonical_bytes(doc)
    return CompileResult(
        goal_file=doc,
        canonical=raw,
        diagnostics=diagnostics,
        overrides=override_tuple,
    )
