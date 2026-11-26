#!/usr/bin/env python3
"""Pure-stdlib tamper-evident audit log, redaction gate, offline spool,
append-only SSH sink receiver, and forensic verifier (issue #119).

Runs under `python3 -I -S` with zero third-party packages, matching
`tools/projector.py` and `tools/approval_enforce.py`'s bare-host stdlib
guarantee and passing `tools/device_boundary_lint.py`.

Implements the shared envelope contract from `djbclark/djbclark-ade#1013` and
`frdminc/tendcf#119`:
  - Envelope: `v`, `src`, `host`, `boot_id`, `seq`, `ts`, `mono_ms`, `prev`,
    `type`, `data`, `h`, where `h = "sha256:" + SHA-256(ascii(prev) || jcs(entry_without_h))`.
  - Canonicalization & strict JSON parsing: reuses `tools/projector.py`'s
    pure-stdlib RFC 8785 JCS serializer and duplicate-key rejection.
  - Redaction gate: closed allowlist of event types and per-type fields
    (`additionalProperties: false`) plus recursive key/value redaction guards
    so CMDB values, goal-file/config contents, command output, env vars,
    secrets, key material, and consent free-text cannot enter the audit stream.
  - Local spool (`AuditSpool`): crash-safe append-only local capture + durable
    cursor (`0700` dir, `0600` files, `O_NOFOLLOW` + `fstat` regular-file
    checks, advisory `flock`, `fsync` before cursor advance). Never contacts
    the network and never blocks `cf-agent`.
  - Offline shipper (`AuditShipper` + `make_ssh_append_transport`): ships
    unshipped spool records in bounded batches over hardened non-interactive
    SSH (`BatchMode=yes`, `IdentitiesOnly=yes`, `StrictHostKeyChecking=yes`,
    dedicated write-only key, no forwarding/PTY). Survives unreachable sinks
    without losing or skipping records and resumes cleanly on reconnect.
  - Append-only sink receiver (`AuditSink` + `run_forced_command`): bound to
    pinned `(expected_host, expected_src)` from SSH `authorized_keys` forced
    command. Strictly refuses read/list/rename/truncate/delete commands,
    appends valid records to `<sink_root>/<host>/<src>/YYYY-MM-DD.jsonl` via
    `O_APPEND | O_NOFOLLOW`, deduplicates idempotent retries, and quarantines
    gaps, forks, hash mismatches, or invalid records into `quarantine.jsonl`
    without storing unredacted raw secret material.
  - Forensic verifier (`verify_local_against_sink`) and intermittent-host
    liveness (`check_host_liveness`): flags deleted, truncated, edited, or
    forked local logs against the off-device sink copy, and reports silent
    hosts as `"unknown"`, never `"fine"`.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import errno
import fcntl
import hashlib
import hmac
import importlib.util
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator


# ---------------------------------------------------------------------------
# Load sibling tools/projector.py for pure-stdlib RFC 8785 JCS canonicalization
# ---------------------------------------------------------------------------

def _load_projector_module() -> Any:
    proj_path = Path(__file__).resolve().with_name("projector.py")
    spec = importlib.util.spec_from_file_location("_tendcf_projector_jcs", proj_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load projector module at {proj_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return mod


_PROJECTOR = _load_projector_module()


# ---------------------------------------------------------------------------
# Constants, regexes, and closed vocabularies
# ---------------------------------------------------------------------------

ENVELOPE_VERSION = 1
DEFAULT_SRC = "tendcf"
GENESIS_PREV = "sha256:" + ("0" * 64)
MAX_SAFE_INT = 2**53 - 1
MAX_LINE_BYTES = 65536
MAX_BATCH_BYTES = 4 * 1024 * 1024
MAX_STRING_LEN = 256

ENVELOPE_REQUIRED_KEYS = frozenset(
    {"v", "src", "host", "boot_id", "seq", "ts", "mono_ms", "prev", "type", "data", "h"}
)
ENVELOPE_UNSIGNED_KEYS = ENVELOPE_REQUIRED_KEYS - {"h"}

SRC_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}\Z")
HOST_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}\Z")
RELEASE_STAMP_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}\Z")
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}\Z")
BOOT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}\Z")
KEY_ID_RE = re.compile(r"^ed25519:[0-9a-f]{64}\Z")
GRANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}\Z")
ENTRY_RE = re.compile(r"^[A-Za-z0-9/_.:@+-]{1,128}\Z")
ABS_PATH_RE = re.compile(r"^/[A-Za-z0-9._+@:,/-]{1,255}\Z")
UNIT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}\Z")
PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.+:-]{0,127}\Z")
VERSION_STR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}\Z")
DAY_FILE_RE = re.compile(r"^([0-9]{4}-[0-9]{2}-[0-9]{2})\.jsonl\Z")
SSH_TARGET_RE = re.compile(r"^[A-Za-z0-9._-]+(?:@[A-Za-z0-9._:-]+)?\Z")
UTC_TS_RE = re.compile(
    r"^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(?:\.([0-9]{1,9}))?Z\Z"
)

EVENT_TYPES = frozenset(
    {
        "release_decision",
        "consent_decision",
        "promise_outcome",
        "service_change",
        "package_change",
        "trust_change",
        "lifecycle",
        "tripwire",
        "heartbeat",
    }
)

OUTCOMES_ENFORCE = frozenset({"success", "repaired", "error", "n-a"})
OUTCOMES_AUDIT = frozenset({"compliant", "noncompliant", "error", "n-a"})

# Belt-and-suspenders forbidden field names (even beyond closed per-type schemas).
FORBIDDEN_KEY_NAMES = frozenset(
    {
        "vars",
        "cmdb",
        "cmdb_values",
        "env",
        "environment",
        "secret",
        "secrets",
        "password",
        "passwd",
        "token",
        "api_key",
        "private_key",
        "key_material",
        "stdout",
        "stderr",
        "output",
        "command_output",
        "content",
        "contents",
        "goal_file",
        "host_specific",
        "message",
        "typed_text",
        "raw_input",
        "reason",
        "reason_text",
        "prompt",
    }
)

# Belt-and-suspenders value-level secret/content leakage markers.
FORBIDDEN_VALUE_SUBSTRINGS = (
    "-----BEGIN ",
    "PRIVATE KEY",
    "ssh-rsa ",
    "ssh-ed25519 ",
    "ghp_",
    "gho_",
    "github_pat_",
    "AKIA",
    "Bearer ",
    "xoxb-",
    "xoxp-",
    '"vars":',
    '"host_specific"',
    '"goal-file"',
    '"schema_version"',
)


# ---------------------------------------------------------------------------
# Exceptions and result dataclasses
# ---------------------------------------------------------------------------

class AuditError(Exception):
    """Base error for tendcf audit logging."""


class AuditValidationError(AuditError):
    """Envelope or event payload failed schema, canonicalization, or redaction."""


class AuditRedactionError(AuditValidationError):
    """Payload attempted to log forbidden content (secrets, CMDB values, etc.)."""


class AuditFileSecurityError(AuditError):
    """Unsafe path, symlink, FIFO, device, or permission violation."""


class ChainTamperError(AuditError):
    """Local audit chain disagrees with persisted cursor or integrity checks."""


class TransportError(AuditError):
    """Off-device shipping transport failed (offline, timeout, bad ack, etc.)."""


class ForcedCommandError(AuditError):
    """Client invoked a disallowed or unsafe command on the append-only sink."""


@dataclasses.dataclass(frozen=True)
class ShipResult:
    ok: bool
    shipped: int
    duplicates: int
    quarantined: int
    remaining: int
    last_acked_seq: int
    last_acked_h: str | None
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class SinkIngestResult:
    ok: bool
    host: str
    src: str
    last_seq: int
    last_h: str | None
    accepted: int
    duplicates: int
    quarantined: int

    def to_ack_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "host": self.host,
            "src": self.src,
            "last_seq": self.last_seq,
            "last_h": self.last_h,
            "accepted": self.accepted,
            "duplicates": self.duplicates,
            "quarantined": self.quarantined,
        }


@dataclasses.dataclass(frozen=True)
class TamperFinding:
    code: str
    seq: int | None
    detail: str


@dataclasses.dataclass(frozen=True)
class VerifyReport:
    ok: bool
    local_count: int
    sink_count: int
    quarantine_count: int
    findings: tuple[TamperFinding, ...]


@dataclasses.dataclass(frozen=True)
class LivenessReport:
    status: str  # "ok" or "unknown" (never "fine")
    reason: str
    host: str
    src: str
    last_seq: int
    last_receive_ts: str | None
    last_heartbeat_receive_ts: str | None
    silence_seconds: float | None
    quarantine_count: int


# ---------------------------------------------------------------------------
# Strict RFC 8259 / RFC 8785 JSON helpers
# ---------------------------------------------------------------------------

def _reject_nonfinite(token: str) -> Any:
    raise AuditValidationError(f"non-finite JSON constant rejected: {token!r}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise AuditValidationError(f"duplicate JSON object key: {k!r}")
        out[k] = v
    return out


def _check_json_tree(node: Any, *, depth: int = 0) -> None:
    if depth > 16:
        raise AuditValidationError("JSON nesting depth exceeds limit")
    if isinstance(node, dict):
        for k, v in node.items():
            if not isinstance(k, str):
                raise AuditValidationError("JSON object key must be string")
            _check_safe_string(k, field="key")
            _check_json_tree(v, depth=depth + 1)
    elif isinstance(node, list):
        raise AuditValidationError("lists are not permitted in audit envelope payloads")
    elif isinstance(node, str):
        _check_safe_string(node, field="value")
    elif isinstance(node, bool):
        return
    elif isinstance(node, int):
        if node < -MAX_SAFE_INT or node > MAX_SAFE_INT:
            raise AuditValidationError(f"integer out of RFC 8785 safe range: {node}")
    elif isinstance(node, float):
        raise AuditValidationError("floating-point numbers are not permitted in audit envelopes")
    elif node is None:
        raise AuditValidationError("null values are not permitted in audit envelopes (omit optional fields)")
    else:
        raise AuditValidationError(f"unsupported JSON value type: {type(node).__name__}")


def _check_safe_string(s: str, *, field: str) -> None:
    if len(s) > MAX_STRING_LEN:
        raise AuditRedactionError(f"{field} exceeds maximum length ({MAX_STRING_LEN})")
    for ch in s:
        cp = ord(ch)
        if cp < 0x20 or cp == 0x7F:
            raise AuditRedactionError(f"{field} contains forbidden control character U+{cp:04X}")
        if 0xD800 <= cp <= 0xDFFF:
            raise AuditValidationError(f"{field} contains lone surrogate U+{cp:04X}")
    if unicodedata.normalize("NFC", s) != s:
        raise AuditValidationError(f"{field} is not Unicode NFC normalized")


def strict_json_loads(raw: bytes | str) -> dict[str, Any]:
    """Parse one canonical JSON object strictly (RFC 8259, no dup keys/NaN/BOM)."""
    if isinstance(raw, bytes):
        if len(raw) > MAX_LINE_BYTES:
            raise AuditValidationError(f"JSON line exceeds {MAX_LINE_BYTES} bytes")
        if b"\x00" in raw or b"\r" in raw:
            raise AuditValidationError("JSON line contains NUL or CR byte")
        if raw.startswith(b"\xef\xbb\xbf"):
            raise AuditValidationError("UTF-8 BOM is forbidden")
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise AuditValidationError(f"invalid UTF-8: {exc}") from exc
    else:
        if len(raw.encode("utf-8", errors="surrogatepass")) > MAX_LINE_BYTES:
            raise AuditValidationError(f"JSON line exceeds {MAX_LINE_BYTES} bytes")
        if "\x00" in raw or "\r" in raw:
            raise AuditValidationError("JSON line contains NUL or CR")
        text = raw
    try:
        obj = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except AuditValidationError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise AuditValidationError(f"malformed JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise AuditValidationError("JSON root must be an object")
    return obj


def jcs_dumps(obj: Any) -> bytes:
    """Serialize `obj` to RFC 8785 JCS canonical UTF-8 bytes (pure stdlib via projector.py)."""
    return bytes(_PROJECTOR._jcs_dumps(obj))


def parse_utc_timestamp(ts: str) -> datetime.datetime:
    """Parse and calendar-validate a UTC RFC 3339 timestamp with trailing `Z`."""
    if not isinstance(ts, str):
        raise AuditValidationError("timestamp must be a string")
    m = UTC_TS_RE.match(ts)
    if not m:
        raise AuditValidationError(f"invalid UTC RFC 3339 timestamp: {ts!r}")
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    frac = m.group(7) or ""
    micro = int(frac.ljust(6, "0")[:6]) if frac else 0
    try:
        return datetime.datetime(
            year, month, day, hour, minute, second, micro, tzinfo=datetime.timezone.utc
        )
    except ValueError as exc:
        raise AuditValidationError(f"non-existent calendar date in timestamp {ts!r}: {exc}") from exc


def utc_now_str() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _detect_boot_id() -> str:
    """Best-effort host boot identifier (Linux boot_id, macOS sysctl, else process-stable fallback)."""
    linux_boot = Path("/proc/sys/kernel/random/boot_id")
    if linux_boot.is_file() and not linux_boot.is_symlink():
        try:
            val = linux_boot.read_text(encoding="ascii").strip()
            if BOOT_ID_RE.match(val):
                return val
        except OSError:
            pass
    if sys.platform == "darwin":
        try:
            proc = subprocess.run(
                ["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if proc.returncode == 0:
                val = proc.stdout.strip()
                if BOOT_ID_RE.match(val):
                    return val
        except OSError:
            pass
    return f"boot-{os.getpid()}-{secrets.token_hex(8)}"


# ---------------------------------------------------------------------------
# Redaction gate and closed event-data validation
# ---------------------------------------------------------------------------

def _is_exact_int(val: Any) -> bool:
    return type(val) is int


def _require_regex(val: Any, rx: re.Pattern[str], field: str) -> str:
    if not isinstance(val, str):
        raise AuditValidationError(f"{field} must be a string")
    _check_redaction_value(val, field=field)
    if not rx.match(val):
        raise AuditValidationError(f"{field} failed format validation: {val!r}")
    return val


def _require_abs_path(val: Any, field: str) -> str:
    s = _require_regex(val, ABS_PATH_RE, field)
    if ".." in s.split("/") or "//" in s:
        raise AuditValidationError(f"{field} must be a normalized path without '..' or '//': {s!r}")
    return s


def _require_enum(val: Any, allowed: frozenset[str], field: str) -> str:
    if not isinstance(val, str) or val not in allowed:
        raise AuditValidationError(f"{field} must be one of {sorted(allowed)}, got {val!r}")
    return val


def _check_redaction_value(val: str, *, field: str) -> None:
    _check_safe_string(val, field=field)
    for marker in FORBIDDEN_VALUE_SUBSTRINGS:
        if marker in val:
            raise AuditRedactionError(f"{field} contains forbidden secret/content marker {marker!r}")


def _check_keys_allowed(
    data: dict[str, Any],
    *,
    required: frozenset[str],
    optional: frozenset[str],
    event_type: str,
) -> None:
    for k in data:
        if not isinstance(k, str):
            raise AuditValidationError(f"{event_type}: key must be string")
        if k.lower() in FORBIDDEN_KEY_NAMES:
            raise AuditRedactionError(f"{event_type}: forbidden field {k!r} blocked by redaction gate")
    allowed = required | optional
    extra = set(data.keys()) - allowed
    if extra:
        raise AuditRedactionError(
            f"{event_type}: disallowed extra field(s) {sorted(extra)} blocked by closed allowlist"
        )
    missing = required - set(data.keys())
    if missing:
        raise AuditValidationError(f"{event_type}: missing required field(s) {sorted(missing)}")


def validate_event_data(event_type: str, data: Any) -> None:
    """Validate and enforce the strict redaction allowlist on event `data`."""
    if not isinstance(event_type, str) or event_type not in EVENT_TYPES:
        raise AuditValidationError(f"unsupported audit event type: {event_type!r}")
    if not isinstance(data, dict):
        raise AuditValidationError(f"{event_type}: data must be a JSON object")
    _check_json_tree(data)

    if event_type == "release_decision":
        _check_keys_allowed(
            data,
            required=frozenset({"release", "release_sha256", "goal_sha256", "projection_sha256", "verdict"}),
            optional=frozenset({"validator_version"}),
            event_type=event_type,
        )
        _require_regex(data["release"], RELEASE_STAMP_RE, "data.release")
        _require_regex(data["release_sha256"], SHA256_RE, "data.release_sha256")
        _require_regex(data["goal_sha256"], SHA256_RE, "data.goal_sha256")
        _require_regex(data["projection_sha256"], SHA256_RE, "data.projection_sha256")
        _require_enum(data["verdict"], frozenset({"pass", "fail", "refused"}), "data.verdict")
        if "validator_version" in data:
            _require_regex(data["validator_version"], RELEASE_STAMP_RE, "data.validator_version")

    elif event_type == "consent_decision":
        _check_keys_allowed(
            data,
            required=frozenset({"verdict", "key_id", "decided_at", "decision_sha256", "ceremony_class"}),
            optional=frozenset({"grant_id"}),
            event_type=event_type,
        )
        _require_enum(data["verdict"], frozenset({"accept", "reject", "withdraw"}), "data.verdict")
        _require_regex(data["key_id"], KEY_ID_RE, "data.key_id")
        parse_utc_timestamp(data["decided_at"])
        _require_regex(data["decision_sha256"], SHA256_RE, "data.decision_sha256")
        _require_enum(data["ceremony_class"], frozenset({"ordinary", "privileged", "baseline"}), "data.ceremony_class")
        if "grant_id" in data:
            _require_regex(data["grant_id"], GRANT_ID_RE, "data.grant_id")

    elif event_type == "promise_outcome":
        _check_keys_allowed(
            data,
            required=frozenset({"release", "domain", "bundle", "entry", "mode", "outcome"}),
            optional=frozenset({"blocked_by_interlock"}),
            event_type=event_type,
        )
        _require_regex(data["release"], RELEASE_STAMP_RE, "data.release")
        _require_regex(data["domain"], IDENTIFIER_RE, "data.domain")
        _require_regex(data["bundle"], IDENTIFIER_RE, "data.bundle")
        _require_regex(data["entry"], ENTRY_RE, "data.entry")
        mode = _require_enum(data["mode"], frozenset({"enforce", "audit"}), "data.mode")
        if mode == "enforce":
            _require_enum(data["outcome"], OUTCOMES_ENFORCE, "data.outcome")
        else:
            _require_enum(data["outcome"], OUTCOMES_AUDIT, "data.outcome")
        if "blocked_by_interlock" in data:
            _require_regex(data["blocked_by_interlock"], IDENTIFIER_RE, "data.blocked_by_interlock")

    elif event_type == "service_change":
        _check_keys_allowed(
            data,
            required=frozenset({"action", "supervisor", "unit", "path"}),
            optional=frozenset({"new_sha256", "prev_sha256"}),
            event_type=event_type,
        )
        action = _require_enum(data["action"], frozenset({"install", "change", "remove"}), "data.action")
        _require_enum(data["supervisor"], frozenset({"launchd", "systemd", "runit"}), "data.supervisor")
        _require_regex(data["unit"], UNIT_NAME_RE, "data.unit")
        _require_abs_path(data["path"], "data.path")
        if action == "remove":
            if "new_sha256" in data:
                raise AuditValidationError("service_change: new_sha256 is forbidden when action == 'remove'")
        else:
            if "new_sha256" not in data:
                raise AuditValidationError(f"service_change: new_sha256 is required when action == {action!r}")
            _require_regex(data["new_sha256"], SHA256_RE, "data.new_sha256")
        if "prev_sha256" in data:
            _require_regex(data["prev_sha256"], SHA256_RE, "data.prev_sha256")

    elif event_type == "package_change":
        _check_keys_allowed(
            data,
            required=frozenset({"action", "package"}),
            optional=frozenset({"version", "prev_version"}),
            event_type=event_type,
        )
        _require_enum(data["action"], frozenset({"install", "upgrade", "remove"}), "data.action")
        _require_regex(data["package"], PACKAGE_NAME_RE, "data.package")
        if "version" in data:
            _require_regex(data["version"], VERSION_STR_RE, "data.version")
        if "prev_version" in data:
            _require_regex(data["prev_version"], VERSION_STR_RE, "data.prev_version")

    elif event_type == "trust_change":
        _check_keys_allowed(
            data,
            required=frozenset({"kind", "action"}),
            optional=frozenset({"key_id", "new_sha256", "prev_sha256"}),
            event_type=event_type,
        )
        _require_enum(
            data["kind"],
            frozenset({"advisor_key", "peer_allowlist", "trust_policy", "emergency_revocation"}),
            "data.kind",
        )
        _require_enum(data["action"], frozenset({"add", "update", "remove", "revoke"}), "data.action")
        if "key_id" in data:
            _require_regex(data["key_id"], KEY_ID_RE, "data.key_id")
        if "new_sha256" in data:
            _require_regex(data["new_sha256"], SHA256_RE, "data.new_sha256")
        if "prev_sha256" in data:
            _require_regex(data["prev_sha256"], SHA256_RE, "data.prev_sha256")

    elif event_type == "lifecycle":
        _check_keys_allowed(
            data,
            required=frozenset({"action", "release"}),
            optional=frozenset({"prefix_sha256", "policy_sha256", "projector_sha256"}),
            event_type=event_type,
        )
        _require_enum(data["action"], frozenset({"install", "rollback", "uninstall"}), "data.action")
        _require_regex(data["release"], RELEASE_STAMP_RE, "data.release")
        for fld in ("prefix_sha256", "policy_sha256", "projector_sha256"):
            if fld in data:
                _require_regex(data[fld], SHA256_RE, f"data.{fld}")

    elif event_type == "tripwire":
        _check_keys_allowed(
            data,
            required=frozenset({"tool", "event", "path"}),
            optional=frozenset({"expected_sha256", "observed_sha256"}),
            event_type=event_type,
        )
        _require_enum(
            data["tool"],
            frozenset({"aide", "tripwire", "auditd", "eslogger", "osquery"}),
            "data.tool",
        )
        _require_enum(
            data["event"],
            frozenset({"modified", "created", "deleted", "permission_change", "unexpected_exec", "decoy_read"}),
            "data.event",
        )
        _require_abs_path(data["path"], "data.path")
        for fld in ("expected_sha256", "observed_sha256"):
            if fld in data:
                _require_regex(data[fld], SHA256_RE, f"data.{fld}")

    elif event_type == "heartbeat":
        _check_keys_allowed(
            data,
            required=frozenset({"running_release", "goal_sha256", "projection_sha256", "converged"}),
            optional=frozenset({"unshipped_count"}),
            event_type=event_type,
        )
        _require_regex(data["running_release"], RELEASE_STAMP_RE, "data.running_release")
        _require_regex(data["goal_sha256"], SHA256_RE, "data.goal_sha256")
        _require_regex(data["projection_sha256"], SHA256_RE, "data.projection_sha256")
        if type(data["converged"]) is not bool:
            raise AuditValidationError("heartbeat: data.converged must be a boolean")
        if "unshipped_count" in data:
            cnt = data["unshipped_count"]
            if not _is_exact_int(cnt) or cnt < 0 or cnt > MAX_SAFE_INT:
                raise AuditValidationError("heartbeat: data.unshipped_count must be a non-negative integer")


def compute_envelope_hash(entry_without_h: dict[str, Any]) -> str:
    """Compute `sha256:<hex>` = SHA-256(ascii(prev) || rfc8785_jcs(entry_without_h))."""
    if "h" in entry_without_h:
        raise AuditValidationError("entry_without_h must not contain 'h'")
    prev = entry_without_h.get("prev")
    if not isinstance(prev, str) or not SHA256_RE.match(prev):
        raise AuditValidationError(f"invalid prev hash: {prev!r}")
    canonical = jcs_dumps(entry_without_h)
    digest = hashlib.sha256(prev.encode("ascii") + canonical).hexdigest()
    return f"sha256:{digest}"


def build_envelope(
    *,
    host: str,
    src: str = DEFAULT_SRC,
    boot_id: str,
    seq: int,
    prev: str,
    event_type: str,
    data: dict[str, Any],
    ts: str | None = None,
    mono_ms: int | None = None,
) -> dict[str, Any]:
    """Construct, validate, redact-check, and hash-seal a canonical v1 audit envelope."""
    body: dict[str, Any] = {
        "v": ENVELOPE_VERSION,
        "src": src,
        "host": host,
        "boot_id": boot_id,
        "seq": seq,
        "ts": ts if ts is not None else utc_now_str(),
        "mono_ms": mono_ms if mono_ms is not None else (time.monotonic_ns() // 1_000_000),
        "prev": prev,
        "type": event_type,
        "data": data,
    }
    _validate_envelope_fields(body, require_h=False)
    h = compute_envelope_hash(body)
    envelope = dict(body)
    envelope["h"] = h
    validate_envelope(envelope, expected_host=host, expected_src=src, verify_hash=True)
    return envelope


def _validate_envelope_fields(
    obj: Any,
    *,
    require_h: bool,
    expected_host: str | None = None,
    expected_src: str | None = None,
) -> None:
    if not isinstance(obj, dict):
        raise AuditValidationError("envelope must be a JSON object")
    expected_keys = ENVELOPE_REQUIRED_KEYS if require_h else ENVELOPE_UNSIGNED_KEYS
    actual_keys = set(obj.keys())
    extra = actual_keys - expected_keys
    if extra:
        raise AuditRedactionError(f"envelope contains disallowed extra field(s): {sorted(extra)}")
    missing = expected_keys - actual_keys
    if missing:
        raise AuditValidationError(f"envelope missing required field(s): {sorted(missing)}")

    if not _is_exact_int(obj["v"]) or obj["v"] != ENVELOPE_VERSION:
        raise AuditValidationError(f"unsupported envelope version: {obj['v']!r}")
    src = _require_regex(obj["src"], SRC_RE, "src")
    if expected_src is not None and src != expected_src:
        raise AuditValidationError(f"envelope src {src!r} does not match expected {expected_src!r}")
    host = _require_regex(obj["host"], HOST_NAME_RE, "host")
    if expected_host is not None and host != expected_host:
        raise AuditValidationError(f"envelope host {host!r} does not match expected {expected_host!r}")
    _require_regex(obj["boot_id"], BOOT_ID_RE, "boot_id")

    seq = obj["seq"]
    if not _is_exact_int(seq) or seq < 1 or seq > MAX_SAFE_INT:
        raise AuditValidationError(f"invalid seq: {seq!r}")
    parse_utc_timestamp(obj["ts"])
    mono_ms = obj["mono_ms"]
    if not _is_exact_int(mono_ms) or mono_ms < 0 or mono_ms > MAX_SAFE_INT:
        raise AuditValidationError(f"invalid mono_ms: {mono_ms!r}")
    prev = _require_regex(obj["prev"], SHA256_RE, "prev")
    if seq == 1 and prev != GENESIS_PREV:
        raise AuditValidationError(f"seq 1 must use genesis prev {GENESIS_PREV}, got {prev}")
    if seq > 1 and prev == GENESIS_PREV:
        raise AuditValidationError(f"seq {seq} cannot reuse genesis prev")

    validate_event_data(obj["type"], obj["data"])
    if require_h:
        _require_regex(obj["h"], SHA256_RE, "h")


def validate_envelope(
    obj: Any,
    *,
    expected_host: str | None = None,
    expected_src: str | None = None,
    verify_hash: bool = True,
) -> dict[str, Any]:
    """Validate structure, redaction allowlist, and cryptographic self-hash of an envelope."""
    _validate_envelope_fields(
        obj,
        require_h=True,
        expected_host=expected_host,
        expected_src=expected_src,
    )
    if verify_hash:
        unsigned = {k: v for k, v in obj.items() if k != "h"}
        expected_h = compute_envelope_hash(unsigned)
        if not hmac.compare_digest(obj["h"], expected_h):
            raise AuditValidationError(
                f"envelope hash mismatch at seq {obj['seq']}: expected {expected_h}, got {obj['h']}"
            )
    return obj


# ---------------------------------------------------------------------------
# Symlink-safe, crash-safe filesystem helpers (O_NOFOLLOW + fstat + flock)
# ---------------------------------------------------------------------------

def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        n = os.write(fd, view[written:])
        if n <= 0:
            raise OSError("short write (0 bytes written)")
        written += n


def _fsync_dir(path: Path) -> None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in (errno.EINVAL, errno.EBADF, errno.EROFS):
            raise
    finally:
        os.close(fd)


def _ensure_safe_dir_chain(root: Path, rel_components: tuple[str, ...] = (), *, mode: int = 0o700) -> Path:
    """Verify `root` is a real non-symlink dir, then safely create/verify `rel_components` under it."""
    try:
        st_root = os.lstat(root)
    except FileNotFoundError:
        os.mkdir(root, mode)
        st_root = os.lstat(root)
    if stat.S_ISLNK(st_root.st_mode) or not stat.S_ISDIR(st_root.st_mode):
        raise AuditFileSecurityError(f"root directory is missing or symlinked: {root}")

    cur = root
    for comp in rel_components:
        if not comp or comp in (".", "..") or "/" in comp or "\x00" in comp:
            raise AuditFileSecurityError(f"unsafe directory component: {comp!r}")
        cur = cur / comp
        created = False
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            try:
                os.mkdir(cur, mode)
                created = True
            except FileExistsError:
                pass
            st = os.lstat(cur)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise AuditFileSecurityError(f"directory component is symlink or non-directory: {cur}")
        if created:
            os.chmod(cur, mode)
            _fsync_dir(cur.parent)
    return cur


def _open_regular_nofollow(path: Path, flags: int, *, mode: int = 0o600) -> int:
    """Open a regular file safely, refusing symlinks, FIFOs, sockets, dirs, and devices."""
    try:
        st_pre = os.lstat(path)
    except FileNotFoundError:
        st_pre = None
    if st_pre is not None:
        if stat.S_ISLNK(st_pre.st_mode) or not stat.S_ISREG(st_pre.st_mode):
            raise AuditFileSecurityError(f"refusing non-regular or symlinked file: {path}")

    open_flags = flags | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(path), open_flags, mode)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise AuditFileSecurityError(f"refusing symlink: {path}") from exc
        raise
    try:
        st_fd = os.fstat(fd)
        if not stat.S_ISREG(st_fd.st_mode):
            raise AuditFileSecurityError(f"opened descriptor is not a regular file: {path}")
        if st_pre is not None and (st_fd.st_dev != st_pre.st_dev or st_fd.st_ino != st_pre.st_ino):
            raise AuditFileSecurityError(f"file identity changed during open (TOCTOU): {path}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_regular_file(path: Path, *, max_bytes: int = 64 * 1024 * 1024) -> bytes:
    fd = _open_regular_nofollow(path, os.O_RDONLY)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise AuditValidationError(f"file exceeds maximum safe read size ({max_bytes} bytes): {path}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _append_line_durable(path: Path, line_bytes: bytes, *, mode: int = 0o600) -> None:
    if not line_bytes.endswith(b"\n"):
        raise ValueError("line_bytes must end with newline")
    existed = path.exists()
    fd = _open_regular_nofollow(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, mode=mode)
    try:
        os.fchmod(fd, mode)
        _write_all(fd, line_bytes)
        os.fsync(fd)
    finally:
        os.close(fd)
    if not existed:
        _fsync_dir(path.parent)


def _write_json_atomic(path: Path, payload: dict[str, Any], *, mode: int = 0o600) -> None:
    data = jcs_dumps(payload) + b"\n"
    parent = path.parent
    tmp_name = f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    tmp_path = parent / tmp_name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(str(tmp_path), flags, mode)
    try:
        os.fchmod(fd, mode)
        _write_all(fd, data)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    else:
        os.close(fd)
    try:
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    _fsync_dir(parent)


@contextmanager
def _exclusive_lock(lock_path: Path) -> Iterator[None]:
    fd = _open_regular_nofollow(lock_path, os.O_RDWR | os.O_CREAT, mode=0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Local hash-chained capture & offline spool
# ---------------------------------------------------------------------------

def _load_jsonl_records(
    path: Path,
    *,
    expected_host: str | None = None,
    expected_src: str | None = None,
) -> list[tuple[dict[str, Any], bytes]]:
    raw = _read_regular_file(path)
    if not raw:
        return []
    if not raw.endswith(b"\n"):
        raise AuditValidationError(f"JSONL file does not end with newline (possible partial write): {path}")
    records: list[tuple[dict[str, Any], bytes]] = []
    for idx, line in enumerate(raw.split(b"\n")[:-1], start=1):
        if not line:
            raise AuditValidationError(f"blank line at {path}:{idx}")
        obj = strict_json_loads(line)
        validate_envelope(obj, expected_host=expected_host, expected_src=expected_src, verify_hash=True)
        canonical = jcs_dumps(obj)
        if line != canonical:
            raise AuditValidationError(f"non-canonical JCS bytes at {path}:{idx}")
        records.append((obj, line))
    return records


def verify_chain_records(
    records: list[dict[str, Any]],
    *,
    expected_host: str | None = None,
    expected_src: str | None = None,
) -> list[TamperFinding]:
    """Verify a sequence of parsed envelopes forms a contiguous valid hash chain from seq=1."""
    findings: list[TamperFinding] = []
    expected_seq = 1
    expected_prev = GENESIS_PREV
    for rec in records:
        seq = rec.get("seq") if isinstance(rec, dict) else None
        try:
            validate_envelope(rec, expected_host=expected_host, expected_src=expected_src, verify_hash=True)
        except AuditError as exc:
            findings.append(TamperFinding("CHAIN_INVALID_RECORD", seq if _is_exact_int(seq) else None, str(exc)))
            continue
        if rec["seq"] != expected_seq:
            findings.append(
                TamperFinding(
                    "CHAIN_SEQ_GAP",
                    rec["seq"],
                    f"expected seq {expected_seq}, got {rec['seq']}",
                )
            )
        if not hmac.compare_digest(rec["prev"], expected_prev):
            findings.append(
                TamperFinding(
                    "CHAIN_PREV_MISMATCH",
                    rec["seq"],
                    f"expected prev {expected_prev}, got {rec['prev']}",
                )
            )
        expected_seq = rec["seq"] + 1
        expected_prev = rec["h"]
    return findings


class AuditSpool:
    """Crash-safe, root/owner-safe local JSONL capture and shipping spool.

    Never touches the network and never blocks `cf-agent` when the sink is down.
    """

    def __init__(
        self,
        spool_dir: Path,
        *,
        host: str,
        src: str = DEFAULT_SRC,
        boot_id: str | None = None,
    ) -> None:
        _require_regex(host, HOST_NAME_RE, "host")
        _require_regex(src, SRC_RE, "src")
        self.spool_dir = _ensure_safe_dir_chain(Path(spool_dir), mode=0o700)
        self.host = host
        self.src = src
        self.boot_id = boot_id if boot_id is not None else _detect_boot_id()
        _require_regex(self.boot_id, BOOT_ID_RE, "boot_id")
        self.log_path = self.spool_dir / "audit.jsonl"
        self.cursor_path = self.spool_dir / "cursor.json"
        self.lock_path = self.spool_dir / ".spool.lock"

    def _read_cursor_unlocked(self) -> dict[str, Any] | None:
        if not self.cursor_path.exists() and not self.cursor_path.is_symlink():
            return None
        raw = _read_regular_file(self.cursor_path, max_bytes=MAX_LINE_BYTES)
        obj = strict_json_loads(raw.rstrip(b"\n"))
        if obj.get("host") != self.host or obj.get("src") != self.src:
            raise ChainTamperError("cursor.json host/src mismatch")
        for key in ("local_seq", "acked_seq"):
            if not _is_exact_int(obj.get(key)) or obj[key] < 0 or obj[key] > MAX_SAFE_INT:
                raise ChainTamperError(f"cursor.json invalid {key}")
        if obj["acked_seq"] > obj["local_seq"]:
            raise ChainTamperError("cursor.json acked_seq exceeds local_seq")
        return obj

    def _load_and_verify_state_unlocked(self) -> tuple[list[tuple[dict[str, Any], bytes]], dict[str, Any]]:
        cursor = self._read_cursor_unlocked()
        has_log = self.log_path.exists() or self.log_path.is_symlink()
        if not has_log:
            if cursor is not None and cursor["local_seq"] > 0:
                raise ChainTamperError(
                    f"local audit.jsonl missing while cursor expects local_seq={cursor['local_seq']}"
                )
            return [], {
                "host": self.host,
                "src": self.src,
                "local_seq": 0,
                "local_h": GENESIS_PREV,
                "acked_seq": 0,
                "acked_h": GENESIS_PREV,
            }

        records = _load_jsonl_records(self.log_path, expected_host=self.host, expected_src=self.src)
        chain_findings = verify_chain_records(
            [r for r, _ in records], expected_host=self.host, expected_src=self.src
        )
        if chain_findings:
            raise ChainTamperError(f"local audit.jsonl chain corrupt: {chain_findings[0].detail}")

        actual_seq = records[-1][0]["seq"] if records else 0
        actual_h = records[-1][0]["h"] if records else GENESIS_PREV

        if cursor is None:
            return records, {
                "host": self.host,
                "src": self.src,
                "local_seq": actual_seq,
                "local_h": actual_h,
                "acked_seq": 0,
                "acked_h": GENESIS_PREV,
            }

        if actual_seq < cursor["local_seq"]:
            raise ChainTamperError(
                f"local audit.jsonl truncated: seq={actual_seq} < cursor local_seq={cursor['local_seq']}"
            )
        if cursor["local_seq"] > 0:
            rec_at_cursor = records[cursor["local_seq"] - 1][0]
            if not hmac.compare_digest(rec_at_cursor["h"], cursor["local_h"]):
                raise ChainTamperError(
                    f"local audit.jsonl hash mismatch at cursor seq={cursor['local_seq']}"
                )
        if cursor["acked_seq"] > 0:
            rec_at_ack = records[cursor["acked_seq"] - 1][0]
            if not hmac.compare_digest(rec_at_ack["h"], cursor["acked_h"]):
                raise ChainTamperError(
                    f"local audit.jsonl hash mismatch at acked seq={cursor['acked_seq']}"
                )

        # If audit.jsonl has valid records past cursor.local_seq (e.g., crash after
        # log fsync before cursor atomic replace), recover forward cleanly.
        recovered = dict(cursor)
        recovered["local_seq"] = actual_seq
        recovered["local_h"] = actual_h
        return records, recovered

    def append(
        self,
        event_type: str,
        data: dict[str, Any],
        *,
        ts: str | None = None,
        mono_ms: int | None = None,
        boot_id: str | None = None,
    ) -> dict[str, Any]:
        """Append one validated, redacted, hash-chained event to the local spool."""
        effective_boot = boot_id if boot_id is not None else self.boot_id
        with _exclusive_lock(self.lock_path):
            _, state = self._load_and_verify_state_unlocked()
            next_seq = state["local_seq"] + 1
            prev_h = state["local_h"] if state["local_seq"] > 0 else GENESIS_PREV
            envelope = build_envelope(
                host=self.host,
                src=self.src,
                boot_id=effective_boot,
                seq=next_seq,
                prev=prev_h,
                event_type=event_type,
                data=data,
                ts=ts,
                mono_ms=mono_ms,
            )
            line_bytes = jcs_dumps(envelope) + b"\n"
            _append_line_durable(self.log_path, line_bytes, mode=0o600)
            state["local_seq"] = next_seq
            state["local_h"] = envelope["h"]
            _write_json_atomic(self.cursor_path, state, mode=0o600)
            return envelope

    def unshipped(self, *, limit: int | None = None) -> tuple[list[tuple[dict[str, Any], bytes]], dict[str, Any]]:
        """Return unshipped `(envelope, canonical_line)` pairs and a copy of current state."""
        with _exclusive_lock(self.lock_path):
            records, state = self._load_and_verify_state_unlocked()
            acked = state["acked_seq"]
            pending = [(rec, raw) for rec, raw in records if rec["seq"] > acked]
            if limit is not None:
                pending = pending[:limit]
            return pending, dict(state)

    def advance_ack(self, acked_seq: int, acked_h: str) -> dict[str, Any]:
        """Durably advance the shipped watermark after verifying exact hash agreement."""
        if not _is_exact_int(acked_seq) or acked_seq < 0 or acked_seq > MAX_SAFE_INT:
            raise TransportError(f"invalid acked_seq: {acked_seq!r}")
        _require_regex(acked_h, SHA256_RE, "acked_h")
        with _exclusive_lock(self.lock_path):
            records, state = self._load_and_verify_state_unlocked()
            if acked_seq < state["acked_seq"]:
                raise TransportError(
                    f"sink ack regressed: {acked_seq} < current acked_seq {state['acked_seq']}"
                )
            if acked_seq > state["local_seq"]:
                raise TransportError(
                    f"sink ack exceeded local_seq: {acked_seq} > {state['local_seq']}"
                )
            if acked_seq == 0:
                if acked_h != GENESIS_PREV:
                    raise TransportError("acked_seq 0 must carry genesis hash")
            else:
                expected_rec = records[acked_seq - 1][0]
                if not hmac.compare_digest(expected_rec["h"], acked_h):
                    raise TransportError(
                        f"sink ack hash mismatch at seq {acked_seq}: "
                        f"expected {expected_rec['h']}, got {acked_h}"
                    )
            state["acked_seq"] = acked_seq
            state["acked_h"] = acked_h
            _write_json_atomic(self.cursor_path, state, mode=0o600)
            return dict(state)


# ---------------------------------------------------------------------------
# Hardened SSH append-only transport and offline-resilient shipper
# ---------------------------------------------------------------------------

def build_ssh_append_argv(
    *,
    target: str,
    identity_file: Path,
    known_hosts_file: Path,
    src: str = DEFAULT_SRC,
    ssh_bin: str = "/usr/bin/ssh",
    port: int | None = None,
    connect_timeout_s: int = 10,
) -> list[str]:
    """Build a hardened, non-interactive argv list for SSH append-only shipping."""
    _require_regex(src, SRC_RE, "src")
    if not isinstance(target, str) or not SSH_TARGET_RE.match(target) or target.startswith("-"):
        raise TransportError(f"unsafe SSH target: {target!r}")
    if not isinstance(ssh_bin, str) or not ssh_bin.startswith("/") or "\x00" in ssh_bin:
        raise TransportError(f"ssh_bin must be an absolute path: {ssh_bin!r}")
    for label, p in (("identity_file", identity_file), ("known_hosts_file", known_hosts_file)):
        if not p.is_absolute():
            raise AuditFileSecurityError(f"{label} must be an absolute path: {p}")
        st = os.lstat(p)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise AuditFileSecurityError(f"{label} must be a regular non-symlink file: {p}")
    if not _is_exact_int(connect_timeout_s) or connect_timeout_s < 1 or connect_timeout_s > 120:
        raise TransportError(f"invalid connect_timeout_s: {connect_timeout_s!r}")

    argv = [
        ssh_bin,
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts_file}",
        "-o", "ClearAllForwardings=yes",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "RequestTTY=no",
        "-o", "PermitLocalCommand=no",
        "-o", "ControlMaster=no",
        "-o", f"ConnectTimeout={connect_timeout_s}",
        "-i", str(identity_file),
    ]
    if port is not None:
        if not _is_exact_int(port) or port < 1 or port > 65535:
            raise TransportError(f"invalid SSH port: {port!r}")
        argv.extend(["-p", str(port)])
    argv.extend(["--", target, f"audit-append {src}"])
    return argv


def make_ssh_append_transport(
    *,
    target: str,
    identity_file: Path,
    known_hosts_file: Path,
    src: str = DEFAULT_SRC,
    ssh_bin: str = "/usr/bin/ssh",
    port: int | None = None,
    connect_timeout_s: int = 10,
    io_timeout_s: int = 30,
) -> Callable[[bytes], dict[str, Any]]:
    """Create a callable transport that pipes JSONL batches to the SSH forced command."""
    argv = build_ssh_append_argv(
        target=target,
        identity_file=identity_file,
        known_hosts_file=known_hosts_file,
        src=src,
        ssh_bin=ssh_bin,
        port=port,
        connect_timeout_s=connect_timeout_s,
    )

    def _send(batch_bytes: bytes) -> dict[str, Any]:
        try:
            proc = subprocess.run(
                argv,
                input=batch_bytes,
                capture_output=True,
                timeout=io_timeout_s,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise TransportError(f"ssh transport failed: {exc}") from exc
        if proc.returncode != 0:
            err_msg = proc.stderr.decode("utf-8", errors="replace").strip()[:200]
            raise TransportError(f"ssh exited {proc.returncode}: {err_msg or 'no stderr'}")
        out = proc.stdout.strip()
        if not out:
            raise TransportError("ssh sink returned empty acknowledgment")
        try:
            return strict_json_loads(out)
        except AuditValidationError as exc:
            raise TransportError(f"malformed sink ack JSON: {exc}") from exc

    return _send


class AuditShipper:
    """Offline-resilient batch shipper draining `AuditSpool` to an append-only sink."""

    def __init__(
        self,
        spool: AuditSpool,
        transport: Callable[[bytes], dict[str, Any]],
        *,
        batch_size: int = 100,
        max_batches: int = 100,
    ) -> None:
        if not _is_exact_int(batch_size) or batch_size < 1 or batch_size > 10000:
            raise ValueError("batch_size must be 1..10000")
        if not _is_exact_int(max_batches) or max_batches < 1 or max_batches > 10000:
            raise ValueError("max_batches must be 1..10000")
        self.spool = spool
        self.transport = transport
        self.batch_size = batch_size
        self.max_batches = max_batches

    def ship(self) -> ShipResult:
        """Drain unshipped records in batches. Never raises on unreachable sink."""
        total_shipped = 0
        total_dups = 0
        total_quarantined = 0
        last_state: dict[str, Any] = {}

        for _ in range(self.max_batches):
            pending, state = self.spool.unshipped(limit=self.batch_size)
            last_state = state
            if not pending:
                return ShipResult(
                    ok=True,
                    shipped=total_shipped,
                    duplicates=total_dups,
                    quarantined=total_quarantined,
                    remaining=0,
                    last_acked_seq=state["acked_seq"],
                    last_acked_h=state["acked_h"] if state["acked_seq"] > 0 else None,
                )

            batch_bytes = b"".join(raw + b"\n" for _, raw in pending)
            sent_by_seq = {rec["seq"]: rec["h"] for rec, _ in pending}
            prev_acked = state["acked_seq"]

            try:
                ack = self.transport(batch_bytes)
                if not isinstance(ack, dict) or ack.get("ok") is not True:
                    raise TransportError(f"sink rejected batch: {ack!r}")
                if ack.get("host") != self.spool.host or ack.get("src") != self.spool.src:
                    raise TransportError("sink ack host/src mismatch")
                ack_seq = ack.get("last_seq")
                ack_h = ack.get("last_h")
                if not _is_exact_int(ack_seq) or ack_seq < prev_acked:
                    raise TransportError(f"invalid or regressed sink ack last_seq: {ack_seq!r}")
                if ack_seq > 0:
                    if not isinstance(ack_h, str) or not SHA256_RE.match(ack_h):
                        raise TransportError(f"invalid sink ack last_h: {ack_h!r}")
                    if ack_seq in sent_by_seq:
                        if not hmac.compare_digest(sent_by_seq[ack_seq], ack_h):
                            raise TransportError("sink ack hash disagrees with sent record")
                    elif ack_seq != prev_acked:
                        raise TransportError(f"sink acked seq {ack_seq} not in current batch")
                    last_state = self.spool.advance_ack(ack_seq, ack_h)
                else:
                    raise TransportError("sink acked 0 records for non-empty batch")
            except (TransportError, AuditError, OSError) as exc:
                rem_pending, cur_state = self.spool.unshipped()
                return ShipResult(
                    ok=False,
                    shipped=total_shipped,
                    duplicates=total_dups,
                    quarantined=total_quarantined,
                    remaining=len(rem_pending),
                    last_acked_seq=cur_state["acked_seq"],
                    last_acked_h=cur_state["acked_h"] if cur_state["acked_seq"] > 0 else None,
                    error=str(exc),
                )

            total_shipped += int(ack.get("accepted", 0)) if _is_exact_int(ack.get("accepted")) else 0
            total_dups += int(ack.get("duplicates", 0)) if _is_exact_int(ack.get("duplicates")) else 0
            total_quarantined += (
                int(ack.get("quarantined", 0)) if _is_exact_int(ack.get("quarantined")) else 0
            )

            # Stop if no progress was made to prevent infinite retry loops on quarantined head.
            if last_state["acked_seq"] == prev_acked:
                rem_pending, cur_state = self.spool.unshipped()
                return ShipResult(
                    ok=False,
                    shipped=total_shipped,
                    duplicates=total_dups,
                    quarantined=total_quarantined,
                    remaining=len(rem_pending),
                    last_acked_seq=cur_state["acked_seq"],
                    last_acked_h=cur_state["acked_h"] if cur_state["acked_seq"] > 0 else None,
                    error="sink did not advance watermark (head record quarantined or rejected)",
                )

        rem_pending, cur_state = self.spool.unshipped()
        return ShipResult(
            ok=len(rem_pending) == 0,
            shipped=total_shipped,
            duplicates=total_dups,
            quarantined=total_quarantined,
            remaining=len(rem_pending),
            last_acked_seq=cur_state["acked_seq"],
            last_acked_h=cur_state["acked_h"] if cur_state["acked_seq"] > 0 else None,
            error=None if not rem_pending else "max_batches reached with remaining records",
        )


# ---------------------------------------------------------------------------
# Append-only sink receiver & forced-command boundary (`audit-append`)
# ---------------------------------------------------------------------------

def _iter_sink_day_files(stream_dir: Path) -> list[Path]:
    entries: list[tuple[str, Path]] = []
    for entry in os.scandir(stream_dir):
        m = DAY_FILE_RE.match(entry.name)
        if not m:
            continue
        p = Path(entry.path)
        st = os.lstat(p)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise AuditFileSecurityError(f"sink daily log is symlink or non-regular: {p}")
        entries.append((m.group(1), p))
    entries.sort(key=lambda item: item[0])
    return [p for _, p in entries]


def _load_sink_committed_records(
    stream_dir: Path,
    *,
    expected_host: str | None = None,
    expected_src: str | None = None,
) -> list[tuple[dict[str, Any], bytes]]:
    all_records: list[tuple[dict[str, Any], bytes]] = []
    seen_seqs: set[int] = set()
    for day_path in _iter_sink_day_files(stream_dir):
        for rec, raw in _load_jsonl_records(
            day_path, expected_host=expected_host, expected_src=expected_src
        ):
            seq = rec["seq"]
            if seq in seen_seqs:
                raise ChainTamperError(f"sink contains duplicate committed seq {seq} in {day_path}")
            seen_seqs.add(seq)
            all_records.append((rec, raw))
    all_records.sort(key=lambda pair: pair[0]["seq"])
    return all_records


class AuditSink:
    """Append-only off-device sink pinned to one `(host, src)` stream.

    Writes valid records exclusively via `O_APPEND | O_NOFOLLOW` to
    `<sink_root>/<host>/<src>/YYYY-MM-DD.jsonl` (keyed on sink receive date so
    an untrusted client clock cannot proliferate arbitrary filenames) and
    quarantines gaps, forks, hash mismatches, or invalid/redaction-failing
    lines to `quarantine.jsonl`.
    """

    def __init__(self, sink_root: Path, *, expected_host: str, expected_src: str = DEFAULT_SRC) -> None:
        _require_regex(expected_host, HOST_NAME_RE, "expected_host")
        _require_regex(expected_src, SRC_RE, "expected_src")
        self.sink_root = _ensure_safe_dir_chain(Path(sink_root), mode=0o700)
        self.expected_host = expected_host
        self.expected_src = expected_src
        self.stream_dir = _ensure_safe_dir_chain(
            self.sink_root, (expected_host, expected_src), mode=0o700
        )
        self.state_path = self.stream_dir / "state.json"
        self.quarantine_path = self.stream_dir / "quarantine.jsonl"
        self.lock_path = self.stream_dir / ".sink.lock"

    def _read_state_unlocked(self, *, now_ts: str) -> tuple[dict[str, Any], dict[int, tuple[dict[str, Any], bytes]]]:
        committed_list = _load_sink_committed_records(
            self.stream_dir,
            expected_host=self.expected_host,
            expected_src=self.expected_src,
        )
        chain_findings = verify_chain_records(
            [r for r, _ in committed_list],
            expected_host=self.expected_host,
            expected_src=self.expected_src,
        )
        if chain_findings:
            raise ChainTamperError(f"sink committed log corrupt: {chain_findings[0].detail}")
        committed_index = {r["seq"]: (r, raw) for r, raw in committed_list}
        actual_seq = committed_list[-1][0]["seq"] if committed_list else 0
        actual_h = committed_list[-1][0]["h"] if committed_list else GENESIS_PREV

        if not self.state_path.exists() and not self.state_path.is_symlink():
            state = {
                "host": self.expected_host,
                "src": self.expected_src,
                "last_seq": actual_seq,
                "last_h": actual_h,
                "last_ts": committed_list[-1][0]["ts"] if committed_list else "",
                "last_receive_ts": now_ts if committed_list else "",
                "last_heartbeat_ts": "",
                "last_heartbeat_receive_ts": "",
            }
            for rec, _ in reversed(committed_list):
                if rec["type"] == "heartbeat":
                    state["last_heartbeat_ts"] = rec["ts"]
                    state["last_heartbeat_receive_ts"] = now_ts
                    break
            return state, committed_index

        raw = _read_regular_file(self.state_path, max_bytes=MAX_LINE_BYTES)
        obj = strict_json_loads(raw.rstrip(b"\n"))
        if obj.get("host") != self.expected_host or obj.get("src") != self.expected_src:
            raise ChainTamperError("sink state.json host/src mismatch")
        if not _is_exact_int(obj.get("last_seq")) or obj["last_seq"] < 0 or obj["last_seq"] > MAX_SAFE_INT:
            raise ChainTamperError("sink state.json invalid last_seq")
        if actual_seq < obj["last_seq"]:
            raise ChainTamperError(
                f"sink log truncated: committed seq={actual_seq} < state last_seq={obj['last_seq']}"
            )
        if obj["last_seq"] > 0:
            rec_at_state = committed_index.get(obj["last_seq"])
            if rec_at_state is None or not hmac.compare_digest(rec_at_state[0]["h"], str(obj.get("last_h", ""))):
                raise ChainTamperError("sink state.json hash disagrees with committed log")
        if actual_seq > obj["last_seq"]:
            # Crash recovery: committed log fsynced ahead of state.json atomic swap.
            obj["last_seq"] = actual_seq
            obj["last_h"] = actual_h
            obj["last_ts"] = committed_list[-1][0]["ts"]
            obj["last_receive_ts"] = obj.get("last_receive_ts") or now_ts
            for rec, _ in reversed(committed_list):
                if rec["type"] == "heartbeat":
                    obj["last_heartbeat_ts"] = rec["ts"]
                    obj["last_heartbeat_receive_ts"] = obj.get("last_heartbeat_receive_ts") or now_ts
                    break
        return obj, committed_index

    def _append_quarantine_unlocked(
        self,
        *,
        received_at: str,
        reason: str,
        expected_seq: int,
        expected_prev: str,
        raw_line: bytes,
        validated_envelope: dict[str, Any] | None = None,
    ) -> None:
        # Never persist unredacted raw bytes in quarantine; store only SHA-256 + length
        # unless the envelope already passed the full redaction allowlist.
        entry: dict[str, Any] = {
            "received_at": received_at,
            "host": self.expected_host,
            "src": self.expected_src,
            "reason": reason,
            "expected_seq": expected_seq,
            "expected_prev": expected_prev,
            "raw_sha256": f"sha256:{hashlib.sha256(raw_line).hexdigest()}",
            "raw_len": len(raw_line),
        }
        if validated_envelope is not None:
            entry["observed_seq"] = validated_envelope["seq"]
            entry["observed_prev"] = validated_envelope["prev"]
            entry["observed_h"] = validated_envelope["h"]
            entry["envelope"] = validated_envelope
        _append_line_durable(self.quarantine_path, jcs_dumps(entry) + b"\n", mode=0o600)

    def ingest_batch(self, stdin_bytes: bytes, *, receive_ts: str | None = None) -> SinkIngestResult:
        """Ingest one newline-delimited JSONL batch from stdin."""
        if not isinstance(stdin_bytes, bytes):
            raise AuditValidationError("stdin_bytes must be bytes")
        if len(stdin_bytes) > MAX_BATCH_BYTES:
            raise AuditValidationError(f"batch exceeds maximum size ({MAX_BATCH_BYTES} bytes)")
        now_ts = receive_ts if receive_ts is not None else utc_now_str()
        parse_utc_timestamp(now_ts)
        receive_day = now_ts[:10]

        with _exclusive_lock(self.lock_path):
            state, committed_index = self._read_state_unlocked(now_ts=now_ts)

            accepted = 0
            duplicates = 0
            quarantined = 0

            raw_lines = stdin_bytes.split(b"\n")
            if raw_lines and raw_lines[-1] == b"":
                raw_lines = raw_lines[:-1]

            for raw_line in raw_lines:
                if not raw_line:
                    continue
                if len(raw_line) > MAX_LINE_BYTES:
                    self._append_quarantine_unlocked(
                        received_at=now_ts,
                        reason="line_too_large",
                        expected_seq=state["last_seq"] + 1,
                        expected_prev=state["last_h"] if state["last_seq"] > 0 else GENESIS_PREV,
                        raw_line=raw_line,
                    )
                    quarantined += 1
                    continue

                try:
                    obj = strict_json_loads(raw_line)
                    validate_envelope(
                        obj,
                        expected_host=self.expected_host,
                        expected_src=self.expected_src,
                        verify_hash=True,
                    )
                    canonical = jcs_dumps(obj)
                    if raw_line != canonical:
                        raise AuditValidationError("non-canonical JCS encoding")
                except AuditError as exc:
                    reason = "redaction_blocked" if isinstance(exc, AuditRedactionError) else "invalid_envelope"
                    self._append_quarantine_unlocked(
                        received_at=now_ts,
                        reason=reason,
                        expected_seq=state["last_seq"] + 1,
                        expected_prev=state["last_h"] if state["last_seq"] > 0 else GENESIS_PREV,
                        raw_line=raw_line,
                    )
                    quarantined += 1
                    continue

                seq = obj["seq"]
                expected_seq = state["last_seq"] + 1
                expected_prev = state["last_h"] if state["last_seq"] > 0 else GENESIS_PREV

                if seq == expected_seq and hmac.compare_digest(obj["prev"], expected_prev):
                    day_path = self.stream_dir / f"{receive_day}.jsonl"
                    _append_line_durable(day_path, canonical + b"\n", mode=0o600)
                    state["last_seq"] = seq
                    state["last_h"] = obj["h"]
                    state["last_ts"] = obj["ts"]
                    state["last_receive_ts"] = now_ts
                    if obj["type"] == "heartbeat":
                        state["last_heartbeat_ts"] = obj["ts"]
                        state["last_heartbeat_receive_ts"] = now_ts
                    _write_json_atomic(self.state_path, state, mode=0o600)
                    committed_index[seq] = (obj, canonical)
                    accepted += 1
                elif seq <= state["last_seq"]:
                    existing = committed_index.get(seq)
                    if (
                        existing is not None
                        and hmac.compare_digest(existing[0]["h"], obj["h"])
                        and existing[1] == canonical
                    ):
                        duplicates += 1
                    else:
                        self._append_quarantine_unlocked(
                            received_at=now_ts,
                            reason="fork",
                            expected_seq=expected_seq,
                            expected_prev=expected_prev,
                            raw_line=canonical,
                            validated_envelope=obj,
                        )
                        quarantined += 1
                else:
                    reason = "gap" if seq > expected_seq else "prev_mismatch"
                    self._append_quarantine_unlocked(
                        received_at=now_ts,
                        reason=reason,
                        expected_seq=expected_seq,
                        expected_prev=expected_prev,
                        raw_line=canonical,
                        validated_envelope=obj,
                    )
                    quarantined += 1

            return SinkIngestResult(
                ok=True,
                host=self.expected_host,
                src=self.expected_src,
                last_seq=state["last_seq"],
                last_h=state["last_h"] if state["last_seq"] > 0 else None,
                accepted=accepted,
                duplicates=duplicates,
                quarantined=quarantined,
            )


def run_forced_command(
    *,
    sink_root: Path,
    expected_host: str,
    expected_src: str,
    stdin_bytes: bytes,
    original_command: str = "",
    receive_ts: str | None = None,
) -> dict[str, Any]:
    """Enforce the append-only SSH forced-command surface (`audit-append <src>`).

    Rejects any attempt to read, list, rename, truncate, delete, or invoke any
    command other than append for the key's pinned `(expected_host, expected_src)`.
    """
    _require_regex(expected_host, HOST_NAME_RE, "expected_host")
    _require_regex(expected_src, SRC_RE, "expected_src")
    cmd = (original_command or "").strip()
    allowed_cmds = {
        "",
        "append",
        f"audit-append {expected_src}",
        f"audit-append --src {expected_src}",
    }
    if cmd not in allowed_cmds:
        raise ForcedCommandError(f"disallowed sink command (append-only boundary): {cmd!r}")

    sink = AuditSink(sink_root, expected_host=expected_host, expected_src=expected_src)
    res = sink.ingest_batch(stdin_bytes, receive_ts=receive_ts)
    return res.to_ack_dict()


# ---------------------------------------------------------------------------
# Forensic cross-verifier & intermittent-host liveness
# ---------------------------------------------------------------------------

def _count_quarantine_lines(stream_dir: Path) -> int:
    q_path = stream_dir / "quarantine.jsonl"
    if not q_path.exists() and not q_path.is_symlink():
        return 0
    raw = _read_regular_file(q_path)
    if not raw:
        return 0
    return len([ln for ln in raw.split(b"\n") if ln])


def verify_local_against_sink(
    local_jsonl_path: Path,
    sink_stream_dir: Path,
    *,
    expected_host: str | None = None,
    expected_src: str = DEFAULT_SRC,
) -> VerifyReport:
    """Compare a host's local JSONL capture against the off-device sink witness.

    Flags missing/deleted local log, tail truncation, mid-log deletion, edited
    lines, chain breaks, and sink quarantine records (forks/gaps).
    """
    findings: list[TamperFinding] = []
    sink_dir = _ensure_safe_dir_chain(Path(sink_stream_dir), mode=0o700)

    quarantine_count = 0
    try:
        quarantine_count = _count_quarantine_lines(sink_dir)
    except AuditError as exc:
        findings.append(TamperFinding("SINK_QUARANTINE_UNREADABLE", None, str(exc)))
    if quarantine_count > 0:
        findings.append(
            TamperFinding(
                "SINK_QUARANTINE_PRESENT",
                None,
                f"sink holds {quarantine_count} quarantined record(s) (gap, fork, or invalid submission)",
            )
        )

    sink_records: list[tuple[dict[str, Any], bytes]] = []
    try:
        sink_records = _load_sink_committed_records(
            sink_dir, expected_host=expected_host, expected_src=expected_src
        )
    except AuditError as exc:
        findings.append(TamperFinding("SINK_CORRUPT", None, str(exc)))

    sink_chain_findings = verify_chain_records(
        [r for r, _ in sink_records], expected_host=expected_host, expected_src=expected_src
    )
    for f in sink_chain_findings:
        findings.append(TamperFinding(f"SINK_{f.code}", f.seq, f.detail))

    sink_by_seq = {r["seq"]: (r, raw) for r, raw in sink_records}
    sink_max_seq = max(sink_by_seq.keys(), default=0)

    local_records: list[tuple[dict[str, Any], bytes]] = []
    local_exists = local_jsonl_path.exists() or local_jsonl_path.is_symlink()
    if not local_exists:
        if sink_max_seq > 0:
            findings.append(
                TamperFinding(
                    "LOCAL_MISSING",
                    1,
                    f"local audit log {local_jsonl_path} is missing while sink has {sink_max_seq} record(s)",
                )
            )
    else:
        try:
            local_records = _load_jsonl_records(
                local_jsonl_path, expected_host=expected_host, expected_src=expected_src
            )
        except AuditError as exc:
            findings.append(TamperFinding("LOCAL_PARSE_ERROR", None, str(exc)))
            # Best-effort line-by-line scan so edits/deletions still get reported alongside parse error.
            try:
                raw_local = _read_regular_file(local_jsonl_path)
                for raw_ln in raw_local.splitlines():
                    if not raw_ln:
                        continue
                    try:
                        obj = strict_json_loads(raw_ln)
                        if _is_exact_int(obj.get("seq")):
                            local_records.append((obj, raw_ln))
                    except AuditError:
                        continue
            except AuditError:
                pass
        else:
            local_chain_findings = verify_chain_records(
                [r for r, _ in local_records], expected_host=expected_host, expected_src=expected_src
            )
            for f in local_chain_findings:
                findings.append(TamperFinding(f"LOCAL_{f.code}", f.seq, f.detail))

    local_by_seq: dict[int, tuple[dict[str, Any], bytes]] = {}
    for rec, raw in local_records:
        seq = rec.get("seq")
        if _is_exact_int(seq):
            if seq in local_by_seq:
                findings.append(TamperFinding("LOCAL_DUPLICATE_SEQ", seq, f"duplicate local seq {seq}"))
            else:
                local_by_seq[seq] = (rec, raw)

    local_max_seq = max(local_by_seq.keys(), default=0)
    if local_exists and local_max_seq < sink_max_seq:
        findings.append(
            TamperFinding(
                "LOCAL_TRUNCATED",
                local_max_seq + 1,
                f"local log ends at seq {local_max_seq} while sink has seq {sink_max_seq}",
            )
        )

    for seq in sorted(sink_by_seq.keys()):
        sink_rec, sink_raw = sink_by_seq[seq]
        loc = local_by_seq.get(seq)
        if loc is None:
            if local_exists and seq <= local_max_seq:
                findings.append(
                    TamperFinding(
                        "LOCAL_LINE_DELETED",
                        seq,
                        f"seq {seq} present on sink ({sink_rec['h']}) is deleted from local log",
                    )
                )
            continue
        loc_rec, loc_raw = loc
        loc_h = loc_rec.get("h") if isinstance(loc_rec, dict) else None
        if not isinstance(loc_h, str) or not hmac.compare_digest(loc_h, sink_rec["h"]) or loc_raw != sink_raw:
            findings.append(
                TamperFinding(
                    "LOCAL_EDITED",
                    seq,
                    f"seq {seq} edited locally: local_h={loc_h!r}, sink_h={sink_rec['h']!r}",
                )
            )

    return VerifyReport(
        ok=len(findings) == 0,
        local_count=len(local_records),
        sink_count=len(sink_records),
        quarantine_count=quarantine_count,
        findings=tuple(findings),
    )


def check_host_liveness(
    sink_stream_dir: Path,
    *,
    host: str,
    src: str = DEFAULT_SRC,
    now_utc: datetime.datetime | None = None,
    max_silence_seconds: int = 600,
) -> LivenessReport:
    """Report host audit liveness. A silent or unseen host is ALWAYS `"unknown"`, never `"fine"`."""
    _require_regex(host, HOST_NAME_RE, "host")
    _require_regex(src, SRC_RE, "src")
    now = now_utc if now_utc is not None else datetime.datetime.now(datetime.timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now_utc must be timezone-aware")

    stream_dir = Path(sink_stream_dir)
    if not stream_dir.exists() or stream_dir.is_symlink() or not stream_dir.is_dir():
        return LivenessReport(
            status="unknown",
            reason="no sink stream recorded for host",
            host=host,
            src=src,
            last_seq=0,
            last_receive_ts=None,
            last_heartbeat_receive_ts=None,
            silence_seconds=None,
            quarantine_count=0,
        )

    quarantine_count = _count_quarantine_lines(stream_dir)
    state_path = stream_dir / "state.json"
    if not state_path.exists() or state_path.is_symlink():
        return LivenessReport(
            status="unknown",
            reason="sink state missing",
            host=host,
            src=src,
            last_seq=0,
            last_receive_ts=None,
            last_heartbeat_receive_ts=None,
            silence_seconds=None,
            quarantine_count=quarantine_count,
        )

    state = strict_json_loads(_read_regular_file(state_path, max_bytes=MAX_LINE_BYTES).rstrip(b"\n"))
    last_seq = state.get("last_seq", 0)
    last_rx = state.get("last_receive_ts") or None
    last_hb_rx = state.get("last_heartbeat_receive_ts") or None
    if not _is_exact_int(last_seq) or last_seq <= 0 or not last_hb_rx:
        return LivenessReport(
            status="unknown",
            reason="no heartbeat received from host",
            host=host,
            src=src,
            last_seq=last_seq if _is_exact_int(last_seq) else 0,
            last_receive_ts=last_rx,
            last_heartbeat_receive_ts=last_hb_rx,
            silence_seconds=None,
            quarantine_count=quarantine_count,
        )

    hb_dt = parse_utc_timestamp(last_hb_rx)
    silence = (now - hb_dt).total_seconds()
    if silence < -60:
        return LivenessReport(
            status="unknown",
            reason="sink heartbeat receive time is in the future (clock skew)",
            host=host,
            src=src,
            last_seq=last_seq,
            last_receive_ts=last_rx,
            last_heartbeat_receive_ts=last_hb_rx,
            silence_seconds=silence,
            quarantine_count=quarantine_count,
        )
    if silence > max_silence_seconds:
        return LivenessReport(
            status="unknown",
            reason=f"host silent for {int(silence)}s (threshold {max_silence_seconds}s)",
            host=host,
            src=src,
            last_seq=last_seq,
            last_receive_ts=last_rx,
            last_heartbeat_receive_ts=last_hb_rx,
            silence_seconds=silence,
            quarantine_count=quarantine_count,
        )

    return LivenessReport(
        status="ok",
        reason="heartbeat within threshold",
        host=host,
        src=src,
        last_seq=last_seq,
        last_receive_ts=last_rx,
        last_heartbeat_receive_ts=last_hb_rx,
        silence_seconds=silence,
        quarantine_count=quarantine_count,
    )


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="tendcf tamper-evident audit log & append-only sink tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_emit = sub.add_parser("emit", help="append one validated event to the local spool")
    p_emit.add_argument("--spool-dir", type=Path, required=True)
    p_emit.add_argument("--host", required=True)
    p_emit.add_argument("--src", default=DEFAULT_SRC)
    p_emit.add_argument("--boot-id")
    p_emit.add_argument("--type", dest="event_type", required=True)
    p_emit.add_argument("--data-json", required=True, help="JSON object for event data")

    p_ship = sub.add_parser("ship", help="ship unshipped spool events over hardened SSH")
    p_ship.add_argument("--spool-dir", type=Path, required=True)
    p_ship.add_argument("--host", required=True)
    p_ship.add_argument("--src", default=DEFAULT_SRC)
    p_ship.add_argument("--target", required=True)
    p_ship.add_argument("--identity", type=Path, required=True)
    p_ship.add_argument("--known-hosts", type=Path, required=True)
    p_ship.add_argument("--ssh-bin", default="/usr/bin/ssh")
    p_ship.add_argument("--port", type=int)
    p_ship.add_argument("--batch-size", type=int, default=100)

    p_sink = sub.add_parser("sink-append", help="append-only SSH forced-command receiver")
    p_sink.add_argument("--sink-root", type=Path, required=True)
    p_sink.add_argument("--host", required=True)
    p_sink.add_argument("--src", default=DEFAULT_SRC)

    p_ver = sub.add_parser("verify", help="verify local audit JSONL standalone or against sink witness")
    p_ver.add_argument("--local", type=Path, required=True)
    p_ver.add_argument("--sink-dir", type=Path)
    p_ver.add_argument("--host")
    p_ver.add_argument("--src", default=DEFAULT_SRC)

    p_stat = sub.add_parser("status", help="check host heartbeat liveness on sink (silent -> unknown)")
    p_stat.add_argument("--sink-dir", type=Path, required=True)
    p_stat.add_argument("--host", required=True)
    p_stat.add_argument("--src", default=DEFAULT_SRC)
    p_stat.add_argument("--max-silence", type=int, default=600)

    args = parser.parse_args(argv)
    try:
        if args.cmd == "emit":
            data = strict_json_loads(args.data_json)
            spool = AuditSpool(args.spool_dir, host=args.host, src=args.src, boot_id=args.boot_id)
            env = spool.append(args.event_type, data)
            sys.stdout.buffer.write(jcs_dumps(env) + b"\n")
            return 0

        if args.cmd == "ship":
            spool = AuditSpool(args.spool_dir, host=args.host, src=args.src)
            transport = make_ssh_append_transport(
                target=args.target,
                identity_file=args.identity,
                known_hosts_file=args.known_hosts,
                src=args.src,
                ssh_bin=args.ssh_bin,
                port=args.port,
            )
            res = AuditShipper(spool, transport, batch_size=args.batch_size).ship()
            print(json.dumps(dataclasses.asdict(res), sort_keys=True))
            return 0 if res.ok else 1

        if args.cmd == "sink-append":
            orig_cmd = os.environ.get("SSH_ORIGINAL_COMMAND", "")
            stdin_bytes = sys.stdin.buffer.read(MAX_BATCH_BYTES + 1)
            ack = run_forced_command(
                sink_root=args.sink_root,
                expected_host=args.host,
                expected_src=args.src,
                stdin_bytes=stdin_bytes,
                original_command=orig_cmd,
            )
            sys.stdout.buffer.write(jcs_dumps(ack) + b"\n")
            return 0

        if args.cmd == "verify":
            if args.sink_dir is not None:
                report = verify_local_against_sink(
                    args.local, args.sink_dir, expected_host=args.host, expected_src=args.src
                )
                out = {
                    "ok": report.ok,
                    "local_count": report.local_count,
                    "sink_count": report.sink_count,
                    "quarantine_count": report.quarantine_count,
                    "findings": [dataclasses.asdict(f) for f in report.findings],
                }
                print(json.dumps(out, sort_keys=True))
                return 0 if report.ok else 1
            records = _load_jsonl_records(args.local, expected_host=args.host, expected_src=args.src)
            findings = verify_chain_records(
                [r for r, _ in records], expected_host=args.host, expected_src=args.src
            )
            print(
                json.dumps(
                    {
                        "ok": len(findings) == 0,
                        "local_count": len(records),
                        "findings": [dataclasses.asdict(f) for f in findings],
                    },
                    sort_keys=True,
                )
            )
            return 0 if not findings else 1

        if args.cmd == "status":
            rep = check_host_liveness(
                args.sink_dir,
                host=args.host,
                src=args.src,
                max_silence_seconds=args.max_silence,
            )
            print(json.dumps(dataclasses.asdict(rep), sort_keys=True))
            return 0 if rep.status == "ok" else 1
    except ForcedCommandError as exc:
        print(f"audit-log: denied: {exc}", file=sys.stderr)
        return 2
    except AuditError as exc:
        print(f"audit-log: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
