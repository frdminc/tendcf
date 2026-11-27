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
    secrets, key material, and consent free-text cannot enter the audit stream
    or leak into validation errors/stderr or `quarantine.jsonl`.
  - Local spool (`AuditSpool`): crash-safe append-only local capture + durable
    cursor (`0700` dir, `0600` files, ancestor symlink checks, `dir_fd` +
    `O_NOFOLLOW` + `fstat` regular-file checks, advisory `flock`, `fsync`
    before cursor advance). Never contacts the network and never blocks
    `cf-agent`.
  - Offline shipper (`AuditShipper` + `make_ssh_append_transport`): ships
    unshipped spool records in bounded batches (`MAX_BATCH_LINES` &
    `MAX_BATCH_BYTES`) over hardened non-interactive SSH (`-F /dev/null`,
    `BatchMode=yes`, `IdentitiesOnly=yes`, `StrictHostKeyChecking=yes`,
    `GlobalKnownHostsFile=/dev/null`, `ProxyCommand=none`, `ProxyJump=none`,
    `ControlPath=none`, `KnownHostsCommand=none`, dedicated write-only `0600`
    key). Survives unreachable sinks without losing or skipping records and
    resumes cleanly on reconnect (including when sink tip is ahead of batch).
  - Append-only sink receiver (`AuditSink` + `run_forced_command`): bound to
    pinned `(expected_host, expected_src)` from SSH `authorized_keys` forced
    command. Strictly refuses read/list/rename/truncate/delete commands,
    appends valid records to `<sink_root>/<host>/<src>/YYYY-MM-DD.jsonl` via
    `O_APPEND | O_NOFOLLOW` (compatible with Linux `chattr +a` on `.jsonl`
    files; `state.json` and `stream_dir` must remain mutable for atomic
    `os.replace`), deduplicates idempotent retries, rejects torn transport
    frames without poisoning `quarantine.jsonl`, and quarantines gaps, forks,
    hash mismatches, or invalid records into `quarantine.jsonl` (bounded per
    batch, without storing unredacted raw secret material).
  - Forensic verifier (`verify_local_against_sink`, strictly read-only) and
    intermittent-host liveness (`check_host_liveness`): flags deleted,
    truncated, edited, or forked local logs (plus sink truncation/quarantine),
    and reports silent, unseen, mismatched, or quarantined hosts as
    `"unknown"`, never `"fine"`.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import errno
import fcntl
import hashlib
import hmac
import io
import json
import math
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
# Self-contained pure-stdlib RFC 8785 (JCS) canonicalizer (H2).
# Keeps audit_log.py 100% standalone under `python3 -I -S` with zero sibling
# module imports, zero dynamic exec/importlib calls, and zero __pycache__
# bytecode execution risk. Matches tools/projector.py::_stdlib_jcs_dumps.
#
# Attribution: `_jcs_write_float` and `_JCS_ESCAPE_MAP` are adapted from the
# `rfc8785` Python package and Andrew Rundgren's `cyberphone/json-canonicalization`
# reference implementation (Apache License, Version 2.0).
# ---------------------------------------------------------------------------

_JCS_INT_MAX = 2**53 - 1
_JCS_INT_MIN = -(2**53) + 1
_JCS_ESCAPE_RE = re.compile(r'[\x00-\x1f\\"]')
_JCS_ESCAPE_MAP: dict[str, str] = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}
for _cp in range(0x20):
    _JCS_ESCAPE_MAP.setdefault(chr(_cp), f"\\u{_cp:04x}")


def _jcs_write_str(s: str, sink: io.BytesIO) -> None:
    """Serialize a JSON string per RFC 8785 §3.2.2.2."""
    sink.write(b'"')
    escaped = _JCS_ESCAPE_RE.sub(lambda m: _JCS_ESCAPE_MAP[m.group(0)], s)
    try:
        sink.write(escaped.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError("input contains lone surrogate or non-UTF-8 codepoints") from exc
    sink.write(b'"')


def _jcs_write_float(f: float, sink: io.BytesIO) -> None:
    """Serialize a finite IEEE-754 float per ES6 / RFC 8785 §3.2.2.3."""
    if math.isnan(f) or math.isinf(f):
        raise ValueError(f"{f} is not representable in JCS")
    if f == 0:
        sink.write(b"0")
        return
    if f < 0:
        sink.write(b"-")
        _jcs_write_float(-f, sink)
        return

    stringified = str(f)
    exponent_str = ""
    exponent_value = 0
    q = stringified.find("e")
    if q > 0:
        exponent_str = stringified[q:]
        if exponent_str[2:3] == "0":
            exponent_str = exponent_str[:2] + exponent_str[3:]
        stringified = stringified[:q]
        exponent_value = int(exponent_str[1:])

    first = stringified
    dot = ""
    last = ""
    q = stringified.find(".")
    if q > 0:
        dot = "."
        first = stringified[:q]
        last = stringified[q + 1 :]

    if last == "0":
        dot = ""
        last = ""

    if 0 < exponent_value < 21:
        first += last
        last = ""
        dot = ""
        exponent_str = ""
        q = exponent_value - len(first)
        while q >= 0:
            q -= 1
            first += "0"
    elif -7 < exponent_value < 0:
        last = first + last
        first = "0"
        dot = "."
        exponent_str = ""
        q = exponent_value
        while q < -1:
            q += 1
            last = "0" + last

    sink.write(f"{first}{dot}{last}{exponent_str}".encode("ascii"))


def _jcs_write_value(obj: Any, sink: io.BytesIO) -> None:
    if obj is None:
        sink.write(b"null")
    elif isinstance(obj, bool):
        sink.write(b"true" if bool(obj) else b"false")
    elif isinstance(obj, int):
        n = int(obj)
        if n < _JCS_INT_MIN or n > _JCS_INT_MAX:
            raise ValueError(f"{n} exceeds safe integer domain for JSON floats")
        sink.write(str(n).encode("ascii"))
    elif isinstance(obj, str):
        _jcs_write_str(obj, sink)
    elif isinstance(obj, float):
        _jcs_write_float(float(obj), sink)
    elif isinstance(obj, (list, tuple)):
        if not obj:
            sink.write(b"[]")
            return
        sink.write(b"[")
        for idx, elem in enumerate(obj):
            if idx > 0:
                sink.write(b",")
            _jcs_write_value(elem, sink)
        sink.write(b"]")
    elif isinstance(obj, dict):
        if not obj:
            sink.write(b"{}")
            return
        keyed: list[tuple[bytes, str, Any]] = []
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
            try:
                sort_key = k.encode("utf-16-be")
            except UnicodeEncodeError as exc:
                raise ValueError("object key contains lone surrogate or non-UTF-8 codepoints") from exc
            keyed.append((sort_key, k, v))
        keyed.sort(key=lambda item: item[0])
        sink.write(b"{")
        for idx, (_, key, value) in enumerate(keyed):
            if idx > 0:
                sink.write(b",")
            _jcs_write_str(key, sink)
            sink.write(b":")
            _jcs_write_value(value, sink)
        sink.write(b"}")
    else:
        raise ValueError(f"unsupported type for JCS: {type(obj).__name__}")


def _stdlib_jcs_dumps(obj: Any) -> bytes:
    """Pure-stdlib RFC 8785 JCS serializer returning canonical UTF-8 bytes."""
    sink = io.BytesIO()
    _jcs_write_value(obj, sink)
    return sink.getvalue()


# ---------------------------------------------------------------------------
# Constants, regexes, and closed vocabularies
# ---------------------------------------------------------------------------

ENVELOPE_VERSION = 1
DEFAULT_SRC = "tendcf"
GENESIS_PREV = "sha256:" + ("0" * 64)
MAX_SAFE_INT = 2**53 - 1
MAX_LINE_BYTES = 65536
MAX_BATCH_BYTES = 4 * 1024 * 1024
MAX_BATCH_LINES = 2000
MAX_QUARANTINE_PER_BATCH = 64
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
ABS_PATH_RE = re.compile(r"^/(?:[A-Za-z0-9._+@:,-]+/)*[A-Za-z0-9._+@:,-]+\Z")
SSH_SAFE_PATH_RE = re.compile(r"^/(?:[A-Za-z0-9._+@:/-]+)\Z")
UNIT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}\Z")
PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.+:-]{0,127}\Z")
VERSION_STR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}\Z")
DAY_FILE_RE = re.compile(r"^([0-9]{4}-[0-9]{2}-[0-9]{2})\.jsonl\Z")
SSH_TARGET_RE = re.compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9._-]{0,63}@)?(?:[A-Za-z0-9][A-Za-z0-9._-]{0,252}|\[[0-9a-fA-F:]+\])\Z"
)
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

# Belt-and-suspenders value-level secret/content leakage patterns.
FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN "),
    re.compile(r"PRIVATE KEY"),
    re.compile(r"ssh-rsa "),
    re.compile(r"ssh-ed25519 "),
    re.compile(r"gh[po]_[A-Za-z0-9]{10,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{10,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"Bearer "),
    re.compile(r"xox[bp]-[A-Za-z0-9-]{8,}"),
    re.compile(r'"vars":'),
    re.compile(r'"host_specific"'),
    re.compile(r'"goal-file"'),
    re.compile(r'"schema_version"'),
)

# Immutable root OS symlinks on macOS (e.g. /var -> private/var).
_DARWIN_OS_ROOT_SYMLINKS = {
    "/var": "private/var",
    "/tmp": "private/tmp",
    "/etc": "private/etc",
}


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
    """Audit chain disagrees with persisted cursor/state or integrity checks."""


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
    raise AuditValidationError(f"non-finite JSON constant rejected: {token}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise AuditValidationError("duplicate JSON object key rejected")
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
            raise AuditValidationError("integer out of RFC 8785 safe range")
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


def _check_json_nesting_depth(text: str, *, max_depth: int = 16) -> None:
    """Iterative O(N) nesting-depth pre-check before `json.loads` (zero recursion)."""
    depth = 0
    in_str = False
    esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch in "{[":
                depth += 1
                if depth > max_depth:
                    raise AuditValidationError(f"JSON nesting depth exceeds limit ({max_depth})")
            elif ch in "}]":
                depth -= 1


def strict_json_loads(raw: bytes | str) -> dict[str, Any]:
    """Parse one canonical JSON object strictly (RFC 8259, no dup keys/NaN/BOM/deep recursion)."""
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
            raise AuditValidationError("invalid UTF-8 in JSON line") from exc
    else:
        if len(raw.encode("utf-8", errors="surrogatepass")) > MAX_LINE_BYTES:
            raise AuditValidationError(f"JSON line exceeds {MAX_LINE_BYTES} bytes")
        if "\x00" in raw or "\r" in raw:
            raise AuditValidationError("JSON line contains NUL or CR")
        text = raw
    _check_json_nesting_depth(text, max_depth=16)
    try:
        obj = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except AuditValidationError:
        raise
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise AuditValidationError(f"malformed JSON ({type(exc).__name__})") from exc
    if not isinstance(obj, dict):
        raise AuditValidationError("JSON root must be an object")
    return obj


def jcs_dumps(obj: Any) -> bytes:
    """Serialize `obj` to RFC 8785 JCS canonical UTF-8 bytes (self-contained pure stdlib)."""
    try:
        return _stdlib_jcs_dumps(obj)
    except Exception as exc:
        raise AuditValidationError(f"JCS canonicalization failed ({type(exc).__name__})") from exc


def parse_utc_timestamp(ts: str) -> datetime.datetime:
    """Parse and calendar-validate a UTC RFC 3339 timestamp with trailing `Z`."""
    if not isinstance(ts, str):
        raise AuditValidationError("timestamp must be a string")
    m = UTC_TS_RE.match(ts)
    if not m:
        raise AuditValidationError(f"invalid UTC RFC 3339 timestamp (len={len(ts)})")
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    frac = m.group(7) or ""
    micro = int(frac.ljust(6, "0")[:6]) if frac else 0
    try:
        return datetime.datetime(
            year, month, day, hour, minute, second, micro, tzinfo=datetime.timezone.utc
        )
    except ValueError as exc:
        raise AuditValidationError("non-existent calendar date in timestamp") from exc


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
        except (OSError, subprocess.SubprocessError):
            pass
    return f"boot-{os.getpid()}-{secrets.token_hex(8)}"


# ---------------------------------------------------------------------------
# Redaction gate and closed event-data validation
# ---------------------------------------------------------------------------

def _is_exact_int(val: Any) -> bool:
    return type(val) is int


def _safe_digest_equal(a: Any, b: Any) -> bool:
    """Constant-time equality safe on untrusted or non-ASCII strings (never raises TypeError)."""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(
        a.encode("utf-8", errors="surrogatepass"),
        b.encode("utf-8", errors="surrogatepass"),
    )


def _require_regex(val: Any, rx: re.Pattern[str], field: str) -> str:
    if not isinstance(val, str):
        raise AuditValidationError(f"{field} must be a string (got {type(val).__name__})")
    _check_redaction_value(val, field=field)
    if not rx.match(val):
        raise AuditValidationError(f"{field} failed format validation (len={len(val)})")
    return val


def _require_abs_path(val: Any, field: str) -> str:
    s = _require_regex(val, ABS_PATH_RE, field)
    if len(s) > 256:
        raise AuditValidationError(f"{field} exceeds maximum path length (256)")
    parts = s.split("/")[1:]
    if any(seg in ("", ".", "..") for seg in parts):
        raise AuditValidationError(f"{field} must be a normalized absolute path without '.', '..', or '//'")
    return s


def _require_enum(val: Any, allowed: frozenset[str], field: str) -> str:
    if not isinstance(val, str) or val not in allowed:
        raise AuditValidationError(
            f"{field} must be one of {sorted(allowed)} (got {type(val).__name__})"
        )
    return val


def _check_redaction_value(val: str, *, field: str) -> None:
    _check_safe_string(val, field=field)
    for pat in FORBIDDEN_VALUE_PATTERNS:
        if pat.search(val):
            raise AuditRedactionError(f"{field} matched forbidden secret/content redaction rule")


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
            raise AuditRedactionError(f"{event_type}: forbidden field blocked by redaction gate")
    allowed = required | optional
    extra = set(data.keys()) - allowed
    if extra:
        raise AuditRedactionError(
            f"{event_type}: {len(extra)} disallowed extra field(s) blocked by closed allowlist"
        )
    missing = required - set(data.keys())
    if missing:
        raise AuditValidationError(f"{event_type}: missing required field(s) {sorted(missing)}")


def validate_event_data(event_type: str, data: Any) -> None:
    """Validate and enforce the strict redaction allowlist on event `data`."""
    if not isinstance(event_type, str) or event_type not in EVENT_TYPES:
        raise AuditValidationError("unsupported audit event type")
    if not isinstance(data, dict):
        raise AuditValidationError(f"{event_type}: data must be a JSON object")

    # Enforce forbidden keys & closed allowlist BEFORE tree-type checks so
    # e.g. `{"vars": ["secret"]}` or `{"env": None}` always raises AuditRedactionError.
    if event_type == "release_decision":
        _check_keys_allowed(
            data,
            required=frozenset({"release", "release_sha256", "goal_sha256", "projection_sha256", "verdict"}),
            optional=frozenset({"validator_version"}),
            event_type=event_type,
        )
        _check_json_tree(data)
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
        _check_json_tree(data)
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
        _check_json_tree(data)
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
        _check_json_tree(data)
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
        _check_json_tree(data)
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
        _check_json_tree(data)
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
        _check_json_tree(data)
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
        _check_json_tree(data)
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
        _check_json_tree(data)
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
        raise AuditValidationError("invalid prev hash")
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
        raise AuditRedactionError(f"envelope contains {len(extra)} disallowed extra field(s)")
    missing = expected_keys - actual_keys
    if missing:
        raise AuditValidationError(f"envelope missing required field(s): {sorted(missing)}")

    if not _is_exact_int(obj["v"]) or obj["v"] != ENVELOPE_VERSION:
        raise AuditValidationError("unsupported envelope version")
    src = _require_regex(obj["src"], SRC_RE, "src")
    if expected_src is not None and src != expected_src:
        raise AuditValidationError("envelope src does not match expected stream src")
    host = _require_regex(obj["host"], HOST_NAME_RE, "host")
    if expected_host is not None and host != expected_host:
        raise AuditValidationError("envelope host does not match expected stream host")
    _require_regex(obj["boot_id"], BOOT_ID_RE, "boot_id")

    seq = obj["seq"]
    if not _is_exact_int(seq) or seq < 1 or seq > MAX_SAFE_INT:
        raise AuditValidationError("invalid seq")
    parse_utc_timestamp(obj["ts"])
    mono_ms = obj["mono_ms"]
    if not _is_exact_int(mono_ms) or mono_ms < 0 or mono_ms > MAX_SAFE_INT:
        raise AuditValidationError("invalid mono_ms")
    prev = _require_regex(obj["prev"], SHA256_RE, "prev")
    if seq == 1 and prev != GENESIS_PREV:
        raise AuditValidationError("seq 1 must use genesis prev")
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
        if not _safe_digest_equal(obj["h"], expected_h):
            raise AuditValidationError(f"envelope hash mismatch at seq {obj['seq']}")
    return obj


# ---------------------------------------------------------------------------
# Symlink-safe, dir_fd-pinned, crash-safe filesystem helpers
# ---------------------------------------------------------------------------

def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        n = os.write(fd, view[written:])
        if n <= 0:
            raise OSError("short write (0 bytes written)")
        written += n


def _fsync_dir_fd(dir_fd: int) -> None:
    try:
        os.fsync(dir_fd)
    except OSError as exc:
        if exc.errno not in (errno.EINVAL, errno.EBADF, errno.EROFS):
            raise


def _fsync_dir_path(path: Path) -> None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return
    try:
        _fsync_dir_fd(fd)
    finally:
        os.close(fd)


def _check_ancestors_no_symlinks(path: Path) -> None:
    """Verify every existing ancestor component of absolute `path` is a real directory.

    On macOS, allows only the immutable root OS symlinks (`/var -> private/var`,
    `/tmp -> private/tmp`, `/etc -> private/etc`) and rejects all other symlinks.
    """
    abs_p = path if path.is_absolute() else (Path.cwd() / path)
    parts = abs_p.parts
    if not parts or parts[0] != "/":
        raise AuditFileSecurityError(f"path must be absolute: {path}")
    cur = Path("/")
    for comp in parts[1:-1]:
        if comp in ("", ".", ".."):
            raise AuditFileSecurityError(f"unnormalized path component in {path}")
        cur = cur / comp
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            raise AuditFileSecurityError(f"ancestor directory missing: {cur}") from None
        if stat.S_ISLNK(st.st_mode):
            if sys.platform == "darwin" and str(cur) in _DARWIN_OS_ROOT_SYMLINKS:
                target = os.readlink(cur)
                if target == _DARWIN_OS_ROOT_SYMLINKS[str(cur)]:
                    continue
            raise AuditFileSecurityError(f"refusing symlinked ancestor directory: {cur}")
        if not stat.S_ISDIR(st.st_mode):
            raise AuditFileSecurityError(f"ancestor is not a directory: {cur}")


def _verify_private_dir_mode(st: os.stat_result, path: Path) -> None:
    if st.st_uid != os.geteuid():
        raise AuditFileSecurityError(
            f"directory {path} is owned by uid {st.st_uid}, expected euid {os.geteuid()}"
        )
    mode_bits = stat.S_IMODE(st.st_mode)
    if mode_bits & 0o077:
        raise AuditFileSecurityError(
            f"directory {path} has unsafe group/world permissions ({oct(mode_bits)}; require 0700)"
        )
    if mode_bits & 0o6000:
        raise AuditFileSecurityError(
            f"directory {path} has SUID/SGID bit set ({oct(mode_bits)})"
        )


def _ensure_safe_dir_chain(root: Path, rel_components: tuple[str, ...] = (), *, mode: int = 0o700) -> Path:
    """Verify ancestors and `root`, then safely create/verify `rel_components` with `0700`."""
    abs_root = root if root.is_absolute() else (Path.cwd() / root)
    _check_ancestors_no_symlinks(abs_root)

    root_created = False
    try:
        st_root = os.lstat(abs_root)
    except FileNotFoundError:
        try:
            os.mkdir(abs_root, mode)
            root_created = True
        except FileExistsError:
            pass
        st_root = os.lstat(abs_root)
    if stat.S_ISLNK(st_root.st_mode) or not stat.S_ISDIR(st_root.st_mode):
        raise AuditFileSecurityError(f"root directory is missing or symlinked: {abs_root}")
    if root_created:
        os.chmod(abs_root, mode)
        _fsync_dir_path(abs_root.parent)
        st_root = os.lstat(abs_root)
    _verify_private_dir_mode(st_root, abs_root)

    cur = abs_root
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
            _fsync_dir_path(cur.parent)
            st = os.lstat(cur)
        _verify_private_dir_mode(st, cur)
    return cur


@contextmanager
def _open_dir_fd(path: Path, *, require_private: bool = False) -> Iterator[int]:
    """Open an existing real directory without following symlinks and yield its `dir_fd`."""
    abs_p = path if path.is_absolute() else (Path.cwd() / path)
    _check_ancestors_no_symlinks(abs_p)
    st_pre = os.lstat(abs_p)
    if stat.S_ISLNK(st_pre.st_mode) or not stat.S_ISDIR(st_pre.st_mode):
        raise AuditFileSecurityError(f"refusing symlink or non-directory: {abs_p}")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        dfd = os.open(str(abs_p), flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise AuditFileSecurityError(f"refusing symlink or non-directory: {abs_p}") from exc
        raise
    try:
        st_fd = os.fstat(dfd)
        if not stat.S_ISDIR(st_fd.st_mode):
            raise AuditFileSecurityError(f"opened descriptor is not a directory: {abs_p}")
        if st_fd.st_dev != st_pre.st_dev or st_fd.st_ino != st_pre.st_ino:
            raise AuditFileSecurityError(f"directory identity changed during open (TOCTOU): {abs_p}")
        if require_private:
            _verify_private_dir_mode(st_fd, abs_p)
        yield dfd
    finally:
        os.close(dfd)


def _open_regular_in_dir(
    dir_fd: int, name: str, flags: int, *, mode: int = 0o600
) -> tuple[int, bool]:
    """Open regular file `name` inside pinned `dir_fd`, refusing symlinks/FIFOs/devices.

    Returns `(fd, existed_before)`.
    """
    if not name or "/" in name or name in (".", "..") or "\x00" in name:
        raise AuditFileSecurityError(f"unsafe leaf filename: {name!r}")
    try:
        st_pre = os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        st_pre = None
    if st_pre is not None:
        if stat.S_ISLNK(st_pre.st_mode) or not stat.S_ISREG(st_pre.st_mode):
            raise AuditFileSecurityError(f"refusing non-regular or symlinked file: {name}")

    open_flags = flags | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(name, open_flags, mode, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise AuditFileSecurityError(f"refusing symlink: {name}") from exc
        raise
    try:
        st_fd = os.fstat(fd)
        if not stat.S_ISREG(st_fd.st_mode):
            raise AuditFileSecurityError(f"opened descriptor is not a regular file: {name}")
        if st_pre is not None and (st_fd.st_dev != st_pre.st_dev or st_fd.st_ino != st_pre.st_ino):
            raise AuditFileSecurityError(f"file identity changed during open (TOCTOU): {name}")
        return fd, (st_pre is not None)
    except BaseException:
        os.close(fd)
        raise


def _read_small_regular_in_dir(dir_fd: int, name: str, *, max_bytes: int = MAX_LINE_BYTES) -> bytes:
    fd, _ = _open_regular_in_dir(dir_fd, name, os.O_RDONLY)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise AuditValidationError(f"file {name} exceeds maximum safe read size ({max_bytes} bytes)")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _iter_regular_lines_in_dir(
    dir_fd: int,
    name: str,
    *,
    max_line_bytes: int = MAX_LINE_BYTES,
    start_offset: int = 0,
    allow_unterminated_tail: bool = False,
) -> Iterator[tuple[int, bytes, int, bool]]:
    """Stream `(lineno, line_bytes, end_offset, is_unterminated)` from a regular JSONL file."""
    fd, _ = _open_regular_in_dir(dir_fd, name, os.O_RDONLY)
    with os.fdopen(fd, "rb") as fh:
        if start_offset > 0:
            fh.seek(start_offset)
        pos = start_offset
        lineno = 0
        while True:
            raw = fh.readline(max_line_bytes + 2)
            if not raw:
                break
            lineno += 1
            pos += len(raw)
            if len(raw) > max_line_bytes + 1:
                raise AuditValidationError(f"{name}:{lineno} exceeds {max_line_bytes} bytes")
            if not raw.endswith(b"\n"):
                if allow_unterminated_tail:
                    yield (lineno, raw, pos, True)
                    break
                raise AuditValidationError(
                    f"unterminated trailing line at {name}:{lineno} (possible partial write)"
                )
            line = raw[:-1]
            if not line:
                raise AuditValidationError(f"blank line at {name}:{lineno}")
            yield (lineno, line, pos, False)


def _count_lines_streaming_in_dir(dir_fd: int, name: str) -> int:
    """Count non-empty lines in a regular file using constant memory (no 64 MiB cliff)."""
    try:
        st = os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        return 0
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise AuditFileSecurityError(f"refusing non-regular or symlinked file: {name}")
    fd, _ = _open_regular_in_dir(dir_fd, name, os.O_RDONLY)
    count = 0
    saw_data_on_line = False
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            for part in chunk.split(b"\n")[:-1]:
                if part or saw_data_on_line:
                    count += 1
                saw_data_on_line = False
            tail = chunk.rsplit(b"\n", 1)[-1]
            if tail:
                saw_data_on_line = True
        if saw_data_on_line:
            count += 1
        return count
    finally:
        os.close(fd)


def _append_bytes_durable_in_dir(
    dir_fd: int, name: str, payload: bytes, *, mode: int = 0o600
) -> None:
    """Append `payload` durably via `O_APPEND | O_NOFOLLOW` + single `fsync`.

    Compatible with Linux `chattr +a` (`S_APPEND`) files: only calls `os.fchmod`
    when the existing mode differs from `mode`, avoiding unconditional `EPERM`.
    """
    if not payload:
        return
    if not payload.endswith(b"\n"):
        raise ValueError("payload must end with newline")
    fd, existed = _open_regular_in_dir(
        dir_fd, name, os.O_WRONLY | os.O_APPEND | os.O_CREAT, mode=mode
    )
    try:
        st = os.fstat(fd)
        cur_mode = stat.S_IMODE(st.st_mode)
        if cur_mode != mode:
            try:
                os.fchmod(fd, mode)
            except OSError as exc:
                if exc.errno in (errno.EPERM, errno.EACCES) and (cur_mode & 0o6077) == 0:
                    # Existing private file protected by append-only inode flag (e.g. Linux chattr +a).
                    pass
                else:
                    raise AuditFileSecurityError(
                        f"cannot enforce private mode {oct(mode)} on {name} (current {oct(cur_mode)})"
                    ) from exc
        _write_all(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    if not existed:
        _fsync_dir_fd(dir_fd)


def _write_json_atomic_in_dir(
    dir_fd: int, name: str, payload: dict[str, Any], *, mode: int = 0o600
) -> None:
    data = jcs_dumps(payload) + b"\n"
    tmp_name = f".{name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(tmp_name, flags, mode, dir_fd=dir_fd)
    try:
        os.fchmod(fd, mode)
        _write_all(fd, data)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except OSError:
            pass
        raise
    else:
        os.close(fd)
    try:
        os.replace(tmp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except OSError:
            pass
        raise
    _fsync_dir_fd(dir_fd)


@contextmanager
def _exclusive_lock_in_dir(dir_fd: int, lock_name: str) -> Iterator[None]:
    fd, _ = _open_regular_in_dir(dir_fd, lock_name, os.O_RDWR | os.O_CREAT, mode=0o600)
    try:
        st = os.fstat(fd)
        if stat.S_IMODE(st.st_mode) != 0o600:
            os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextmanager
def _shared_lock_if_present(dir_fd: int, lock_name: str) -> Iterator[None]:
    """Acquire shared `LOCK_SH` on `lock_name` if it exists (strictly read-only, never creates)."""
    try:
        fd, _ = _open_regular_in_dir(dir_fd, lock_name, os.O_RDONLY)
    except FileNotFoundError:
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Local hash-chained capture & offline spool
# ---------------------------------------------------------------------------

def _load_jsonl_records_in_dir(
    dir_fd: int,
    name: str,
    *,
    expected_host: str | None = None,
    expected_src: str | None = None,
    recovered_partials: dict[tuple[str, int], tuple[str, int]] | None = None,
) -> list[tuple[dict[str, Any], bytes]]:
    records: list[tuple[dict[str, Any], bytes]] = []
    partials = recovered_partials or {}
    for lineno, line, _, _ in _iter_regular_lines_in_dir(dir_fd, name):
        partial_spec = partials.get((name, lineno))
        if partial_spec is not None:
            exp_sha, exp_len = partial_spec
            act_sha = f"sha256:{hashlib.sha256(line).hexdigest()}"
            if len(line) != exp_len or not _safe_digest_equal(act_sha, exp_sha):
                raise ChainTamperError(f"recovered partial line at {name}:{lineno} was modified")
            continue
        obj = strict_json_loads(line)
        validate_envelope(obj, expected_host=expected_host, expected_src=expected_src, verify_hash=True)
        canonical = jcs_dumps(obj)
        if line != canonical:
            raise AuditValidationError(f"non-canonical JCS bytes at {name}:{lineno}")
        records.append((obj, line))
    return records


def verify_chain_records(
    records: list[dict[str, Any]],
    *,
    expected_host: str | None = None,
    expected_src: str | None = None,
) -> list[TamperFinding]:
    """Verify a sequence of parsed envelopes forms a contiguous valid single-stream hash chain."""
    findings: list[TamperFinding] = []
    expected_seq = 1
    expected_prev = GENESIS_PREV
    pinned_host = expected_host
    pinned_src = expected_src

    for rec in records:
        seq = rec.get("seq") if isinstance(rec, dict) else None
        try:
            validate_envelope(rec, verify_hash=True)
        except AuditError as exc:
            findings.append(TamperFinding("CHAIN_INVALID_RECORD", seq if _is_exact_int(seq) else None, str(exc)))
            continue

        if pinned_host is None:
            pinned_host = rec["host"]
        elif rec["host"] != pinned_host:
            findings.append(
                TamperFinding(
                    "CHAIN_HOST_MISMATCH",
                    rec["seq"],
                    f"expected host {pinned_host!r}, got {rec['host']!r}",
                )
            )
        if pinned_src is None:
            pinned_src = rec["src"]
        elif rec["src"] != pinned_src:
            findings.append(
                TamperFinding(
                    "CHAIN_SRC_MISMATCH",
                    rec["seq"],
                    f"expected src {pinned_src!r}, got {rec['src']!r}",
                )
            )
        if rec["seq"] != expected_seq:
            findings.append(
                TamperFinding(
                    "CHAIN_SEQ_GAP",
                    rec["seq"],
                    f"expected seq {expected_seq}, got {rec['seq']}",
                )
            )
        if not _safe_digest_equal(rec["prev"], expected_prev):
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
        self.log_name = "audit.jsonl"
        self.cursor_name = "cursor.json"
        self.lock_name = ".spool.lock"
        self.log_path = self.spool_dir / self.log_name
        self.cursor_path = self.spool_dir / self.cursor_name
        self.lock_path = self.spool_dir / self.lock_name

    def _read_cursor_unlocked(self, dir_fd: int) -> dict[str, Any] | None:
        try:
            os.lstat(self.cursor_name, dir_fd=dir_fd)
        except FileNotFoundError:
            return None
        try:
            raw = _read_small_regular_in_dir(dir_fd, self.cursor_name, max_bytes=MAX_LINE_BYTES)
            obj = strict_json_loads(raw.rstrip(b"\n"))
        except AuditValidationError as exc:
            raise ChainTamperError(f"cursor.json corrupt: {exc}") from exc
        if obj.get("host") != self.host or obj.get("src") != self.src:
            raise ChainTamperError("cursor.json host/src mismatch")
        for key in ("local_seq", "acked_seq"):
            if not _is_exact_int(obj.get(key)) or obj[key] < 0 or obj[key] > MAX_SAFE_INT:
                raise ChainTamperError(f"cursor.json invalid {key}")
        for key in ("local_h", "acked_h"):
            val = obj.get(key)
            if not isinstance(val, str) or not SHA256_RE.match(val):
                raise ChainTamperError(f"cursor.json invalid {key}")
        for key in ("local_offset", "acked_offset"):
            if key in obj:
                if not _is_exact_int(obj[key]) or obj[key] < 0 or obj[key] > MAX_SAFE_INT:
                    raise ChainTamperError(f"cursor.json invalid {key}")
        if obj["acked_seq"] > obj["local_seq"]:
            raise ChainTamperError("cursor.json acked_seq exceeds local_seq")
        if "local_offset" in obj and "acked_offset" in obj and obj["acked_offset"] > obj["local_offset"]:
            raise ChainTamperError("cursor.json acked_offset exceeds local_offset")
        if obj["local_seq"] == 0 and obj["local_h"] != GENESIS_PREV:
            raise ChainTamperError("cursor.json local_seq 0 must use genesis hash")
        if obj["acked_seq"] == 0 and obj["acked_h"] != GENESIS_PREV:
            raise ChainTamperError("cursor.json acked_seq 0 must use genesis hash")
        if obj["local_seq"] == 0 and obj.get("local_offset", 0) != 0:
            raise ChainTamperError("cursor.json local_seq 0 must have local_offset 0")
        if obj["acked_seq"] == 0 and obj.get("acked_offset", 0) != 0:
            raise ChainTamperError("cursor.json acked_seq 0 must have acked_offset 0")
        return obj

    def _read_last_record_ending_at(
        self, dir_fd: int, end_offset: int
    ) -> dict[str, Any]:
        """O(1) read & validation of the single canonical record ending at `end_offset`."""
        fd, _ = _open_regular_in_dir(dir_fd, self.log_name, os.O_RDONLY)
        try:
            start = max(0, end_offset - (MAX_LINE_BYTES + 2))
            os.lseek(fd, start, os.SEEK_SET)
            buf = b""
            to_read = end_offset - start
            while len(buf) < to_read:
                chunk = os.read(fd, to_read - len(buf))
                if not chunk:
                    break
                buf += chunk
        finally:
            os.close(fd)
        if len(buf) != (end_offset - start) or not buf.endswith(b"\n"):
            raise ChainTamperError("local audit.jsonl missing newline at cursor local_offset")
        body = buf[:-1]
        last_line = body.rsplit(b"\n", 1)[-1]
        try:
            obj = strict_json_loads(last_line)
            validate_envelope(obj, expected_host=self.host, expected_src=self.src, verify_hash=True)
            if last_line != jcs_dumps(obj):
                raise AuditValidationError("non-canonical JCS bytes at tail")
        except AuditError as exc:
            raise ChainTamperError(f"local audit.jsonl tail corrupt: {exc}") from exc
        return obj

    def _sync_state_unlocked(self, dir_fd: int) -> dict[str, Any]:
        """O(1) tail verification & crash-recovery against `cursor.json` byte offsets.

        Falls back to a full scan only when `cursor.json` is absent or lacks
        byte offsets (e.g. first recovery after cursor deletion).
        """
        cursor = self._read_cursor_unlocked(dir_fd)
        try:
            st_log = os.lstat(self.log_name, dir_fd=dir_fd)
            has_log = True
        except FileNotFoundError:
            st_log = None
            has_log = False

        if not has_log:
            if cursor is not None and cursor["local_seq"] > 0:
                raise ChainTamperError(
                    f"local audit.jsonl missing while cursor expects local_seq={cursor['local_seq']}"
                )
            return {
                "host": self.host,
                "src": self.src,
                "local_seq": 0,
                "local_h": GENESIS_PREV,
                "local_offset": 0,
                "acked_seq": 0,
                "acked_h": GENESIS_PREV,
                "acked_offset": 0,
            }

        assert st_log is not None
        if stat.S_ISLNK(st_log.st_mode) or not stat.S_ISREG(st_log.st_mode):
            raise AuditFileSecurityError(f"refusing non-regular or symlinked file: {self.log_name}")
        file_size = st_log.st_size

        # Fast O(1) path when cursor has verified byte offsets.
        if cursor is not None and "local_offset" in cursor and "acked_offset" in cursor:
            local_off = cursor["local_offset"]
            acked_off = cursor["acked_offset"]
            if file_size < local_off:
                raise ChainTamperError(
                    f"local audit.jsonl truncated: size={file_size} < cursor local_offset={local_off}"
                )
            if cursor["local_seq"] > 0:
                if local_off == 0:
                    raise ChainTamperError("cursor.json local_seq > 0 with local_offset == 0")
                tail_rec = self._read_last_record_ending_at(dir_fd, local_off)
                if tail_rec["seq"] != cursor["local_seq"] or not _safe_digest_equal(
                    tail_rec["h"], cursor["local_h"]
                ):
                    raise ChainTamperError(
                        f"local audit.jsonl tail mismatch at cursor seq={cursor['local_seq']}"
                    )
            if cursor["acked_seq"] > 0:
                if acked_off == 0 or acked_off > local_off:
                    raise ChainTamperError("cursor.json invalid acked_offset")
                ack_rec = self._read_last_record_ending_at(dir_fd, acked_off)
                if ack_rec["seq"] != cursor["acked_seq"] or not _safe_digest_equal(
                    ack_rec["h"], cursor["acked_h"]
                ):
                    raise ChainTamperError(
                        f"local audit.jsonl mismatch at acked seq={cursor['acked_seq']}"
                    )

            state = dict(cursor)
            if file_size > local_off:
                # Crash recovery: scan ONLY the new bytes appended past cursor.local_offset.
                cur_seq = state["local_seq"]
                cur_h = state["local_h"] if cur_seq > 0 else GENESIS_PREV
                cur_off = local_off
                try:
                    for _, line, end_off, _ in _iter_regular_lines_in_dir(
                        dir_fd, self.log_name, start_offset=local_off
                    ):
                        obj = strict_json_loads(line)
                        validate_envelope(
                            obj, expected_host=self.host, expected_src=self.src, verify_hash=True
                        )
                        if line != jcs_dumps(obj):
                            raise AuditValidationError("non-canonical JCS bytes")
                        if obj["seq"] != cur_seq + 1 or not _safe_digest_equal(obj["prev"], cur_h):
                            raise ChainTamperError("local audit.jsonl crash-recovery chain break")
                        cur_seq = obj["seq"]
                        cur_h = obj["h"]
                        cur_off = end_off
                except AuditValidationError as exc:
                    raise ChainTamperError(f"local audit.jsonl unreadable or torn: {exc}") from exc
                state["local_seq"] = cur_seq
                state["local_h"] = cur_h
                state["local_offset"] = cur_off
            return state

        # One-time full scan when cursor.json is missing or predates byte offsets.
        cur_seq = 0
        cur_h = GENESIS_PREV
        cur_off = 0
        seq_to_meta: dict[int, tuple[str, int]] = {}
        try:
            for _, line, end_off, _ in _iter_regular_lines_in_dir(dir_fd, self.log_name):
                obj = strict_json_loads(line)
                validate_envelope(
                    obj, expected_host=self.host, expected_src=self.src, verify_hash=True
                )
                if line != jcs_dumps(obj):
                    raise AuditValidationError("non-canonical JCS bytes")
                if obj["seq"] != cur_seq + 1 or not _safe_digest_equal(obj["prev"], cur_h):
                    raise ChainTamperError("local audit.jsonl chain corrupt")
                cur_seq = obj["seq"]
                cur_h = obj["h"]
                cur_off = end_off
                if cursor is not None and cur_seq in (cursor["local_seq"], cursor["acked_seq"]):
                    seq_to_meta[cur_seq] = (cur_h, end_off)
        except AuditValidationError as exc:
            raise ChainTamperError(f"local audit.jsonl unreadable or torn: {exc}") from exc

        if cursor is None:
            return {
                "host": self.host,
                "src": self.src,
                "local_seq": cur_seq,
                "local_h": cur_h,
                "local_offset": cur_off,
                "acked_seq": 0,
                "acked_h": GENESIS_PREV,
                "acked_offset": 0,
            }

        if cur_seq < cursor["local_seq"]:
            raise ChainTamperError(
                f"local audit.jsonl truncated: seq={cur_seq} < cursor local_seq={cursor['local_seq']}"
            )
        if cursor["local_seq"] > 0:
            meta = seq_to_meta.get(cursor["local_seq"])
            if meta is None or not _safe_digest_equal(meta[0], cursor["local_h"]):
                raise ChainTamperError(
                    f"local audit.jsonl hash mismatch at cursor seq={cursor['local_seq']}"
                )
        acked_off = 0
        if cursor["acked_seq"] > 0:
            meta = seq_to_meta.get(cursor["acked_seq"])
            if meta is None or not _safe_digest_equal(meta[0], cursor["acked_h"]):
                raise ChainTamperError(
                    f"local audit.jsonl hash mismatch at acked seq={cursor['acked_seq']}"
                )
            acked_off = meta[1]

        recovered = dict(cursor)
        recovered["local_seq"] = cur_seq
        recovered["local_h"] = cur_h
        recovered["local_offset"] = cur_off
        recovered["acked_offset"] = acked_off
        return recovered

    def append(
        self,
        event_type: str,
        data: dict[str, Any],
        *,
        ts: str | None = None,
        mono_ms: int | None = None,
        boot_id: str | None = None,
    ) -> dict[str, Any]:
        """Append one validated, redacted, hash-chained event to the local spool in O(1) time."""
        effective_boot = boot_id if boot_id is not None else self.boot_id
        with _open_dir_fd(self.spool_dir, require_private=True) as dfd:
            with _exclusive_lock_in_dir(dfd, self.lock_name):
                state = self._sync_state_unlocked(dfd)
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
                _append_bytes_durable_in_dir(dfd, self.log_name, line_bytes, mode=0o600)
                state["local_seq"] = next_seq
                state["local_h"] = envelope["h"]
                state["local_offset"] = state["local_offset"] + len(line_bytes)
                _write_json_atomic_in_dir(dfd, self.cursor_name, state, mode=0o600)
                return envelope

    def watermark(self) -> dict[str, Any]:
        """Return synchronized O(1) cursor watermark without materializing pending records."""
        with _open_dir_fd(self.spool_dir, require_private=True) as dfd:
            with _exclusive_lock_in_dir(dfd, self.lock_name):
                return dict(self._sync_state_unlocked(dfd))

    def unshipped(self, *, limit: int | None = None) -> tuple[list[tuple[dict[str, Any], bytes]], dict[str, Any]]:
        """Return unshipped `(envelope, canonical_line)` pairs by seeking to `acked_offset`."""
        with _open_dir_fd(self.spool_dir, require_private=True) as dfd:
            with _exclusive_lock_in_dir(dfd, self.lock_name):
                state = self._sync_state_unlocked(dfd)
                if state["acked_seq"] >= state["local_seq"]:
                    return [], dict(state)
                pending: list[tuple[dict[str, Any], bytes]] = []
                exp_seq = state["acked_seq"] + 1
                exp_prev = state["acked_h"] if state["acked_seq"] > 0 else GENESIS_PREV
                try:
                    for _, line, _, _ in _iter_regular_lines_in_dir(
                        dfd, self.log_name, start_offset=state["acked_offset"]
                    ):
                        obj = strict_json_loads(line)
                        validate_envelope(
                            obj, expected_host=self.host, expected_src=self.src, verify_hash=True
                        )
                        if line != jcs_dumps(obj):
                            raise AuditValidationError("non-canonical JCS bytes")
                        if obj["seq"] != exp_seq or not _safe_digest_equal(obj["prev"], exp_prev):
                            raise ChainTamperError("local audit.jsonl chain mismatch during unshipped read")
                        pending.append((obj, line))
                        exp_seq += 1
                        exp_prev = obj["h"]
                        if limit is not None and len(pending) >= limit:
                            break
                except AuditValidationError as exc:
                    raise ChainTamperError(f"local audit.jsonl unreadable: {exc}") from exc
                return pending, dict(state)

    def advance_ack(self, acked_seq: int, acked_h: str) -> dict[str, Any]:
        """Durably advance the shipped watermark by scanning forward from `acked_offset`."""
        if not _is_exact_int(acked_seq) or acked_seq < 0 or acked_seq > MAX_SAFE_INT:
            raise TransportError("invalid acked_seq")
        _require_regex(acked_h, SHA256_RE, "acked_h")
        with _open_dir_fd(self.spool_dir, require_private=True) as dfd:
            with _exclusive_lock_in_dir(dfd, self.lock_name):
                state = self._sync_state_unlocked(dfd)
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
                    new_acked_off = 0
                elif acked_seq == state["acked_seq"]:
                    if not _safe_digest_equal(state["acked_h"], acked_h):
                        raise TransportError(f"sink ack hash mismatch at seq {acked_seq}")
                    new_acked_off = state["acked_offset"]
                else:
                    found_off: int | None = None
                    exp_seq = state["acked_seq"] + 1
                    exp_prev = state["acked_h"] if state["acked_seq"] > 0 else GENESIS_PREV
                    try:
                        for _, line, end_off, _ in _iter_regular_lines_in_dir(
                            dfd, self.log_name, start_offset=state["acked_offset"]
                        ):
                            obj = strict_json_loads(line)
                            validate_envelope(
                                obj, expected_host=self.host, expected_src=self.src, verify_hash=True
                            )
                            if line != jcs_dumps(obj):
                                raise AuditValidationError("non-canonical JCS bytes")
                            if obj["seq"] != exp_seq or not _safe_digest_equal(obj["prev"], exp_prev):
                                raise ChainTamperError("local audit.jsonl chain mismatch during ack")
                            if obj["seq"] == acked_seq:
                                if not _safe_digest_equal(obj["h"], acked_h):
                                    raise TransportError(f"sink ack hash mismatch at seq {acked_seq}")
                                found_off = end_off
                                break
                            exp_seq += 1
                            exp_prev = obj["h"]
                    except AuditValidationError as exc:
                        raise ChainTamperError(f"local audit.jsonl unreadable during ack: {exc}") from exc
                    if found_off is None:
                        raise ChainTamperError(f"seq {acked_seq} missing in local audit.jsonl")
                    new_acked_off = found_off

                state["acked_seq"] = acked_seq
                state["acked_h"] = acked_h
                state["acked_offset"] = new_acked_off
                _write_json_atomic_in_dir(dfd, self.cursor_name, state, mode=0o600)
                return dict(state)


# ---------------------------------------------------------------------------
# Hardened SSH append-only transport and offline-resilient shipper
# ---------------------------------------------------------------------------

_DARWIN_ACL_LINE_RE = re.compile(r"^ \d+: ")


def _check_darwin_no_extended_acl(path: Path) -> None:
    """On macOS, fail closed if `path` carries any extended ACL or cannot be inspected (H3)."""
    if sys.platform != "darwin":
        return
    try:
        proc = subprocess.run(
            ["/bin/ls", "-lde", "--", str(path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AuditFileSecurityError(f"cannot inspect macOS ACL on {path}") from exc
    if proc.returncode != 0:
        raise AuditFileSecurityError(f"cannot inspect macOS ACL on {path}")
    for line in proc.stdout.splitlines()[1:]:
        if _DARWIN_ACL_LINE_RE.match(line):
            raise AuditFileSecurityError(f"{path} has a macOS extended ACL; refusing")


def _check_ancestors_trusted_unwritable(path: Path, *, allowed_uids: set[int]) -> None:
    """Verify every ancestor directory from `/` down to `path.parent` is real, trusted-owned, and go-w."""
    parts = path.parts
    if not parts or parts[0] != "/":
        raise AuditFileSecurityError(f"path must be absolute: {path}")
    cur = Path("/")
    for idx in range(len(parts) - 1):
        if idx > 0:
            cur = cur / parts[idx]
        st = os.lstat(cur)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise AuditFileSecurityError(f"ancestor {cur} is symlink or non-directory")
        if st.st_uid not in allowed_uids:
            raise AuditFileSecurityError(f"ancestor {cur} owned by untrusted uid {st.st_uid}")
        if (stat.S_IMODE(st.st_mode) & 0o022) != 0:
            raise AuditFileSecurityError(
                f"ancestor {cur} is group- or world-writable (mode {oct(stat.S_IMODE(st.st_mode))})"
            )
        _check_darwin_no_extended_acl(cur)


def _validate_ssh_safe_file_path(
    p: Path,
    *,
    label: str,
    require_private_mode: bool = False,
    require_exec: bool = False,
    enforce_owner_and_ancestors: bool = False,
) -> Path:
    if not p.is_absolute():
        raise AuditFileSecurityError(f"{label} must be an absolute path")
    s = str(p)
    if not SSH_SAFE_PATH_RE.match(s) or "//" in s:
        raise AuditFileSecurityError(f"{label} contains unsafe characters for OpenSSH option/path")
    parts = s.split("/")[1:]
    if any(seg in ("", ".", "..") for seg in parts):
        raise AuditFileSecurityError(f"{label} must be normalized without '.' or '..'")
    _check_ancestors_no_symlinks(p)
    st = os.lstat(p)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise AuditFileSecurityError(f"{label} must be a regular non-symlink file")
    mode = stat.S_IMODE(st.st_mode)
    if enforce_owner_and_ancestors:
        euid = os.geteuid()
        allowed = {0} if euid == 0 else {0, euid}
        _check_ancestors_trusted_unwritable(p, allowed_uids=allowed)
        if st.st_uid not in allowed:
            raise AuditFileSecurityError(f"{label} owned by untrusted uid {st.st_uid}")
        if (mode & 0o6022) != 0:
            raise AuditFileSecurityError(f"{label} has writable or SUID/SGID mode {oct(mode)}")
        _check_darwin_no_extended_acl(p)
    if require_private_mode and (mode & 0o6077) != 0:
        raise AuditFileSecurityError(
            f"{label} must be private without group/other or SUID/SGID bits (mode {oct(mode)})"
        )
    if require_exec and not os.access(p, os.X_OK):
        raise AuditFileSecurityError(f"{label} is not executable")
    return p


def build_ssh_append_argv(
    *,
    target: str,
    identity_file: Path,
    known_hosts_file: Path,
    src: str = DEFAULT_SRC,
    ssh_bin: str = "/usr/bin/ssh",
    port: int | None = None,
    connect_timeout_s: int = 10,
    enforce_owner_and_ancestors: bool = False,
) -> list[str]:
    """Build a hardened, non-interactive argv list for SSH append-only shipping."""
    _require_regex(src, SRC_RE, "src")
    if not isinstance(target, str) or not SSH_TARGET_RE.match(target) or target.startswith("-"):
        raise TransportError("unsafe SSH target")
    ssh_path = _validate_ssh_safe_file_path(
        Path(ssh_bin),
        label="ssh_bin",
        require_exec=True,
        enforce_owner_and_ancestors=enforce_owner_and_ancestors,
    )
    id_path = _validate_ssh_safe_file_path(
        identity_file,
        label="identity_file",
        require_private_mode=True,
        enforce_owner_and_ancestors=enforce_owner_and_ancestors,
    )
    kh_path = _validate_ssh_safe_file_path(
        known_hosts_file,
        label="known_hosts_file",
        enforce_owner_and_ancestors=enforce_owner_and_ancestors,
    )
    if not _is_exact_int(connect_timeout_s) or connect_timeout_s < 1 or connect_timeout_s > 120:
        raise TransportError("invalid connect_timeout_s")

    argv = [
        str(ssh_path),
        "-F", "/dev/null",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "CheckHostIP=yes",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"UserKnownHostsFile={kh_path}",
        "-o", "KnownHostsCommand=none",
        "-o", "ProxyCommand=none",
        "-o", "ProxyJump=none",
        "-o", "ClearAllForwardings=yes",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "RequestTTY=no",
        "-o", "PermitLocalCommand=no",
        "-o", "ControlMaster=no",
        "-o", "ControlPath=none",
        "-o", "ControlPersist=no",
        "-o", f"ConnectTimeout={connect_timeout_s}",
        "-i", str(id_path),
    ]
    if port is not None:
        if not _is_exact_int(port) or port < 1 or port > 65535:
            raise TransportError("invalid SSH port")
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
    enforce_owner_and_ancestors: bool = False,
) -> Callable[[bytes], dict[str, Any]]:
    """Create a callable transport that pipes JSONL batches to the SSH forced command."""
    if not _is_exact_int(io_timeout_s) or io_timeout_s < 1 or io_timeout_s > 600:
        raise TransportError("invalid io_timeout_s")
    argv = build_ssh_append_argv(
        target=target,
        identity_file=identity_file,
        known_hosts_file=known_hosts_file,
        src=src,
        ssh_bin=ssh_bin,
        port=port,
        connect_timeout_s=connect_timeout_s,
        enforce_owner_and_ancestors=enforce_owner_and_ancestors,
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
        except subprocess.TimeoutExpired as exc:
            raise TransportError("ssh_timeout") from exc
        except (OSError, subprocess.SubprocessError) as exc:
            err_code = getattr(exc, "errno", None)
            suffix = f"_errno_{err_code}" if err_code is not None else ""
            raise TransportError(f"ssh_exec_error{suffix}") from exc
        if proc.returncode != 0:
            # Never propagate remote-influenced stderr into structured results or scheduler logs (M6).
            raise TransportError(f"ssh_exit_{proc.returncode}")
        out = proc.stdout.strip()
        if not out:
            raise TransportError("ssh_empty_ack")
        try:
            return strict_json_loads(out)
        except AuditValidationError as exc:
            raise TransportError("ssh_malformed_ack") from exc

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
        max_batch_bytes: int = MAX_BATCH_BYTES,
    ) -> None:
        if not _is_exact_int(batch_size) or batch_size < 1 or batch_size > MAX_BATCH_LINES:
            raise ValueError(f"batch_size must be 1..{MAX_BATCH_LINES}")
        if not _is_exact_int(max_batches) or max_batches < 1 or max_batches > 10000:
            raise ValueError("max_batches must be 1..10000")
        if not _is_exact_int(max_batch_bytes) or max_batch_bytes < MAX_LINE_BYTES or max_batch_bytes > MAX_BATCH_BYTES:
            raise ValueError(f"max_batch_bytes must be {MAX_LINE_BYTES}..{MAX_BATCH_BYTES}")
        self.spool = spool
        self.transport = transport
        self.batch_size = batch_size
        self.max_batches = max_batches
        self.max_batch_bytes = max_batch_bytes

    def _slice_batch(
        self, pending: list[tuple[dict[str, Any], bytes]]
    ) -> list[tuple[dict[str, Any], bytes]]:
        batch: list[tuple[dict[str, Any], bytes]] = []
        total_bytes = 0
        for item in pending:
            line_len = len(item[1]) + 1
            if batch and (len(batch) >= self.batch_size or total_bytes + line_len > self.max_batch_bytes):
                break
            batch.append(item)
            total_bytes += line_len
        return batch

    def ship(self) -> ShipResult:
        """Drain unshipped records in bounded batches. Never raises on unreachable sink."""
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

            batch = self._slice_batch(pending)
            batch_bytes = b"".join(raw + b"\n" for _, raw in batch)
            sent_by_seq = {rec["seq"]: rec["h"] for rec, _ in batch}
            prev_acked = state["acked_seq"]

            try:
                ack = self.transport(batch_bytes)
                if not isinstance(ack, dict) or ack.get("ok") is not True:
                    raise TransportError("sink rejected batch")
                if ack.get("host") != self.spool.host or ack.get("src") != self.spool.src:
                    raise TransportError("sink ack host/src mismatch")
                ack_seq = ack.get("last_seq")
                ack_h = ack.get("last_h")
                if not _is_exact_int(ack_seq) or ack_seq < prev_acked:
                    raise TransportError("invalid or regressed sink ack last_seq")
                if ack_seq == 0:
                    raise TransportError("sink acked 0 records for non-empty batch")
                if not isinstance(ack_h, str) or not SHA256_RE.match(ack_h):
                    raise TransportError("invalid sink ack last_h")

                if ack_seq == prev_acked:
                    # No watermark progress (e.g. head record quarantined).
                    last_state = state
                else:
                    # If ack_seq is within this batch, verify directly; if the sink is
                    # ahead (e.g. batch_size shrank or cursor.json was rebuilt),
                    # spool.advance_ack verifies ack_seq <= local_seq and exact hash
                    # match against the local audit chain.
                    if ack_seq in sent_by_seq and not _safe_digest_equal(sent_by_seq[ack_seq], ack_h):
                        raise TransportError("sink ack hash disagrees with sent record")
                    last_state = self.spool.advance_ack(ack_seq, ack_h)
            except (TransportError, AuditError, OSError) as exc:
                cur_state = self.spool.watermark()
                rem_count = max(0, cur_state["local_seq"] - cur_state["acked_seq"])
                return ShipResult(
                    ok=False,
                    shipped=total_shipped,
                    duplicates=total_dups,
                    quarantined=total_quarantined,
                    remaining=rem_count,
                    last_acked_seq=cur_state["acked_seq"],
                    last_acked_h=cur_state["acked_h"] if cur_state["acked_seq"] > 0 else None,
                    error=str(exc),
                )

            total_shipped += int(ack.get("accepted", 0)) if _is_exact_int(ack.get("accepted")) else 0
            total_dups += int(ack.get("duplicates", 0)) if _is_exact_int(ack.get("duplicates")) else 0
            total_quarantined += (
                int(ack.get("quarantined", 0)) if _is_exact_int(ack.get("quarantined")) else 0
            )

            if last_state["acked_seq"] == prev_acked:
                cur_state = self.spool.watermark()
                rem_count = max(0, cur_state["local_seq"] - cur_state["acked_seq"])
                return ShipResult(
                    ok=False,
                    shipped=total_shipped,
                    duplicates=total_dups,
                    quarantined=total_quarantined,
                    remaining=rem_count,
                    last_acked_seq=cur_state["acked_seq"],
                    last_acked_h=cur_state["acked_h"] if cur_state["acked_seq"] > 0 else None,
                    error="sink did not advance watermark (head record quarantined or rejected)",
                )

        cur_state = self.spool.watermark()
        rem_count = max(0, cur_state["local_seq"] - cur_state["acked_seq"])
        return ShipResult(
            ok=rem_count == 0,
            shipped=total_shipped,
            duplicates=total_dups,
            quarantined=total_quarantined,
            remaining=rem_count,
            last_acked_seq=cur_state["acked_seq"],
            last_acked_h=cur_state["acked_h"] if cur_state["acked_seq"] > 0 else None,
            error=None if rem_count == 0 else "max_batches reached with remaining records",
        )


# ---------------------------------------------------------------------------
# Append-only sink receiver & forced-command boundary (`audit-append`)
# ---------------------------------------------------------------------------

def _iter_sink_day_names(dir_fd: int) -> list[str]:
    entries: list[tuple[str, str]] = []
    for name in os.listdir(dir_fd):
        m = DAY_FILE_RE.match(name)
        if not m:
            continue
        st = os.lstat(name, dir_fd=dir_fd)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise AuditFileSecurityError(f"sink daily log is symlink or non-regular: {name}")
        entries.append((m.group(1), name))
    entries.sort(key=lambda item: item[0])
    return [name for _, name in entries]


RECOVERED_PARTIALS_DIR = "recovered_partials"
RECOVERED_PARTIAL_FILE_RE = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2}\.jsonl)\.([1-9][0-9]*)\.json\Z"
)
RECOVERED_PARTIAL_TMP_RE = re.compile(
    r"^\.[0-9]{4}-[0-9]{2}-[0-9]{2}\.jsonl\.[1-9][0-9]*\.json\.tmp\.[0-9]+\.[0-9a-f]{16}\Z"
)


def _open_child_dir_fd(
    parent_fd: int, name: str, *, create: bool = False, require_private: bool = False
) -> int | None:
    """Open (optionally create) a direct child directory inside `parent_fd` without following symlinks."""
    if not name or "/" in name or name in (".", "..") or "\x00" in name:
        raise AuditFileSecurityError(f"unsafe child directory name: {name!r}")
    created = False
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            pass
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        child_fd = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            return None
        raise
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise AuditFileSecurityError(f"refusing symlink or non-directory: {name}") from exc
        raise
    try:
        st_fd = os.fstat(child_fd)
        if not stat.S_ISDIR(st_fd.st_mode):
            raise AuditFileSecurityError(f"opened descriptor is not a directory: {name}")
        if created:
            os.fchmod(child_fd, 0o700)
            _fsync_dir_fd(parent_fd)
            st_fd = os.fstat(child_fd)
        if require_private:
            _verify_private_dir_mode(st_fd, Path(name))
        return child_fd
    except BaseException:
        os.close(child_fd)
        raise


def _parse_recovered_partial_item(item: Any) -> tuple[tuple[str, int], tuple[str, int]]:
    if not isinstance(item, dict) or set(item.keys()) != {"file", "line", "raw_sha256", "raw_len"}:
        raise ChainTamperError("invalid recovered_partials entry")
    fn = item.get("file")
    ln = item.get("line")
    sha = item.get("raw_sha256")
    rlen = item.get("raw_len")
    if (
        not isinstance(fn, str)
        or not DAY_FILE_RE.match(fn)
        or not _is_exact_int(ln)
        or ln < 1
        or ln > MAX_SAFE_INT
        or not isinstance(sha, str)
        or not SHA256_RE.match(sha)
        or not _is_exact_int(rlen)
        or rlen < 1
        or rlen > MAX_SAFE_INT
    ):
        raise ChainTamperError("malformed recovered_partials entry")
    return (fn, ln), (sha, rlen)


def _load_recovered_partials_in_dir(
    dir_fd: int,
    legacy_state_obj: dict[str, Any] | None = None,
    *,
    require_private: bool = False,
) -> dict[tuple[str, int], tuple[str, int]]:
    """Load atomic per-pin files from `recovered_partials/` (unbounded, crash-safe, no 64 KiB cap)."""
    out: dict[tuple[str, int], tuple[str, int]] = {}
    if legacy_state_obj is not None and legacy_state_obj.get("recovered_partials") is not None:
        raw_list = legacy_state_obj["recovered_partials"]
        if not isinstance(raw_list, list):
            raise ChainTamperError("sink state.json invalid recovered_partials")
        for item in raw_list:
            key, val = _parse_recovered_partial_item(item)
            if key in out and out[key] != val:
                raise ChainTamperError(f"conflicting recovered_partials pin for {key[0]}:{key[1]}")
            out[key] = val
    rp_dfd = _open_child_dir_fd(
        dir_fd, RECOVERED_PARTIALS_DIR, create=False, require_private=require_private
    )
    if rp_dfd is None:
        return out
    try:
        for name in sorted(os.listdir(rp_dfd)):
            st = os.lstat(name, dir_fd=rp_dfd)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                raise AuditFileSecurityError(
                    f"{RECOVERED_PARTIALS_DIR}/{name} is symlink or non-regular"
                )
            if RECOVERED_PARTIAL_TMP_RE.match(name):
                # Interrupted pre-rename temp file from _write_json_atomic_in_dir; safe to ignore.
                continue
            m = RECOVERED_PARTIAL_FILE_RE.match(name)
            if not m:
                raise ChainTamperError(f"unexpected file in {RECOVERED_PARTIALS_DIR}: {name}")
            expected_key = (m.group(1), int(m.group(2)))
            try:
                raw = _read_small_regular_in_dir(rp_dfd, name, max_bytes=4096)
                key, val = _parse_recovered_partial_item(strict_json_loads(raw.rstrip(b"\n")))
            except AuditValidationError as exc:
                raise ChainTamperError(f"{RECOVERED_PARTIALS_DIR}/{name} corrupt: {exc}") from exc
            if key != expected_key:
                raise ChainTamperError(
                    f"{RECOVERED_PARTIALS_DIR}/{name} disagrees with payload key {key[0]}:{key[1]}"
                )
            if key in out and out[key] != val:
                raise ChainTamperError(f"conflicting recovered_partials pin for {key[0]}:{key[1]}")
            out[key] = val
    finally:
        os.close(rp_dfd)
    return out


def _load_sink_committed_records_in_dir(
    dir_fd: int,
    *,
    expected_host: str | None = None,
    expected_src: str | None = None,
    recovered_partials: dict[tuple[str, int], tuple[str, int]] | None = None,
    allow_unterminated_tail: bool = False,
) -> tuple[list[tuple[dict[str, Any], bytes]], list[tuple[str, int, bytes]]]:
    all_records: list[tuple[dict[str, Any], bytes]] = []
    unterminated: list[tuple[str, int, bytes]] = []
    seen_seqs: set[int] = set()
    partials = recovered_partials or {}
    for day_name in _iter_sink_day_names(dir_fd):
        for lineno, line, _, is_unterm in _iter_regular_lines_in_dir(
            dir_fd, day_name, allow_unterminated_tail=allow_unterminated_tail
        ):
            if is_unterm:
                unterminated.append((day_name, lineno, line))
                continue
            partial_spec = partials.get((day_name, lineno))
            if partial_spec is not None:
                exp_sha, exp_len = partial_spec
                act_sha = f"sha256:{hashlib.sha256(line).hexdigest()}"
                if len(line) != exp_len or not _safe_digest_equal(act_sha, exp_sha):
                    raise ChainTamperError(
                        f"sink recovered partial line at {day_name}:{lineno} was modified"
                    )
                continue
            obj = strict_json_loads(line)
            validate_envelope(
                obj, expected_host=expected_host, expected_src=expected_src, verify_hash=True
            )
            canonical = jcs_dumps(obj)
            if line != canonical:
                raise AuditValidationError(f"non-canonical JCS bytes at {day_name}:{lineno}")
            seq = obj["seq"]
            if seq in seen_seqs:
                raise ChainTamperError(f"sink contains duplicate committed seq {seq} in {day_name}")
            seen_seqs.add(seq)
            all_records.append((obj, line))
    all_records.sort(key=lambda pair: pair[0]["seq"])
    return all_records, unterminated


class AuditSink:
    """Append-only off-device sink pinned to one `(host, src)` stream.

    Writes valid records exclusively via `O_APPEND | O_NOFOLLOW` to
    `<sink_root>/<host>/<src>/YYYY-MM-DD.jsonl` (keyed on sink receive date so
    an untrusted client clock cannot proliferate arbitrary filenames) and
    quarantines gaps, forks, hash mismatches, or invalid/redaction-failing
    lines to `quarantine.jsonl`.

    Deployment note for Linux `chattr +a`: apply `chattr +a` to the `.jsonl`
    files (`YYYY-MM-DD.jsonl` and `quarantine.jsonl`), NOT to `state.json` or
    `stream_dir` (which require atomic temp-file creation and `os.replace`).
    If an interrupted append leaves an unterminated trailing fragment on a
    daily `.jsonl` file, recovery seals it append-only with `\\n`, pins its
    `(file, line, raw_sha256, raw_len)` in `state.json["recovered_partials"]`,
    and witnesses the recovery in `quarantine.jsonl` so retries succeed.
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
        self.state_name = "state.json"
        self.quarantine_name = "quarantine.jsonl"
        self.lock_name = ".sink.lock"
        self.state_path = self.stream_dir / self.state_name
        self.quarantine_path = self.stream_dir / self.quarantine_name
        self.lock_path = self.stream_dir / self.lock_name

    def _read_state_unlocked(
        self, dir_fd: int, *, now_ts: str
    ) -> tuple[dict[str, Any], dict[int, tuple[dict[str, Any], bytes]], bool, list[bytes]]:
        try:
            os.lstat(self.state_name, dir_fd=dir_fd)
            has_state = True
        except FileNotFoundError:
            has_state = False

        raw_state: dict[str, Any] | None = None
        recovered_partials: dict[tuple[str, int], tuple[str, int]] = {}
        if has_state:
            try:
                raw = _read_small_regular_in_dir(dir_fd, self.state_name, max_bytes=MAX_LINE_BYTES)
                raw_state = strict_json_loads(raw.rstrip(b"\n"))
            except AuditValidationError as exc:
                raise ChainTamperError(f"sink state.json corrupt: {exc}") from exc
            if raw_state.get("host") != self.expected_host or raw_state.get("src") != self.expected_src:
                raise ChainTamperError("sink state.json host/src mismatch")
            if (
                not _is_exact_int(raw_state.get("last_seq"))
                or raw_state["last_seq"] < 0
                or raw_state["last_seq"] > MAX_SAFE_INT
            ):
                raise ChainTamperError("sink state.json invalid last_seq")
        recovered_partials = _load_recovered_partials_in_dir(
            dir_fd, raw_state, require_private=True
        )

        committed_list, unterminated = _load_sink_committed_records_in_dir(
            dir_fd,
            expected_host=self.expected_host,
            expected_src=self.expected_src,
            recovered_partials=recovered_partials,
            allow_unterminated_tail=True,
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

        recovery_quarantine_lines: list[bytes] = []
        state_dirty = False

        if raw_state is None:
            obj: dict[str, Any] = {
                "host": self.expected_host,
                "src": self.expected_src,
                "last_seq": actual_seq,
                "last_h": actual_h,
                "last_ts": committed_list[-1][0]["ts"] if committed_list else "",
                "last_receive_ts": "",
                "last_heartbeat_ts": "",
                "last_heartbeat_receive_ts": "",
            }
            for rec, _ in reversed(committed_list):
                if rec["type"] == "heartbeat":
                    obj["last_heartbeat_ts"] = rec["ts"]
                    break
            state_dirty = actual_seq > 0
        else:
            obj = raw_state
            if actual_seq < obj["last_seq"]:
                raise ChainTamperError(
                    f"sink log truncated: committed seq={actual_seq} < state last_seq={obj['last_seq']}"
                )
            if obj["last_seq"] > 0:
                rec_at_state = committed_index.get(obj["last_seq"])
                if rec_at_state is None or not _safe_digest_equal(
                    rec_at_state[0]["h"], obj.get("last_h")
                ):
                    raise ChainTamperError("sink state.json hash disagrees with committed log")
            if actual_seq > obj["last_seq"]:
                obj["last_seq"] = actual_seq
                obj["last_h"] = actual_h
                obj["last_ts"] = committed_list[-1][0]["ts"]
                for rec, _ in reversed(committed_list):
                    if rec["type"] == "heartbeat":
                        obj["last_heartbeat_ts"] = rec["ts"]
                        break
                state_dirty = True

        # Write-ahead atomic per-pin recovery for any interrupted partial trailing write on
        # daily files (crash-safe at every syscall boundary, chattr +a compatible on daily
        # logs, and scalable without growing state.json beyond MAX_LINE_BYTES):
        # 1. Verify against existing pin or build new atomic pin + quarantine witness.
        # 2. Durably append witness to `quarantine.jsonl`, atomically persist each pin file
        #    `recovered_partials/<day>.<lineno>.json` (temp + fsync + os.replace + dir fsync),
        #    and persist state.json if dirty — all BEFORE sealing `day_name` with '\n'.
        # 3. Append '\n' to seal each unterminated daily file.
        if unterminated:
            partials_map = dict(recovered_partials)
            new_pins: list[tuple[str, dict[str, Any]]] = []
            new_witnesses: list[bytes] = []
            for day_name, lineno, tail_bytes in unterminated:
                tail_sha = f"sha256:{hashlib.sha256(tail_bytes).hexdigest()}"
                tail_len = len(tail_bytes)
                existing_pin = partials_map.get((day_name, lineno))
                if existing_pin is not None:
                    if existing_pin != (tail_sha, tail_len):
                        raise ChainTamperError(
                            f"unterminated partial line at {day_name}:{lineno} disagrees with persisted pin"
                        )
                    # Pin was already persisted before an earlier crash prior to '\n' seal.
                    continue
                pin_entry = {
                    "file": day_name,
                    "line": lineno,
                    "raw_sha256": tail_sha,
                    "raw_len": tail_len,
                }
                new_pins.append((f"{day_name}.{lineno}.json", pin_entry))
                partials_map[(day_name, lineno)] = (tail_sha, tail_len)
                new_witnesses.append(
                    self._build_quarantine_line(
                        received_at=now_ts,
                        reason="sink_partial_write_recovered",
                        expected_seq=obj["last_seq"] + 1,
                        expected_prev=obj["last_h"] if obj["last_seq"] > 0 else GENESIS_PREV,
                        raw_line=tail_bytes,
                    )
                )
            if new_witnesses:
                _append_bytes_durable_in_dir(
                    dir_fd, self.quarantine_name, b"".join(new_witnesses), mode=0o600
                )
            if new_pins:
                rp_dfd = _open_child_dir_fd(
                    dir_fd, RECOVERED_PARTIALS_DIR, create=True, require_private=True
                )
                assert rp_dfd is not None
                try:
                    for pin_name, pin_entry in new_pins:
                        _write_json_atomic_in_dir(rp_dfd, pin_name, pin_entry, mode=0o600)
                finally:
                    os.close(rp_dfd)
            if state_dirty:
                _write_json_atomic_in_dir(dir_fd, self.state_name, obj, mode=0o600)
                state_dirty = False
            for day_name, _, _ in unterminated:
                _append_bytes_durable_in_dir(dir_fd, day_name, b"\n", mode=0o600)

        return obj, committed_index, state_dirty, recovery_quarantine_lines

    def _build_quarantine_line(
        self,
        *,
        received_at: str,
        reason: str,
        expected_seq: int,
        expected_prev: str,
        raw_line: bytes,
        validated_envelope: dict[str, Any] | None = None,
    ) -> bytes:
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
        return jcs_dumps(entry) + b"\n"

    def ingest_batch(self, stdin_bytes: bytes, *, receive_ts: str | None = None) -> SinkIngestResult:
        """Ingest one newline-terminated JSONL batch from stdin with single-fsync batching."""
        if not isinstance(stdin_bytes, bytes):
            raise AuditValidationError("stdin_bytes must be bytes")
        if len(stdin_bytes) > MAX_BATCH_BYTES:
            raise AuditValidationError(f"batch exceeds maximum size ({MAX_BATCH_BYTES} bytes)")
        if stdin_bytes and not stdin_bytes.endswith(b"\n"):
            # Reject torn mid-batch transport stream without poisoning quarantine.jsonl.
            raise AuditValidationError("unterminated JSONL batch (truncated transport stream)")
        if stdin_bytes.count(b"\n") > MAX_BATCH_LINES:
            raise AuditValidationError(f"batch exceeds maximum line count ({MAX_BATCH_LINES})")

        now_ts = receive_ts if receive_ts is not None else utc_now_str()
        parse_utc_timestamp(now_ts)
        receive_day = now_ts[:10]

        raw_lines = [ln for ln in stdin_bytes.split(b"\n")[:-1] if ln] if stdin_bytes else []

        with _open_dir_fd(self.stream_dir, require_private=True) as dfd:
            with _exclusive_lock_in_dir(dfd, self.lock_name):
                state, committed_index, state_dirty, recovery_q = self._read_state_unlocked(
                    dfd, now_ts=now_ts
                )

                accepted = 0
                duplicates = 0
                quarantined = 0
                quarantine_suppressed = 0
                accepted_buf: list[bytes] = []
                quarantine_buf: list[bytes] = list(recovery_q)

                def _queue_quarantine(
                    *,
                    reason: str,
                    raw_line: bytes,
                    validated_envelope: dict[str, Any] | None = None,
                ) -> None:
                    nonlocal quarantined, quarantine_suppressed
                    quarantined += 1
                    if len(quarantine_buf) < MAX_QUARANTINE_PER_BATCH:
                        quarantine_buf.append(
                            self._build_quarantine_line(
                                received_at=now_ts,
                                reason=reason,
                                expected_seq=state["last_seq"] + 1,
                                expected_prev=state["last_h"] if state["last_seq"] > 0 else GENESIS_PREV,
                                raw_line=raw_line,
                                validated_envelope=validated_envelope,
                            )
                        )
                    else:
                        quarantine_suppressed += 1

                for raw_line in raw_lines:
                    if len(raw_line) > MAX_LINE_BYTES:
                        _queue_quarantine(reason="line_too_large", raw_line=raw_line)
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
                        reason = (
                            "redaction_blocked"
                            if isinstance(exc, AuditRedactionError)
                            else "invalid_envelope"
                        )
                        _queue_quarantine(reason=reason, raw_line=raw_line)
                        continue

                    seq = obj["seq"]
                    expected_seq = state["last_seq"] + 1
                    expected_prev = state["last_h"] if state["last_seq"] > 0 else GENESIS_PREV

                    if seq == expected_seq and _safe_digest_equal(obj["prev"], expected_prev):
                        accepted_buf.append(canonical + b"\n")
                        state["last_seq"] = seq
                        state["last_h"] = obj["h"]
                        state["last_ts"] = obj["ts"]
                        state["last_receive_ts"] = now_ts
                        if obj["type"] == "heartbeat":
                            state["last_heartbeat_ts"] = obj["ts"]
                            state["last_heartbeat_receive_ts"] = now_ts
                        committed_index[seq] = (obj, canonical)
                        accepted += 1
                    elif seq <= state["last_seq"]:
                        existing = committed_index.get(seq)
                        if (
                            existing is not None
                            and _safe_digest_equal(existing[0]["h"], obj["h"])
                            and existing[1] == canonical
                        ):
                            duplicates += 1
                        else:
                            _queue_quarantine(
                                reason="fork", raw_line=canonical, validated_envelope=obj
                            )
                    else:
                        reason = "gap" if seq > expected_seq else "prev_mismatch"
                        _queue_quarantine(
                            reason=reason, raw_line=canonical, validated_envelope=obj
                        )

                if quarantine_suppressed > 0:
                    summary = {
                        "received_at": now_ts,
                        "host": self.expected_host,
                        "src": self.expected_src,
                        "reason": "quarantine_batch_cap_reached",
                        "suppressed_count": quarantine_suppressed,
                    }
                    quarantine_buf.append(jcs_dumps(summary) + b"\n")

                # Single durable append + fsync per touched log file, then atomic state.json.
                if accepted_buf:
                    _append_bytes_durable_in_dir(
                        dfd, f"{receive_day}.jsonl", b"".join(accepted_buf), mode=0o600
                    )
                if quarantine_buf:
                    _append_bytes_durable_in_dir(
                        dfd, self.quarantine_name, b"".join(quarantine_buf), mode=0o600
                    )
                if accepted_buf or state_dirty:
                    _write_json_atomic_in_dir(dfd, self.state_name, state, mode=0o600)

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
        raise ForcedCommandError("disallowed sink command (append-only boundary)")

    sink = AuditSink(sink_root, expected_host=expected_host, expected_src=expected_src)
    res = sink.ingest_batch(stdin_bytes, receive_ts=receive_ts)
    return res.to_ack_dict()


# ---------------------------------------------------------------------------
# Forensic cross-verifier (strictly read-only) & intermittent-host liveness
# ---------------------------------------------------------------------------

def verify_local_against_sink(
    local_jsonl_path: Path,
    sink_stream_dir: Path,
    *,
    expected_host: str | None = None,
    expected_src: str = DEFAULT_SRC,
) -> VerifyReport:
    """Compare a host's local JSONL capture against the off-device sink witness.

    Strictly read-only (never calls `os.mkdir` or modifies disk). Flags missing
    sink stream, sink state truncation/mismatch, sink quarantine entries,
    missing/deleted/unsafe local log, tail truncation, mid-log deletion, edited
    or re-chained local lines, and chain breaks.
    """
    findings: list[TamperFinding] = []
    sink_dir = Path(sink_stream_dir)
    if not sink_dir.exists() and not sink_dir.is_symlink():
        return VerifyReport(
            ok=False,
            local_count=0,
            sink_count=0,
            quarantine_count=0,
            findings=(
                TamperFinding(
                    "SINK_MISSING",
                    None,
                    f"sink stream directory does not exist: {sink_dir}",
                ),
            ),
        )

    quarantine_count = 0
    sink_records: list[tuple[dict[str, Any], bytes]] = []
    try:
        with _open_dir_fd(sink_dir, require_private=False) as sdfd:
            with _shared_lock_if_present(sdfd, ".sink.lock"):
                try:
                    quarantine_count = _count_lines_streaming_in_dir(sdfd, "quarantine.jsonl")
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

                # Read sink state.json first (if present) so verified recovered_partials
                # are respected while loading committed daily files and state consistency
                # is cross-checked against committed records.
                st_obj: dict[str, Any] | None = None
                recovered_partials: dict[tuple[str, int], tuple[str, int]] = {}
                try:
                    os.lstat("state.json", dir_fd=sdfd)
                    has_sink_state = True
                except FileNotFoundError:
                    has_sink_state = False
                if has_sink_state:
                    try:
                        st_raw = _read_small_regular_in_dir(sdfd, "state.json", max_bytes=MAX_LINE_BYTES)
                        st_obj = strict_json_loads(st_raw.rstrip(b"\n"))
                    except AuditError as exc:
                        findings.append(TamperFinding("SINK_STATE_MISMATCH", None, str(exc)))
                try:
                    recovered_partials = _load_recovered_partials_in_dir(sdfd, st_obj)
                except AuditError as exc:
                    findings.append(TamperFinding("SINK_STATE_MISMATCH", None, str(exc)))

                try:
                    sink_records, _ = _load_sink_committed_records_in_dir(
                        sdfd,
                        expected_host=expected_host,
                        expected_src=expected_src,
                        recovered_partials=recovered_partials,
                        allow_unterminated_tail=False,
                    )
                except AuditError as exc:
                    findings.append(TamperFinding("SINK_CORRUPT", None, str(exc)))

                if st_obj is not None:
                    st_seq = st_obj.get("last_seq")
                    st_h = st_obj.get("last_h")
                    if expected_host is not None and st_obj.get("host") != expected_host:
                        findings.append(
                            TamperFinding("SINK_STATE_MISMATCH", None, "sink state.json host mismatch")
                        )
                    if expected_src is not None and st_obj.get("src") != expected_src:
                        findings.append(
                            TamperFinding("SINK_STATE_MISMATCH", None, "sink state.json src mismatch")
                        )
                    if not _is_exact_int(st_seq) or st_seq < 0:
                        findings.append(
                            TamperFinding("SINK_STATE_MISMATCH", None, "sink state.json invalid last_seq")
                        )
                    else:
                        committed_by_seq = {r["seq"]: r for r, _ in sink_records}
                        committed_max = max(committed_by_seq.keys(), default=0)
                        if committed_max < st_seq:
                            findings.append(
                                TamperFinding(
                                    "SINK_TRUNCATED",
                                    committed_max + 1,
                                    f"sink committed log ends at seq {committed_max} while state.json expects {st_seq}",
                                )
                            )
                        elif st_seq > 0:
                            rec_at = committed_by_seq.get(st_seq)
                            if rec_at is None or not _safe_digest_equal(rec_at["h"], st_h):
                                findings.append(
                                    TamperFinding(
                                        "SINK_STATE_MISMATCH",
                                        st_seq,
                                        f"sink state.json hash disagrees with committed seq {st_seq}",
                                    )
                                )
    except AuditFileSecurityError as exc:
        return VerifyReport(
            ok=False,
            local_count=0,
            sink_count=0,
            quarantine_count=0,
            findings=(TamperFinding("SINK_UNSAFE_DIR", None, str(exc)),),
        )

    sink_chain_findings = verify_chain_records(
        [r for r, _ in sink_records], expected_host=expected_host, expected_src=expected_src
    )
    for f in sink_chain_findings:
        findings.append(TamperFinding(f"SINK_{f.code}", f.seq, f.detail))

    sink_by_seq = {r["seq"]: (r, raw) for r, raw in sink_records}
    sink_max_seq = max(sink_by_seq.keys(), default=0)

    local_records: list[tuple[dict[str, Any], bytes]] = []
    local_p = Path(local_jsonl_path)
    local_exists = local_p.exists() or local_p.is_symlink()
    if not local_exists:
        if sink_max_seq > 0:
            findings.append(
                TamperFinding(
                    "LOCAL_MISSING",
                    1,
                    f"local audit log {local_p} is missing while sink has {sink_max_seq} record(s)",
                )
            )
    else:
        try:
            with _open_dir_fd(local_p.parent, require_private=False) as ldfd:
                try:
                    local_records = _load_jsonl_records_in_dir(
                        ldfd, local_p.name, expected_host=expected_host, expected_src=expected_src
                    )
                except AuditFileSecurityError as exc:
                    findings.append(TamperFinding("LOCAL_UNSAFE_FILE", None, str(exc)))
                except AuditError as exc:
                    findings.append(TamperFinding("LOCAL_PARSE_ERROR", None, str(exc)))
                    # Best-effort bounded streaming scan so edits/deletions still surface alongside parse error.
                    try:
                        fd, _ = _open_regular_in_dir(ldfd, local_p.name, os.O_RDONLY)
                        with os.fdopen(fd, "rb") as fh:
                            while True:
                                raw_ln = fh.readline(MAX_LINE_BYTES + 2)
                                if not raw_ln:
                                    break
                                if len(raw_ln) > MAX_LINE_BYTES + 1:
                                    # Discard rest of overlong line without loading it into memory.
                                    while raw_ln and not raw_ln.endswith(b"\n"):
                                        raw_ln = fh.readline(MAX_LINE_BYTES + 2)
                                    continue
                                raw_ln = raw_ln.rstrip(b"\n")
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
                        [r for r, _ in local_records],
                        expected_host=expected_host,
                        expected_src=expected_src,
                    )
                    for f in local_chain_findings:
                        findings.append(TamperFinding(f"LOCAL_{f.code}", f.seq, f.detail))
        except AuditFileSecurityError as exc:
            findings.append(TamperFinding("LOCAL_UNSAFE_FILE", None, str(exc)))

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
        if not _safe_digest_equal(loc_h, sink_rec["h"]) or loc_raw != sink_raw:
            findings.append(
                TamperFinding(
                    "LOCAL_EDITED",
                    seq,
                    f"seq {seq} edited locally (hash or canonical bytes differ from sink {sink_rec['h']})",
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
    """Report host audit liveness. Silent, unseen, mismatched, or quarantined hosts are ALWAYS `"unknown"`."""
    _require_regex(host, HOST_NAME_RE, "host")
    _require_regex(src, SRC_RE, "src")
    if not _is_exact_int(max_silence_seconds) or max_silence_seconds <= 0:
        raise ValueError("max_silence_seconds must be a positive integer")
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

    try:
        with _open_dir_fd(stream_dir, require_private=False) as sdfd:
            with _shared_lock_if_present(sdfd, ".sink.lock"):
                quarantine_count = _count_lines_streaming_in_dir(sdfd, "quarantine.jsonl")
                try:
                    os.lstat("state.json", dir_fd=sdfd)
                except FileNotFoundError:
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
                raw = _read_small_regular_in_dir(sdfd, "state.json", max_bytes=MAX_LINE_BYTES)
                state = strict_json_loads(raw.rstrip(b"\n"))
    except (AuditError, OSError) as exc:
        return LivenessReport(
            status="unknown",
            reason=f"sink state unreadable: {exc}",
            host=host,
            src=src,
            last_seq=0,
            last_receive_ts=None,
            last_heartbeat_receive_ts=None,
            silence_seconds=None,
            quarantine_count=0,
        )

    if state.get("host") != host or state.get("src") != src:
        return LivenessReport(
            status="unknown",
            reason="sink state host/src mismatch",
            host=host,
            src=src,
            last_seq=0,
            last_receive_ts=None,
            last_heartbeat_receive_ts=None,
            silence_seconds=None,
            quarantine_count=quarantine_count,
        )

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

    try:
        hb_dt = parse_utc_timestamp(last_hb_rx)
    except AuditValidationError:
        return LivenessReport(
            status="unknown",
            reason="invalid heartbeat receive timestamp in sink state",
            host=host,
            src=src,
            last_seq=last_seq,
            last_receive_ts=last_rx,
            last_heartbeat_receive_ts=last_hb_rx,
            silence_seconds=None,
            quarantine_count=quarantine_count,
        )

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
    if quarantine_count > 0:
        return LivenessReport(
            status="unknown",
            reason=f"sink has {quarantine_count} quarantined record(s) requiring investigation",
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
# Shipper config loader (for systemd timer / launchd LaunchDaemon, #119 Slice 2)
# ---------------------------------------------------------------------------

SHIPPER_CONFIG_KEYS = frozenset(
    {
        "enabled",
        "spool_dir",
        "host",
        "src",
        "target",
        "identity",
        "known_hosts",
        "ssh_bin",
        "port",
        "batch_size",
    }
)


def load_shipper_config(
    config_path: Path, *, expected_spool_dir: Path | None = None
) -> dict[str, Any]:
    """Load and validate a private (exact `0600`, `nlink==1`, inside `0700` dir) shipper JSON config."""
    abs_cfg = config_path if config_path.is_absolute() else (Path.cwd() / config_path)
    _check_ancestors_no_symlinks(abs_cfg)
    if os.geteuid() == 0:
        _check_ancestors_trusted_unwritable(abs_cfg, allowed_uids={0})
    _check_darwin_no_extended_acl(abs_cfg.parent)
    _check_darwin_no_extended_acl(abs_cfg)
    with _open_dir_fd(abs_cfg.parent, require_private=True) as dfd:
        fd, _ = _open_regular_in_dir(dfd, abs_cfg.name, os.O_RDONLY)
        try:
            st = os.fstat(fd)
            if st.st_uid != os.geteuid():
                raise AuditFileSecurityError(
                    f"shipper config {abs_cfg} owned by uid {st.st_uid}, expected euid {os.geteuid()}"
                )
            if st.st_nlink != 1:
                raise AuditFileSecurityError(
                    f"shipper config {abs_cfg} has link count {st.st_nlink}, expected 1"
                )
            mode = stat.S_IMODE(st.st_mode)
            if mode != 0o600:
                raise AuditFileSecurityError(
                    f"shipper config {abs_cfg} mode {oct(mode)} must be exact 0600"
                )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, 8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > 16384:
                    raise AuditValidationError("shipper config exceeds 16384 bytes")
                chunks.append(chunk)
        finally:
            os.close(fd)
    obj = strict_json_loads(b"".join(chunks).rstrip(b"\n"))
    if not isinstance(obj, dict):
        raise AuditValidationError("shipper config must be a JSON object")
    extra = set(obj.keys()) - SHIPPER_CONFIG_KEYS
    if extra:
        raise AuditValidationError("shipper config contains unexpected key(s)")
    enabled = obj.get("enabled")
    if not isinstance(enabled, bool):
        raise AuditValidationError("shipper config 'enabled' must be a boolean")
    if not enabled:
        return {"enabled": False}

    spool_dir = obj.get("spool_dir")
    host = obj.get("host")
    src = obj.get("src", DEFAULT_SRC)
    target = obj.get("target")
    identity = obj.get("identity")
    known_hosts = obj.get("known_hosts")
    ssh_bin = obj.get("ssh_bin", "/usr/bin/ssh")
    port = obj.get("port")
    batch_size = obj.get("batch_size", 100)

    for label, val in (
        ("spool_dir", spool_dir),
        ("identity", identity),
        ("known_hosts", known_hosts),
        ("ssh_bin", ssh_bin),
    ):
        if not isinstance(val, str) or not ABS_PATH_RE.match(val):
            raise AuditValidationError(f"shipper config '{label}' must be an absolute path")
    if expected_spool_dir is not None and Path(spool_dir) != expected_spool_dir:
        raise AuditValidationError("shipper config 'spool_dir' does not match pinned spool path")
    if os.geteuid() == 0 and ssh_bin != "/usr/bin/ssh":
        raise AuditFileSecurityError("root shipper config must pin ssh_bin to /usr/bin/ssh")
    _require_regex(host, HOST_NAME_RE, "host")
    _require_regex(src, SRC_RE, "src")
    if not isinstance(target, str) or not target or target.startswith("-"):
        raise AuditValidationError("shipper config 'target' must be a non-empty SSH destination")
    if port is not None and (not _is_exact_int(port) or port < 1 or port > 65535):
        raise AuditValidationError("shipper config 'port' must be an integer 1..65535")
    if not _is_exact_int(batch_size) or batch_size < 1 or batch_size > MAX_BATCH_LINES:
        raise AuditValidationError(f"shipper config 'batch_size' must be 1..{MAX_BATCH_LINES}")
    return {
        "enabled": True,
        "spool_dir": Path(spool_dir),
        "host": host,
        "src": src,
        "target": target,
        "identity": Path(identity),
        "known_hosts": Path(known_hosts),
        "ssh_bin": ssh_bin,
        "port": port,
        "batch_size": batch_size,
    }


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
    p_ship.add_argument("--config", type=Path, help="private exact-0600 JSON shipper config file")
    p_ship.add_argument("--expected-spool-dir", type=Path, help="optional pinned spool_dir when using --config")
    p_ship.add_argument("--spool-dir", type=Path, default=None)
    p_ship.add_argument("--host", default=None)
    p_ship.add_argument("--src", default=None)
    p_ship.add_argument("--target", default=None)
    p_ship.add_argument("--identity", type=Path, default=None)
    p_ship.add_argument("--known-hosts", type=Path, default=None)
    p_ship.add_argument("--ssh-bin", default=None)
    p_ship.add_argument("--port", type=int, default=None)
    p_ship.add_argument("--batch-size", type=int, default=None)

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
            if args.config is not None:
                if any(
                    v is not None
                    for v in (
                        args.spool_dir,
                        args.host,
                        args.src,
                        args.target,
                        args.identity,
                        args.known_hosts,
                        args.ssh_bin,
                        args.port,
                        args.batch_size,
                    )
                ):
                    raise AuditValidationError("--config cannot be combined with explicit ship target flags")
                cfg = load_shipper_config(args.config, expected_spool_dir=args.expected_spool_dir)
                if not cfg["enabled"]:
                    print(
                        json.dumps(
                            {
                                "ok": True,
                                "skipped": True,
                                "reason": "audit shipper disabled (sink not enrolled)",
                            },
                            sort_keys=True,
                        )
                    )
                    return 0
                spool_dir = cfg["spool_dir"]
                host = cfg["host"]
                src = cfg["src"]
                target = cfg["target"]
                identity = cfg["identity"]
                known_hosts = cfg["known_hosts"]
                ssh_bin = cfg["ssh_bin"]
                port = cfg["port"]
                batch_size = cfg["batch_size"]
                strict_paths = True
            else:
                if args.expected_spool_dir is not None:
                    raise AuditValidationError("--expected-spool-dir requires --config")
                missing = [
                    flag
                    for flag, val in (
                        ("--spool-dir", args.spool_dir),
                        ("--host", args.host),
                        ("--target", args.target),
                        ("--identity", args.identity),
                        ("--known-hosts", args.known_hosts),
                    )
                    if val is None
                ]
                if missing:
                    raise AuditValidationError(f"ship requires --config or {', '.join(missing)}")
                spool_dir = args.spool_dir
                host = args.host
                src = args.src if args.src is not None else DEFAULT_SRC
                target = args.target
                identity = args.identity
                known_hosts = args.known_hosts
                ssh_bin = args.ssh_bin if args.ssh_bin is not None else "/usr/bin/ssh"
                port = args.port
                batch_size = args.batch_size if args.batch_size is not None else 100
                strict_paths = os.geteuid() == 0
            spool = AuditSpool(spool_dir, host=host, src=src)
            transport = make_ssh_append_transport(
                target=target,
                identity_file=identity,
                known_hosts_file=known_hosts,
                src=src,
                ssh_bin=ssh_bin,
                port=port,
                enforce_owner_and_ancestors=strict_paths,
            )
            res = AuditShipper(spool, transport, batch_size=batch_size).ship()
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
            local_p = Path(args.local)
            with _open_dir_fd(local_p.parent, require_private=False) as ldfd:
                records = _load_jsonl_records_in_dir(
                    ldfd, local_p.name, expected_host=args.host, expected_src=args.src
                )
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
    except (AuditError, OSError, ValueError) as exc:
        print(f"audit-log: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
