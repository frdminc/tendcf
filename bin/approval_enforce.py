#!/usr/bin/env python3
"""Pure-stdlib reference enforcement engine for tendcf v9 approval records (issue #76).

Runs under `python3 -I -S` with zero third-party packages, matching
`bin/projector.py`'s bare-host stdlib guarantee.

Implements:
  - Strict JSON parsing (duplicate-key rejection, NaN/Infinity rejection, NFC check),
    type-preserving JCS equality (`jcs_equal`), and RFC 8785 JCS canonicalization
    reused directly from `bin/projector.py`.
  - Pure-stdlib RFC 8032 Ed25519 public-input verification with strict canonical
    encodings (`0 <= S < L`, canonical public key `A` and `R` with `y < p` and
    `(x == 0 && sign == 1)` rejected, small-order `A` and small-order `R` rejected,
    exact cofactorless equation `[S]B == R + [k]A`). Non-constant-time signing
    helpers live exclusively in `tests/approval/_ed25519_test_signer.py`.
  - Crash-safe two-phase durable `ReplayStore` storing generation-versioned
    immutable state files (`replay-store.v<gen>.json`) written via full-loop
    `os.write` + `fsync` + `os.replace` + dir `fsync` BEFORE advancing an
    explicit, independently protected `RollbackAnchor` storing
    `(store_generation, store_sha256)`, with re-entrant thread + advisory `flock`
    locking and authoritative persisted applied baseline.
  - Device-side authoritative goal-diff computation (`compute_authoritative_diff`),
    strict diff validation, confirmed hold-window display with monotonic clock
    validation and boot-epoch binding, microsecond-accurate non-reversible expiry
    tracking, and full enforcement for `per-change`, `standing-enrollment`
    (active, Option B zero-write redelivery, and terminal revocation), and
    `standing-application` covering all 26 items of frdminc/tendcf#76,
    PR #75 R4 #1-#5, and the 2026-11-26 operator rulings.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import datetime
import fcntl
import hashlib
import hmac
import importlib.util
import json
import math
import os
import re
import secrets
import sys
import tempfile
import threading
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Collection, Iterator


# ---------------------------------------------------------------------------
# Load bin/projector.py for shared pure-stdlib RFC 8785 JCS canonicalization
# ---------------------------------------------------------------------------

def _load_projector_module() -> Any:
    proj_path = Path(__file__).resolve().with_name("projector.py")
    spec = importlib.util.spec_from_file_location("_tendcf_projector_jcs", proj_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load projector module at {proj_path}")
    mod = importlib.util.module_from_spec(spec)
    # Register in sys.modules BEFORE exec_module (required on Python 3.14+ for
    # annotations / dataclasses lookup; clean up on failure).
    sys.modules[spec.name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return mod


_PROJECTOR = _load_projector_module()


# ---------------------------------------------------------------------------
# Constants and compiled patterns
# ---------------------------------------------------------------------------

SUPPORTED_SCHEMA_VERSION = 9
MAX_SAFE_INT = 2**53 - 1  # 9007199254740991 (RFC 8785 IEEE-754 exact int ceiling)
TRUST_DOMAIN = "device-trust"
ALLOWED_STANDING_DEVICE_TRUST_KINDS = frozenset({"supervisor"})

SUPPORTED_SIG_ALGS = frozenset({"ed25519"})
RECORD_KINDS = frozenset({"per-change", "standing-enrollment", "standing-application"})
CEREMONY_CLASSES = ("ordinary", "privileged", "baseline")
CEREMONY_RANK: dict[str, int] = {"ordinary": 1, "privileged": 2, "baseline": 3}
STANDING_MODES = frozenset(
    {"standing-approval", "hold-window", "wait-for-user", "standing-refusal"}
)
MODE_RESTRICTIVENESS: dict[str, int] = {
    "standing-approval": 1,
    "hold-window": 2,
    "wait-for-user": 3,
    "standing-refusal": 4,
}
VERDICTS = frozenset({"accept", "reject", "withdraw"})
GRANT_STATES = frozenset({"active", "revoked"})

GOAL_COVERAGE_VALUES = frozenset(
    {"comprehensive", "not-yet-migrated", "deliberately-unmanaged"}
)
DIFF_COVERAGE_VALUES = GOAL_COVERAGE_VALUES | frozenset({"undeclared"})

KEY_ID_RE = re.compile(r"^ed25519:[0-9a-f]{64}\Z")
ED25519_SIG_RE = re.compile(r"^ed25519-sig:[0-9a-f]{128}\Z")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}\Z")
RAW_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}\Z")
GRANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}\Z")
NONCE_RE = re.compile(r"^[!-~]{22,128}\Z")
UTC_TS_RE = re.compile(
    r"^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])Z\Z"
)
INTERNAL_UTC_TS_RE = re.compile(
    r"^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(?:\.([0-9]{6}))?Z\Z"
)
STORE_VERSION_FILE_RE = re.compile(r"^replay-store\.v([0-9]+)\.json\Z")

_COMMON_KEYS = frozenset(
    {"schema_version", "record_kind", "host", "signer", "sig_alg", "signature"}
)
_PER_CHANGE_ALLOWED = _COMMON_KEYS | frozenset(
    {
        "baseline_sha256",
        "proposed_sha256",
        "nonce",
        "approval_seq",
        "briefing_sha256",
        "verdict",
        "refused",
        "ceremony_class",
    }
)
_ENROLLMENT_REVOKED_ALLOWED = _COMMON_KEYS | frozenset(
    {"grant_id", "generation", "grant_state"}
)
_ENROLLMENT_ACTIVE_ALLOWED = _ENROLLMENT_REVOKED_ALLOWED | frozenset(
    {
        "nonce",
        "mode",
        "hold_seconds",
        "covered_signers",
        "class",
        "developer_mode",
        "not_after",
    }
)
_APPLICATION_ALLOWED = _COMMON_KEYS | frozenset(
    {
        "grant_id",
        "generation",
        "application_seq",
        "enrollment_nonce",
        "baseline_sha256",
        "proposed_sha256",
        "ceremony_class",
    }
)
_DIFF_ALLOWED_KEYS = frozenset(
    {
        "schema_version",
        "host",
        "baseline_sha256",
        "proposed_sha256",
        "version_bump",
        "hunks",
        "coverage_changes",
    }
)


# ---------------------------------------------------------------------------
# Typed exceptions & results
# ---------------------------------------------------------------------------

class EnforcementError(Exception):
    """Base refusal error carrying a machine-readable code and local detail."""

    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details


class StoreRollbackError(EnforcementError):
    """Rollback, store loss, corruption, partial restore, or voided store."""


class ClockRollbackError(EnforcementError):
    """UTC or monotonic clock moved backward, non-finite, or crossed boot epoch."""


class MalformedRecordError(EnforcementError):
    """JSON syntax, duplicate key, non-NFC, schema, or schema_version violation."""


class SignatureError(EnforcementError):
    """Algorithm/prefix mismatch or invalid/non-canonical Ed25519 signature."""


class TrustRootError(EnforcementError):
    """Trust root violation (host key trusted, missing/wrong baseline signer role)."""


class NonceError(EnforcementError):
    """Missing, reused, scope-mismatched, or invalid ceremony/enrollment nonce."""


class ReplayError(EnforcementError):
    """Replay, stale generation/seq, equivocation, tombstone, or persisted reject."""


class ScopeError(EnforcementError):
    """Target host, hash, carve-out, class, migration, expiry, hold, or mode refusal."""


@dataclasses.dataclass(frozen=True)
class EnrollmentReceipt:
    """External delivery receipt — identical shape for initial accept and Option B redelivery."""

    status: str
    host: str
    grant_id: str
    generation: int
    grant_state: str


@dataclasses.dataclass(frozen=True)
class ApplicationResult:
    decision: str  # "applied" | "held" | "parked"
    host: str
    grant_id: str
    generation: int
    application_seq: int
    proposed_sha256: str
    effective_mode: str
    hold_seconds: int | None = None
    hold_id: str | None = None


@dataclasses.dataclass(frozen=True)
class PerChangeResult:
    decision: str  # "applied" | "rejected" | "withdrawn"
    host: str
    proposed_sha256: str
    approval_seq: int | None
    cancelled_holds: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Strict JSON parsing, NFC validation, and JCS canonicalization / equality
# ---------------------------------------------------------------------------

def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"non-JSON constant {token!r} is forbidden")


def _check_nfc(node: Any, path: str = "") -> None:
    """Verify every key and string value is Unicode NFC-normalized."""
    stack: list[tuple[str, Any]] = [(path, node)]
    while stack:
        cur_path, cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                here = f"{cur_path}/{k}"
                if not unicodedata.is_normalized("NFC", k):
                    raise MalformedRecordError(
                        "non_nfc_string", f"{here} (key) is not NFC-normalized"
                    )
                stack.append((here, v))
        elif isinstance(cur, list):
            for idx, v in enumerate(cur):
                stack.append((f"{cur_path}/{idx}", v))
        elif isinstance(cur, str):
            if not unicodedata.is_normalized("NFC", cur):
                raise MalformedRecordError(
                    "non_nfc_string", f"{cur_path or '<root>'} is not NFC-normalized"
                )


def parse_strict_json(raw: bytes | str) -> Any:
    """Parse JSON strictly: reject duplicate keys, NaN/Infinity, bad UTF-8, and non-NFC."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MalformedRecordError("invalid_utf8", f"not valid UTF-8: {exc}") from exc
    elif isinstance(raw, str):
        text = raw
    else:
        raise MalformedRecordError("invalid_input", "raw input must be bytes or str")

    try:
        doc = json.loads(
            text,
            object_pairs_hook=_PROJECTOR._reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise MalformedRecordError("invalid_json", f"JSON parse error: {exc}") from exc
    except (ValueError, RecursionError) as exc:
        raise MalformedRecordError("duplicate_or_invalid_json", str(exc)) from exc

    _check_nfc(doc)
    return doc


def jcs_dumps(obj: Any) -> bytes:
    """Return RFC 8785 JCS canonical UTF-8 bytes using projector.py's pure-stdlib encoder."""
    try:
        return _PROJECTOR._stdlib_jcs_dumps(obj)
    except (ValueError, TypeError, OverflowError) as exc:
        raise MalformedRecordError("jcs_unrepresentable", str(exc)) from exc


def jcs_equal(a: Any, b: Any) -> bool:
    """Type-preserving JSON equality via canonical RFC 8785 JCS bytes.

    Unlike Python `==`, this never aliases `True == 1` or `False == 0`.
    """
    return hmac.compare_digest(jcs_dumps(a), jcs_dumps(b))


def canonical_sha256(doc: Any) -> str:
    """Return `sha256:<64 hex>` digest of the RFC 8785 JCS canonical bytes of `doc`."""
    return "sha256:" + hashlib.sha256(jcs_dumps(doc)).hexdigest()


def signing_payload_bytes(record: dict[str, Any]) -> bytes:
    """Return canonical JCS bytes of `record` with top-level `signature` removed (C-5)."""
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    return jcs_dumps(unsigned)


def _is_exact_int(value: Any) -> bool:
    return type(value) is int


def _is_exact_bool(value: Any) -> bool:
    return type(value) is bool


# ---------------------------------------------------------------------------
# Pure-stdlib RFC 8032 Ed25519 Verification (public inputs only, Item 11)
# ---------------------------------------------------------------------------

ED25519_P = 2**255 - 19
ED25519_L = 2**252 + 27742317777372353535851937790883648493
ED25519_D = (-121665 * pow(121666, ED25519_P - 2, ED25519_P)) % ED25519_P
_SQRT_M1 = pow(2, (ED25519_P - 1) // 4, ED25519_P)

# Extended homogeneous coordinates (X, Y, Z, T) on -x^2 + y^2 = 1 + d*x^2*y^2
_Point = tuple[int, int, int, int]
_NEUTRAL_POINT: _Point = (0, 1, 1, 0)


def _ed25519_recover_x(y: int, sign: int) -> int | None:
    """RFC 8032 §5.1.3 strict canonical x-coordinate recovery."""
    if y < 0 or y >= ED25519_P:
        return None
    u = (y * y - 1) % ED25519_P
    v = (ED25519_D * y * y + 1) % ED25519_P
    v3 = pow(v, 3, ED25519_P)
    v7 = (v3 * v3 % ED25519_P) * v % ED25519_P
    x = (
        (u * v3 % ED25519_P)
        * pow((u * v7) % ED25519_P, (ED25519_P - 5) // 8, ED25519_P)
    ) % ED25519_P
    vx2 = (v * x * x) % ED25519_P
    if vx2 == u:
        pass
    elif vx2 == (-u) % ED25519_P:
        x = (x * _SQRT_M1) % ED25519_P
    else:
        return None
    if x == 0 and sign == 1:
        # Non-canonical encoding of x = 0 with sign bit 1 MUST be rejected.
        return None
    if (x & 1) != sign:
        x = ED25519_P - x
    return x


def ed25519_decompress_point(encoded: bytes) -> _Point | None:
    """Strictly decode a 32-byte canonical Edwards25519 point (RFC 8032 §5.1.3)."""
    if not isinstance(encoded, (bytes, bytearray)) or len(encoded) != 32:
        return None
    val = int.from_bytes(encoded, "little")
    sign = val >> 255
    y = val & ((1 << 255) - 1)
    if y >= ED25519_P:
        return None
    x = _ed25519_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % ED25519_P)


def _point_add(p1: _Point, p2: _Point) -> _Point:
    """RFC 8032 §5.1.4 unified extended-coordinate addition for a = -1."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % ED25519_P
    b = ((y1 + x1) * (y2 + x2)) % ED25519_P
    c = (2 * t1 * t2 * ED25519_D) % ED25519_P
    d = (2 * z1 * z2) % ED25519_P
    e = (b - a) % ED25519_P
    f = (d - c) % ED25519_P
    g = (d + c) % ED25519_P
    h = (b + a) % ED25519_P
    return (
        (e * f) % ED25519_P,
        (g * h) % ED25519_P,
        (f * g) % ED25519_P,
        (e * h) % ED25519_P,
    )


def _point_mul(scalar: int, pt: _Point) -> _Point:
    """Scalar multiplication over public inputs (verification only)."""
    acc = _NEUTRAL_POINT
    cur = pt
    k = scalar
    while k > 0:
        if k & 1:
            acc = _point_add(acc, cur)
        cur = _point_add(cur, cur)
        k >>= 1
    return acc


def _point_equal(p1: _Point, p2: _Point) -> bool:
    if (p1[0] * p2[2] - p2[0] * p1[2]) % ED25519_P != 0:
        return False
    if (p1[1] * p2[2] - p2[1] * p1[2]) % ED25519_P != 0:
        return False
    return True


_BASE_Y = (4 * pow(5, ED25519_P - 2, ED25519_P)) % ED25519_P
_BASE_X = _ed25519_recover_x(_BASE_Y, 0)
assert _BASE_X is not None
_BASE_POINT: _Point = (_BASE_X, _BASE_Y, 1, (_BASE_X * _BASE_Y) % ED25519_P)


def verify_ed25519(pubkey_bytes: bytes, msg_bytes: bytes, sig_bytes: bytes) -> bool:
    """Strictly verify RFC 8032 pure Ed25519 signature with canonical encodings.

    Enforces (aligned with libsodium / `ed25519-dalek::verify_strict`):
      - `len(pubkey_bytes) == 32`, `len(sig_bytes) == 64`
      - `0 <= S < L` (non-malleable scalar)
      - Canonical public key `A` (`y < p`, reject `x == 0 && sign == 1`)
      - Reject small-order public key `A` (`[8]A == O`)
      - Canonical `R` (`y < p`, reject `x == 0 && sign == 1`)
      - Reject small-order `R` (`[8]R == O`)
      - Exact cofactorless equation `[S]B == R + [k]A`
    """
    if (
        not isinstance(pubkey_bytes, (bytes, bytearray))
        or not isinstance(msg_bytes, (bytes, bytearray))
        or not isinstance(sig_bytes, (bytes, bytearray))
    ):
        return False
    if len(pubkey_bytes) != 32 or len(sig_bytes) != 64:
        return False

    r_bytes = bytes(sig_bytes[:32])
    s = int.from_bytes(sig_bytes[32:], "little")
    if s >= ED25519_L:
        return False

    pt_a = ed25519_decompress_point(bytes(pubkey_bytes))
    if pt_a is None:
        return False
    if _point_equal(_point_mul(8, pt_a), _NEUTRAL_POINT):
        return False

    pt_r = ed25519_decompress_point(r_bytes)
    if pt_r is None:
        return False
    if _point_equal(_point_mul(8, pt_r), _NEUTRAL_POINT):
        return False

    k = (
        int.from_bytes(
            hashlib.sha512(r_bytes + bytes(pubkey_bytes) + bytes(msg_bytes)).digest(),
            "little",
        )
        % ED25519_L
    )
    lhs = _point_mul(s, _BASE_POINT)
    rhs = _point_add(pt_r, _point_mul(k, pt_a))
    return _point_equal(lhs, rhs)


def key_id_from_pubkey(pubkey_bytes: bytes) -> str:
    if len(pubkey_bytes) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return "ed25519:" + pubkey_bytes.hex()


def verify_record_signature(record: dict[str, Any]) -> None:
    """Verify X-trust-06 algorithm binding and strict canonical pure Ed25519 signature."""
    sig_alg = record.get("sig_alg")
    signer = record.get("signer")
    signature = record.get("signature")

    if not isinstance(sig_alg, str) or sig_alg not in SUPPORTED_SIG_ALGS:
        raise SignatureError("unsupported_sig_alg", f"unsupported sig_alg {sig_alg!r}")
    if not isinstance(signer, str) or not isinstance(signature, str):
        raise SignatureError("malformed_signature_fields", "signer and signature must be strings")

    if sig_alg == "ed25519":
        if not KEY_ID_RE.match(signer):
            raise SignatureError(
                "sig_alg_signer_mismatch",
                f"signer {signer!r} does not match sig_alg 'ed25519' prefix/format",
            )
        if not ED25519_SIG_RE.match(signature):
            raise SignatureError(
                "sig_alg_signature_mismatch",
                "signature does not match 'ed25519-sig:<128 lowercase hex>'",
            )
        pubkey_bytes = bytes.fromhex(signer.split(":", 1)[1])
        sig_bytes = bytes.fromhex(signature.split(":", 1)[1])
        payload = signing_payload_bytes(record)
        if not verify_ed25519(pubkey_bytes, payload, sig_bytes):
            raise SignatureError(
                "invalid_signature",
                "RFC 8032 canonical Ed25519 signature verification failed",
            )
    else:
        raise SignatureError("unsupported_sig_alg", f"unsupported sig_alg {sig_alg!r}")


# ---------------------------------------------------------------------------
# Strict UTC timestamp & monotonic clock helpers (Items 17 & 18)
# ---------------------------------------------------------------------------

def parse_utc_timestamp(value: Any, *, field: str = "not_after") -> datetime.datetime:
    """Strictly parse `YYYY-MM-DDTHH:MM:SSZ` with real calendar validation.

    Refuses fractional seconds, numeric offsets, trailing newlines, and
    impossible dates (e.g. Feb 30 or Feb 29 on a non-leap year). No maximum
    horizon cap is imposed (operator ruling 2026-11-26, Item 17).
    """
    if not isinstance(value, str):
        raise MalformedRecordError("invalid_timestamp", f"{field} must be a string")
    match = UTC_TS_RE.match(value)
    if match is None:
        raise MalformedRecordError(
            "invalid_timestamp_format",
            f"{field} {value!r} is not YYYY-MM-DDTHH:MM:SSZ",
        )
    year, month, day, hour, minute, second = (int(g) for g in match.groups())
    try:
        return datetime.datetime(
            year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc
        )
    except ValueError as exc:
        raise MalformedRecordError(
            "impossible_calendar_date",
            f"{field} {value!r} is not a valid calendar date: {exc}",
        ) from exc


def _parse_internal_utc_timestamp(value: Any, *, field: str = "last_seen_utc") -> datetime.datetime:
    """Parse internal store UTC timestamps preserving optional 6-digit microseconds."""
    if not isinstance(value, str):
        raise MalformedRecordError("invalid_timestamp", f"{field} must be a string")
    match = INTERNAL_UTC_TS_RE.match(value)
    if match is None:
        raise MalformedRecordError(
            "invalid_timestamp_format",
            f"{field} {value!r} is not a valid internal UTC timestamp",
        )
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    micro = int(match.group(7)) if match.group(7) is not None else 0
    try:
        return datetime.datetime(
            year, month, day, hour, minute, second, micro, tzinfo=datetime.timezone.utc
        )
    except ValueError as exc:
        raise MalformedRecordError(
            "impossible_calendar_date",
            f"{field} {value!r} is not a valid calendar date: {exc}",
        ) from exc


def format_utc_timestamp(dt: datetime.datetime) -> str:
    """Format UTC datetime preserving microsecond precision when non-zero."""
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware UTC")
    utc = dt.astimezone(datetime.timezone.utc)
    if utc.microsecond:
        return utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def _coerce_utc(now_utc: datetime.datetime | str) -> datetime.datetime:
    """Coerce UTC observation without truncating microseconds."""
    if isinstance(now_utc, str):
        return _parse_internal_utc_timestamp(now_utc, field="now_utc")
    if isinstance(now_utc, datetime.datetime):
        if now_utc.tzinfo is None:
            raise ValueError("now_utc must be timezone-aware")
        return now_utc.astimezone(datetime.timezone.utc)
    raise TypeError("now_utc must be a timezone-aware datetime or UTC ISO string")


def _coerce_mono(now_mono: Any) -> float:
    """Validate finite, non-negative, non-boolean monotonic timestamp (Item 18)."""
    if isinstance(now_mono, bool) or not isinstance(now_mono, (int, float)):
        raise ClockRollbackError(
            "invalid_monotonic_time",
            f"now_mono must be a finite non-negative number, got {type(now_mono).__name__}",
        )
    val = float(now_mono)
    if not math.isfinite(val) or val < 0.0:
        raise ClockRollbackError(
            "invalid_monotonic_time",
            f"now_mono must be finite and >= 0, got {now_mono!r}",
        )
    return val


def _validate_boot_epoch(boot_epoch: Any) -> str:
    if not isinstance(boot_epoch, str) or not boot_epoch or "\n" in boot_epoch:
        raise ClockRollbackError(
            "invalid_boot_epoch",
            "boot_epoch must be a non-empty single-line string",
        )
    _check_nfc(boot_epoch, "boot_epoch")
    return boot_epoch


# ---------------------------------------------------------------------------
# Structural validation matching schema/approval-record.schema.json (v9)
# ---------------------------------------------------------------------------

def validate_approval_record_shape(record: Any) -> dict[str, Any]:
    """Validate an approval record against v9 schema rules (floor == ceiling == 9)."""
    if not isinstance(record, dict):
        raise MalformedRecordError("not_object", "approval record must be a JSON object")

    schema_version = record.get("schema_version")
    if not _is_exact_int(schema_version) or schema_version != SUPPORTED_SCHEMA_VERSION:
        raise MalformedRecordError(
            "unsupported_schema_version",
            f"schema_version must be {SUPPORTED_SCHEMA_VERSION}, got {schema_version!r}",
        )

    missing_common = _COMMON_KEYS - set(record)
    if missing_common:
        raise MalformedRecordError(
            "missing_required_fields",
            f"missing required common fields: {sorted(missing_common)}",
        )

    kind = record["record_kind"]
    if not isinstance(kind, str) or kind not in RECORD_KINDS:
        raise MalformedRecordError("invalid_record_kind", f"invalid record_kind {kind!r}")

    if not isinstance(record["host"], str) or not KEY_ID_RE.match(record["host"]):
        raise MalformedRecordError("invalid_host", f"invalid host key_id {record['host']!r}")
    if not isinstance(record["signer"], str) or not record["signer"]:
        raise MalformedRecordError("invalid_signer", "signer must be a non-empty string")
    if not isinstance(record["sig_alg"], str) or not record["sig_alg"]:
        raise MalformedRecordError("invalid_sig_alg", "sig_alg must be a non-empty string")
    if not isinstance(record["signature"], str) or not record["signature"]:
        raise MalformedRecordError("invalid_signature_str", "signature must be a non-empty string")

    if kind == "per-change":
        extra = set(record) - _PER_CHANGE_ALLOWED
        if extra:
            raise MalformedRecordError("unexpected_fields", f"unexpected fields: {sorted(extra)}")
        required = {"proposed_sha256", "nonce", "approval_seq", "verdict", "ceremony_class"}
        missing = required - set(record)
        if missing:
            raise MalformedRecordError("missing_required_fields", f"missing: {sorted(missing)}")
        if "baseline_sha256" in record:
            if not isinstance(record["baseline_sha256"], str) or not SHA256_RE.match(
                record["baseline_sha256"]
            ):
                raise MalformedRecordError("invalid_baseline_sha256", "invalid baseline_sha256")
        if not isinstance(record["proposed_sha256"], str) or not SHA256_RE.match(
            record["proposed_sha256"]
        ):
            raise MalformedRecordError("invalid_proposed_sha256", "invalid proposed_sha256")
        if "briefing_sha256" in record:
            if not isinstance(record["briefing_sha256"], str) or not SHA256_RE.match(
                record["briefing_sha256"]
            ):
                raise MalformedRecordError("invalid_briefing_sha256", "invalid briefing_sha256")
        if not isinstance(record["nonce"], str) or not NONCE_RE.match(record["nonce"]):
            raise MalformedRecordError("invalid_nonce", "invalid nonce format/length")
        seq = record["approval_seq"]
        if not _is_exact_int(seq) or seq < 0 or seq > MAX_SAFE_INT:
            raise MalformedRecordError("invalid_approval_seq", "approval_seq out of range")
        verdict = record["verdict"]
        if not isinstance(verdict, str) or verdict not in VERDICTS:
            raise MalformedRecordError("invalid_verdict", f"invalid verdict {verdict!r}")
        if verdict == "reject":
            refused = record.get("refused")
            if (
                not isinstance(refused, list)
                or not refused
                or not all(isinstance(x, str) for x in refused)
            ):
                raise MalformedRecordError(
                    "invalid_refused", "verdict 'reject' requires non-empty string list 'refused'"
                )
        elif "refused" in record:
            raise MalformedRecordError(
                "unexpected_refused", "'refused' is only permitted when verdict is 'reject'"
            )
        cc = record["ceremony_class"]
        if not isinstance(cc, str) or cc not in CEREMONY_CLASSES:
            raise MalformedRecordError("invalid_ceremony_class", f"invalid ceremony_class {cc!r}")

    elif kind == "standing-enrollment":
        grant_state = record.get("grant_state")
        if not isinstance(grant_state, str) or grant_state not in GRANT_STATES:
            raise MalformedRecordError("invalid_grant_state", f"invalid grant_state {grant_state!r}")
        grant_id = record.get("grant_id")
        if not isinstance(grant_id, str) or not GRANT_ID_RE.match(grant_id):
            raise MalformedRecordError("invalid_grant_id", f"invalid grant_id {grant_id!r}")
        gen = record.get("generation")
        if not _is_exact_int(gen) or gen < 1 or gen > MAX_SAFE_INT:
            raise MalformedRecordError("invalid_generation", "generation out of range")

        if grant_state == "revoked":
            extra = set(record) - _ENROLLMENT_REVOKED_ALLOWED
            if extra:
                raise MalformedRecordError(
                    "unexpected_revocation_fields",
                    f"revocation forbids fields: {sorted(extra)}",
                )
        else:  # active
            extra = set(record) - _ENROLLMENT_ACTIVE_ALLOWED
            if extra:
                raise MalformedRecordError("unexpected_fields", f"unexpected fields: {sorted(extra)}")
            required = {
                "grant_id",
                "generation",
                "grant_state",
                "nonce",
                "mode",
                "covered_signers",
                "class",
                "developer_mode",
            }
            missing = required - set(record)
            if missing:
                raise MalformedRecordError("missing_required_fields", f"missing: {sorted(missing)}")
            if not isinstance(record["nonce"], str) or not NONCE_RE.match(record["nonce"]):
                raise MalformedRecordError("invalid_nonce", "invalid enrollment nonce")
            mode = record["mode"]
            if not isinstance(mode, str) or mode not in STANDING_MODES:
                raise MalformedRecordError("invalid_mode", f"invalid mode {mode!r}")
            if mode == "hold-window":
                hs = record.get("hold_seconds")
                if not _is_exact_int(hs) or hs < 1 or hs > MAX_SAFE_INT:
                    raise MalformedRecordError(
                        "invalid_hold_seconds", "hold-window requires valid hold_seconds"
                    )
            elif "hold_seconds" in record:
                raise MalformedRecordError(
                    "unexpected_hold_seconds", "hold_seconds is only allowed for mode hold-window"
                )
            covered = record["covered_signers"]
            if (
                not isinstance(covered, list)
                or not covered
                or not all(isinstance(k, str) and KEY_ID_RE.match(k) for k in covered)
            ):
                raise MalformedRecordError(
                    "invalid_covered_signers", "covered_signers must be non-empty list of key_ids"
                )
            if len(set(covered)) != len(covered):
                raise MalformedRecordError(
                    "duplicate_covered_signers", "covered_signers must not contain duplicates"
                )
            if covered != sorted(covered):
                raise MalformedRecordError(
                    "unsorted_covered_signers",
                    "covered_signers must be in ascending byte order",
                )
            grant_class = record["class"]
            if not isinstance(grant_class, str) or grant_class not in CEREMONY_CLASSES:
                raise MalformedRecordError("invalid_class", f"invalid class {grant_class!r}")
            dev_mode = record["developer_mode"]
            if not _is_exact_bool(dev_mode):
                raise MalformedRecordError("invalid_developer_mode", "developer_mode must be bool")
            if dev_mode and grant_class != "ordinary":
                raise MalformedRecordError(
                    "developer_mode_non_ordinary",
                    "developer_mode: true is permitted only for class 'ordinary' (R6)",
                )
            needs_not_after = mode in ("standing-approval", "hold-window") or dev_mode
            if needs_not_after and "not_after" not in record:
                raise MalformedRecordError(
                    "missing_not_after",
                    "not_after is required for standing-approval, hold-window, and developer_mode",
                )
            if "not_after" in record:
                parse_utc_timestamp(record["not_after"], field="not_after")

    elif kind == "standing-application":
        extra = set(record) - _APPLICATION_ALLOWED
        if extra:
            raise MalformedRecordError("unexpected_fields", f"unexpected fields: {sorted(extra)}")
        required = {
            "grant_id",
            "generation",
            "application_seq",
            "enrollment_nonce",
            "baseline_sha256",
            "proposed_sha256",
            "ceremony_class",
        }
        missing = required - set(record)
        if missing:
            raise MalformedRecordError("missing_required_fields", f"missing: {sorted(missing)}")
        if not isinstance(record["grant_id"], str) or not GRANT_ID_RE.match(record["grant_id"]):
            raise MalformedRecordError("invalid_grant_id", "invalid grant_id")
        gen = record["generation"]
        if not _is_exact_int(gen) or gen < 1 or gen > MAX_SAFE_INT:
            raise MalformedRecordError("invalid_generation", "generation out of range")
        aseq = record["application_seq"]
        if not _is_exact_int(aseq) or aseq < 1 or aseq > MAX_SAFE_INT:
            raise MalformedRecordError("invalid_application_seq", "application_seq out of range")
        if not isinstance(record["enrollment_nonce"], str) or not NONCE_RE.match(
            record["enrollment_nonce"]
        ):
            raise MalformedRecordError("invalid_enrollment_nonce", "invalid enrollment_nonce")
        if not isinstance(record["baseline_sha256"], str) or not SHA256_RE.match(
            record["baseline_sha256"]
        ):
            raise MalformedRecordError("invalid_baseline_sha256", "invalid baseline_sha256")
        if not isinstance(record["proposed_sha256"], str) or not SHA256_RE.match(
            record["proposed_sha256"]
        ):
            raise MalformedRecordError("invalid_proposed_sha256", "invalid proposed_sha256")
        cc = record["ceremony_class"]
        if not isinstance(cc, str) or cc not in CEREMONY_CLASSES:
            raise MalformedRecordError("invalid_ceremony_class", f"invalid ceremony_class {cc!r}")

    return record


# ---------------------------------------------------------------------------
# Crash-safe two-phase durable ReplayStore & independent RollbackAnchor (Item 1)
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class AnchorState:
    store_generation: int
    store_sha256: str


class RollbackAnchor:
    """Abstract monotonic anchor stored outside the replay store rollback domain."""

    def read(self) -> AnchorState | None:
        raise NotImplementedError

    def write(self, state: AnchorState) -> None:
        raise NotImplementedError


class InMemoryRollbackAnchor(RollbackAnchor):
    """In-memory hardware-counter/Keystore stand-in for hermetic tests."""

    def __init__(self, initial: AnchorState | None = None) -> None:
        self._state = initial

    def read(self) -> AnchorState | None:
        return self._state

    def write(self, state: AnchorState) -> None:
        self._state = state


def _atomic_write_file(
    path: Path,
    data: bytes,
    *,
    before_replace_hook: Callable[[], None] | None = None,
) -> None:
    """Atomically write all bytes via short-write loop + fsync + os.replace + dir fsync."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.tmp-")
    tmp_path = Path(tmp_name)
    try:
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        if before_replace_hook is not None:
            before_replace_hook()
        os.replace(tmp_path, path)
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


class FileRollbackAnchor(RollbackAnchor):
    """File-backed monotonic rollback anchor for simulation (separate rollback domain)."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def read(self) -> AnchorState | None:
        if not self.path.exists():
            return None
        try:
            doc = parse_strict_json(self.path.read_bytes())
        except (OSError, MalformedRecordError) as exc:
            raise StoreRollbackError(
                "anchor_corrupt", f"rollback anchor unreadable/corrupt: {exc}"
            ) from exc
        if (
            not isinstance(doc, dict)
            or set(doc) != {"store_generation", "store_sha256"}
            or not _is_exact_int(doc.get("store_generation"))
            or doc["store_generation"] < 0
            or doc["store_generation"] > MAX_SAFE_INT
            or not isinstance(doc.get("store_sha256"), str)
            or not RAW_SHA256_HEX_RE.match(doc["store_sha256"])
        ):
            raise StoreRollbackError("anchor_corrupt", "rollback anchor has invalid shape")
        return AnchorState(
            store_generation=doc["store_generation"],
            store_sha256=doc["store_sha256"],
        )

    def write(self, state: AnchorState) -> None:
        if (
            not _is_exact_int(state.store_generation)
            or state.store_generation < 0
            or state.store_generation > MAX_SAFE_INT
            or not isinstance(state.store_sha256, str)
            or not RAW_SHA256_HEX_RE.match(state.store_sha256)
        ):
            raise ValueError("invalid AnchorState")
        payload = jcs_dumps(
            {
                "store_generation": state.store_generation,
                "store_sha256": state.store_sha256,
            }
        )
        _atomic_write_file(self.path, payload)


def _fresh_store_state(
    host: str,
    *,
    store_generation: int = 0,
    applied_baseline_goal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base_copy = copy.deepcopy(applied_baseline_goal) if applied_baseline_goal is not None else None
    base_sha = canonical_sha256(base_copy) if base_copy is not None else None
    return {
        "store_version": 2,
        "host": host,
        "store_generation": store_generation,
        "voided": False,
        "void_reason": None,
        "approval_seq": -1,
        "last_seen_utc": None,
        "applied_baseline_goal": base_copy,
        "applied_baseline_sha256": base_sha,
        "pending_actuation": None,
        "persisted_rejects": {},
        "outstanding_nonces": {},
        "grants": {},
        "pending_holds": {},
    }


def _validate_store_shape(doc: Any, expected_host: str) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise StoreRollbackError("store_corrupt", "replay store root is not a JSON object")
    required = {
        "store_version",
        "host",
        "store_generation",
        "voided",
        "void_reason",
        "approval_seq",
        "last_seen_utc",
        "applied_baseline_goal",
        "applied_baseline_sha256",
        "pending_actuation",
        "persisted_rejects",
        "outstanding_nonces",
        "grants",
        "pending_holds",
    }
    if set(doc) != required:
        raise StoreRollbackError(
            "store_corrupt",
            f"replay store keys mismatch: missing={sorted(required - set(doc))}, extra={sorted(set(doc) - required)}",
        )
    if not _is_exact_int(doc["store_version"]) or doc["store_version"] != 2:
        raise StoreRollbackError(
            "store_corrupt", f"unsupported store_version {doc['store_version']!r}"
        )
    if doc["host"] != expected_host:
        raise StoreRollbackError("store_host_mismatch", "replay store belongs to a different host")
    if (
        not _is_exact_int(doc["store_generation"])
        or doc["store_generation"] < 0
        or doc["store_generation"] > MAX_SAFE_INT
    ):
        raise StoreRollbackError("store_corrupt", "invalid store_generation")
    if not _is_exact_bool(doc["voided"]):
        raise StoreRollbackError("store_corrupt", "invalid voided flag")
    if doc["void_reason"] is not None and not isinstance(doc["void_reason"], str):
        raise StoreRollbackError("store_corrupt", "invalid void_reason")
    if (
        not _is_exact_int(doc["approval_seq"])
        or doc["approval_seq"] < -1
        or doc["approval_seq"] > MAX_SAFE_INT
    ):
        raise StoreRollbackError("store_corrupt", "invalid approval_seq")
    if doc["last_seen_utc"] is not None:
        try:
            _parse_internal_utc_timestamp(doc["last_seen_utc"], field="last_seen_utc")
        except MalformedRecordError as exc:
            raise StoreRollbackError("store_corrupt", f"invalid last_seen_utc: {exc}") from exc
    base_goal = doc["applied_baseline_goal"]
    base_sha = doc["applied_baseline_sha256"]
    if base_goal is None:
        if base_sha is not None:
            raise StoreRollbackError(
                "store_corrupt", "applied_baseline_sha256 set without applied_baseline_goal"
            )
    else:
        if not isinstance(base_goal, dict) or not isinstance(base_sha, str) or not SHA256_RE.match(base_sha):
            raise StoreRollbackError("store_corrupt", "invalid applied_baseline_goal/sha256")
        if not hmac.compare_digest(canonical_sha256(base_goal), base_sha):
            raise StoreRollbackError(
                "store_corrupt", "applied_baseline_sha256 does not match applied_baseline_goal"
            )
    pa = doc["pending_actuation"]
    if pa is not None:
        if (
            not isinstance(pa, dict)
            or set(pa) != {"actuation_id", "proposed_sha256", "proposed_goal", "baseline_sha256"}
            or not isinstance(pa["actuation_id"], str)
            or not pa["actuation_id"]
            or not isinstance(pa["proposed_sha256"], str)
            or not SHA256_RE.match(pa["proposed_sha256"])
            or not isinstance(pa["proposed_goal"], dict)
            or (
                pa["baseline_sha256"] is not None
                and (
                    not isinstance(pa["baseline_sha256"], str)
                    or not SHA256_RE.match(pa["baseline_sha256"])
                )
            )
            or not hmac.compare_digest(canonical_sha256(pa["proposed_goal"]), pa["proposed_sha256"])
        ):
            raise StoreRollbackError("store_corrupt", "invalid pending_actuation record")
    for dict_key in ("persisted_rejects", "outstanding_nonces", "grants", "pending_holds"):
        if not isinstance(doc[dict_key], dict):
            raise StoreRollbackError("store_corrupt", f"store field {dict_key!r} is not an object")
    return doc


class ReplayStore:
    """Serialized, crash-safe, two-phase rollback-protected replay store per host.

    Requires an explicit `anchor: RollbackAnchor` from an independent rollback
    domain (no default adjacent file in `store_dir`). Use `ReplayStore.provision()`
    to initialize a brand-new store; opening an unprovisioned or missing store
    fails closed.
    """

    def __init__(
        self,
        store_dir: Path | str,
        host: str,
        *,
        anchor: RollbackAnchor,
    ) -> None:
        if not isinstance(host, str) or not KEY_ID_RE.match(host):
            raise ValueError(f"invalid host key_id: {host!r}")
        if not isinstance(anchor, RollbackAnchor):
            raise TypeError(
                "ReplayStore requires an explicit RollbackAnchor from an independent rollback domain"
            )
        self.store_dir = Path(store_dir)
        if isinstance(anchor, FileRollbackAnchor):
            # Fail closed on resolution failure and reject store_dir itself or any resolved descendant!
            store_resolved = self.store_dir.resolve(strict=False)
            anchor_resolved = anchor.path.resolve(strict=False)
            if anchor_resolved == store_resolved or anchor_resolved.is_relative_to(store_resolved):
                raise ValueError(
                    "FileRollbackAnchor must live outside store_dir (cannot be store_dir or any descendant)"
                )
        self.lock_path = self.store_dir / "replay-store.lock"
        self.host = host
        self.anchor = anchor
        self._thread_lock = threading.RLock()
        self._lock_depth: int = 0
        self._lock_fd: int | None = None
        self._in_actuation_tx: bool = False
        self.write_count: int = 0
        self.nonce_consume_count: int = 0
        self._seen_nonces_memory: set[str] = set()

    @classmethod
    def provision(
        cls,
        store_dir: Path | str,
        host: str,
        *,
        anchor: RollbackAnchor,
        baseline_goal: dict[str, Any] | None = None,
    ) -> "ReplayStore":
        """Explicitly provision a brand-new replay store and anchor."""
        baseline_snap = copy.deepcopy(baseline_goal) if baseline_goal is not None else None
        store = cls(store_dir, host, anchor=anchor)
        if baseline_snap is not None:
            validate_goal_file_basics(baseline_snap, host)
        with store.locked():
            if store.anchor.read() is not None:
                raise StoreRollbackError(
                    "already_provisioned",
                    "cannot provision store while rollback anchor already exists",
                )
            if store._list_version_files():
                raise StoreRollbackError(
                    "already_provisioned",
                    "cannot provision store while versioned store files already exist",
                )
            initial = _fresh_store_state(
                host, store_generation=0, applied_baseline_goal=baseline_snap
            )
            store._two_phase_commit_unlocked(initial, count_write=False)
        return store

    def version_path(self, generation: int) -> Path:
        return self.store_dir / f"replay-store.v{generation}.json"

    def _list_version_files(self) -> list[Path]:
        if not self.store_dir.exists():
            return []
        out: list[Path] = []
        for entry in self.store_dir.iterdir():
            if entry.is_file() and STORE_VERSION_FILE_RE.match(entry.name):
                out.append(entry)
        return sorted(out)

    @property
    def current_store_path(self) -> Path | None:
        anchor_state = self.anchor.read()
        if anchor_state is None:
            return None
        return self.version_path(anchor_state.store_generation)

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Re-entrant in-process RLock + cross-process advisory flock (zero self-deadlock)."""
        self.store_dir.mkdir(parents=True, exist_ok=True)
        with self._thread_lock:
            if self._lock_depth == 0:
                lock_fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                except BaseException:
                    os.close(lock_fd)
                    raise
                self._lock_fd = lock_fd
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
                if self._lock_depth == 0:
                    fd = self._lock_fd
                    self._lock_fd = None
                    if fd is not None:
                        try:
                            fcntl.flock(fd, fcntl.LOCK_UN)
                        finally:
                            os.close(fd)

    def _fail_closed_void_unlocked(
        self,
        reason: str,
        *,
        anchor_gen: int = 0,
    ) -> None:
        """Void all standing grants, holds, and nonces from a clean state.

        SECURITY (Neon F3 / Adversary C4): NEVER copies any field from an
        unauthenticated / SHA-256-failed store file into the voided state or
        anchor. Starts strictly from a clean `_fresh_store_state` at
        `anchor_gen + 1` with `voided = True`.
        """
        next_gen = max(0, anchor_gen) + 1
        voided_state = _fresh_store_state(self.host, store_generation=next_gen)
        voided_state["voided"] = True
        voided_state["void_reason"] = reason
        self._two_phase_commit_unlocked(voided_state, count_write=True)

    def load_verified_unlocked(self, *, allow_voided: bool = False) -> dict[str, Any]:
        """Load the anchored store generation and verify exact SHA-256; fail closed on mismatch."""
        anchor_state = self.anchor.read()
        if anchor_state is None:
            if self._list_version_files():
                self._fail_closed_void_unlocked(
                    "rollback anchor missing while store files exist", anchor_gen=0
                )
                raise StoreRollbackError(
                    "anchor_missing",
                    "rollback anchor missing while store exists; all standing grants voided",
                )
            raise StoreRollbackError(
                "store_unprovisioned",
                "replay store is not provisioned (missing both anchor and store files)",
            )

        target_path = self.version_path(anchor_state.store_generation)
        if not target_path.exists():
            self._fail_closed_void_unlocked(
                "store file missing for anchored generation (store loss or directory rollback)",
                anchor_gen=anchor_state.store_generation,
            )
            raise StoreRollbackError(
                "store_missing_rollback",
                "anchored replay store file missing; all standing grants and nonces voided",
            )

        try:
            raw = target_path.read_bytes()
        except OSError as exc:
            self._fail_closed_void_unlocked(
                f"store unreadable: {exc}", anchor_gen=anchor_state.store_generation
            )
            raise StoreRollbackError("store_unreadable", str(exc)) from exc

        # Authenticate bytes BEFORE parsing or trusting any field!
        actual_sha = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(actual_sha, anchor_state.store_sha256):
            self._fail_closed_void_unlocked(
                "store digest mismatch vs rollback anchor",
                anchor_gen=anchor_state.store_generation,
            )
            raise StoreRollbackError(
                "store_rollback_detected",
                "replay store digest does not match rollback anchor; all standing grants and nonces voided",
            )

        try:
            doc = parse_strict_json(raw)
            doc = _validate_store_shape(doc, self.host)
        except (MalformedRecordError, StoreRollbackError) as exc:
            self._fail_closed_void_unlocked(
                f"store corrupt: {exc}", anchor_gen=anchor_state.store_generation
            )
            raise StoreRollbackError(
                "store_corrupt", f"replay store corrupted/invalid: {exc}"
            ) from exc

        if doc["store_generation"] != anchor_state.store_generation:
            self._fail_closed_void_unlocked(
                "store generation mismatch vs rollback anchor",
                anchor_gen=anchor_state.store_generation,
            )
            raise StoreRollbackError(
                "store_rollback_detected",
                "replay store generation does not match rollback anchor; all standing grants voided",
            )

        if doc["voided"] and not allow_voided:
            raise StoreRollbackError(
                "store_voided",
                f"replay store is voided ({doc['void_reason']}); fresh owner recovery required",
            )

        return doc

    def _cleanup_old_generations_unlocked(self, keep_generation: int) -> None:
        keep_name = self.version_path(keep_generation).name
        for path in self._list_version_files():
            if path.name != keep_name:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass

    def _two_phase_commit_unlocked(
        self,
        state: dict[str, Any],
        *,
        before_replace_hook: Callable[[], None] | None = None,
        before_anchor_hook: Callable[[], None] | None = None,
        after_commit_hook: Callable[[], None] | None = None,
        count_write: bool = True,
    ) -> None:
        """Crash-safe two-phase commit:

        Phase 1: Atomically write & fsync immutable `replay-store.v<gen>.json`
                 (leaving `v<gen-1>` completely untouched).
        Phase 2: Advance independent `RollbackAnchor` to `(gen, sha256)` — this
                 is the single atomic commit point.
        Cleanup: Best-effort unlink of older `v<old>.json` files.
        """
        raw = jcs_dumps(state)
        digest = hashlib.sha256(raw).hexdigest()
        gen = state["store_generation"]
        target = self.version_path(gen)

        _atomic_write_file(target, raw, before_replace_hook=before_replace_hook)
        if before_anchor_hook is not None:
            before_anchor_hook()
        self.anchor.write(AnchorState(store_generation=gen, store_sha256=digest))
        if count_write:
            self.write_count += 1
        if after_commit_hook is not None:
            after_commit_hook()
        self._cleanup_old_generations_unlocked(gen)

    def commit_unlocked(
        self,
        state: dict[str, Any],
        *,
        before_replace_hook: Callable[[], None] | None = None,
        before_anchor_hook: Callable[[], None] | None = None,
        after_commit_hook: Callable[[], None] | None = None,
    ) -> None:
        if self._in_actuation_tx:
            raise ReplayError(
                "nested_mutation_during_actuation",
                "nested store mutations are forbidden while an actuation callback is running",
            )
        expected_gen = state["store_generation"]
        current_anchor = self.anchor.read()
        if current_anchor is None or current_anchor.store_generation != expected_gen:
            raise StoreRollbackError(
                "anchor_generation_conflict",
                f"anchor generation mismatch before commit (expected {expected_gen}, "
                f"got {current_anchor.store_generation if current_anchor else None})",
            )
        state["store_generation"] = expected_gen + 1
        self._two_phase_commit_unlocked(
            state,
            before_replace_hook=before_replace_hook,
            before_anchor_hook=before_anchor_hook,
            after_commit_hook=after_commit_hook,
            count_write=True,
        )

    def snapshot(self, *, allow_voided: bool = True) -> dict[str, Any]:
        """Return a deep copy of the verified store state for read-only inspection."""
        with self.locked():
            return copy.deepcopy(self.load_verified_unlocked(allow_voided=allow_voided))

    def recover_after_store_loss(
        self,
        *,
        baseline_goal: dict[str, Any] | None = None,
    ) -> None:
        """Owner-initiated recovery after rollback/store-loss voiding.

        Clears `voided`, leaves all standing grants empty and all old nonces
        cleared, and restores the authoritative applied baseline supplied by the
        owner recovery ceremony (if provided).
        """
        baseline_snap = copy.deepcopy(baseline_goal) if baseline_goal is not None else None
        if baseline_snap is not None:
            validate_goal_file_basics(baseline_snap, self.host)
        with self.locked():
            state = self.load_verified_unlocked(allow_voided=True)
            if state.get("pending_actuation") is not None:
                raise ReplayError(
                    "pending_actuation_unreconciled",
                    "cannot run recover_after_store_loss while pending_actuation is unreconciled",
                )
            if not state.get("voided"):
                raise ReplayError(
                    "store_not_voided",
                    "recover_after_store_loss is only permitted on a voided store",
                )
            state["voided"] = False
            state["void_reason"] = None
            state["pending_actuation"] = None
            state["outstanding_nonces"] = {}
            state["pending_holds"] = {}
            state["grants"] = {
                gid: g for gid, g in state["grants"].items() if g.get("tombstoned") is True
            }
            if baseline_snap is not None:
                state["applied_baseline_goal"] = copy.deepcopy(baseline_snap)
                state["applied_baseline_sha256"] = canonical_sha256(baseline_snap)
            self.commit_unlocked(state)


# ---------------------------------------------------------------------------
# Goal-file validation, authoritative diff computation, carve-out & migrations
# ---------------------------------------------------------------------------

def validate_trust_root_no_host_key(goal_file: dict[str, Any], host: str) -> None:
    """Enforce Item 10: the device's own host key is never an advisor-key."""
    if not isinstance(goal_file, dict):
        raise TrustRootError("invalid_goal_file", "goal file must be a JSON object")
    domains = goal_file.get("domains")
    if not isinstance(domains, dict):
        return
    dt = domains.get(TRUST_DOMAIN)
    if not isinstance(dt, dict):
        return
    entries = dt.get("entries")
    if not isinstance(entries, dict):
        return
    advisor = entries.get("advisor-key")
    if isinstance(advisor, dict) and host in advisor:
        raise TrustRootError(
            "host_key_in_trust_root",
            "device's own host key must never appear as a device-trust advisor-key (Item 10)",
        )


def validate_goal_file_basics(goal_file: Any, host: str) -> None:
    """Validate goal-file NFC, closed keys, host, schema_version, coverages, and Item 10 ban."""
    if not isinstance(goal_file, dict):
        raise MalformedRecordError("invalid_goal_file", "goal file must be a JSON object")
    _check_nfc(goal_file)
    if goal_file.get("host") != host:
        raise ScopeError(
            "goal_host_mismatch",
            f"goal file host {goal_file.get('host')!r} != device host {host!r}",
        )
    if set(goal_file) != {"schema_version", "host", "domains"}:
        raise MalformedRecordError(
            "unexpected_goal_fields",
            f"goal file must have exact keys schema_version, host, domains; got {sorted(goal_file)}",
        )
    sv = goal_file["schema_version"]
    if not _is_exact_int(sv) or sv < 1 or sv > MAX_SAFE_INT:
        raise MalformedRecordError(
            "invalid_goal_schema_version", f"invalid goal schema_version {sv!r}"
        )
    domains = goal_file["domains"]
    if not isinstance(domains, dict):
        raise MalformedRecordError("invalid_goal_domains", "goal file domains must be an object")
    for dom_name, dom_obj in domains.items():
        if not isinstance(dom_name, str) or not isinstance(dom_obj, dict):
            raise MalformedRecordError("invalid_goal_domain", f"domain {dom_name!r} must be an object")
        extra_dom_keys = set(dom_obj) - {"coverage", "entries"}
        if extra_dom_keys:
            raise MalformedRecordError(
                "unexpected_domain_fields",
                f"domain {dom_name!r} has unexpected keys: {sorted(extra_dom_keys)}",
            )
        cov = dom_obj.get("coverage")
        if not isinstance(cov, str) or cov not in GOAL_COVERAGE_VALUES:
            raise MalformedRecordError(
                "invalid_coverage_value",
                f"domain {dom_name!r} has invalid coverage {cov!r}",
            )
        if "entries" in dom_obj:
            entries = dom_obj["entries"]
            if cov == "deliberately-unmanaged":
                raise MalformedRecordError(
                    "entries_in_unmanaged_domain",
                    f"deliberately-unmanaged domain {dom_name!r} must not carry entries",
                )
            if not isinstance(entries, dict) or not entries:
                raise MalformedRecordError(
                    "invalid_domain_entries",
                    f"domain {dom_name!r} entries must be a non-empty object",
                )
            for kind_name, ids in entries.items():
                if not isinstance(kind_name, str) or not isinstance(ids, dict) or not ids:
                    raise MalformedRecordError(
                        "invalid_kind_bucket",
                        f"domain {dom_name!r} kind {kind_name!r} must be a non-empty object",
                    )
                for eid, body in ids.items():
                    if not isinstance(eid, str) or not isinstance(body, dict):
                        raise MalformedRecordError(
                            "invalid_entry_body",
                            f"{dom_name}/{kind_name}/{eid} must be a JSON object",
                        )
    validate_trust_root_no_host_key(goal_file, host)


def extract_baseline_roles(baseline_goal: dict[str, Any], host: str) -> dict[str, str]:
    """Extract active (`state == 'present'`) advisor-key roles from applied baseline only."""
    validate_trust_root_no_host_key(baseline_goal, host)
    try:
        advisor = baseline_goal["domains"][TRUST_DOMAIN]["entries"]["advisor-key"]
    except (KeyError, TypeError) as exc:
        raise TrustRootError(
            "missing_trust_root",
            "baseline goal file has no readable device-trust/advisor-key map",
        ) from exc
    if not isinstance(advisor, dict):
        raise TrustRootError("invalid_trust_root", "advisor-key map is not an object")

    roles: dict[str, str] = {}
    for key_id, entry in advisor.items():
        if not isinstance(entry, dict):
            continue
        if entry.get("state") == "present":
            role = entry.get("role")
            if role in ("owner", "covered-signer"):
                roles[key_id] = role
    return roles


def derive_hunk_class(domain: str, kind: str) -> str:
    """Derive ceremony class for a single hunk."""
    return "privileged" if domain == TRUST_DOMAIN else "ordinary"


def derive_coverage_change_class(old: str, new: str) -> str:
    """Derive ceremony class for a single validated domain coverage transition (§4.3)."""
    if (
        not isinstance(old, str)
        or not isinstance(new, str)
        or old not in DIFF_COVERAGE_VALUES
        or new not in DIFF_COVERAGE_VALUES
    ):
        raise MalformedRecordError(
            "invalid_coverage_value",
            f"coverage transition ({old!r} -> {new!r}) outside closed enum",
        )
    if "deliberately-unmanaged" in (old, new):
        return "privileged"
    if old == "comprehensive" and new != "comprehensive":
        return "privileged"
    return "ordinary"


def compute_authoritative_diff(
    baseline_goal: dict[str, Any],
    proposed_goal: dict[str, Any],
    host: str,
) -> dict[str, Any]:
    """Compute the authoritative device-side goal diff between baseline and proposed."""
    validate_goal_file_basics(baseline_goal, host)
    validate_goal_file_basics(proposed_goal, host)

    base_hash = canonical_sha256(baseline_goal)
    prop_hash = canonical_sha256(proposed_goal)
    if hmac.compare_digest(base_hash, prop_hash):
        raise ScopeError("empty_diff", "baseline and proposed goal files are identical")

    old_ver = baseline_goal["schema_version"]
    new_ver = proposed_goal["schema_version"]
    if new_ver < old_ver:
        raise ScopeError(
            "downward_version_bump",
            f"refusing downward schema_version {old_ver} -> {new_ver}",
        )
    if new_ver > old_ver:
        return {
            "schema_version": SUPPORTED_SCHEMA_VERSION,
            "host": host,
            "baseline_sha256": base_hash,
            "proposed_sha256": prop_hash,
            "version_bump": {"old": old_ver, "new": new_ver},
        }

    # Same schema_version: reject any top-level header difference outside `domains`.
    base_extra = {k: v for k, v in baseline_goal.items() if k != "domains"}
    prop_extra = {k: v for k, v in proposed_goal.items() if k != "domains"}
    if not jcs_equal(base_extra, prop_extra):
        raise ScopeError(
            "unsupported_header_change",
            "goal files differ in header fields outside schema_version and domains",
        )

    base_domains: dict[str, Any] = baseline_goal["domains"]
    prop_domains: dict[str, Any] = proposed_goal["domains"]

    coverage_changes: dict[str, dict[str, str]] = {}
    hunks: dict[str, dict[str, dict[str, dict[str, Any]]]] = {}

    for dom_name in sorted(set(base_domains) | set(prop_domains)):
        old_dom = base_domains.get(dom_name)
        new_dom = prop_domains.get(dom_name)
        old_cov = old_dom["coverage"] if old_dom is not None else "undeclared"
        new_cov = new_dom["coverage"] if new_dom is not None else "undeclared"
        if old_cov != new_cov:
            coverage_changes[dom_name] = {"old": old_cov, "new": new_cov}

        # Reject domain-level keys outside {"coverage", "entries"} that changed.
        if old_dom is not None and new_dom is not None:
            od_meta = {k: v for k, v in old_dom.items() if k not in ("coverage", "entries")}
            nd_meta = {k: v for k, v in new_dom.items() if k not in ("coverage", "entries")}
            if not jcs_equal(od_meta, nd_meta):
                raise ScopeError(
                    "unsupported_domain_change",
                    f"domain {dom_name!r} differs in non-entry metadata",
                )

        old_entries = (old_dom or {}).get("entries") or {}
        new_entries = (new_dom or {}).get("entries") or {}
        dom_hunks: dict[str, dict[str, dict[str, Any]]] = {}
        for kind_name in sorted(set(old_entries) | set(new_entries)):
            old_bucket = old_entries.get(kind_name) or {}
            new_bucket = new_entries.get(kind_name) or {}
            kind_hunks: dict[str, dict[str, Any]] = {}
            for eid in sorted(set(old_bucket) | set(new_bucket)):
                in_old = eid in old_bucket
                in_new = eid in new_bucket
                if in_old and in_new:
                    if not jcs_equal(old_bucket[eid], new_bucket[eid]):
                        kind_hunks[eid] = {
                            "old": copy.deepcopy(old_bucket[eid]),
                            "new": copy.deepcopy(new_bucket[eid]),
                        }
                elif in_new:
                    kind_hunks[eid] = {"new": copy.deepcopy(new_bucket[eid])}
                else:
                    kind_hunks[eid] = {"old": copy.deepcopy(old_bucket[eid])}
            if kind_hunks:
                dom_hunks[kind_name] = kind_hunks
        if dom_hunks:
            hunks[dom_name] = dom_hunks

    diff: dict[str, Any] = {
        "schema_version": SUPPORTED_SCHEMA_VERSION,
        "host": host,
        "baseline_sha256": base_hash,
        "proposed_sha256": prop_hash,
    }
    if coverage_changes:
        diff["coverage_changes"] = coverage_changes
    if hunks:
        diff["hunks"] = hunks
    if not coverage_changes and not hunks:
        raise ScopeError("empty_diff", "no representable diff between baseline and proposed")
    reconstructed = _apply_validated_diff_to_baseline(baseline_goal, diff)
    if not hmac.compare_digest(canonical_sha256(reconstructed), prop_hash):
        raise ScopeError(
            "diff_reconstruct_mismatch",
            "authoritative diff does not reproduce proposed goal file byte-for-byte",
        )
    return diff


def analyze_diff_classes(diff: dict[str, Any]) -> tuple[str, set[str]]:
    """Validate `diff` strictly and return `(overall_derived_class, per_item_classes)`.

    Always run BEFORE `verify_diff_matches_goals()` so malformed diffs raise
    `MalformedRecordError` rather than `KeyError`/`TypeError`. Enforces:
      - closed top-level keys, `schema_version == 9`, valid `host` and hashes,
        `baseline_sha256 != proposed_sha256`
      - non-null `version_bump`, `hunks`, `coverage_changes`
      - `version_bump` mutually exclusive with `hunks` and `coverage_changes`
      - downward/equal `version_bump` (`new <= old`) refused unconditionally
        (operator ruling 2026-11-26, Item 15)
      - closed coverage enum on `coverage_changes`
      - object-only `old`/`new` on every hunk, `set(hunk) <= {"old", "new"}`,
        no no-op hunks under `jcs_equal`
    """
    if not isinstance(diff, dict):
        raise MalformedRecordError("invalid_diff", "goal diff must be an object")

    extra_keys = set(diff) - _DIFF_ALLOWED_KEYS
    if extra_keys:
        raise MalformedRecordError("unexpected_diff_fields", f"unexpected diff keys: {sorted(extra_keys)}")

    sv = diff.get("schema_version")
    if not _is_exact_int(sv) or sv != SUPPORTED_SCHEMA_VERSION:
        raise MalformedRecordError(
            "invalid_diff_schema_version",
            f"diff schema_version must be {SUPPORTED_SCHEMA_VERSION}, got {sv!r}",
        )
    if not isinstance(diff.get("host"), str) or not KEY_ID_RE.match(diff["host"]):
        raise MalformedRecordError("invalid_diff_host", "diff host must be a valid key_id")
    if not isinstance(diff.get("baseline_sha256"), str) or not SHA256_RE.match(
        diff["baseline_sha256"]
    ):
        raise MalformedRecordError("invalid_diff_baseline_sha256", "invalid diff baseline_sha256")
    if not isinstance(diff.get("proposed_sha256"), str) or not SHA256_RE.match(
        diff["proposed_sha256"]
    ):
        raise MalformedRecordError("invalid_diff_proposed_sha256", "invalid diff proposed_sha256")

    has_bump = "version_bump" in diff
    has_hunks = "hunks" in diff
    has_cov = "coverage_changes" in diff

    if has_bump:
        if has_hunks or has_cov:
            raise ScopeError(
                "migration_not_empty",
                "version_bump diff must carry neither hunks nor coverage_changes",
            )
        bump = diff["version_bump"]
        if not isinstance(bump, dict) or set(bump) != {"old", "new"}:
            raise MalformedRecordError(
                "invalid_version_bump", "version_bump must be an object with exact keys old, new"
            )
        old_v, new_v = bump["old"], bump["new"]
        if (
            not _is_exact_int(old_v)
            or not _is_exact_int(new_v)
            or old_v < 1
            or new_v < 1
            or old_v > MAX_SAFE_INT
            or new_v > MAX_SAFE_INT
        ):
            raise MalformedRecordError(
                "invalid_version_bump", "version_bump old/new must be positive safe ints"
            )
        if new_v <= old_v:
            raise ScopeError(
                "downward_version_bump",
                f"refusing version_bump with new ({new_v}) <= old ({old_v})",
            )
        if hmac.compare_digest(diff["baseline_sha256"], diff["proposed_sha256"]):
            raise ScopeError("empty_diff", "diff baseline_sha256 equals proposed_sha256")
        return "baseline", {"baseline"}

    if hmac.compare_digest(diff["baseline_sha256"], diff["proposed_sha256"]):
        raise ScopeError("empty_diff", "diff baseline_sha256 equals proposed_sha256")

    per_item: set[str] = set()
    if has_hunks:
        hunks = diff["hunks"]
        if not isinstance(hunks, dict) or not hunks:
            raise MalformedRecordError("invalid_hunks", "hunks must be a non-empty object")
        for domain_name, kinds in hunks.items():
            if not isinstance(domain_name, str) or not isinstance(kinds, dict) or not kinds:
                raise MalformedRecordError("invalid_hunks", f"hunks/{domain_name!r} must be non-empty object")
            for kind_name, ids in kinds.items():
                if not isinstance(kind_name, str) or not isinstance(ids, dict) or not ids:
                    raise MalformedRecordError(
                        "invalid_hunks", f"hunks/{domain_name}/{kind_name!r} must be non-empty object"
                    )
                for entry_id, hunk in ids.items():
                    if (
                        not isinstance(entry_id, str)
                        or not isinstance(hunk, dict)
                        or not hunk
                        or not set(hunk).issubset({"old", "new"})
                    ):
                        raise MalformedRecordError(
                            "invalid_hunk",
                            f"hunk {domain_name}/{kind_name}/{entry_id!r} must have non-empty subset of old/new",
                        )
                    if "old" in hunk and not isinstance(hunk["old"], dict):
                        raise MalformedRecordError(
                            "invalid_hunk_old",
                            f"hunk {domain_name}/{kind_name}/{entry_id} old must be a JSON object",
                        )
                    if "new" in hunk and not isinstance(hunk["new"], dict):
                        raise MalformedRecordError(
                            "invalid_hunk_new",
                            f"hunk {domain_name}/{kind_name}/{entry_id} new must be a JSON object",
                        )
                    if "old" in hunk and "new" in hunk and jcs_equal(hunk["old"], hunk["new"]):
                        raise ScopeError(
                            "noop_hunk",
                            f"hunk {domain_name}/{kind_name}/{entry_id} has identical old and new",
                        )
                    per_item.add(derive_hunk_class(domain_name, kind_name))

    if has_cov:
        cov = diff["coverage_changes"]
        if not isinstance(cov, dict) or not cov:
            raise MalformedRecordError(
                "invalid_coverage_changes", "coverage_changes must be a non-empty object"
            )
        for domain_name, change in cov.items():
            if (
                not isinstance(domain_name, str)
                or not isinstance(change, dict)
                or set(change) != {"old", "new"}
            ):
                raise MalformedRecordError(
                    "invalid_coverage_change",
                    f"coverage_changes/{domain_name!r} must have exact keys old, new",
                )
            old_c, new_c = change["old"], change["new"]
            cls = derive_coverage_change_class(old_c, new_c)
            if old_c == new_c:
                raise ScopeError(
                    "noop_coverage_change",
                    f"coverage_changes/{domain_name} states identical old and new",
                )
            per_item.add(cls)

    if not per_item:
        raise MalformedRecordError(
            "empty_diff", "goal diff has no version_bump, hunks, or coverage_changes"
        )

    overall = "privileged" if "privileged" in per_item else "ordinary"
    return overall, per_item


def check_standing_carve_out(
    diff: dict[str, Any],
    *,
    touches_replay_store: bool = False,
) -> None:
    """Enforce R1/R7 default-deny carve-out over `device-trust` and replay state (Item 13)."""
    if touches_replay_store:
        raise ScopeError(
            "carve_out_replay_store",
            "standing grants never cover changes touching or resetting grant replay state (R1)",
        )
    cov = diff.get("coverage_changes") or {}
    if TRUST_DOMAIN in cov:
        raise ScopeError(
            "carve_out_device_trust",
            "standing grants never cover device-trust coverage changes (R1/R7)",
        )
    trust_hunks = (diff.get("hunks") or {}).get(TRUST_DOMAIN)
    if isinstance(trust_hunks, dict):
        for kind_name in sorted(trust_hunks):
            if kind_name not in ALLOWED_STANDING_DEVICE_TRUST_KINDS:
                raise ScopeError(
                    "carve_out_device_trust",
                    f"standing grants never cover device-trust/{kind_name} (R1/R7 default-deny)",
                )


def _apply_validated_diff_to_baseline(
    baseline_goal: dict[str, Any],
    diff: dict[str, Any],
) -> dict[str, Any]:
    """Apply a pre-validated non-migration diff to `baseline_goal` and return resulting goal."""
    result = copy.deepcopy(baseline_goal)
    baseline_domains = baseline_goal.get("domains") or {}
    domains = result.setdefault("domains", {})

    for domain_name, kinds in (diff.get("hunks") or {}).items():
        domain = domains.setdefault(domain_name, {})
        entries = domain.setdefault("entries", {})
        for kind_name, ids in kinds.items():
            bucket = entries.setdefault(kind_name, {})
            for entry_id, hunk in ids.items():
                if "old" in hunk:
                    if entry_id not in bucket or not jcs_equal(bucket[entry_id], hunk["old"]):
                        raise ScopeError(
                            "hunk_old_mismatch",
                            f"hunk {domain_name}/{kind_name}/{entry_id} old != baseline entry",
                        )
                elif entry_id in bucket:
                    raise ScopeError(
                        "hunk_add_exists",
                        f"hunk {domain_name}/{kind_name}/{entry_id} adds an existing entry",
                    )
                if "new" in hunk:
                    bucket[entry_id] = copy.deepcopy(hunk["new"])
                else:
                    bucket.pop(entry_id, None)
            if not bucket:
                del entries[kind_name]
        if not entries:
            del domain["entries"]

    for domain_name, change in (diff.get("coverage_changes") or {}).items():
        actual_old = (baseline_domains.get(domain_name) or {}).get("coverage", "undeclared")
        if actual_old != change["old"]:
            raise ScopeError(
                "coverage_old_mismatch",
                f"coverage_changes/{domain_name} claims old={change['old']!r}, baseline has {actual_old!r}",
            )
        if change["new"] == "undeclared":
            leftover = (domains.get(domain_name) or {}).get("entries") or {}
            if leftover:
                raise ScopeError(
                    "coverage_retreat_nonempty",
                    f"coverage_changes/{domain_name} retreats to undeclared while entries remain",
                )
            domains.pop(domain_name, None)
        else:
            dom_obj = domains.setdefault(domain_name, {})
            dom_obj["coverage"] = change["new"]

    # Post-apply domain invariants (matching schema_lint.py:2527-2534):
    for domain_name, dom_obj in domains.items():
        cov = dom_obj.get("coverage")
        if not isinstance(cov, str) or cov not in GOAL_COVERAGE_VALUES:
            raise ScopeError(
                "domain_missing_coverage",
                f"domain {domain_name!r} lacks valid coverage after applying diff",
            )
        if cov == "deliberately-unmanaged" and dom_obj.get("entries"):
            raise ScopeError(
                "entries_in_unmanaged_domain",
                f"deliberately-unmanaged domain {domain_name!r} retains entries after applying diff",
            )

    return result


def verify_diff_matches_goals(
    baseline_goal: dict[str, Any],
    proposed_goal: dict[str, Any],
    diff: dict[str, Any],
    host: str,
) -> None:
    """Validate `diff` structurally, verify host/hashes, and prove exact application to baseline."""
    # Always run structural validation BEFORE traversing diff!
    analyze_diff_classes(diff)
    validate_goal_file_basics(baseline_goal, host)
    validate_goal_file_basics(proposed_goal, host)

    if diff["host"] != host:
        raise ScopeError("diff_host_mismatch", "diff host does not match device host")

    actual_base_hash = canonical_sha256(baseline_goal)
    actual_prop_hash = canonical_sha256(proposed_goal)
    if not hmac.compare_digest(diff["baseline_sha256"], actual_base_hash):
        raise ReplayError("diff_baseline_hash_mismatch", "diff baseline_sha256 != baseline hash")
    if not hmac.compare_digest(diff["proposed_sha256"], actual_prop_hash):
        raise ScopeError("diff_proposed_hash_mismatch", "diff proposed_sha256 != proposed hash")

    if "version_bump" in diff:
        bump = diff["version_bump"]
        if baseline_goal["schema_version"] != bump["old"]:
            raise ScopeError(
                "version_bump_old_mismatch",
                "baseline schema_version does not match version_bump.old",
            )
        if proposed_goal["schema_version"] != bump["new"]:
            raise ScopeError(
                "version_bump_new_mismatch",
                "proposed schema_version does not match version_bump.new",
            )
        return

    applied = _apply_validated_diff_to_baseline(baseline_goal, diff)
    if not hmac.compare_digest(canonical_sha256(applied), actual_prop_hash):
        raise ScopeError(
            "diff_apply_mismatch",
            "applying diff to baseline does not reproduce proposed goal file",
        )


def check_standing_migration_invariants(
    baseline_goal: dict[str, Any],
    proposed_goal: dict[str, Any],
    *,
    migrate_fn: Callable[[dict[str, Any], int], dict[str, Any]] | None = None,
    device_trust_comparable: bool = False,
) -> None:
    """Enforce Item 15 on `baseline`-class standing-application migrations.

    Fail-closed default (Codex #10): requires BOTH explicit
    `device_trust_comparable=True` AND a recognized `migrate_fn` proving
    type-preserving JCS equality of `device-trust` under one schema.
    """
    if not device_trust_comparable or migrate_fn is None:
        raise ScopeError(
            "migration_device_trust_incomparable",
            "baseline standing migration requires explicit migrate_fn and device_trust_comparable=True (Item 15)",
        )

    base_dt = (baseline_goal.get("domains") or {}).get(TRUST_DOMAIN)
    prop_dt = (proposed_goal.get("domains") or {}).get(TRUST_DOMAIN)
    if not isinstance(base_dt, dict) or not isinstance(prop_dt, dict):
        raise ScopeError(
            "migration_device_trust_incomparable",
            "missing device-trust in baseline or proposed goal file",
        )

    target_version = proposed_goal.get("schema_version")
    try:
        migrated = migrate_fn(copy.deepcopy(baseline_goal), target_version)
    except Exception as exc:
        raise ScopeError(
            "migration_failed",
            f"migrate() failed; cannot verify device-trust preservation: {exc}",
        ) from exc
    if not isinstance(migrated, dict):
        raise ScopeError("migration_failed", "migrate() did not return a goal-file object")
    mig_dt = (migrated.get("domains") or {}).get(TRUST_DOMAIN)
    if not isinstance(mig_dt, dict):
        raise ScopeError("migration_failed", "migrated goal file lacks device-trust")

    # Type-preserving JCS equality prevents Python True==1 / False==0 smuggling (Adversary C2)!
    if not jcs_equal(mig_dt, base_dt) or not jcs_equal(mig_dt, prop_dt):
        raise ScopeError(
            "migration_mutated_device_trust",
            "migration alters device-trust content (including defaults/types); requires per-change owner record",
        )
    if not hmac.compare_digest(canonical_sha256(migrated), canonical_sha256(proposed_goal)):
        raise ScopeError(
            "migration_content_mismatch",
            "proposed goal file differs from migrated baseline",
        )


# ---------------------------------------------------------------------------
# R9 enrollment briefing rendering (Item 16)
# ---------------------------------------------------------------------------

def render_enrollment_briefing(enrollment: dict[str, Any]) -> str:
    """Render the owner ceremony briefing with mandatory R9 root-equivalent disclosure."""
    validate_approval_record_shape(enrollment)
    if enrollment["record_kind"] != "standing-enrollment" or enrollment["grant_state"] != "active":
        raise MalformedRecordError(
            "not_active_enrollment",
            "render_enrollment_briefing expects an active standing-enrollment record",
        )
    lines = [
        "=== tendcf Standing Grant Enrollment Ceremony ===",
        f"Host:            {enrollment['host']}",
        f"Grant ID:        {enrollment['grant_id']} (generation {enrollment['generation']})",
        f"Mode:            {enrollment['mode']}",
        f"Class:           {enrollment['class']}",
        f"Developer mode:  {enrollment['developer_mode']}",
        f"Covered signers: {', '.join(enrollment['covered_signers'])}",
        f"Hold seconds:    {enrollment.get('hold_seconds', 'n/a')}",
        f"Expires (UTC):   {enrollment.get('not_after', 'until revoked')}",
        "",
        "SECURITY DISCLOSURE (R9 — Root-Equivalent Authority):",
        "  - This standing grant delegates root-equivalent authority to its covered",
        "    signers: covered service and interlock changes run as root.",
        "  - Grant standing authority ONLY to a signer you would trust with root.",
        "  - Revocation or expiry stops ONLY future applications and pending holds;",
        "    it NEVER undoes code or state an earlier application already installed.",
        "  - Because that authority is root-equivalent, a covered signer can also,",
        "    through the code it installs, alter the trust root, the replay store,",
        "    the validator, and the clock. The R1/R7 carve-out and revocation bind",
        "    the approval path, not already-installed root code.",
    ]
    if enrollment["developer_mode"]:
        lines.extend(
            [
                "",
                "DEVELOPER MODE NOTICE (R6):",
                "  - Developer mode enrolls covered signers for THIS host and THIS grant",
                "    only (even if absent from the baseline trust root). A persistent",
                "    developer-mode indicator will remain visible while this grant is active.",
            ]
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Cryptographic device nonce generation (Item 12)
# ---------------------------------------------------------------------------

def generate_device_nonce(num_bytes: int = 24) -> str:
    """Generate a cryptographic random device nonce with >= 128 bits of entropy.

    Uses `os.urandom` exclusively (never a counter, never derived from replay
    store state). Default 24 bytes = 192 bits -> 32 printable ASCII chars.
    """
    if not _is_exact_int(num_bytes) or num_bytes < 16:
        raise ValueError("device nonce requires an exact integer >= 16 bytes (128 bits)")
    token = base64.urlsafe_b64encode(os.urandom(num_bytes)).rstrip(b"=").decode("ascii")
    if not NONCE_RE.match(token):
        raise RuntimeError("generated nonce failed schema alphabet check")
    return token


# ---------------------------------------------------------------------------
# ApprovalEnforcer — complete serialized stateful enforcement engine
# ---------------------------------------------------------------------------

class ApprovalEnforcer:
    """Reference enforcement engine for tendcf v9 consent records on one host.

    Reads and updates the authoritative applied baseline strictly through the
    rollback-protected `ReplayStore` under `self.store.locked()` so independent
    instances sharing one store never diverge or suffer pre-lock TOCTOU races.
    """

    def __init__(
        self,
        host: str,
        store: ReplayStore,
        *,
        apply_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if not isinstance(host, str) or not KEY_ID_RE.match(host):
            raise ValueError(f"invalid host key_id: {host!r}")
        if store.host != host:
            raise ValueError("ReplayStore host does not match ApprovalEnforcer host")
        self.host = host
        self.store = store
        self._apply_callback = apply_callback
        # Diagnostic counters (used by tests to assert Option B zero side effects).
        self.prompt_count: int = 0
        self.actuation_count: int = 0

    @property
    def baseline_goal(self) -> dict[str, Any] | None:
        """Authoritative applied baseline goal file read from the protected store."""
        return self.store.snapshot(allow_voided=True)["applied_baseline_goal"]

    def _check_utc_clock_monotonic(
        self, state: dict[str, Any], now_dt: datetime.datetime
    ) -> None:
        last_str = state.get("last_seen_utc")
        if last_str is not None:
            last_dt = _parse_internal_utc_timestamp(last_str, field="last_seen_utc")
            if now_dt < last_dt:
                raise ClockRollbackError(
                    "utc_clock_rollback",
                    f"UTC clock moved backward: now {format_utc_timestamp(now_dt)} < last_seen {last_str}",
                )

    def _advance_utc_clock(self, state: dict[str, Any], now_dt: datetime.datetime) -> None:
        self._check_utc_clock_monotonic(state, now_dt)
        state["last_seen_utc"] = format_utc_timestamp(now_dt)

    def _is_expired(self, not_after_str: str | None, now_dt: datetime.datetime) -> bool:
        if not_after_str is None:
            return False
        expiry_dt = parse_utc_timestamp(not_after_str, field="not_after")
        return now_dt > expiry_dt

    def _record_observed_expiry_unlocked(
        self, state: dict[str, Any], now_dt: datetime.datetime
    ) -> None:
        """Durably advance `last_seen_utc` on expiry refusal so expiry cannot reverse (Codex #7)."""
        self._advance_utc_clock(state, now_dt)
        self.store.commit_unlocked(state)

    def _required_enrollment_ceremony_rank(self, grant_class: str, developer_mode: bool) -> int:
        base = CEREMONY_RANK[grant_class]
        if developer_mode:
            return max(base, CEREMONY_RANK["privileged"])
        return base

    def _ensure_no_pending_actuation(self, state: dict[str, Any]) -> None:
        if self.store._in_actuation_tx:
            raise ReplayError(
                "nested_mutation_during_actuation",
                "nested enforcer mutation is forbidden inside an actuation callback",
            )
        if state.get("pending_actuation") is not None:
            raise ReplayError(
                "pending_actuation_unreconciled",
                "unreconciled pending actuation exists; call reconcile_pending_actuation() first",
            )

    @staticmethod
    def _new_pending_actuation(
        proposed_sha256: str,
        proposed_goal: dict[str, Any],
        baseline_sha256: str | None,
    ) -> dict[str, Any]:
        return {
            "actuation_id": secrets.token_hex(16),
            "proposed_sha256": proposed_sha256,
            "proposed_goal": copy.deepcopy(proposed_goal),
            "baseline_sha256": baseline_sha256,
        }

    def _actuate_and_publish_baseline_unlocked(
        self,
        proposed_goal: dict[str, Any],
        proposed_sha256: str,
        *,
        before_apply_hook: Callable[[], None] | None = None,
        before_publish_hook: Callable[[], None] | None = None,
    ) -> None:
        """Actuate `proposed_goal` and publish baseline ONLY after callback confirmation (Codex R2/R3; R2-H2).

        Caller has ALREADY durably committed the pre-actuation replay reservation
        together with `pending_actuation` intent before invoking this method.
        - Nested mutations from inside `_apply_callback` are forbidden while
          non-expired read-only calls (`store.snapshot()`, non-expired
          `developer_mode_indicator_active()`) remain allowed.
        - Any exception from `before_apply_hook`, `_apply_callback`, or
          `before_publish_hook` leaves `pending_actuation` durably persisted on
          disk (Codex R3 #1 / Macroscope 4709558270) because a callback failure
          cannot prove the device was left unchanged; subsequent mutating calls
          fail closed until `reconcile_pending_actuation(actuation_id, ...)`
          resolves the exact intent instance.
        """
        if before_apply_hook is not None:
            before_apply_hook()

        self.store._in_actuation_tx = True
        try:
            if self._apply_callback is not None:
                self._apply_callback(copy.deepcopy(proposed_goal))
        finally:
            self.store._in_actuation_tx = False

        # Reload fresh state after callback, publish confirmed baseline, clear pending_actuation.
        fresh = self.store.load_verified_unlocked()
        fresh["applied_baseline_goal"] = copy.deepcopy(proposed_goal)
        fresh["applied_baseline_sha256"] = proposed_sha256
        fresh["pending_actuation"] = None
        fresh["pending_holds"].pop(proposed_sha256, None)
        self.store.commit_unlocked(fresh, before_replace_hook=before_publish_hook)
        self.actuation_count += 1

    def reconcile_pending_actuation(
        self, actuation_id: str, *, applied_on_device: bool
    ) -> dict[str, Any]:
        """Reconcile a specific crash/error-interrupted actuation intent against real device state (Codex R2 #1, R3 #3)."""
        if not isinstance(actuation_id, str) or not actuation_id:
            raise MalformedRecordError(
                "invalid_actuation_id", "actuation_id must be a non-empty string"
            )
        if not _is_exact_bool(applied_on_device):
            raise MalformedRecordError(
                "invalid_reconcile_flag", "applied_on_device must be an exact bool"
            )
        with self.store.locked():
            if self.store._in_actuation_tx:
                raise ReplayError(
                    "nested_mutation_during_actuation",
                    "cannot reconcile pending_actuation from inside an active actuation callback",
                )
            state = self.store.load_verified_unlocked()
            pa = state.get("pending_actuation")
            if pa is None:
                raise ReplayError("no_pending_actuation", "no pending actuation to reconcile")
            if not hmac.compare_digest(pa["actuation_id"], actuation_id):
                raise ReplayError(
                    "actuation_id_mismatch",
                    "reconciliation actuation_id does not match current pending_actuation intent",
                )
            if applied_on_device:
                state["applied_baseline_goal"] = copy.deepcopy(pa["proposed_goal"])
                state["applied_baseline_sha256"] = pa["proposed_sha256"]
                state["pending_holds"].pop(pa["proposed_sha256"], None)
                state["pending_actuation"] = None
                self.store.commit_unlocked(state)
                self.actuation_count += 1
                return {
                    "status": "promoted",
                    "actuation_id": actuation_id,
                    "applied_baseline_sha256": state["applied_baseline_sha256"],
                }
            state["pending_actuation"] = None
            self.store.commit_unlocked(state)
            return {
                "status": "aborted",
                "actuation_id": actuation_id,
                "applied_baseline_sha256": state["applied_baseline_sha256"],
            }

    # ------------------------------------------------------------------
    # Ceremony nonce issuance (Items 2, 12, 22, PR #75 R4 #3 & #5)
    # ------------------------------------------------------------------

    def issue_enrollment_nonce(
        self,
        *,
        grant_id: str,
        mode: str,
        covered_signers: list[str],
        grant_class: str,
        developer_mode: bool,
        ceremony_level: str,
        hold_seconds: int | None = None,
        not_after: str | None = None,
        now_utc: datetime.datetime | str | None = None,
    ) -> str:
        """Issue and durably bind a >=128-bit single-use nonce for an owner enrollment ceremony."""
        if not isinstance(grant_id, str) or not GRANT_ID_RE.match(grant_id):
            raise MalformedRecordError("invalid_grant_id", f"invalid grant_id {grant_id!r}")
        if mode not in STANDING_MODES:
            raise MalformedRecordError("invalid_mode", f"invalid mode {mode!r}")
        if grant_class not in CEREMONY_CLASSES:
            raise MalformedRecordError("invalid_class", f"invalid grant_class {grant_class!r}")
        if ceremony_level not in CEREMONY_CLASSES:
            raise MalformedRecordError(
                "invalid_ceremony_level", f"invalid ceremony_level {ceremony_level!r}"
            )
        if not _is_exact_bool(developer_mode):
            raise MalformedRecordError("invalid_developer_mode", "developer_mode must be bool")
        if mode == "hold-window":
            if not _is_exact_int(hold_seconds) or hold_seconds < 1 or hold_seconds > MAX_SAFE_INT:
                raise MalformedRecordError(
                    "invalid_hold_seconds",
                    "hold-window requires exact integer hold_seconds in 1..2^53-1",
                )
        elif hold_seconds is not None:
            raise MalformedRecordError(
                "unexpected_hold_seconds", "hold_seconds is only allowed for hold-window"
            )
        if (
            not isinstance(covered_signers, list)
            or not covered_signers
            or not all(isinstance(k, str) and KEY_ID_RE.match(k) for k in covered_signers)
            or len(set(covered_signers)) != len(covered_signers)
            or covered_signers != sorted(covered_signers)
        ):
            raise MalformedRecordError(
                "invalid_covered_signers",
                "covered_signers must be a non-empty ascending unique list of key_ids",
            )
        if not_after is not None:
            parse_utc_timestamp(not_after, field="not_after")

        with self.store.locked():
            state = self.store.load_verified_unlocked()
            self._ensure_no_pending_actuation(state)
            if now_utc is not None:
                self._advance_utc_clock(state, _coerce_utc(now_utc))
            nonce = generate_device_nonce()
            while nonce in state["outstanding_nonces"] or nonce in self.store._seen_nonces_memory:
                nonce = generate_device_nonce()
            self.store._seen_nonces_memory.add(nonce)
            state["outstanding_nonces"][nonce] = {
                "record_kind": "standing-enrollment",
                "host": self.host,
                "grant_id": grant_id,
                "mode": mode,
                "covered_signers": list(covered_signers),
                "class": grant_class,
                "developer_mode": developer_mode,
                "hold_seconds": hold_seconds,
                "not_after": not_after,
                "ceremony_level": ceremony_level,
            }
            self.store.commit_unlocked(state)
            return nonce

    def issue_per_change_nonce(
        self,
        *,
        proposed_sha256: str,
        ceremony_class: str,
        now_utc: datetime.datetime | str | None = None,
    ) -> str:
        """Issue and durably bind a >=128-bit single-use nonce for a per-change ceremony."""
        if not isinstance(proposed_sha256, str) or not SHA256_RE.match(proposed_sha256):
            raise MalformedRecordError("invalid_proposed_sha256", "invalid proposed_sha256")
        if ceremony_class not in CEREMONY_CLASSES:
            raise MalformedRecordError("invalid_ceremony_class", f"invalid class {ceremony_class!r}")

        with self.store.locked():
            state = self.store.load_verified_unlocked()
            self._ensure_no_pending_actuation(state)
            if now_utc is not None:
                self._advance_utc_clock(state, _coerce_utc(now_utc))
            nonce = generate_device_nonce()
            while nonce in state["outstanding_nonces"] or nonce in self.store._seen_nonces_memory:
                nonce = generate_device_nonce()
            self.store._seen_nonces_memory.add(nonce)
            state["outstanding_nonces"][nonce] = {
                "record_kind": "per-change",
                "host": self.host,
                "proposed_sha256": proposed_sha256,
                "ceremony_class": ceremony_class,
            }
            self.store.commit_unlocked(state)
            return nonce

    # ------------------------------------------------------------------
    # Persistent developer-mode indicator (Item 9, R6)
    # ------------------------------------------------------------------

    def developer_mode_indicator_active(self, now_utc: datetime.datetime | str) -> bool:
        """True iff at least one active, unexpired developer-mode grant exists on this host.

        Codex R2 #3: if any active grant is observed expired at `now_utc`,
        durably advances `last_seen_utc` (unless running read-only inside an
        actuation callback) so a backward clock cannot resurrect the grant.
        """
        now_dt = _coerce_utc(now_utc)
        with self.store.locked():
            try:
                state = self.store.load_verified_unlocked(allow_voided=True)
            except StoreRollbackError:
                return False
            if state["voided"]:
                return False
            self._check_utc_clock_monotonic(state, now_dt)
            indicator_on = False
            observed_expired = False
            for grant in state["grants"].values():
                if grant.get("grant_state") != "active" or grant.get("tombstoned"):
                    continue
                scope = grant.get("scope") or {}
                expired = self._is_expired(scope.get("not_after"), now_dt)
                if expired:
                    observed_expired = True
                    continue
                if scope.get("developer_mode") is True:
                    indicator_on = True
            if observed_expired:
                if self.store._in_actuation_tx:
                    raise ReplayError(
                        "expiry_observation_during_actuation",
                        "cannot expose observed grant expiry during an actuation callback without persisting watermark",
                    )
                self._record_observed_expiry_unlocked(state, now_dt)
            return indicator_on

    # ------------------------------------------------------------------
    # Standing enrollment & terminal revocation (Items 1, 2, 6, 7, 8-11, 20, 22)
    # ------------------------------------------------------------------

    def process_enrollment(
        self,
        raw_record: bytes | str,
        *,
        now_utc: datetime.datetime | str,
        before_replace_hook: Callable[[], None] | None = None,
        before_anchor_hook: Callable[[], None] | None = None,
        after_commit_hook: Callable[[], None] | None = None,
    ) -> EnrollmentReceipt:
        """Process a `standing-enrollment` (active enrollment, Option B redelivery, or revocation)."""
        now_dt = _coerce_utc(now_utc)
        # Stateless checks outside lock: strict parse, schema shape, host, host!=signer, signature.
        doc = parse_strict_json(raw_record)
        record = validate_approval_record_shape(doc)
        if record["record_kind"] != "standing-enrollment":
            raise MalformedRecordError(
                "wrong_record_kind",
                f"expected standing-enrollment, got {record['record_kind']!r}",
            )
        if record["host"] != self.host:
            raise ScopeError("wrong_host", f"record host {record['host']!r} != {self.host!r}")
        if record["signer"] == self.host:
            raise TrustRootError("host_key_as_signer", "device host key may never sign records")
        verify_record_signature(record)

        grant_id = record["grant_id"]
        generation = record["generation"]
        grant_state = record["grant_state"]

        # ALL stateful checks (store integrity, clock, baseline roles, revocations,
        # Option B equality, nonce consumption) run strictly inside self.store.locked()!
        with self.store.locked():
            state = self.store.load_verified_unlocked()
            self._ensure_no_pending_actuation(state)
            self._check_utc_clock_monotonic(state, now_dt)

            baseline_goal = state["applied_baseline_goal"]
            if baseline_goal is None:
                raise TrustRootError(
                    "no_applied_baseline",
                    "standing-enrollment requires an applied baseline trust root",
                )
            roles = extract_baseline_roles(baseline_goal, self.host)
            if roles.get(record["signer"]) != "owner":
                raise TrustRootError(
                    "signer_not_owner",
                    f"standing-enrollment requires baseline owner role; got {roles.get(record['signer'])!r}",
                )

            if grant_state == "revoked":
                # Item 7 + PR #75 R4 #1: terminal revocation at ANY generation,
                # wins equivocation, accepted for unseen grant_id, owner sig only,
                # nonce-less, ends any pending hold.
                existing = state["grants"].get(grant_id)
                prev_mark = existing["application_seq_mark"] if existing else 0
                prev_gen = existing["generation"] if existing else 0
                state["grants"][grant_id] = {
                    "generation": max(prev_gen, generation),
                    "grant_state": "revoked",
                    "tombstoned": True,
                    "active_payload_jcs_b64": None,
                    "enrollment_nonce": None,
                    "scope": None,
                    "application_seq_mark": prev_mark,
                }
                for prop_hash in [
                    h for h, hold in state["pending_holds"].items() if hold.get("grant_id") == grant_id
                ]:
                    del state["pending_holds"][prop_hash]

                self._advance_utc_clock(state, now_dt)
                self.store.commit_unlocked(
                    state,
                    before_replace_hook=before_replace_hook,
                    before_anchor_hook=before_anchor_hook,
                    after_commit_hook=after_commit_hook,
                )
                return EnrollmentReceipt(
                    status="accepted",
                    host=self.host,
                    grant_id=grant_id,
                    generation=generation,
                    grant_state="revoked",
                )

            # Active enrollment: check expiry (durably advance last_seen_utc so expiry cannot reverse).
            if self._is_expired(record.get("not_after"), now_dt):
                self._record_observed_expiry_unlocked(state, now_dt)
                raise ScopeError("enrollment_expired", "active enrollment is already expired")

            existing = state["grants"].get(grant_id)

            # Item 7 + PR #75 R4 #1: Tombstone is terminal forever.
            if existing is not None and (
                existing.get("tombstoned") is True or existing.get("grant_state") == "revoked"
            ):
                raise ReplayError(
                    "grant_tombstoned",
                    f"grant_id {grant_id!r} is permanently revoked (terminal tombstone)",
                )

            incoming_payload_bytes = signing_payload_bytes(record)

            # Item 6 (Astra Option B, operator ruling 2026-11-26):
            # Verified identical redelivery at generation == stored returns identical
            # receipt with ZERO writes, ZERO mutations, ZERO prompts, ZERO actuation.
            if existing is not None and generation == existing["generation"]:
                if existing.get("grant_state") != "active":
                    raise ReplayError(
                        "grant_not_active",
                        f"grant_id {grant_id!r} at generation {generation} is not live active",
                    )
                stored_b64 = existing.get("active_payload_jcs_b64")
                if not isinstance(stored_b64, str) or not stored_b64:
                    raise ReplayError(
                        "missing_stored_payload",
                        "stored canonical enrollment bytes missing; failing closed on equal generation",
                    )
                try:
                    stored_payload_bytes = base64.b64decode(stored_b64.encode("ascii"), validate=True)
                except Exception as exc:
                    raise ReplayError(
                        "corrupt_stored_payload",
                        f"stored canonical enrollment bytes corrupt: {exc}",
                    ) from exc

                if hmac.compare_digest(incoming_payload_bytes, stored_payload_bytes):
                    return EnrollmentReceipt(
                        status="accepted",
                        host=self.host,
                        grant_id=grant_id,
                        generation=generation,
                        grant_state="active",
                    )
                raise ReplayError(
                    "enrollment_equivocation",
                    f"conflicting active enrollment bytes at stored generation {generation}",
                )

            # Item 20: stale generation (< stored) refused.
            if existing is not None and generation < existing["generation"]:
                raise ReplayError(
                    "stale_generation",
                    f"active enrollment generation {generation} <= stored {existing['generation']}",
                )

            # Validate covered_signers trust rules against current baseline inside lock.
            dev_mode = record["developer_mode"]
            for cs in record["covered_signers"]:
                if cs == self.host:
                    raise TrustRootError(
                        "host_key_in_covered_signers",
                        "device host key may never appear in covered_signers (Item 10)",
                    )
                if roles.get(cs) == "owner":
                    raise TrustRootError(
                        "owner_in_covered_signers",
                        "an owner key may never be listed in covered_signers (even in developer mode)",
                    )
                if not dev_mode and roles.get(cs) != "covered-signer":
                    raise TrustRootError(
                        "untrusted_covered_signer",
                        f"covered signer {cs!r} is not a baseline covered-signer entry",
                    )

            # Item 2 & Item 22 (R3, R6, PR #75 R4 #3):
            nonce = record["nonce"]
            matched_nonce_key: str | None = None
            for k in state["outstanding_nonces"]:
                if hmac.compare_digest(k.encode("utf-8"), nonce.encode("utf-8")):
                    matched_nonce_key = k
                    break
            if matched_nonce_key is None:
                raise NonceError(
                    "unknown_or_consumed_nonce",
                    "enrollment nonce is not an outstanding device-issued ceremony nonce",
                )

            bound = state["outstanding_nonces"][matched_nonce_key]
            if bound.get("record_kind") != "standing-enrollment" or bound.get("host") != self.host:
                raise NonceError(
                    "nonce_scope_mismatch",
                    "nonce was not issued for a standing-enrollment on this host",
                )

            # Compare full shown scope via type-preserving JCS equality (prevents True == 1).
            expected_scope = {
                "grant_id": grant_id,
                "mode": record["mode"],
                "covered_signers": record["covered_signers"],
                "class": record["class"],
                "developer_mode": dev_mode,
                "hold_seconds": record.get("hold_seconds"),
                "not_after": record.get("not_after"),
            }
            for field_name, field_val in expected_scope.items():
                if not jcs_equal(bound.get(field_name), field_val):
                    raise NonceError(
                        "nonce_scope_mismatch",
                        f"enrollment {field_name!r} does not match ceremony-shown scope",
                    )

            ceremony_level = bound.get("ceremony_level")
            if ceremony_level not in CEREMONY_RANK:
                raise NonceError("invalid_ceremony_level", "missing ceremony level on nonce")
            required_rank = self._required_enrollment_ceremony_rank(record["class"], dev_mode)
            if CEREMONY_RANK[ceremony_level] < required_rank:
                raise NonceError(
                    "insufficient_ceremony_level",
                    f"ceremony level {ceremony_level!r} insufficient for class={record['class']!r}, "
                    f"developer_mode={dev_mode}",
                )

            # Atomic install: consume nonce once, preserve application_seq_mark across generations,
            # and prune stranded old-generation pending holds belonging to this grant_id (Neon F9).
            del state["outstanding_nonces"][matched_nonce_key]
            prev_mark = existing["application_seq_mark"] if existing else 0
            for prop_hash in [
                h for h, hold in state["pending_holds"].items() if hold.get("grant_id") == grant_id
            ]:
                del state["pending_holds"][prop_hash]

            state["grants"][grant_id] = {
                "generation": generation,
                "grant_state": "active",
                "tombstoned": False,
                "active_payload_jcs_b64": base64.b64encode(incoming_payload_bytes).decode("ascii"),
                "enrollment_nonce": nonce,
                "scope": {
                    "mode": record["mode"],
                    "covered_signers": list(record["covered_signers"]),
                    "class": record["class"],
                    "developer_mode": dev_mode,
                    "hold_seconds": record.get("hold_seconds"),
                    "not_after": record.get("not_after"),
                },
                "application_seq_mark": prev_mark,
            }

            self._advance_utc_clock(state, now_dt)
            self.store.commit_unlocked(
                state,
                before_replace_hook=before_replace_hook,
                before_anchor_hook=before_anchor_hook,
                after_commit_hook=after_commit_hook,
            )
            self.store.nonce_consume_count += 1

            return EnrollmentReceipt(
                status="accepted",
                host=self.host,
                grant_id=grant_id,
                generation=generation,
                grant_state="active",
            )

    # ------------------------------------------------------------------
    # Precedence helper (Item 19)
    # ------------------------------------------------------------------

    def _resolve_covering_precedence(
        self,
        state: dict[str, Any],
        *,
        signer: str,
        derived_class: str,
        now_dt: datetime.datetime,
        roles: dict[str, str],
    ) -> tuple[str, int | None, bool]:
        """Evaluate every active, unexpired grant covering `(signer, derived_class)`.

        Returns `(effective_mode, longest_hold, observed_expired)` where
        `observed_expired` is True if ANY active grant on the host was observed
        past its `not_after` at `now_dt` (Codex R2 #3).
        """
        winning_mode: str | None = None
        winning_rank = 0
        longest_hold: int | None = None
        observed_expired = False

        for grant in state["grants"].values():
            if grant.get("grant_state") != "active" or grant.get("tombstoned"):
                continue
            scope = grant.get("scope") or {}
            if self._is_expired(scope.get("not_after"), now_dt):
                observed_expired = True
                continue
            if scope.get("class") != derived_class:
                continue
            if signer not in (scope.get("covered_signers") or []):
                continue
            mode = scope.get("mode")
            if mode not in MODE_RESTRICTIVENESS:
                continue
            if not scope.get("developer_mode") and mode in ("standing-approval", "hold-window"):
                if roles.get(signer) != "covered-signer":
                    continue
            rank = MODE_RESTRICTIVENESS[mode]
            if rank > winning_rank:
                winning_rank = rank
                winning_mode = mode
                longest_hold = scope.get("hold_seconds") if mode == "hold-window" else None
            elif rank == winning_rank and mode == "hold-window":
                hs = scope.get("hold_seconds")
                if longest_hold is None or (hs is not None and hs > longest_hold):
                    longest_hold = hs

        if winning_mode is None:
            if observed_expired:
                self._record_observed_expiry_unlocked(state, now_dt)
            raise ScopeError("no_covering_grant", "no active unexpired grant covers this application")
        return winning_mode, longest_hold, observed_expired

    # ------------------------------------------------------------------
    # Standing application intake, hold display confirm & hold completion
    # ------------------------------------------------------------------

    def process_standing_application(
        self,
        raw_record: bytes | str,
        *,
        proposed_goal: dict[str, Any],
        diff: dict[str, Any] | None = None,
        now_utc: datetime.datetime | str,
        now_mono: float | None = None,
        boot_epoch: str | None = None,
        display_confirmed: bool = False,
        is_readoption: bool = False,
        touches_replay_store: bool = False,
        migrate_fn: Callable[[dict[str, Any], int], dict[str, Any]] | None = None,
        device_trust_comparable: bool = False,
        before_replace_hook: Callable[[], None] | None = None,
        before_anchor_hook: Callable[[], None] | None = None,
        before_apply_hook: Callable[[], None] | None = None,
        before_publish_hook: Callable[[], None] | None = None,
    ) -> ApplicationResult:
        """Validate and execute/hold/park a `standing-application`.

        Item 26 + PR #75 R4 #2: EVERY check passes BEFORE `application_seq` is
        persisted. Snapshots caller-owned `proposed_goal` and `diff` at entry
        (Codex R2 #5). All baseline/role/diff/store checks run strictly inside
        `self.store.locked()` (zero TOCTOU).
        """
        proposed_goal = copy.deepcopy(proposed_goal)
        diff = copy.deepcopy(diff) if diff is not None else None

        now_dt = _coerce_utc(now_utc)
        if now_mono is not None:
            validated_mono: float | None = _coerce_mono(now_mono)
        else:
            validated_mono = None
        if display_confirmed:
            if validated_mono is None:
                raise ClockRollbackError(
                    "missing_monotonic_time",
                    "display_confirmed=True requires finite non-negative now_mono",
                )
            validated_epoch: str | None = _validate_boot_epoch(boot_epoch)
        else:
            validated_epoch = _validate_boot_epoch(boot_epoch) if boot_epoch is not None else None

        # Pure stateless checks outside lock.
        doc = parse_strict_json(raw_record)
        record = validate_approval_record_shape(doc)
        if record["record_kind"] != "standing-application":
            raise MalformedRecordError(
                "wrong_record_kind",
                f"expected standing-application, got {record['record_kind']!r}",
            )
        if record["host"] != self.host:
            raise ScopeError("wrong_host", f"record host {record['host']!r} != {self.host!r}")
        if record["signer"] == self.host:
            raise TrustRootError("host_key_as_signer", "device host key may never sign records")
        validate_goal_file_basics(proposed_goal, self.host)
        verify_record_signature(record)

        if is_readoption:
            raise ScopeError(
                "readoption_disallowed",
                "re-adoption is never permitted via standing-application (Item 15)",
            )

        actual_proposed_hash = canonical_sha256(proposed_goal)
        if not hmac.compare_digest(record["proposed_sha256"], actual_proposed_hash):
            raise ScopeError(
                "proposed_sha256_mismatch",
                "application proposed_sha256 does not match proposed goal file (Item 25)",
            )

        signer = record["signer"]
        grant_id = record["grant_id"]
        generation = record["generation"]
        app_seq = record["application_seq"]

        # ALL stateful checks run atomically inside self.store.locked().
        with self.store.locked():
            state = self.store.load_verified_unlocked()
            self._ensure_no_pending_actuation(state)
            self._check_utc_clock_monotonic(state, now_dt)

            baseline_goal = state["applied_baseline_goal"]
            if baseline_goal is None:
                raise ReplayError(
                    "first_adoption_disallowed",
                    "first adoption is never permitted via standing-application (Item 4)",
                )
            current_baseline_hash = state["applied_baseline_sha256"]
            assert current_baseline_hash is not None
            if not hmac.compare_digest(record["baseline_sha256"], current_baseline_hash):
                raise ReplayError(
                    "baseline_sha256_mismatch",
                    "application baseline_sha256 does not match currently applied baseline (Item 4)",
                )

            # Validate caller-supplied preview diff (if any) BEFORE traversal, and verify
            # exact JCS match against the device-computed authoritative diff!
            if diff is not None:
                analyze_diff_classes(diff)
                verify_diff_matches_goals(baseline_goal, proposed_goal, diff, self.host)
            auth_diff = compute_authoritative_diff(baseline_goal, proposed_goal, self.host)
            if diff is not None and not jcs_equal(diff, auth_diff):
                raise ScopeError(
                    "diff_authoritative_mismatch",
                    "caller diff does not match device-computed authoritative diff",
                )

            # Item 13 (R1/R7): default-deny carve-out over device-trust and replay store.
            check_standing_carve_out(auth_diff, touches_replay_store=touches_replay_store)

            # Item 14 + PR #75 R4 #4 + Item 15 + Item 23:
            overall_class, per_item_classes = analyze_diff_classes(auth_diff)
            if len(per_item_classes) != 1:
                raise ScopeError(
                    "mixed_class_application",
                    f"standing-application refuses mixed-class diff: {sorted(per_item_classes)}",
                )
            derived_class = next(iter(per_item_classes))
            assert derived_class == overall_class
            if record["ceremony_class"] != derived_class:
                raise ScopeError(
                    "ceremony_class_mismatch",
                    f"asserted ceremony_class {record['ceremony_class']!r} != derived {derived_class!r}",
                )

            if "version_bump" in auth_diff:
                check_standing_migration_invariants(
                    baseline_goal,
                    proposed_goal,
                    migrate_fn=migrate_fn,
                    device_trust_comparable=device_trust_comparable,
                )

            # Item 8: baseline trust root roles inside lock.
            roles = extract_baseline_roles(baseline_goal, self.host)
            if roles.get(signer) == "owner":
                raise TrustRootError(
                    "owner_cannot_sign_application",
                    "an owner key may never sign a standing-application (even in developer mode)",
                )

            # Item 19: persisted DC-2 reject wins over every grant!
            if actual_proposed_hash in state["persisted_rejects"]:
                raise ReplayError(
                    "persisted_reject_active",
                    "proposed_sha256 has a persisted DC-2 owner reject (wins over all grants)",
                )

            grant = state["grants"].get(grant_id)
            if grant is None:
                raise ReplayError("unknown_grant", f"grant_id {grant_id!r} is not enrolled")
            if grant.get("tombstoned") is True or grant.get("grant_state") != "active":
                raise ReplayError("grant_revoked", f"grant_id {grant_id!r} is revoked/inactive")

            if generation != grant["generation"]:
                raise ReplayError(
                    "generation_mismatch",
                    f"application generation {generation} != stored active {grant['generation']}",
                )

            stored_enonce = grant.get("enrollment_nonce")
            if not isinstance(stored_enonce, str) or not hmac.compare_digest(
                record["enrollment_nonce"].encode("utf-8"), stored_enonce.encode("utf-8")
            ):
                raise NonceError(
                    "enrollment_nonce_mismatch",
                    "application enrollment_nonce does not match stored active enrollment (R10)",
                )

            scope = grant["scope"]
            # Item 17 + Codex #7: record observed expiry durably so backward UTC clock cannot reverse it!
            if self._is_expired(scope.get("not_after"), now_dt):
                self._record_observed_expiry_unlocked(state, now_dt)
                raise ScopeError("grant_expired", f"grant_id {grant_id!r} has expired")

            if scope["class"] != derived_class:
                raise ScopeError(
                    "grant_class_mismatch",
                    f"grant class {scope['class']!r} != derived class {derived_class!r}",
                )

            if signer not in scope["covered_signers"]:
                raise ScopeError(
                    "signer_not_covered",
                    f"signer {signer!r} is not in grant {grant_id!r}'s covered_signers",
                )

            if not scope["developer_mode"] and roles.get(signer) != "covered-signer":
                raise TrustRootError(
                    "signer_not_covered_signer_role",
                    f"signer {signer!r} is not a baseline covered-signer (non-developer grant)",
                )

            effective_mode, effective_hold_seconds, observed_expired = self._resolve_covering_precedence(
                state,
                signer=signer,
                derived_class=derived_class,
                now_dt=now_dt,
                roles=roles,
            )

            if effective_mode == "standing-refusal":
                if observed_expired:
                    self._record_observed_expiry_unlocked(state, now_dt)
                raise ScopeError(
                    "standing_refusal",
                    "a covering active standing-refusal grant refuses this change",
                )

            # Adversary M2: refuse overwriting an existing pending hold BEFORE burning mark!
            if effective_mode == "hold-window" and actual_proposed_hash in state["pending_holds"]:
                if observed_expired:
                    self._record_observed_expiry_unlocked(state, now_dt)
                raise ReplayError(
                    "duplicate_pending_hold",
                    "a pending hold already exists for this proposed_sha256",
                )

            # Item 5 & Item 26: check application_seq AFTER every other check!
            stored_mark = grant["application_seq_mark"]
            if app_seq <= stored_mark:
                if observed_expired:
                    self._record_observed_expiry_unlocked(state, now_dt)
                raise ReplayError(
                    "stale_application_seq",
                    f"application_seq {app_seq} <= stored mark {stored_mark}",
                )

            if effective_mode == "wait-for-user":
                if observed_expired:
                    self._record_observed_expiry_unlocked(state, now_dt)
                return ApplicationResult(
                    decision="parked",
                    host=self.host,
                    grant_id=grant_id,
                    generation=generation,
                    application_seq=app_seq,
                    proposed_sha256=actual_proposed_hash,
                    effective_mode="wait-for-user",
                )

            # Persist application_seq durably BEFORE actuation or starting hold (Item 5).
            grant["application_seq_mark"] = app_seq
            self._advance_utc_clock(state, now_dt)

            if effective_mode == "hold-window":
                assert effective_hold_seconds is not None
                hold_id = f"{grant_id}:{generation}:{app_seq}"
                state["pending_holds"][actual_proposed_hash] = {
                    "hold_id": hold_id,
                    "grant_id": grant_id,
                    "generation": generation,
                    "enrollment_nonce": stored_enonce,
                    "signer": signer,
                    "ceremony_class": derived_class,
                    "baseline_sha256": current_baseline_hash,
                    "proposed_sha256": actual_proposed_hash,
                    "displayed": bool(display_confirmed),
                    "first_shown_mono": validated_mono if display_confirmed else None,
                    "boot_epoch": validated_epoch if display_confirmed else None,
                    "hold_seconds": effective_hold_seconds,
                    "application_seq": app_seq,
                }
                self.store.commit_unlocked(
                    state,
                    before_replace_hook=before_replace_hook,
                    before_anchor_hook=before_anchor_hook,
                )
                if display_confirmed:
                    self.prompt_count += 1
                return ApplicationResult(
                    decision="held",
                    host=self.host,
                    grant_id=grant_id,
                    generation=generation,
                    application_seq=app_seq,
                    proposed_sha256=actual_proposed_hash,
                    effective_mode="hold-window",
                    hold_seconds=effective_hold_seconds,
                    hold_id=hold_id,
                )

            # effective_mode == "standing-approval":
            # Phase A: durably persist replay reservation + pending_actuation intent BEFORE actuation.
            state["pending_actuation"] = self._new_pending_actuation(
                actual_proposed_hash, proposed_goal, current_baseline_hash
            )
            self.store.commit_unlocked(
                state,
                before_replace_hook=before_replace_hook,
                before_anchor_hook=before_anchor_hook,
            )
            # Phase B & C: invoke callback and publish new authoritative baseline ONLY on success.
            self._actuate_and_publish_baseline_unlocked(
                proposed_goal,
                actual_proposed_hash,
                before_apply_hook=before_apply_hook,
                before_publish_hook=before_publish_hook,
            )
            return ApplicationResult(
                decision="applied",
                host=self.host,
                grant_id=grant_id,
                generation=generation,
                application_seq=app_seq,
                proposed_sha256=actual_proposed_hash,
                effective_mode="standing-approval",
            )

    def confirm_hold_displayed(
        self,
        proposed_sha256: str,
        *,
        now_mono: float,
        boot_epoch: str,
    ) -> None:
        """Record trusted UI display confirmation to start a hold window's monotonic timer (Codex #6)."""
        mono = _coerce_mono(now_mono)
        epoch = _validate_boot_epoch(boot_epoch)
        with self.store.locked():
            state = self.store.load_verified_unlocked()
            self._ensure_no_pending_actuation(state)
            hold = state["pending_holds"].get(proposed_sha256)
            if hold is None:
                raise ReplayError(
                    "no_pending_hold",
                    f"no pending hold exists for {proposed_sha256!r}",
                )
            # Allow re-display after a reboot (boot_epoch change), refuse duplicate confirm on same epoch.
            if hold.get("displayed") is True and hold.get("boot_epoch") == epoch:
                raise ReplayError(
                    "hold_already_displayed",
                    f"hold for {proposed_sha256!r} already confirmed displayed in epoch {epoch!r}",
                )
            hold["displayed"] = True
            hold["first_shown_mono"] = mono
            hold["boot_epoch"] = epoch
            self.store.commit_unlocked(state)
            self.prompt_count += 1

    def complete_hold_window(
        self,
        proposed_sha256: str,
        *,
        proposed_goal: dict[str, Any],
        diff: dict[str, Any] | None = None,
        now_utc: datetime.datetime | str,
        now_mono: float,
        boot_epoch: str,
        touches_replay_store: bool = False,
        migrate_fn: Callable[[dict[str, Any], int], dict[str, Any]] | None = None,
        device_trust_comparable: bool = False,
        before_apply_hook: Callable[[], None] | None = None,
        before_publish_hook: Callable[[], None] | None = None,
    ) -> ApplicationResult:
        """Complete a confirmed hold window after monotonic elapsed time, re-evaluating EVERY check."""
        proposed_goal = copy.deepcopy(proposed_goal)
        diff = copy.deepcopy(diff) if diff is not None else None

        now_dt = _coerce_utc(now_utc)
        mono = _coerce_mono(now_mono)
        epoch = _validate_boot_epoch(boot_epoch)
        validate_goal_file_basics(proposed_goal, self.host)

        with self.store.locked():
            state = self.store.load_verified_unlocked()
            self._ensure_no_pending_actuation(state)
            self._check_utc_clock_monotonic(state, now_dt)

            hold = state["pending_holds"].get(proposed_sha256)
            if hold is None:
                raise ReplayError(
                    "no_pending_hold",
                    f"no pending hold exists for {proposed_sha256!r} (cancelled, revoked, or absent)",
                )

            def prune_dead_hold_and_commit() -> None:
                state["pending_holds"].pop(proposed_sha256, None)
                self._advance_utc_clock(state, now_dt)
                self.store.commit_unlocked(state)

            # Codex #6: display MUST be confirmed before hold can ever complete!
            if (
                hold.get("displayed") is not True
                or hold.get("first_shown_mono") is None
                or hold.get("boot_epoch") is None
            ):
                raise ScopeError(
                    "hold_display_unconfirmed",
                    "hold window cannot complete before trusted UI display confirmation",
                )

            # Codex #6 & Macroscope 4709254027: reset display state on reboot so UI can re-show cleanly!
            if hold["boot_epoch"] != epoch:
                prev_epoch = hold["boot_epoch"]
                hold["displayed"] = False
                hold["first_shown_mono"] = None
                hold["boot_epoch"] = None
                self._advance_utc_clock(state, now_dt)
                self.store.commit_unlocked(state)
                raise ClockRollbackError(
                    "monotonic_boot_epoch_mismatch",
                    f"boot_epoch changed during hold ({prev_epoch!r} -> {epoch!r}); display reset, re-show required",
                )

            first_shown = _coerce_mono(hold["first_shown_mono"])
            if mono < first_shown:
                raise ClockRollbackError(
                    "monotonic_clock_rollback",
                    f"monotonic clock moved backward: {mono} < {first_shown}",
                )

            # Re-evaluate EVERY check at apply time (Items 17 & 18):
            if proposed_sha256 in state["persisted_rejects"]:
                prune_dead_hold_and_commit()
                raise ReplayError(
                    "persisted_reject_active",
                    "pending hold stopped by persisted DC-2 reject",
                )

            baseline_goal = state["applied_baseline_goal"]
            current_baseline_hash = state["applied_baseline_sha256"]
            if baseline_goal is None or current_baseline_hash is None:
                prune_dead_hold_and_commit()
                raise ReplayError("no_applied_baseline", "no applied baseline for hold completion")
            if not hmac.compare_digest(hold["baseline_sha256"], current_baseline_hash):
                prune_dead_hold_and_commit()
                raise ReplayError(
                    "baseline_changed_during_hold",
                    "applied baseline changed while change was held (Item 4 / Item 18)",
                )

            actual_prop_hash = canonical_sha256(proposed_goal)
            if not hmac.compare_digest(actual_prop_hash, proposed_sha256):
                raise ScopeError(
                    "proposed_sha256_mismatch",
                    "proposed goal file does not match held proposed_sha256 (Item 25)",
                )

            if diff is not None:
                analyze_diff_classes(diff)
                verify_diff_matches_goals(baseline_goal, proposed_goal, diff, self.host)
            auth_diff = compute_authoritative_diff(baseline_goal, proposed_goal, self.host)
            if diff is not None and not jcs_equal(diff, auth_diff):
                raise ScopeError(
                    "diff_authoritative_mismatch",
                    "caller diff does not match device-computed authoritative diff",
                )
            check_standing_carve_out(auth_diff, touches_replay_store=touches_replay_store)
            overall_class, per_item_classes = analyze_diff_classes(auth_diff)
            if len(per_item_classes) != 1 or overall_class != hold["ceremony_class"]:
                raise ScopeError("class_mismatch_at_hold_apply", "diff class no longer matches hold")
            if "version_bump" in auth_diff:
                check_standing_migration_invariants(
                    baseline_goal,
                    proposed_goal,
                    migrate_fn=migrate_fn,
                    device_trust_comparable=device_trust_comparable,
                )

            grant_id = hold["grant_id"]
            grant = state["grants"].get(grant_id)
            if grant is None or grant.get("tombstoned") or grant.get("grant_state") != "active":
                prune_dead_hold_and_commit()
                raise ReplayError(
                    "grant_inactive_at_hold_apply",
                    f"grant {grant_id!r} is no longer active at hold completion",
                )
            if grant["generation"] != hold["generation"]:
                prune_dead_hold_and_commit()
                raise ReplayError(
                    "generation_changed_during_hold",
                    "grant generation changed while change was held",
                )
            if not hmac.compare_digest(
                str(grant.get("enrollment_nonce") or "").encode("utf-8"),
                str(hold["enrollment_nonce"]).encode("utf-8"),
            ):
                prune_dead_hold_and_commit()
                raise NonceError(
                    "enrollment_nonce_changed_during_hold",
                    "grant enrollment_nonce changed while change was held (R10 / Item 18)",
                )

            scope = grant["scope"]
            # Codex #7: prune dead hold AND durably record observed post-expiry UTC!
            if self._is_expired(scope.get("not_after"), now_dt):
                prune_dead_hold_and_commit()
                raise ScopeError(
                    "grant_expired_at_hold_apply",
                    f"grant {grant_id!r} expired before hold completion (Item 17)",
                )

            roles = extract_baseline_roles(baseline_goal, self.host)
            signer = hold["signer"]
            if roles.get(signer) == "owner":
                prune_dead_hold_and_commit()
                raise TrustRootError("owner_cannot_sign_application", "signer became owner")
            if signer not in scope["covered_signers"]:
                prune_dead_hold_and_commit()
                raise ScopeError("signer_removed_from_grant", "signer no longer covered")
            if not scope["developer_mode"] and roles.get(signer) != "covered-signer":
                prune_dead_hold_and_commit()
                raise TrustRootError(
                    "signer_role_revoked_during_hold",
                    "signer lost baseline covered-signer role during hold",
                )

            effective_mode, effective_hold_seconds, observed_expired = self._resolve_covering_precedence(
                state,
                signer=signer,
                derived_class=hold["ceremony_class"],
                now_dt=now_dt,
                roles=roles,
            )
            if effective_mode == "standing-refusal":
                prune_dead_hold_and_commit()
                raise ScopeError(
                    "standing_refusal_at_hold_apply",
                    "a covering standing-refusal grant now refuses this held change",
                )
            if effective_mode == "wait-for-user":
                if observed_expired:
                    self._record_observed_expiry_unlocked(state, now_dt)
                return ApplicationResult(
                    decision="parked",
                    host=self.host,
                    grant_id=grant_id,
                    generation=hold["generation"],
                    application_seq=hold["application_seq"],
                    proposed_sha256=proposed_sha256,
                    effective_mode="wait-for-user",
                )

            required_hold = max(
                int(hold["hold_seconds"]),
                int(effective_hold_seconds) if effective_hold_seconds is not None else 0,
            )
            elapsed = mono - first_shown
            # Defense in depth against NaN: require `elapsed >= required_hold` explicitly!
            if not (elapsed >= required_hold):
                if observed_expired:
                    self._record_observed_expiry_unlocked(state, now_dt)
                raise ScopeError(
                    "hold_window_not_elapsed",
                    f"hold window elapsed {elapsed:.3f}s < required {required_hold}s",
                )

            # Phase A: remove pending hold, record pending_actuation & UTC durably BEFORE actuating.
            del state["pending_holds"][proposed_sha256]
            state["pending_actuation"] = self._new_pending_actuation(
                proposed_sha256, proposed_goal, current_baseline_hash
            )
            self._advance_utc_clock(state, now_dt)
            self.store.commit_unlocked(state)

            # Phase B & C: actuate & publish new baseline only on callback success.
            self._actuate_and_publish_baseline_unlocked(
                proposed_goal,
                proposed_sha256,
                before_apply_hook=before_apply_hook,
                before_publish_hook=before_publish_hook,
            )
            return ApplicationResult(
                decision="applied",
                host=self.host,
                grant_id=grant_id,
                generation=hold["generation"],
                application_seq=hold["application_seq"],
                proposed_sha256=proposed_sha256,
                effective_mode="hold-window",
                hold_seconds=required_hold,
                hold_id=hold["hold_id"],
            )

    # ------------------------------------------------------------------
    # Per-change owner record evaluation (Items 4, 8, 10, 11, 15, 18, 19, 23-26)
    # ------------------------------------------------------------------

    def process_per_change(
        self,
        raw_record: bytes | str,
        *,
        proposed_goal: dict[str, Any] | None = None,
        diff: dict[str, Any] | None = None,
        now_utc: datetime.datetime | str,
        bootstrap_owner_keys: Collection[str] | None = None,
        is_readoption: bool = False,
        before_replace_hook: Callable[[], None] | None = None,
        before_anchor_hook: Callable[[], None] | None = None,
        before_apply_hook: Callable[[], None] | None = None,
        before_publish_hook: Callable[[], None] | None = None,
    ) -> PerChangeResult:
        """Process an owner `per-change` approval/reject/withdraw record.

        Hardened invariants:
          - Snapshots caller-owned `proposed_goal` and `diff` at entry (Codex R2 #5).
          - All baseline/role/diff/store checks run strictly inside `self.store.locked()`.
          - `verdict == "accept"` ALWAYS requires `proposed_goal is not None`.
          - First adoption (`baseline_goal is None`) requires an explicit non-empty
            `bootstrap_owner_keys` authority (never trusts proposed goal alone).
          - Every adoption/accept checks `proposed_goal["host"] == self.host`,
            `validate_trust_root_no_host_key`, and anti-downgrade `new >= old`
            (and `new > old` on migrations, 2026-11-26 ruling Item 15).
          - Never falls back to `record["ceremony_class"]`; derives class
            authoritatively from `(baseline_goal, proposed_goal)` or verified `diff`
            (requiring `proposed_goal` for non-hold `version_bump` reject/withdraw).
          - Narrow hold-window override reject (Item 18): owner `per-change` `reject`
            naming `(host, proposed_sha256)` stops a pending hold immediately and
            persists as a DC-2 reject regardless of `ceremony_class`, `nonce`, or
            `approval_seq`.
        """
        proposed_goal = copy.deepcopy(proposed_goal) if proposed_goal is not None else None
        diff = copy.deepcopy(diff) if diff is not None else None

        now_dt = _coerce_utc(now_utc)
        # Pure stateless checks outside lock.
        doc = parse_strict_json(raw_record)
        record = validate_approval_record_shape(doc)
        if record["record_kind"] != "per-change":
            raise MalformedRecordError(
                "wrong_record_kind",
                f"expected per-change, got {record['record_kind']!r}",
            )
        if record["host"] != self.host:
            raise ScopeError("wrong_host", f"record host {record['host']!r} != {self.host!r}")
        if record["signer"] == self.host:
            raise TrustRootError("host_key_as_signer", "device host key may never sign records")
        if proposed_goal is not None:
            validate_goal_file_basics(proposed_goal, self.host)
        verify_record_signature(record)

        proposed_sha256 = record["proposed_sha256"]
        verdict = record["verdict"]

        # Codex #4 / Neon F4 / Macroscope 4708874692: accept requires proposed_goal BEFORE state mutation!
        if verdict == "accept" and proposed_goal is None:
            raise MalformedRecordError(
                "missing_proposed_goal", "per-change verdict 'accept' requires proposed_goal"
            )

        with self.store.locked():
            state = self.store.load_verified_unlocked()
            self._ensure_no_pending_actuation(state)
            self._check_utc_clock_monotonic(state, now_dt)

            baseline_goal = state["applied_baseline_goal"]
            is_first_adoption = baseline_goal is None

            # Item 8 & Codex #5: owner role check strictly inside lock!
            if is_first_adoption:
                if proposed_goal is None:
                    raise MalformedRecordError(
                        "missing_proposed_goal", "first adoption requires proposed_goal"
                    )
                if "baseline_sha256" in record:
                    raise ScopeError(
                        "unexpected_baseline_sha256",
                        "first adoption has no prior baseline_sha256",
                    )
                if not bootstrap_owner_keys:
                    raise TrustRootError(
                        "missing_bootstrap_authority",
                        "first adoption requires independently established bootstrap_owner_keys",
                    )
                boot_set = set(bootstrap_owner_keys)
                if self.host in boot_set:
                    raise TrustRootError(
                        "host_key_in_trust_root",
                        "device host key may never be a bootstrap owner (Item 10)",
                    )
                proposed_roles = extract_baseline_roles(proposed_goal, self.host)
                if (
                    record["signer"] not in boot_set
                    or proposed_roles.get(record["signer"]) != "owner"
                ):
                    raise TrustRootError(
                        "signer_not_owner",
                        "first adoption signer must be an authorized bootstrap owner present as owner in proposed trust root",
                    )
            else:
                roles = extract_baseline_roles(baseline_goal, self.host)
                if roles.get(record["signer"]) != "owner":
                    raise TrustRootError(
                        "signer_not_owner",
                        f"per-change record requires baseline owner role; got {roles.get(record['signer'])!r}",
                    )

            # Narrow Item 18 hold-window override reject!
            if verdict == "reject" and proposed_sha256 in state["pending_holds"]:
                hold = state["pending_holds"].pop(proposed_sha256)
                state["persisted_rejects"][proposed_sha256] = {
                    "recorded_utc": format_utc_timestamp(now_dt),
                    "refused": list(record["refused"]),
                    "signer": record["signer"],
                }
                self._advance_utc_clock(state, now_dt)
                self.store.commit_unlocked(
                    state,
                    before_replace_hook=before_replace_hook,
                    before_anchor_hook=before_anchor_hook,
                )
                return PerChangeResult(
                    decision="rejected",
                    host=self.host,
                    proposed_sha256=proposed_sha256,
                    approval_seq=None,
                    cancelled_holds=(hold["hold_id"],),
                )

            # Standard DC-2 per-change checks (ALL pass BEFORE persisting approval_seq!).
            if proposed_goal is not None:
                actual_prop_hash = canonical_sha256(proposed_goal)
                if not hmac.compare_digest(proposed_sha256, actual_prop_hash):
                    raise ScopeError(
                        "proposed_sha256_mismatch",
                        "per-change proposed_sha256 does not match proposed goal file (Item 25)",
                    )

            if is_first_adoption:
                derived_class = "baseline"
            elif is_readoption:
                assert baseline_goal is not None
                if "baseline_sha256" not in record:
                    raise ScopeError(
                        "missing_baseline_sha256",
                        "re-adoption over an existing baseline requires baseline_sha256",
                    )
                current_base_hash = state["applied_baseline_sha256"]
                assert current_base_hash is not None
                if not hmac.compare_digest(record["baseline_sha256"], current_base_hash):
                    raise ReplayError(
                        "baseline_sha256_mismatch",
                        "per-change baseline_sha256 does not match applied baseline",
                    )
                if proposed_goal is None:
                    raise MalformedRecordError(
                        "readoption_requires_proposal",
                        "non-hold per-change re-adoption requires proposed_goal to verify anti-downgrade and exact hash",
                    )
                # Enforce anti-downgrade even on re-adoption (Codex #4 / Macroscope 4708874598).
                if proposed_goal["schema_version"] < baseline_goal["schema_version"]:
                    raise ScopeError(
                        "downward_version_bump",
                        f"refusing downward schema_version {baseline_goal['schema_version']} -> "
                        f"{proposed_goal['schema_version']} during re-adoption",
                    )
                derived_class = "baseline"
            else:
                assert baseline_goal is not None
                if "baseline_sha256" not in record:
                    raise ScopeError(
                        "missing_baseline_sha256",
                        "non-first-adoption per-change record requires baseline_sha256",
                    )
                current_base_hash = state["applied_baseline_sha256"]
                assert current_base_hash is not None
                if not hmac.compare_digest(record["baseline_sha256"], current_base_hash):
                    raise ReplayError(
                        "baseline_sha256_mismatch",
                        "per-change baseline_sha256 does not match applied baseline",
                    )

                if proposed_goal is not None:
                    if diff is not None:
                        analyze_diff_classes(diff)
                        verify_diff_matches_goals(baseline_goal, proposed_goal, diff, self.host)
                    auth_diff = compute_authoritative_diff(baseline_goal, proposed_goal, self.host)
                    if diff is not None and not jcs_equal(diff, auth_diff):
                        raise ScopeError(
                            "diff_authoritative_mismatch",
                            "caller diff does not match device-computed authoritative diff",
                        )
                    # Adversary C5: version_bump alone must differ in schema_version ONLY!
                    if "version_bump" in auth_diff:
                        base_body = {k: v for k, v in baseline_goal.items() if k != "schema_version"}
                        prop_body = {k: v for k, v in proposed_goal.items() if k != "schema_version"}
                        if not jcs_equal(base_body, prop_body):
                            raise ScopeError(
                                "migration_not_version_only",
                                "version_bump alters content beyond schema_version; requires is_readoption=True",
                            )
                    derived_class, _ = analyze_diff_classes(auth_diff)
                else:
                    # reject / withdraw without proposed_goal: MUST supply verified diff (never trust record!).
                    if diff is None:
                        raise MalformedRecordError(
                            "missing_diff_or_proposal",
                            "non-hold per-change record requires proposed_goal or verified diff to derive ceremony_class",
                        )
                    derived_class, _ = analyze_diff_classes(diff)
                    if diff["host"] != self.host:
                        raise ScopeError("diff_host_mismatch", "diff host does not match device host")
                    if not hmac.compare_digest(diff["baseline_sha256"], current_base_hash):
                        raise ReplayError("diff_baseline_hash_mismatch", "diff baseline_sha256 != baseline hash")
                    if not hmac.compare_digest(diff["proposed_sha256"], proposed_sha256):
                        raise ScopeError("diff_proposed_hash_mismatch", "diff proposed_sha256 != record proposed_sha256")
                    if "version_bump" in diff:
                        # Codex R2 #6 / Adversary R2-L1 #1: require proposed_goal for version_bump
                        # reject/withdraw so migration content & hashes are verified authoritatively.
                        raise MalformedRecordError(
                            "version_bump_requires_proposal",
                            "non-hold per-change reject/withdraw with version_bump requires proposed_goal",
                        )
                    applied = _apply_validated_diff_to_baseline(baseline_goal, diff)
                    if not hmac.compare_digest(canonical_sha256(applied), proposed_sha256):
                        raise ScopeError(
                            "diff_apply_mismatch",
                            "applying diff to baseline does not match record proposed_sha256",
                        )

            # Item 23: asserted ceremony_class must equal derived class exactly.
            if record["ceremony_class"] != derived_class:
                raise ScopeError(
                    "ceremony_class_mismatch",
                    f"asserted ceremony_class {record['ceremony_class']!r} != derived {derived_class!r}",
                )

            # PR #75 R4 #5: per-change nonce bound to (host, proposed_sha256, ceremony_class).
            nonce = record["nonce"]
            matched_nonce_key: str | None = None
            for k in state["outstanding_nonces"]:
                if hmac.compare_digest(k.encode("utf-8"), nonce.encode("utf-8")):
                    matched_nonce_key = k
                    break
            if matched_nonce_key is None:
                raise NonceError(
                    "unknown_or_consumed_nonce",
                    "per-change nonce is not an outstanding device-issued nonce",
                )
            bound = state["outstanding_nonces"][matched_nonce_key]
            if (
                bound.get("record_kind") != "per-change"
                or bound.get("host") != self.host
                or bound.get("proposed_sha256") != proposed_sha256
                or bound.get("ceremony_class") != derived_class
            ):
                raise NonceError(
                    "nonce_scope_mismatch",
                    "per-change nonce does not match (host, proposed_sha256, ceremony_class)",
                )

            # DC-2 monotonic approval_seq check (AFTER every other check!).
            seq = record["approval_seq"]
            if seq <= state["approval_seq"]:
                raise ReplayError(
                    "stale_approval_seq",
                    f"approval_seq {seq} <= stored {state['approval_seq']}",
                )

            # Consume nonce & persist approval_seq durably BEFORE actuation.
            del state["outstanding_nonces"][matched_nonce_key]
            state["approval_seq"] = seq
            cancelled_holds: list[str] = []

            if verdict == "reject":
                if proposed_sha256 in state["pending_holds"]:
                    cancelled_holds.append(state["pending_holds"].pop(proposed_sha256)["hold_id"])
                state["persisted_rejects"][proposed_sha256] = {
                    "recorded_utc": format_utc_timestamp(now_dt),
                    "refused": list(record["refused"]),
                    "signer": record["signer"],
                }
                self._advance_utc_clock(state, now_dt)
                self.store.commit_unlocked(
                    state,
                    before_replace_hook=before_replace_hook,
                    before_anchor_hook=before_anchor_hook,
                )
                self.store.nonce_consume_count += 1
                return PerChangeResult(
                    decision="rejected",
                    host=self.host,
                    proposed_sha256=proposed_sha256,
                    approval_seq=seq,
                    cancelled_holds=tuple(cancelled_holds),
                )

            if verdict == "withdraw":
                self._advance_utc_clock(state, now_dt)
                self.store.commit_unlocked(
                    state,
                    before_replace_hook=before_replace_hook,
                    before_anchor_hook=before_anchor_hook,
                )
                self.store.nonce_consume_count += 1
                return PerChangeResult(
                    decision="withdrawn",
                    host=self.host,
                    proposed_sha256=proposed_sha256,
                    approval_seq=seq,
                )

            # verdict == "accept":
            assert proposed_goal is not None
            state["persisted_rejects"].pop(proposed_sha256, None)
            if proposed_sha256 in state["pending_holds"]:
                cancelled_holds.append(state["pending_holds"].pop(proposed_sha256)["hold_id"])
            state["pending_actuation"] = self._new_pending_actuation(
                proposed_sha256, proposed_goal, state["applied_baseline_sha256"]
            )
            self._advance_utc_clock(state, now_dt)
            # Phase A: commit replay reservation + pending_actuation intent BEFORE actuation.
            self.store.commit_unlocked(
                state,
                before_replace_hook=before_replace_hook,
                before_anchor_hook=before_anchor_hook,
            )
            self.store.nonce_consume_count += 1

            # Phase B & C: actuate & publish confirmed baseline only on callback success.
            self._actuate_and_publish_baseline_unlocked(
                proposed_goal,
                proposed_sha256,
                before_apply_hook=before_apply_hook,
                before_publish_hook=before_publish_hook,
            )
            return PerChangeResult(
                decision="applied",
                host=self.host,
                proposed_sha256=proposed_sha256,
                approval_seq=seq,
                cancelled_holds=tuple(cancelled_holds),
            )


__all__ = [
    "ALLOWED_STANDING_DEVICE_TRUST_KINDS",
    "AnchorState",
    "ApplicationResult",
    "ApprovalEnforcer",
    "CEREMONY_CLASSES",
    "CEREMONY_RANK",
    "ClockRollbackError",
    "DIFF_COVERAGE_VALUES",
    "ED25519_D",
    "ED25519_L",
    "ED25519_P",
    "EnforcementError",
    "EnrollmentReceipt",
    "FileRollbackAnchor",
    "GOAL_COVERAGE_VALUES",
    "InMemoryRollbackAnchor",
    "MAX_SAFE_INT",
    "MalformedRecordError",
    "NonceError",
    "PerChangeResult",
    "ReplayError",
    "ReplayStore",
    "RollbackAnchor",
    "SUPPORTED_SCHEMA_VERSION",
    "ScopeError",
    "SignatureError",
    "StoreRollbackError",
    "TRUST_DOMAIN",
    "TrustRootError",
    "analyze_diff_classes",
    "canonical_sha256",
    "check_standing_carve_out",
    "check_standing_migration_invariants",
    "compute_authoritative_diff",
    "derive_coverage_change_class",
    "derive_hunk_class",
    "ed25519_decompress_point",
    "extract_baseline_roles",
    "format_utc_timestamp",
    "generate_device_nonce",
    "jcs_dumps",
    "jcs_equal",
    "key_id_from_pubkey",
    "parse_strict_json",
    "parse_utc_timestamp",
    "render_enrollment_briefing",
    "signing_payload_bytes",
    "validate_approval_record_shape",
    "validate_goal_file_basics",
    "validate_trust_root_no_host_key",
    "verify_diff_matches_goals",
    "verify_ed25519",
    "verify_record_signature",
]
