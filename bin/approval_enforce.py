#!/usr/bin/env python3
"""Pure-stdlib reference enforcement engine for tendcf v9 approval records (issue #76).

Runs under `python3 -I -S` with zero third-party packages, matching
`bin/projector.py`'s bare-host stdlib guarantee.

Implements:
  - Strict JSON parsing (duplicate-key rejection, NaN/Infinity rejection, NFC check)
    and RFC 8785 JCS canonicalization reused directly from `bin/projector.py`.
  - Pure-stdlib RFC 8032 Ed25519 verification (and signing helper) with strict
    canonical encodings (`0 <= S < L`, canonical public key `A` and `R` with
    `y < p` and `(x == 0 && sign == 1)` rejected, exact equation `[S]B == R + [k]A`).
  - Rollback-protected durable `ReplayStore` with atomic file writes
    (`mkstemp` + `fsync` + `os.replace` + dir `fsync`), advisory file + thread
    locking, and a pluggable `RollbackAnchor` storing `(store_generation, store_sha256)`
    outside the store file.
  - Full enforcement semantics for `per-change`, `standing-enrollment` (active &
    terminal revocation), and `standing-application` covering all 26 items in
    frdminc/tendcf#76, PR #75 R4 items 1-5, Astra Option B (identical active
    enrollment redelivery with zero writes/side effects), and the 2026-11-26
    operator rulings (Item 6 Option B, Item 15 downward version_bump refusal for
    both standing-application and per-change, Item 17 no horizon cap with strict
    calendar parsing and clock-rollback fail-closed).
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
import os
import re
import tempfile
import threading
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator


# ---------------------------------------------------------------------------
# Load bin/projector.py for shared pure-stdlib RFC 8785 JCS canonicalization
# ---------------------------------------------------------------------------

def _load_projector_module() -> Any:
    proj_path = Path(__file__).resolve().with_name("projector.py")
    spec = importlib.util.spec_from_file_location("_tendcf_projector_jcs", proj_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load projector module at {proj_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
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

KEY_ID_RE = re.compile(r"^ed25519:[0-9a-f]{64}\Z")
ED25519_SIG_RE = re.compile(r"^ed25519-sig:[0-9a-f]{128}\Z")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}\Z")
GRANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}\Z")
NONCE_RE = re.compile(r"^[!-~]{22,128}\Z")
UTC_TS_RE = re.compile(
    r"^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])Z\Z"
)

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
    """UTC or monotonic clock moved backward (fail closed)."""


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
# Strict JSON parsing, NFC validation, and JCS canonicalization
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
# Pure-stdlib RFC 8032 Ed25519 with strict canonical encodings (Item 11)
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


def ed25519_compress_point(pt: _Point) -> bytes:
    """Encode a point into 32 little-endian canonical bytes (RFC 8032 §5.1.2)."""
    z_inv = pow(pt[2], ED25519_P - 2, ED25519_P)
    x = (pt[0] * z_inv) % ED25519_P
    y = (pt[1] * z_inv) % ED25519_P
    encoded = y | ((x & 1) << 255)
    return encoded.to_bytes(32, "little")


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


def ed25519_public_key_from_seed(seed: bytes) -> bytes:
    """Derive 32-byte Ed25519 public key from 32-byte secret seed (RFC 8032 §5.1.5)."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    a_bytes = bytearray(digest[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a = int.from_bytes(a_bytes, "little")
    return ed25519_compress_point(_point_mul(a, _BASE_POINT))


def ed25519_sign(seed: bytes, msg_bytes: bytes) -> bytes:
    """Produce a 64-byte RFC 8032 pure Ed25519 signature (RFC 8032 §5.1.6)."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    if not isinstance(msg_bytes, (bytes, bytearray)):
        raise ValueError("message must be bytes")
    digest = hashlib.sha512(seed).digest()
    a_bytes = bytearray(digest[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a = int.from_bytes(a_bytes, "little")
    prefix = digest[32:]
    pub = ed25519_compress_point(_point_mul(a, _BASE_POINT))

    r = int.from_bytes(hashlib.sha512(prefix + msg_bytes).digest(), "little") % ED25519_L
    r_bytes = ed25519_compress_point(_point_mul(r, _BASE_POINT))
    k = (
        int.from_bytes(hashlib.sha512(r_bytes + pub + msg_bytes).digest(), "little")
        % ED25519_L
    )
    s = (r + k * a) % ED25519_L
    return r_bytes + s.to_bytes(32, "little")


def verify_ed25519(pubkey_bytes: bytes, msg_bytes: bytes, sig_bytes: bytes) -> bool:
    """Strictly verify RFC 8032 pure Ed25519 signature with canonical encodings.

    Enforces:
      - `len(pubkey_bytes) == 32`, `len(sig_bytes) == 64`
      - `0 <= S < L` (non-malleable scalar)
      - Canonical public key `A` (`y < p`, reject `x == 0 && sign == 1`)
      - Canonical `R` (`y < p`, reject `x == 0 && sign == 1`)
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
    # Reject small-order public keys (order dividing 8, including the identity
    # point (0, 1) which would otherwise satisfy [0]B == O + [k]O for any msg).
    if _point_equal(_point_mul(8, pt_a), _NEUTRAL_POINT):
        return False
    pt_r = ed25519_decompress_point(r_bytes)
    if pt_r is None:
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


def sign_approval_record(record_without_sig: dict[str, Any], seed: bytes) -> dict[str, Any]:
    """Return a copy of `record_without_sig` signed under pure Ed25519 over JCS bytes."""
    unsigned = {k: copy.deepcopy(v) for k, v in record_without_sig.items() if k != "signature"}
    payload = jcs_dumps(unsigned)
    sig = ed25519_sign(seed, payload)
    signed = dict(unsigned)
    signed["signature"] = "ed25519-sig:" + sig.hex()
    return signed


def verify_record_signature(record: dict[str, Any]) -> None:
    """Verify X-trust-06 algorithm binding and strict canonical pure Ed25519 signature."""
    sig_alg = record.get("sig_alg")
    signer = record.get("signer")
    signature = record.get("signature")

    if not isinstance(sig_alg, str) or sig_alg not in SUPPORTED_SIG_ALGS:
        raise SignatureError("unsupported_sig_alg", f"unsupported sig_alg {sig_alg!r}")
    if not isinstance(signer, str) or not isinstance(signature, str):
        raise SignatureError("malformed_signature_fields", "signer and signature must be strings")

    # Enforce strict sig_alg <-> signer prefix <-> signature prefix agreement (Item 11).
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
# Strict UTC timestamp parsing (Item 17 — no horizon cap, strict calendar)
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


def format_utc_timestamp(dt: datetime.datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware UTC")
    utc = dt.astimezone(datetime.timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def _coerce_utc(now_utc: datetime.datetime | str) -> datetime.datetime:
    if isinstance(now_utc, str):
        return parse_utc_timestamp(now_utc, field="now_utc")
    if isinstance(now_utc, datetime.datetime):
        if now_utc.tzinfo is None:
            raise ValueError("now_utc must be timezone-aware")
        return now_utc.astimezone(datetime.timezone.utc).replace(microsecond=0)
    raise TypeError("now_utc must be a timezone-aware datetime or UTC ISO string")


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

    # Note: sig_alg / signer / signature prefix agreement is checked in
    # verify_record_signature() so algorithm mismatches raise SignatureError
    # cleanly as Item 11 requires.

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
# Rollback-protected durable ReplayStore & RollbackAnchor (Item 1, R3)
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class AnchorState:
    store_generation: int
    store_sha256: str


class RollbackAnchor:
    """Abstract monotonic anchor stored outside the replay store file."""

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
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.tmp-")
    tmp_path = Path(tmp_name)
    try:
        try:
            os.write(fd, data)
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
    """Separate file-backed monotonic rollback anchor."""

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
            or not _is_exact_int(doc.get("store_generation"))
            or not isinstance(doc.get("store_sha256"), str)
        ):
            raise StoreRollbackError("anchor_corrupt", "rollback anchor has invalid shape")
        return AnchorState(
            store_generation=doc["store_generation"],
            store_sha256=doc["store_sha256"],
        )

    def write(self, state: AnchorState) -> None:
        payload = jcs_dumps(
            {
                "store_generation": state.store_generation,
                "store_sha256": state.store_sha256,
            }
        )
        _atomic_write_file(self.path, payload)


def _fresh_store_state(host: str, *, store_generation: int = 0) -> dict[str, Any]:
    return {
        "store_version": 1,
        "host": host,
        "store_generation": store_generation,
        "voided": False,
        "void_reason": None,
        "approval_seq": -1,
        "last_seen_utc": None,
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
        "persisted_rejects",
        "outstanding_nonces",
        "grants",
        "pending_holds",
    }
    if not required.issubset(doc):
        raise StoreRollbackError(
            "store_corrupt", f"replay store missing keys: {sorted(required - set(doc))}"
        )
    if doc["store_version"] != 1:
        raise StoreRollbackError("store_corrupt", f"unsupported store_version {doc['store_version']!r}")
    if doc["host"] != expected_host:
        raise StoreRollbackError("store_host_mismatch", "replay store belongs to a different host")
    if not _is_exact_int(doc["store_generation"]) or doc["store_generation"] < 0:
        raise StoreRollbackError("store_corrupt", "invalid store_generation")
    if not _is_exact_bool(doc["voided"]):
        raise StoreRollbackError("store_corrupt", "invalid voided flag")
    if not _is_exact_int(doc["approval_seq"]) or doc["approval_seq"] < -1:
        raise StoreRollbackError("store_corrupt", "invalid approval_seq")
    for dict_key in ("persisted_rejects", "outstanding_nonces", "grants", "pending_holds"):
        if not isinstance(doc[dict_key], dict):
            raise StoreRollbackError("store_corrupt", f"store field {dict_key!r} is not an object")
    return doc


class ReplayStore:
    """Serialized, rollback-protected, atomically persisted replay store per host."""

    def __init__(
        self,
        store_path: Path | str,
        host: str,
        anchor: RollbackAnchor | None = None,
    ) -> None:
        if not isinstance(host, str) or not KEY_ID_RE.match(host):
            raise ValueError(f"invalid host key_id: {host!r}")
        self.store_path = Path(store_path)
        self.lock_path = Path(str(self.store_path) + ".lock")
        self.host = host
        self.anchor: RollbackAnchor = (
            anchor if anchor is not None else FileRollbackAnchor(str(self.store_path) + ".anchor")
        )
        self._thread_lock = threading.RLock()
        self.write_count: int = 0
        self.nonce_consume_count: int = 0
        self._seen_nonces_memory: set[str] = set()

        # Initialize fresh store if neither store file nor anchor exists.
        with self.locked():
            anchor_state = self.anchor.read()
            if not self.store_path.exists() and anchor_state is None:
                initial = _fresh_store_state(self.host, store_generation=0)
                self._commit_unlocked(initial, count_write=False)

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Acquire both in-process RLock and cross-process advisory flock."""
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with self._thread_lock:
            lock_fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def _fail_closed_void_unlocked(
        self,
        reason: str,
        *,
        anchor_gen: int = 0,
        existing_doc: dict[str, Any] | None = None,
    ) -> None:
        """Void all standing grants, pending holds, and outstanding nonces on rollback/loss.

        Preserves any tombstones, persisted_rejects, approval_seq, and last_seen_utc
        that could still be read safely, and persists the voided state with an
        incremented generation so restarts stay fail-closed until explicit recovery.
        """
        next_gen = max(
            anchor_gen,
            existing_doc["store_generation"]
            if isinstance(existing_doc, dict) and _is_exact_int(existing_doc.get("store_generation"))
            else 0,
        ) + 1
        voided_state = _fresh_store_state(self.host, store_generation=next_gen)
        voided_state["voided"] = True
        voided_state["void_reason"] = reason
        if isinstance(existing_doc, dict):
            if _is_exact_int(existing_doc.get("approval_seq")):
                voided_state["approval_seq"] = existing_doc["approval_seq"]
            if isinstance(existing_doc.get("last_seen_utc"), str):
                voided_state["last_seen_utc"] = existing_doc["last_seen_utc"]
            if isinstance(existing_doc.get("persisted_rejects"), dict):
                voided_state["persisted_rejects"] = copy.deepcopy(existing_doc["persisted_rejects"])
            if isinstance(existing_doc.get("grants"), dict):
                # Never delete tombstones (Item 1 / Item 7).
                for gid, g in existing_doc["grants"].items():
                    if isinstance(g, dict) and g.get("tombstoned") is True:
                        voided_state["grants"][gid] = copy.deepcopy(g)
        self._commit_unlocked(voided_state, count_write=True)

    def load_verified_unlocked(self, *, allow_voided: bool = False) -> dict[str, Any]:
        """Load store and verify against RollbackAnchor; fail closed on any discrepancy."""
        anchor_state = self.anchor.read()
        if not self.store_path.exists():
            if anchor_state is not None:
                self._fail_closed_void_unlocked(
                    "store file missing while rollback anchor exists",
                    anchor_gen=anchor_state.store_generation,
                )
                raise StoreRollbackError(
                    "store_missing_rollback",
                    "replay store missing while rollback anchor exists; all standing grants voided",
                )
            raise StoreRollbackError(
                "store_uninitialized", "replay store and anchor both missing"
            )

        if anchor_state is None:
            self._fail_closed_void_unlocked("rollback anchor missing for existing store")
            raise StoreRollbackError(
                "anchor_missing",
                "rollback anchor missing while store exists; all standing grants voided",
            )

        try:
            raw = self.store_path.read_bytes()
        except OSError as exc:
            self._fail_closed_void_unlocked(
                f"store unreadable: {exc}", anchor_gen=anchor_state.store_generation
            )
            raise StoreRollbackError("store_unreadable", str(exc)) from exc

        actual_sha = hashlib.sha256(raw).hexdigest()
        try:
            doc = parse_strict_json(raw)
            doc = _validate_store_shape(doc, self.host)
        except (MalformedRecordError, StoreRollbackError) as exc:
            self._fail_closed_void_unlocked(
                f"store corrupt: {exc}", anchor_gen=anchor_state.store_generation
            )
            raise StoreRollbackError(
                "store_corrupt", f"replay store corrupted/truncated: {exc}"
            ) from exc

        if (
            doc["store_generation"] != anchor_state.store_generation
            or actual_sha != anchor_state.store_sha256
        ):
            self._fail_closed_void_unlocked(
                "rollback or partial restore detected (anchor mismatch)",
                anchor_gen=anchor_state.store_generation,
                existing_doc=doc,
            )
            raise StoreRollbackError(
                "store_rollback_detected",
                "replay store does not match rollback anchor; all standing grants and nonces voided",
            )

        if doc["voided"] and not allow_voided:
            raise StoreRollbackError(
                "store_voided",
                f"replay store is voided ({doc['void_reason']}); fresh owner recovery required",
            )

        return doc

    def _commit_unlocked(
        self,
        state: dict[str, Any],
        *,
        before_replace_hook: Callable[[], None] | None = None,
        after_commit_hook: Callable[[], None] | None = None,
        count_write: bool = True,
    ) -> None:
        raw = jcs_dumps(state)
        digest = hashlib.sha256(raw).hexdigest()
        _atomic_write_file(self.store_path, raw, before_replace_hook=before_replace_hook)
        self.anchor.write(AnchorState(store_generation=state["store_generation"], store_sha256=digest))
        if count_write:
            self.write_count += 1
        if after_commit_hook is not None:
            after_commit_hook()

    def commit_unlocked(
        self,
        state: dict[str, Any],
        *,
        before_replace_hook: Callable[[], None] | None = None,
        after_commit_hook: Callable[[], None] | None = None,
    ) -> None:
        state["store_generation"] = state["store_generation"] + 1
        self._commit_unlocked(
            state,
            before_replace_hook=before_replace_hook,
            after_commit_hook=after_commit_hook,
            count_write=True,
        )

    def snapshot(self, *, allow_voided: bool = True) -> dict[str, Any]:
        """Return a deep copy of the verified store state for read-only inspection."""
        with self.locked():
            return copy.deepcopy(self.load_verified_unlocked(allow_voided=allow_voided))

    def recover_after_store_loss(self) -> None:
        """Owner-initiated recovery after rollback/store-loss voiding.

        Clears the `voided` flag while keeping all standing grants empty, all
        old nonces cleared, and preserving any surviving tombstones and DC-2
        rejects. Subsequent enrollments require fresh owner ceremonies with
        fresh 128-bit+ OS-random nonces.
        """
        with self.locked():
            state = self.load_verified_unlocked(allow_voided=True)
            state["voided"] = False
            state["void_reason"] = None
            state["outstanding_nonces"] = {}
            state["pending_holds"] = {}
            # Retain tombstones only; active grants were already voided.
            state["grants"] = {
                gid: g for gid, g in state["grants"].items() if g.get("tombstoned") is True
            }
            self.commit_unlocked(state)


# ---------------------------------------------------------------------------
# Diff derivation, carve-out, migration, and trust-root helpers
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
    """Derive ceremony class for a single domain coverage transition (§4.3)."""
    if "deliberately-unmanaged" in (old, new):
        return "privileged"
    if old == "comprehensive" and new != "comprehensive":
        return "privileged"
    return "ordinary"


def analyze_diff_classes(diff: dict[str, Any]) -> tuple[str, set[str]]:
    """Return `(overall_derived_class, per_item_classes)` for `diff`.

    Also validates structural invariants: `version_bump` forbids `hunks` and
    `coverage_changes`, non-migration diffs must have at least one hunk or
    coverage change, and downward/equal `version_bump` (`new <= old`) is
    refused unconditionally (2026-11-26 operator ruling, Item 15).
    """
    if not isinstance(diff, dict):
        raise MalformedRecordError("invalid_diff", "goal diff must be an object")

    has_bump = "version_bump" in diff
    hunks = diff.get("hunks")
    cov = diff.get("coverage_changes")

    if has_bump:
        if hunks is not None or cov is not None:
            raise ScopeError(
                "migration_not_empty",
                "version_bump diff must carry neither hunks nor coverage_changes",
            )
        bump = diff["version_bump"]
        if not isinstance(bump, dict):
            raise MalformedRecordError("invalid_version_bump", "version_bump must be an object")
        old_v, new_v = bump.get("old"), bump.get("new")
        if not _is_exact_int(old_v) or not _is_exact_int(new_v) or old_v < 1 or new_v < 1:
            raise MalformedRecordError("invalid_version_bump", "version_bump old/new must be positive ints")
        # Operator ruling 2026-11-26 (Item 15): refuse downward or equal bump for BOTH
        # standing-application and per-change owner records (fail-closed anti-downgrade).
        if new_v <= old_v:
            raise ScopeError(
                "downward_version_bump",
                f"refusing version_bump with new ({new_v}) <= old ({old_v})",
            )
        return "baseline", {"baseline"}

    per_item: set[str] = set()
    if hunks is not None:
        if not isinstance(hunks, dict) or not hunks:
            raise MalformedRecordError("invalid_hunks", "hunks must be a non-empty object")
        for domain_name, kinds in hunks.items():
            if not isinstance(kinds, dict) or not kinds:
                raise MalformedRecordError("invalid_hunks", f"hunks/{domain_name} must be non-empty")
            for kind_name, ids in kinds.items():
                if not isinstance(ids, dict) or not ids:
                    raise MalformedRecordError(
                        "invalid_hunks", f"hunks/{domain_name}/{kind_name} must be non-empty"
                    )
                for _entry_id, hunk in ids.items():
                    if not isinstance(hunk, dict) or ("old" not in hunk and "new" not in hunk):
                        raise MalformedRecordError("invalid_hunk", "hunk must have old and/or new")
                    per_item.add(derive_hunk_class(domain_name, kind_name))

    if cov is not None:
        if not isinstance(cov, dict) or not cov:
            raise MalformedRecordError(
                "invalid_coverage_changes", "coverage_changes must be a non-empty object"
            )
        for domain_name, change in cov.items():
            if not isinstance(change, dict) or "old" not in change or "new" not in change:
                raise MalformedRecordError(
                    "invalid_coverage_change", f"coverage_changes/{domain_name} missing old/new"
                )
            if change["old"] == change["new"]:
                raise ScopeError(
                    "noop_coverage_change",
                    f"coverage_changes/{domain_name} states identical old and new",
                )
            per_item.add(derive_coverage_change_class(change["old"], change["new"]))

    if not per_item:
        raise MalformedRecordError("empty_diff", "goal diff has no version_bump, hunks, or coverage_changes")

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


def verify_diff_matches_goals(
    baseline_goal: dict[str, Any],
    proposed_goal: dict[str, Any],
    diff: dict[str, Any],
    host: str,
) -> None:
    """Verify diff host, hashes, and that applying diff to baseline reproduces proposed."""
    if diff.get("host") != host:
        raise ScopeError("diff_host_mismatch", "diff host does not match device host")
    if baseline_goal.get("host") != host:
        raise ScopeError("baseline_host_mismatch", "baseline goal host does not match device host")
    if proposed_goal.get("host") != host:
        raise ScopeError("proposed_host_mismatch", "proposed goal host does not match device host")

    actual_base_hash = canonical_sha256(baseline_goal)
    actual_prop_hash = canonical_sha256(proposed_goal)
    if diff.get("baseline_sha256") != actual_base_hash:
        raise ReplayError("diff_baseline_hash_mismatch", "diff baseline_sha256 != baseline hash")
    if diff.get("proposed_sha256") != actual_prop_hash:
        raise ScopeError("diff_proposed_hash_mismatch", "diff proposed_sha256 != proposed hash")

    if "version_bump" in diff:
        bump = diff["version_bump"]
        if baseline_goal.get("schema_version") != bump["old"]:
            raise ScopeError(
                "version_bump_old_mismatch",
                "baseline schema_version does not match version_bump.old",
            )
        if proposed_goal.get("schema_version") != bump["new"]:
            raise ScopeError(
                "version_bump_new_mismatch",
                "proposed schema_version does not match version_bump.new",
            )
        return

    # Non-migration diff: apply hunks & coverage changes to baseline and verify
    # exact canonical match with proposed_goal (stops lying `old` downgrade!).
    result = copy.deepcopy(baseline_goal)
    baseline_domains = baseline_goal.get("domains") or {}
    domains = result.setdefault("domains", {})

    for domain_name, kinds in (diff.get("hunks") or {}).items():
        domain = domains.setdefault(domain_name, {})
        entries = domain.setdefault("entries", {})
        for kind_name, ids in kinds.items():
            bucket = entries.setdefault(kind_name, {})
            for entry_id, hunk in ids.items():
                if "old" in hunk and "new" in hunk and hunk["old"] == hunk["new"]:
                    raise ScopeError("noop_hunk", f"hunk {domain_name}/{kind_name}/{entry_id} is a no-op")
                if "old" in hunk:
                    if bucket.get(entry_id) != hunk["old"]:
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

    if canonical_sha256(result) != actual_prop_hash:
        raise ScopeError(
            "diff_apply_mismatch",
            "applying diff to baseline does not reproduce proposed goal file",
        )


def check_standing_migration_invariants(
    baseline_goal: dict[str, Any],
    proposed_goal: dict[str, Any],
    *,
    migrate_fn: Callable[[dict[str, Any], int], dict[str, Any]] | None = None,
    device_trust_comparable: bool = True,
) -> None:
    """Enforce Item 15 on `baseline`-class standing-application migrations."""
    if not device_trust_comparable:
        raise ScopeError(
            "migration_device_trust_incomparable",
            "cannot compare device-trust of baseline and proposal under one schema (Item 15)",
        )

    base_dt = (baseline_goal.get("domains") or {}).get(TRUST_DOMAIN)
    prop_dt = (proposed_goal.get("domains") or {}).get(TRUST_DOMAIN)
    if not isinstance(base_dt, dict) or not isinstance(prop_dt, dict):
        raise ScopeError(
            "migration_device_trust_incomparable",
            "missing device-trust in baseline or proposed goal file",
        )

    target_version = proposed_goal.get("schema_version")
    if migrate_fn is not None:
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
        # Item 15: a migration whose migrate() changes ANY device-trust entry
        # (a role default included) is never by standing application.
        if mig_dt != base_dt or mig_dt != prop_dt:
            raise ScopeError(
                "migration_mutated_device_trust",
                "migration alters device-trust content (including defaults); requires per-change owner record",
            )
        if canonical_sha256(migrated) != canonical_sha256(proposed_goal):
            raise ScopeError(
                "migration_content_mismatch",
                "proposed goal file differs from migrated baseline",
            )
    else:
        if base_dt != prop_dt:
            raise ScopeError(
                "migration_mutated_device_trust",
                "proposed device-trust differs from baseline device-trust during migration",
            )
        base_body = {k: v for k, v in baseline_goal.items() if k != "schema_version"}
        prop_body = {k: v for k, v in proposed_goal.items() if k != "schema_version"}
        if base_body != prop_body:
            raise ScopeError(
                "migration_not_version_only",
                "migration alters fields beyond schema_version; requires per-change owner record",
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
    store state). Default 24 bytes = 192 bits -> 32 printable ASCII chars
    (unpadded base64url, matching `^[!-~]{22,128}\\Z`).
    """
    if num_bytes < 16:
        raise ValueError("device nonce requires at least 16 bytes (128 bits) of entropy")
    token = base64.urlsafe_b64encode(os.urandom(num_bytes)).rstrip(b"=").decode("ascii")
    if not NONCE_RE.match(token):
        raise RuntimeError("generated nonce failed schema alphabet check")
    return token


# ---------------------------------------------------------------------------
# ApprovalEnforcer — complete stateful reference enforcement engine
# ---------------------------------------------------------------------------

class ApprovalEnforcer:
    """Reference enforcement engine for tendcf v9 consent records on one host."""

    def __init__(
        self,
        host: str,
        store: ReplayStore,
        baseline_goal: dict[str, Any] | None = None,
        *,
        apply_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if not isinstance(host, str) or not KEY_ID_RE.match(host):
            raise ValueError(f"invalid host key_id: {host!r}")
        if store.host != host:
            raise ValueError("ReplayStore host does not match ApprovalEnforcer host")
        if baseline_goal is not None:
            validate_trust_root_no_host_key(baseline_goal, host)
            if baseline_goal.get("host") != host:
                raise ValueError("baseline_goal host does not match ApprovalEnforcer host")
        self.host = host
        self.store = store
        self.baseline_goal: dict[str, Any] | None = (
            copy.deepcopy(baseline_goal) if baseline_goal is not None else None
        )
        self._apply_callback = apply_callback
        # Diagnostic counters (used by tests to assert Option B zero side effects).
        self.prompt_count: int = 0
        self.actuation_count: int = 0

    def _check_utc_clock_monotonic(
        self, state: dict[str, Any], now_dt: datetime.datetime
    ) -> None:
        last_str = state.get("last_seen_utc")
        if last_str is not None:
            last_dt = parse_utc_timestamp(last_str, field="last_seen_utc")
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

    def _required_enrollment_ceremony_rank(self, grant_class: str, developer_mode: bool) -> int:
        base = CEREMONY_RANK[grant_class]
        if developer_mode:
            return max(base, CEREMONY_RANK["privileged"])
        return base

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
        if not_after is not None:
            parse_utc_timestamp(not_after, field="not_after")

        with self.store.locked():
            state = self.store.load_verified_unlocked()
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
        """True iff at least one active, unexpired developer-mode grant exists on this host."""
        now_dt = _coerce_utc(now_utc)
        with self.store.locked():
            try:
                state = self.store.load_verified_unlocked(allow_voided=True)
            except StoreRollbackError:
                return False
            if state["voided"]:
                return False
            self._check_utc_clock_monotonic(state, now_dt)
            for grant in state["grants"].values():
                if grant.get("grant_state") != "active" or grant.get("tombstoned"):
                    continue
                scope = grant.get("scope") or {}
                if scope.get("developer_mode") is not True:
                    continue
                if not self._is_expired(scope.get("not_after"), now_dt):
                    return True
            return False

    # ------------------------------------------------------------------
    # Standing enrollment & terminal revocation (Items 1, 2, 6, 7, 8, 9, 10, 11, 20, 22)
    # ------------------------------------------------------------------

    def process_enrollment(
        self,
        raw_record: bytes | str,
        *,
        now_utc: datetime.datetime | str,
        before_replace_hook: Callable[[], None] | None = None,
        after_commit_hook: Callable[[], None] | None = None,
    ) -> EnrollmentReceipt:
        """Process a `standing-enrollment` (active enrollment, Option B redelivery, or revocation)."""
        now_dt = _coerce_utc(now_utc)
        doc = parse_strict_json(raw_record)
        record = validate_approval_record_shape(doc)
        if record["record_kind"] != "standing-enrollment":
            raise MalformedRecordError(
                "wrong_record_kind",
                f"expected standing-enrollment, got {record['record_kind']!r}",
            )

        # Item 24: per-target host binding.
        if record["host"] != self.host:
            raise ScopeError("wrong_host", f"record host {record['host']!r} != {self.host!r}")

        # Item 10: host key never signs.
        if record["signer"] == self.host:
            raise TrustRootError("host_key_as_signer", "device host key may never sign records")

        # Item 11: sig_alg/prefix binding & strict canonical RFC 8032 Ed25519 verification.
        verify_record_signature(record)

        # Item 8: baseline owner role verification (never proposed).
        if self.baseline_goal is None:
            raise TrustRootError(
                "no_applied_baseline",
                "standing-enrollment requires an applied baseline trust root",
            )
        roles = extract_baseline_roles(self.baseline_goal, self.host)
        if roles.get(record["signer"]) != "owner":
            raise TrustRootError(
                "signer_not_owner",
                f"standing-enrollment requires baseline owner role; got {roles.get(record['signer'])!r}",
            )

        grant_id = record["grant_id"]
        generation = record["generation"]
        grant_state = record["grant_state"]

        # Serialized decision under lock against revocations, redeliveries, and store integrity.
        with self.store.locked():
            state = self.store.load_verified_unlocked()
            self._check_utc_clock_monotonic(state, now_dt)

            if grant_state == "revoked":
                # Item 7 + PR #75 R4 #1:
                # Honoured at ANY generation, wins equivocation, accepted for unseen grant_id,
                # owner signature only, nonce-less, ends any pending hold, terminal forever.
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
                # Cancel any pending holds belonging to this grant immediately.
                cancelled = [
                    prop_hash
                    for prop_hash, hold in state["pending_holds"].items()
                    if hold.get("grant_id") == grant_id
                ]
                for prop_hash in cancelled:
                    del state["pending_holds"][prop_hash]

                self._advance_utc_clock(state, now_dt)
                self.store.commit_unlocked(
                    state,
                    before_replace_hook=before_replace_hook,
                    after_commit_hook=after_commit_hook,
                )
                return EnrollmentReceipt(
                    status="accepted",
                    host=self.host,
                    grant_id=grant_id,
                    generation=generation,
                    grant_state="revoked",
                )

            # Active enrollment checks.
            # Refuse expired enrollment (Item 17).
            if self._is_expired(record.get("not_after"), now_dt):
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
            # Identical redelivery at generation == stored returns identical receipt
            # with ZERO writes, ZERO nonce/counter mutation, ZERO prompts, ZERO actuation,
            # and ZERO changes to pending holds or application_seq.
            if existing is not None and generation == existing["generation"]:
                if existing.get("grant_state") != "active":
                    raise ReplayError(
                        "grant_not_active",
                        f"grant_id {grant_id!r} at generation {generation} is not live active",
                    )
                stored_b64 = existing.get("active_payload_jcs_b64")
                if not isinstance(stored_b64, str) or not stored_b64:
                    # Missing equality evidence MUST fail closed (Astra Option B §2).
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
                    # Exact verified match! Perform ZERO writes and return identical receipt shape.
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

            # Item 20: Stale generation (< stored) is refused.
            if existing is not None and generation < existing["generation"]:
                raise ReplayError(
                    "stale_generation",
                    f"active enrollment generation {generation} <= stored {existing['generation']}",
                )

            # Validate covered_signers trust rules (Items 8, 9, 10).
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
            # New or higher-generation active enrollment requires an outstanding,
            # single-use ceremony nonce bound to the FULL shown scope.
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

            # Verify full shown scope matches record verbatim.
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
                if bound.get(field_name) != field_val:
                    raise NonceError(
                        "nonce_scope_mismatch",
                        f"enrollment {field_name!r} does not match ceremony-shown scope",
                    )

            # Verify ceremony level satisfies class and R6 developer_mode >= privileged.
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

            # Atomic install: consume nonce once, preserve application_seq_mark across generations.
            del state["outstanding_nonces"][matched_nonce_key]
            prev_mark = existing["application_seq_mark"] if existing else 0
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
    ) -> tuple[str, int | None]:
        """Evaluate every active, unexpired grant covering `(signer, derived_class)`.

        Returns `(effective_mode, effective_hold_seconds)` where most restrictive
        wins: `standing-refusal` > `wait-for-user` > `hold-window` (longest
        `hold_seconds`) > `standing-approval`.
        """
        winning_mode: str | None = None
        winning_rank = 0
        longest_hold: int | None = None

        for grant in state["grants"].values():
            if grant.get("grant_state") != "active" or grant.get("tombstoned"):
                continue
            scope = grant.get("scope") or {}
            if scope.get("class") != derived_class:
                continue
            if self._is_expired(scope.get("not_after"), now_dt):
                continue
            if signer not in (scope.get("covered_signers") or []):
                continue
            mode = scope.get("mode")
            if mode not in MODE_RESTRICTIVENESS:
                continue
            # Non-developer apply modes require signer to still hold baseline covered-signer role.
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
            raise ScopeError("no_covering_grant", "no active unexpired grant covers this application")
        return winning_mode, longest_hold

    # ------------------------------------------------------------------
    # Standing application intake & hold-window completion (Items 3-5, 8-26)
    # ------------------------------------------------------------------

    def process_standing_application(
        self,
        raw_record: bytes | str,
        *,
        proposed_goal: dict[str, Any],
        diff: dict[str, Any],
        now_utc: datetime.datetime | str,
        now_mono: float,
        is_readoption: bool = False,
        touches_replay_store: bool = False,
        migrate_fn: Callable[[dict[str, Any], int], dict[str, Any]] | None = None,
        device_trust_comparable: bool = True,
        before_replace_hook: Callable[[], None] | None = None,
        before_apply_hook: Callable[[], None] | None = None,
    ) -> ApplicationResult:
        """Validate and execute/hold/park a `standing-application`.

        Item 26 + PR #75 R4 #2: EVERY check MUST pass BEFORE `application_seq`
        is persisted, so a refused application never burns or raises the mark.
        Item 5: `application_seq` is durably persisted BEFORE actuation (or
        before starting the hold window).
        """
        now_dt = _coerce_utc(now_utc)
        doc = parse_strict_json(raw_record)
        record = validate_approval_record_shape(doc)
        if record["record_kind"] != "standing-application":
            raise MalformedRecordError(
                "wrong_record_kind",
                f"expected standing-application, got {record['record_kind']!r}",
            )

        # Item 24: per-target host binding.
        if record["host"] != self.host:
            raise ScopeError("wrong_host", f"record host {record['host']!r} != {self.host!r}")

        # Item 10: host key never signs and never appears in proposed trust root.
        if record["signer"] == self.host:
            raise TrustRootError("host_key_as_signer", "device host key may never sign records")
        validate_trust_root_no_host_key(proposed_goal, self.host)

        # Item 11: sig_alg/prefix binding & strict canonical RFC 8032 Ed25519 verification.
        verify_record_signature(record)

        # Item 4 & Item 15: first adoption and re-adoption are NEVER by standing application.
        if self.baseline_goal is None:
            raise ReplayError(
                "first_adoption_disallowed",
                "first adoption is never permitted via standing-application (Item 4)",
            )
        if is_readoption:
            raise ScopeError(
                "readoption_disallowed",
                "re-adoption is never permitted via standing-application (Item 15)",
            )

        # Item 4 & Item 25: exact baseline_sha256 and proposed_sha256 binding.
        current_baseline_hash = canonical_sha256(self.baseline_goal)
        if not hmac.compare_digest(record["baseline_sha256"], current_baseline_hash):
            raise ReplayError(
                "baseline_sha256_mismatch",
                "application baseline_sha256 does not match currently applied baseline (Item 4)",
            )
        actual_proposed_hash = canonical_sha256(proposed_goal)
        if not hmac.compare_digest(record["proposed_sha256"], actual_proposed_hash):
            raise ScopeError(
                "proposed_sha256_mismatch",
                "application proposed_sha256 does not match proposed goal file (Item 25)",
            )

        # Verify diff integrity against baseline and proposed goal files.
        verify_diff_matches_goals(self.baseline_goal, proposed_goal, diff, self.host)

        # Item 13 (R1/R7): default-deny carve-out over device-trust and replay store.
        check_standing_carve_out(diff, touches_replay_store=touches_replay_store)

        # Item 14 + PR #75 R4 #4 + Item 15 + Item 23:
        # Derive per-item classes; standing application refuses mixed-class diffs!
        overall_class, per_item_classes = analyze_diff_classes(diff)
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

        # Item 15: baseline migration checks.
        if "version_bump" in diff:
            check_standing_migration_invariants(
                self.baseline_goal,
                proposed_goal,
                migrate_fn=migrate_fn,
                device_trust_comparable=device_trust_comparable,
            )

        # Item 8: baseline trust root roles (NEVER proposed!).
        roles = extract_baseline_roles(self.baseline_goal, self.host)
        signer = record["signer"]
        if roles.get(signer) == "owner":
            raise TrustRootError(
                "owner_cannot_sign_application",
                "an owner key may never sign a standing-application (even in developer mode)",
            )

        grant_id = record["grant_id"]
        generation = record["generation"]
        app_seq = record["application_seq"]

        with self.store.locked():
            state = self.store.load_verified_unlocked()
            self._check_utc_clock_monotonic(state, now_dt)

            # Item 19: Persisted DC-2 reject of proposed_sha256 wins over every grant!
            if actual_proposed_hash in state["persisted_rejects"]:
                raise ReplayError(
                    "persisted_reject_active",
                    "proposed_sha256 has a persisted DC-2 owner reject (wins over all grants)",
                )

            # Lookup named grant.
            grant = state["grants"].get(grant_id)
            if grant is None:
                raise ReplayError("unknown_grant", f"grant_id {grant_id!r} is not enrolled")
            if grant.get("tombstoned") is True or grant.get("grant_state") != "active":
                raise ReplayError("grant_revoked", f"grant_id {grant_id!r} is revoked/inactive")

            # Item 20: generation must equal stored active generation.
            if generation != grant["generation"]:
                raise ReplayError(
                    "generation_mismatch",
                    f"application generation {generation} != stored active {grant['generation']}",
                )

            # Item 3 (R10): enrollment_nonce must match stored active enrollment's nonce.
            stored_enonce = grant.get("enrollment_nonce")
            if not isinstance(stored_enonce, str) or not hmac.compare_digest(
                record["enrollment_nonce"].encode("utf-8"), stored_enonce.encode("utf-8")
            ):
                raise NonceError(
                    "enrollment_nonce_mismatch",
                    "application enrollment_nonce does not match stored active enrollment (R10)",
                )

            scope = grant["scope"]
            # Item 17: not_after expiry check at intake.
            if self._is_expired(scope.get("not_after"), now_dt):
                raise ScopeError("grant_expired", f"grant_id {grant_id!r} has expired")

            # Item 23: grant class must equal derived class.
            if scope["class"] != derived_class:
                raise ScopeError(
                    "grant_class_mismatch",
                    f"grant class {scope['class']!r} != derived class {derived_class!r}",
                )

            # Item 21: signer must be a member of stored grant's covered_signers.
            if signer not in scope["covered_signers"]:
                raise ScopeError(
                    "signer_not_covered",
                    f"signer {signer!r} is not in grant {grant_id!r}'s covered_signers",
                )

            # Item 8 & Item 9: outside developer_mode, signer must be baseline covered-signer.
            if not scope["developer_mode"] and roles.get(signer) != "covered-signer":
                raise TrustRootError(
                    "signer_not_covered_signer_role",
                    f"signer {signer!r} is not a baseline covered-signer (non-developer grant)",
                )

            # Item 19: evaluate covering precedence across ALL active unexpired grants BEFORE mark!
            effective_mode, effective_hold_seconds = self._resolve_covering_precedence(
                state,
                signer=signer,
                derived_class=derived_class,
                now_dt=now_dt,
                roles=roles,
            )

            if effective_mode == "standing-refusal":
                raise ScopeError(
                    "standing_refusal",
                    "a covering active standing-refusal grant refuses this change",
                )

            # Item 5: application_seq must exceed stored mark (checked AFTER every other check, Item 26!).
            stored_mark = grant["application_seq_mark"]
            if app_seq <= stored_mark:
                raise ReplayError(
                    "stale_application_seq",
                    f"application_seq {app_seq} <= stored mark {stored_mark}",
                )

            if effective_mode == "wait-for-user":
                # Parked for owner per-change answer; never applied by standing grant.
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
                    "first_shown_mono": float(now_mono),
                    "hold_seconds": effective_hold_seconds,
                    "application_seq": app_seq,
                }
                self.store.commit_unlocked(state, before_replace_hook=before_replace_hook)
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
            # Persist mark durably BEFORE applying change.
            self.store.commit_unlocked(state, before_replace_hook=before_replace_hook)
            if before_apply_hook is not None:
                before_apply_hook()
            self._actuate_goal_file(proposed_goal)
            return ApplicationResult(
                decision="applied",
                host=self.host,
                grant_id=grant_id,
                generation=generation,
                application_seq=app_seq,
                proposed_sha256=actual_proposed_hash,
                effective_mode="standing-approval",
            )

    def complete_hold_window(
        self,
        proposed_sha256: str,
        *,
        proposed_goal: dict[str, Any],
        diff: dict[str, Any],
        now_utc: datetime.datetime | str,
        now_mono: float,
        touches_replay_store: bool = False,
        migrate_fn: Callable[[dict[str, Any], int], dict[str, Any]] | None = None,
        device_trust_comparable: bool = True,
        before_apply_hook: Callable[[], None] | None = None,
    ) -> ApplicationResult:
        """Complete a pending hold window after monotonic elapsed time, re-evaluating EVERY check."""
        now_dt = _coerce_utc(now_utc)
        validate_trust_root_no_host_key(proposed_goal, self.host)

        with self.store.locked():
            state = self.store.load_verified_unlocked()
            self._check_utc_clock_monotonic(state, now_dt)

            hold = state["pending_holds"].get(proposed_sha256)
            if hold is None:
                raise ReplayError(
                    "no_pending_hold",
                    f"no pending hold exists for {proposed_sha256!r} (cancelled, revoked, or absent)",
                )

            # Item 18: monotonic clock check (does not advance while off/asleep).
            first_shown = float(hold["first_shown_mono"])
            if float(now_mono) < first_shown:
                raise ClockRollbackError(
                    "monotonic_clock_rollback",
                    f"monotonic clock moved backward: {now_mono} < {first_shown}",
                )

            # Re-evaluate EVERY check at apply time (Item 17 & Item 18):
            if proposed_sha256 in state["persisted_rejects"]:
                del state["pending_holds"][proposed_sha256]
                self._advance_utc_clock(state, now_dt)
                self.store.commit_unlocked(state)
                raise ReplayError(
                    "persisted_reject_active",
                    "pending hold stopped by persisted DC-2 reject",
                )

            if self.baseline_goal is None:
                raise ReplayError("no_applied_baseline", "no applied baseline for hold completion")
            current_baseline_hash = canonical_sha256(self.baseline_goal)
            if hold["baseline_sha256"] != current_baseline_hash:
                raise ReplayError(
                    "baseline_changed_during_hold",
                    "applied baseline changed while change was held (Item 4 / Item 18)",
                )

            actual_prop_hash = canonical_sha256(proposed_goal)
            if actual_prop_hash != proposed_sha256:
                raise ScopeError(
                    "proposed_sha256_mismatch",
                    "proposed goal file does not match held proposed_sha256 (Item 25)",
                )

            verify_diff_matches_goals(self.baseline_goal, proposed_goal, diff, self.host)
            check_standing_carve_out(diff, touches_replay_store=touches_replay_store)
            overall_class, per_item_classes = analyze_diff_classes(diff)
            if len(per_item_classes) != 1 or overall_class != hold["ceremony_class"]:
                raise ScopeError("class_mismatch_at_hold_apply", "diff class no longer matches hold")
            if "version_bump" in diff:
                check_standing_migration_invariants(
                    self.baseline_goal,
                    proposed_goal,
                    migrate_fn=migrate_fn,
                    device_trust_comparable=device_trust_comparable,
                )

            grant_id = hold["grant_id"]
            grant = state["grants"].get(grant_id)
            if grant is None or grant.get("tombstoned") or grant.get("grant_state") != "active":
                raise ReplayError(
                    "grant_inactive_at_hold_apply",
                    f"grant {grant_id!r} is no longer active at hold completion",
                )
            if grant["generation"] != hold["generation"]:
                raise ReplayError(
                    "generation_changed_during_hold",
                    "grant generation changed while change was held",
                )
            if not hmac.compare_digest(
                str(grant.get("enrollment_nonce") or "").encode("utf-8"),
                str(hold["enrollment_nonce"]).encode("utf-8"),
            ):
                raise NonceError(
                    "enrollment_nonce_changed_during_hold",
                    "grant enrollment_nonce changed while change was held (R10 / Item 18)",
                )

            scope = grant["scope"]
            if self._is_expired(scope.get("not_after"), now_dt):
                raise ScopeError(
                    "grant_expired_at_hold_apply",
                    f"grant {grant_id!r} expired before hold completion (Item 17)",
                )

            roles = extract_baseline_roles(self.baseline_goal, self.host)
            signer = hold["signer"]
            if roles.get(signer) == "owner":
                raise TrustRootError("owner_cannot_sign_application", "signer became owner")
            if signer not in scope["covered_signers"]:
                raise ScopeError("signer_removed_from_grant", "signer no longer covered")
            if not scope["developer_mode"] and roles.get(signer) != "covered-signer":
                raise TrustRootError(
                    "signer_role_revoked_during_hold",
                    "signer lost baseline covered-signer role during hold",
                )

            # Re-evaluate covering set precedence at apply time.
            effective_mode, effective_hold_seconds = self._resolve_covering_precedence(
                state,
                signer=signer,
                derived_class=hold["ceremony_class"],
                now_dt=now_dt,
                roles=roles,
            )
            if effective_mode == "standing-refusal":
                raise ScopeError(
                    "standing_refusal_at_hold_apply",
                    "a covering standing-refusal grant now refuses this held change",
                )
            if effective_mode == "wait-for-user":
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
            elapsed = float(now_mono) - first_shown
            if elapsed < required_hold:
                raise ScopeError(
                    "hold_window_not_elapsed",
                    f"hold window elapsed {elapsed:.3f}s < required {required_hold}s",
                )

            # Remove pending hold durably before actuating.
            del state["pending_holds"][proposed_sha256]
            self._advance_utc_clock(state, now_dt)
            self.store.commit_unlocked(state)

            if before_apply_hook is not None:
                before_apply_hook()
            self._actuate_goal_file(proposed_goal)
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
        bootstrap_owner_keys: set[str] | None = None,
        is_readoption: bool = False,
        before_replace_hook: Callable[[], None] | None = None,
    ) -> PerChangeResult:
        """Process an owner `per-change` approval/reject/withdraw record.

        Special hold-window reject rule (Item 18): during a pending hold for
        `proposed_sha256`, an owner-signed `per-change` `reject` naming
        `(host, proposed_sha256)` stops the hold IMMEDIATELY and persists as a
        DC-2 reject regardless of `ceremony_class`, `nonce`, or `approval_seq`.

        Downward `version_bump` rule (Item 15, 2026-11-26 operator ruling):
        `new <= old` is refused for `per-change` owner records too.
        """
        now_dt = _coerce_utc(now_utc)
        doc = parse_strict_json(raw_record)
        record = validate_approval_record_shape(doc)
        if record["record_kind"] != "per-change":
            raise MalformedRecordError(
                "wrong_record_kind",
                f"expected per-change, got {record['record_kind']!r}",
            )

        # Item 24: per-target host binding.
        if record["host"] != self.host:
            raise ScopeError("wrong_host", f"record host {record['host']!r} != {self.host!r}")

        # Item 10: host key never signs, and never appears in proposed/baseline trust root.
        if record["signer"] == self.host:
            raise TrustRootError("host_key_as_signer", "device host key may never sign records")
        if proposed_goal is not None:
            validate_trust_root_no_host_key(proposed_goal, self.host)

        # Item 11: sig_alg/prefix binding & strict canonical RFC 8032 Ed25519 verification.
        verify_record_signature(record)

        # Item 8: owner role verification against currently applied baseline (or bootstrap on first adoption).
        is_first_adoption = self.baseline_goal is None
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
            proposed_roles = extract_baseline_roles(proposed_goal, self.host)
            allowed_owners = (
                bootstrap_owner_keys
                if bootstrap_owner_keys is not None
                else {k for k, r in proposed_roles.items() if r == "owner"}
            )
            if record["signer"] not in allowed_owners or proposed_roles.get(record["signer"]) != "owner":
                raise TrustRootError(
                    "signer_not_owner",
                    "first adoption requires an owner key present in the initial trust root",
                )
        else:
            assert self.baseline_goal is not None
            roles = extract_baseline_roles(self.baseline_goal, self.host)
            if roles.get(record["signer"]) != "owner":
                raise TrustRootError(
                    "signer_not_owner",
                    f"per-change record requires baseline owner role; got {roles.get(record['signer'])!r}",
                )

        proposed_sha256 = record["proposed_sha256"]
        verdict = record["verdict"]

        with self.store.locked():
            state = self.store.load_verified_unlocked()
            self._check_utc_clock_monotonic(state, now_dt)

            # Item 18: Hold-window override reject!
            # Stops pending hold for (host, proposed_sha256) immediately regardless
            # of ceremony_class, nonce, or approval_seq, and persists as DC-2 reject.
            if verdict == "reject" and proposed_sha256 in state["pending_holds"]:
                hold = state["pending_holds"].pop(proposed_sha256)
                state["persisted_rejects"][proposed_sha256] = {
                    "recorded_utc": format_utc_timestamp(now_dt),
                    "refused": list(record["refused"]),
                    "signer": record["signer"],
                }
                self._advance_utc_clock(state, now_dt)
                self.store.commit_unlocked(state, before_replace_hook=before_replace_hook)
                return PerChangeResult(
                    decision="rejected",
                    host=self.host,
                    proposed_sha256=proposed_sha256,
                    approval_seq=None,
                    cancelled_holds=(hold["hold_id"],),
                )

            # Standard DC-2 per-change checks (all must pass BEFORE persisting approval_seq!).
            if proposed_goal is not None:
                actual_prop_hash = canonical_sha256(proposed_goal)
                if not hmac.compare_digest(proposed_sha256, actual_prop_hash):
                    raise ScopeError(
                        "proposed_sha256_mismatch",
                        "per-change proposed_sha256 does not match proposed goal file (Item 25)",
                    )

            if is_first_adoption or is_readoption:
                derived_class = "baseline"
            else:
                assert self.baseline_goal is not None
                if "baseline_sha256" not in record:
                    raise ScopeError(
                        "missing_baseline_sha256",
                        "non-first-adoption per-change record requires baseline_sha256",
                    )
                current_base_hash = canonical_sha256(self.baseline_goal)
                if not hmac.compare_digest(record["baseline_sha256"], current_base_hash):
                    raise ReplayError(
                        "baseline_sha256_mismatch",
                        "per-change baseline_sha256 does not match applied baseline",
                    )
                if diff is not None:
                    if proposed_goal is not None:
                        verify_diff_matches_goals(self.baseline_goal, proposed_goal, diff, self.host)
                    # Note: analyze_diff_classes enforces Item 15 downward version_bump refusal!
                    derived_class, _ = analyze_diff_classes(diff)
                else:
                    derived_class = record["ceremony_class"]

            # Item 23: asserted ceremony_class must equal derived class exactly.
            if record["ceremony_class"] != derived_class:
                raise ScopeError(
                    "ceremony_class_mismatch",
                    f"asserted ceremony_class {record['ceremony_class']!r} != derived {derived_class!r}",
                )

            # Nonce check (single-use, bound to host + proposed_sha256 + ceremony_class).
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

            # DC-2 monotonic approval_seq check (after all other checks!).
            seq = record["approval_seq"]
            if seq <= state["approval_seq"]:
                raise ReplayError(
                    "stale_approval_seq",
                    f"approval_seq {seq} <= stored {state['approval_seq']}",
                )

            # Consume nonce & persist approval_seq durably before side effects.
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
                self.store.commit_unlocked(state, before_replace_hook=before_replace_hook)
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
                self.store.commit_unlocked(state, before_replace_hook=before_replace_hook)
                self.store.nonce_consume_count += 1
                return PerChangeResult(
                    decision="withdrawn",
                    host=self.host,
                    proposed_sha256=proposed_sha256,
                    approval_seq=seq,
                )

            # verdict == "accept":
            # Owner per-change accept stays available against standing-refusal / wait-for-user
            # and clears any prior persisted reject of this exact proposed_sha256 (Item 19).
            state["persisted_rejects"].pop(proposed_sha256, None)
            if proposed_sha256 in state["pending_holds"]:
                cancelled_holds.append(state["pending_holds"].pop(proposed_sha256)["hold_id"])
            self._advance_utc_clock(state, now_dt)
            self.store.commit_unlocked(state, before_replace_hook=before_replace_hook)
            self.store.nonce_consume_count += 1

            if proposed_goal is not None:
                self._actuate_goal_file(proposed_goal)
            return PerChangeResult(
                decision="applied",
                host=self.host,
                proposed_sha256=proposed_sha256,
                approval_seq=seq,
                cancelled_holds=tuple(cancelled_holds),
            )

    def _actuate_goal_file(self, proposed_goal: dict[str, Any]) -> None:
        self.baseline_goal = copy.deepcopy(proposed_goal)
        self.actuation_count += 1
        if self._apply_callback is not None:
            self._apply_callback(copy.deepcopy(proposed_goal))


__all__ = [
    "ALLOWED_STANDING_DEVICE_TRUST_KINDS",
    "AnchorState",
    "ApplicationResult",
    "ApprovalEnforcer",
    "CEREMONY_CLASSES",
    "CEREMONY_RANK",
    "ClockRollbackError",
    "ED25519_D",
    "ED25519_L",
    "ED25519_P",
    "EnforcementError",
    "EnrollmentReceipt",
    "FileRollbackAnchor",
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
    "derive_coverage_change_class",
    "derive_hunk_class",
    "ed25519_compress_point",
    "ed25519_decompress_point",
    "ed25519_public_key_from_seed",
    "ed25519_sign",
    "extract_baseline_roles",
    "format_utc_timestamp",
    "generate_device_nonce",
    "jcs_dumps",
    "key_id_from_pubkey",
    "parse_strict_json",
    "parse_utc_timestamp",
    "render_enrollment_briefing",
    "sign_approval_record",
    "signing_payload_bytes",
    "validate_approval_record_shape",
    "validate_trust_root_no_host_key",
    "verify_diff_matches_goals",
    "verify_ed25519",
    "verify_record_signature",
]
