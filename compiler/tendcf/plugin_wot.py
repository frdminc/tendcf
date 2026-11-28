"""Offline OpenPGP Web-of-Trust verifier for third-party tendcf plugins (issue #47).

Implements the 2026-11-28 operator rulings and Fable R1 security hardening:
- Offline site-private keyring only (never contacts keyservers or WKD; never reads `~/.gnupg`).
- Bounded Web of Trust: default `max_depth = 1`, configurable `0..2`, with `full_threshold`
  and `marginal_threshold` support, plus `role = "root"` vs `role = "direct"` separation.
- Offline GnuPG backend (`backend = "auto"` or `"gpg"`): ephemeral `0700` short-path `GNUPGHOME`
  (macOS 104-byte Unix-socket safe), `--batch --no-tty --no-options --trust-model pgp`,
  `--no-auto-key-retrieve --no-auto-key-locate`, `--weak-digest SHA1`, `--max-cert-depth (max_depth+1)`.
  Note (M7): `backend = "sequoia"` fails closed until tested against real Sequoia `sq`/`sq-wot`
  binaries in CI (`auto` always selects verified `gpg` rather than guessing untested Sequoia flags).
- Zero TOCTOU on manifest/signature (M1): verifies the exact in-memory bytes already parsed by
  `PluginReleaseManifest` (written into the private `0700` temp dir) rather than re-opening paths.
- Strong signature algorithm policy (L1): requires OpenPGP hash algorithm >= 8 (SHA-256/384/512/224),
  rejecting MD5/SHA-1/RIPEMD-160, and rejects legacy DSA/Elgamal signing keys.
- Full revocation enforcement across roots, introducers, primary keys, AND signing subkeys (M3, L7):
  - `hard` revocations (and `soft` revocations in non-historical mode) are deleted from the
    ephemeral verification keyring and stripped from ownertrust BEFORE `--check-trustdb`, so a
    revoked root or introducer cannot vouch for any downstream leaf key even without a `.rev` cert.
  - Revocation cert files (`cert_file`) are imported AFTER public keys, and in `--historical`
    pre-revocation mode a `soft` revocation's `cert_file` is skipped when `as_of < revoked_at`
    (while `hard` revocation certs are ALWAYS imported).
- `verify_signer_reachable_in_wot()` allows `tendcf plugin verify` and `load_out_of_tree_plugin`
  to confirm a pinned signer is still reachable from current `[[trust.anchors]]` (closing M3.3).
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .plugin_manifest import (
    KEYRING_FILE_EXTS,
    KeyRevocation,
    PluginManifestError,
    TrustAnchor,
    TrustPolicy,
    format_rfc3339_utc,
    read_regular_file_bytes,
    utc_now,
    validate_fingerprint,
)

MAX_KEY_FILE_BYTES = 1024 * 1024
MAX_SIG_FILE_BYTES = 128 * 1024
PGP_COMMAND_TIMEOUT = 30.0

ARMORED_SIG_BEGIN = "-----BEGIN PGP SIGNATURE-----"
ARMORED_SIG_END = "-----END PGP SIGNATURE-----"

# OpenPGP RFC 4880 / 9580 strong hash algorithms allowed for plugin release signatures (L1):
# 8 = SHA-256, 9 = SHA-384, 10 = SHA-512, 11 = SHA-224, 12 = SHA3-256, 14 = SHA3-512.
ALLOWED_HASH_ALGOS: frozenset[int] = frozenset({8, 9, 10, 11, 12, 14})
# Allowed OpenPGP signing public-key algorithms: RSA(1,3), ECDSA(19), EdDSA(22), Ed25519(27), Ed448(28).
ALLOWED_PUBKEY_ALGOS: frozenset[int] = frozenset({1, 3, 19, 22, 27, 28})


class PluginTrustError(Exception):
    """OpenPGP signature, Web-of-Trust path, revocation, or keyring check failed closed."""


@dataclass(frozen=True)
class WoTVerificationResult:
    backend: str  # "gpg"
    primary_fingerprint: str
    signing_fingerprint: str
    sig_created_at: str  # RFC 3339 UTC
    trust_level: str  # "ultimate" | "full" | "direct"
    historical: bool
    as_of: str  # RFC 3339 UTC
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "primary_fingerprint": self.primary_fingerprint,
            "signing_fingerprint": self.signing_fingerprint,
            "sig_created_at": self.sig_created_at,
            "trust_level": self.trust_level,
            "historical": self.historical,
            "as_of": self.as_of,
            "warnings": list(self.warnings),
        }


def resolve_keyring_dir(site_root: Path, keyring_rel: str, *, create: bool = False) -> Path:
    """Resolve `<site_root>/<keyring_rel>` without symlinks or escapes."""
    try:
        st_site = os.lstat(site_root)
    except OSError as exc:
        raise PluginTrustError(f"cannot inspect site directory {site_root}: {exc}") from exc
    if stat.S_ISLNK(st_site.st_mode) or not stat.S_ISDIR(st_site.st_mode):
        raise PluginTrustError(f"site directory must be a real non-symlink directory: {site_root}")
    resolved_site = site_root.resolve(strict=True)

    cur = resolved_site
    for part in keyring_rel.split("/"):
        if part in ("", ".", ".."):
            raise PluginTrustError(f"unsafe keyring_dir component in {keyring_rel!r}")
        cur = cur / part
        try:
            st = os.lstat(cur)
        except FileNotFoundError as exc:
            if create:
                cur.mkdir(mode=0o755)
                st = os.lstat(cur)
            else:
                raise PluginTrustError(f"site-private keyring directory missing: {cur} ({exc})") from exc
        except OSError as exc:
            raise PluginTrustError(f"site-private keyring directory error: {cur} ({exc})") from exc
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise PluginTrustError(f"keyring directory component must be a real non-symlink directory: {cur}")
    resolved_kr = cur.resolve(strict=True)
    if not resolved_kr.is_relative_to(resolved_site):
        raise PluginTrustError(f"keyring directory {resolved_kr} escapes site directory {resolved_site}")
    return resolved_kr


def collect_keyring_files(keyring_dir: Path, policy: TrustPolicy) -> tuple[list[Path], list[Path]]:
    """Collect verified non-symlink public key files and revocation cert files inside `keyring_dir`.

    Returns `(key_files, rev_cert_files)` ordered so public keys are imported BEFORE revocation
    certificates (L7). Refuses any symlink inside `keyring_dir` and verifies every declared
    anchor `key_file` and revocation `cert_file` exists.
    """
    rev_cert_names = {r.cert_file for r in policy.revocations if r.cert_file is not None}
    key_files: list[Path] = []
    rev_files: list[Path] = []
    seen_names: set[str] = set()

    try:
        entries = sorted(os.scandir(keyring_dir), key=lambda e: e.name)
    except OSError as exc:
        raise PluginTrustError(f"cannot list keyring directory {keyring_dir}: {exc}") from exc

    for entry in entries:
        if entry.name.startswith("."):
            continue
        p = Path(entry.path)
        try:
            st = os.lstat(p)
        except OSError as exc:
            raise PluginTrustError(f"cannot inspect keyring entry {p}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise PluginTrustError(f"symlink forbidden inside site-private keyring: {p}")
        if not stat.S_ISREG(st.st_mode):
            continue
        if p.suffix.lower() not in KEYRING_FILE_EXTS:
            continue
        resolved = p.resolve(strict=True)
        if resolved.parent != keyring_dir:
            raise PluginTrustError(f"keyring file {p} resolves outside {keyring_dir}")
        seen_names.add(entry.name)
        if entry.name in rev_cert_names or entry.name.lower().endswith(".rev.asc") or entry.name.lower().endswith(".rev"):
            rev_files.append(resolved)
        else:
            key_files.append(resolved)

    for anchor in policy.anchors:
        if anchor.key_file not in seen_names:
            raise PluginTrustError(
                f"trust anchor {anchor.label!r} ({anchor.fingerprint}) key_file {anchor.key_file!r} "
                f"is missing from {keyring_dir}"
            )

    for rev in policy.revocations:
        if rev.cert_file is not None and rev.cert_file not in seen_names:
            raise PluginTrustError(
                f"revocation cert_file {rev.cert_file!r} for {rev.fingerprint} is missing from {keyring_dir}"
            )

    return key_files, rev_files


def select_wot_backend(
    preferred: str,
    *,
    env: Mapping[str, str] | None = None,
    gpg_bin: str | None = None,
) -> tuple[str, dict[str, str]]:
    """Select verified offline OpenPGP backend (`gpg`).

    `backend = "auto"` always selects `gpg` (M7: never routes to an untested Sequoia CLI).
    `backend = "sequoia"` fails closed explicitly until real Sequoia CI verification exists.
    """
    path_env = (os.environ if env is None else env).get("PATH")
    found_gpg = gpg_bin if gpg_bin is not None else shutil.which("gpg", path=path_env)

    if preferred == "sequoia":
        raise PluginTrustError(
            "trust.backend='sequoia' is not yet enabled (Sequoia sq/sq-wot CLI flags are unverified "
            "without CI binaries); set trust.backend='gpg' or 'auto'"
        )
    if preferred in ("auto", "gpg"):
        if not found_gpg:
            raise PluginTrustError("offline OpenPGP backend 'gpg' not found on PATH")
        return "gpg", {"gpg": found_gpg}
    raise PluginTrustError(f"unsupported OpenPGP backend {preferred!r}")


def _validate_detached_armored_sig(sig_bytes: bytes, sig_label: str) -> None:
    """Require an ASCII-armored detached PGP signature (refuse clearsigned/multi-sig blobs)."""
    try:
        text = sig_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PluginTrustError(
            f"detached signature {sig_label} must be ASCII-armored UTF-8 OpenPGP signature: {exc}"
        ) from exc
    if "-----BEGIN PGP SIGNED MESSAGE-----" in text:
        raise PluginTrustError(
            f"clearsigned document refused for {sig_label}; detached ASCII-armored signature required"
        )
    begins = text.count(ARMORED_SIG_BEGIN)
    ends = text.count(ARMORED_SIG_END)
    if begins != 1 or ends != 1:
        raise PluginTrustError(
            f"signature {sig_label} must contain exactly one '{ARMORED_SIG_BEGIN}' block (found {begins}/{ends})"
        )


def evaluate_revocation_policy(
    fingerprint: str,
    policy: TrustPolicy,
    *,
    historical: bool,
    as_of: datetime,
    issued_at: datetime | None = None,
    verified_at: datetime | None = None,
    sig_created_at: datetime | None = None,
) -> tuple[str, ...]:
    """Evaluate `[[trust.revocations]]` against `fingerprint`. Returns warnings or raises PluginTrustError."""
    rev: KeyRevocation | None = None
    for item in policy.revocations:
        if item.fingerprint == fingerprint:
            rev = item
            break
    if rev is None:
        return ()

    rev_dt = rev.revoked_at_dt
    if rev.mode == "hard":
        raise PluginTrustError(
            f"key {fingerprint} is HARD-REVOKED as of {rev.revoked_at} ({rev.reason}); "
            "all verification including historical rebuilds is refused"
        )

    if not historical:
        raise PluginTrustError(
            f"key {fingerprint} is SOFT-REVOKED as of {rev.revoked_at} ({rev.reason}); "
            "new installs/updates and current releases are refused (historical rebuilds require "
            "--historical --as-of before revoked_at)"
        )

    checks = [("as_of", as_of)]
    if issued_at is not None:
        checks.append(("issued_at", issued_at))
    if verified_at is not None:
        checks.append(("verified_at", verified_at))
    if sig_created_at is not None:
        checks.append(("sig_created_at", sig_created_at))

    for label, ts in checks:
        if ts >= rev_dt:
            raise PluginTrustError(
                f"key {fingerprint} was SOFT-REVOKED at {rev.revoked_at} ({rev.reason}), "
                f"and {label} ({format_rfc3339_utc(ts)}) is not strictly before revocation"
            )

    return (
        f"soft_revoked_after_pin: key {fingerprint} was soft-revoked at {rev.revoked_at} "
        f"({rev.reason}); historical verification at {format_rfc3339_utc(as_of)} permitted",
    )


def _active_revoked_fingerprints(policy: TrustPolicy, *, historical: bool, as_of: datetime) -> set[str]:
    """Fingerprints that must be actively revoked/removed in the ephemeral WoT graph (M3)."""
    blocked: set[str] = set()
    for rev in policy.revocations:
        if rev.mode == "hard":
            blocked.add(rev.fingerprint)
        elif not historical or as_of >= rev.revoked_at_dt:
            blocked.add(rev.fingerprint)
    return blocked


def _offline_clean_env(base_env: Mapping[str, str] | None) -> dict[str, str]:
    src = os.environ if base_env is None else base_env
    clean: dict[str, str] = {"LC_ALL": "C"}
    for keep in ("PATH", "TMPDIR", "TEMP", "TMP"):
        if keep in src:
            clean[keep] = src[keep]
    return clean


def _short_gpg_tempdir() -> tempfile.TemporaryDirectory[str]:
    """Create a short-path temp dir so macOS's 104-byte Unix socket limit never breaks gpg-agent."""
    base = Path("/tmp") if Path("/tmp").is_dir() and len(tempfile.gettempdir()) > 40 else None
    return tempfile.TemporaryDirectory(prefix="tgpg.", dir=str(base) if base is not None else None)


def _run_gpg(
    gpg_bin: str,
    homedir: Path,
    args: list[str],
    *,
    env: dict[str, str],
    inp: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    run_env = dict(env)
    run_env["GNUPGHOME"] = str(homedir)
    argv = [
        gpg_bin,
        "--batch",
        "--no-tty",
        "--yes",
        "--no-options",
        "--homedir",
        str(homedir),
        "--no-auto-key-retrieve",
        "--no-auto-key-locate",
        "--keyserver-options",
        "no-auto-key-retrieve",
        "--weak-digest",
        "SHA1",
        *args,
    ]
    try:
        return subprocess.run(
            argv,
            input=inp,
            capture_output=True,
            env=run_env,
            timeout=PGP_COMMAND_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PluginTrustError(f"gpg timed out after {PGP_COMMAND_TIMEOUT}s") from exc
    except OSError as exc:
        raise PluginTrustError(f"failed to invoke gpg ({gpg_bin}): {exc}") from exc


def inspect_openpgp_key(
    key_path: Path,
    *,
    env: Mapping[str, str] | None = None,
    gpg_bin: str | None = None,
) -> dict[str, Any]:
    """Inspect a public OpenPGP key file offline and return primary fingerprint + user IDs."""
    key_bytes = read_regular_file_bytes(key_path, max_bytes=MAX_KEY_FILE_BYTES, label="OpenPGP key file")
    clean_env = _offline_clean_env(env)
    _, bins = select_wot_backend("gpg", env=clean_env, gpg_bin=gpg_bin)
    found_gpg = bins["gpg"]
    with _short_gpg_tempdir() as td:
        home = Path(td) / "g"
        home.mkdir(mode=0o700)
        imp = _run_gpg(found_gpg, home, ["--import"], env=clean_env, inp=key_bytes)
        if imp.returncode != 0:
            raise PluginTrustError(
                f"failed to parse OpenPGP key {key_path}: {imp.stderr.decode('utf-8', 'replace').strip()}"
            )
        lst = _run_gpg(found_gpg, home, ["--with-colons", "--list-keys"], env=clean_env)
        if lst.returncode != 0:
            raise PluginTrustError(f"failed to list imported key from {key_path}")
        primary_fprs: list[str] = []
        uids: list[str] = []
        in_pub = False
        for line in lst.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split(":")
            rec = parts[0]
            if rec == "pub":
                in_pub = True
            elif rec == "sub":
                in_pub = False
            elif rec == "fpr" and in_pub and len(parts) > 9:
                primary_fprs.append(parts[9].upper())
                in_pub = False
            elif rec == "uid" and len(parts) > 9:
                uids.append(parts[9])
        if len(primary_fprs) != 1:
            raise PluginTrustError(
                f"OpenPGP key file {key_path} must contain exactly one primary key (found {len(primary_fprs)})"
            )
        return {
            "fingerprint": validate_fingerprint(primary_fprs[0], label="imported key fingerprint"),
            "uids": uids,
        }


def validate_openpgp_revocation_cert(
    cert_path: Path,
    expected_fingerprint: str,
    *,
    site_root: Path,
    policy: TrustPolicy,
    env: Mapping[str, str] | None = None,
    gpg_bin: str | None = None,
) -> bytes:
    """Verify `cert_path` is a valid OpenPGP revocation certificate targeting `expected_fingerprint` (L4)."""
    cert_bytes = read_regular_file_bytes(cert_path, max_bytes=MAX_KEY_FILE_BYTES, label="revocation certificate")
    clean_env = _offline_clean_env(env)
    _, bins = select_wot_backend("gpg", env=clean_env, gpg_bin=gpg_bin)
    found_gpg = bins["gpg"]
    # Verify packets contain a key revocation signature (sigclass 0x20 or 0x28).
    with _short_gpg_tempdir() as td:
        home = Path(td) / "g"
        home.mkdir(mode=0o700)
        pkt = _run_gpg(found_gpg, home, ["--list-packets"], env=clean_env, inp=cert_bytes)
        out = pkt.stdout.decode("utf-8", "replace")
        if pkt.returncode != 0 or "sigclass 0x20" not in out and "sigclass 0x28" not in out:
            raise PluginTrustError(
                f"revocation certificate {cert_path} does not contain a valid OpenPGP key revocation signature (0x20/0x28)"
            )
        # If the key is already in site-private keyring, prove the cert actually revokes expected_fingerprint.
        try:
            kr_dir = resolve_keyring_dir(site_root, policy.keyring_dir)
            key_files, _ = collect_keyring_files(kr_dir, policy)
            for kf in key_files:
                raw = read_regular_file_bytes(kf, max_bytes=MAX_KEY_FILE_BYTES, label=f"keyring file {kf.name}")
                _run_gpg(found_gpg, home, ["--import"], env=clean_env, inp=raw)
            has_key = _run_gpg(found_gpg, home, ["--with-colons", "--list-keys", expected_fingerprint], env=clean_env)
            if has_key.returncode == 0:
                imp_rev = _run_gpg(found_gpg, home, ["--import"], env=clean_env, inp=cert_bytes)
                if imp_rev.returncode != 0:
                    raise PluginTrustError(f"failed to apply revocation cert {cert_path} to keyring")
                after = _run_gpg(found_gpg, home, ["--with-colons", "--list-keys", expected_fingerprint], env=clean_env)
                pub_lines = [l for l in after.stdout.decode("utf-8", "replace").splitlines() if l.startswith("pub:")]
                if not pub_lines or pub_lines[0].split(":")[1] != "r":
                    raise PluginTrustError(
                        f"revocation certificate {cert_path} did not revoke target key {expected_fingerprint}"
                    )
        except PluginTrustError:
            raise
        except PluginManifestError as exc:
            raise PluginTrustError(str(exc)) from exc
    return cert_bytes


def _verify_anchor_key_files_match_gpg(
    gpg_bin: str,
    keyring_dir: Path,
    anchors: tuple[TrustAnchor, ...],
    clean_env: dict[str, str],
) -> None:
    """Confirm each declared anchor's `key_file` actually carries its declared primary fingerprint."""
    for anchor in anchors:
        info = inspect_openpgp_key(keyring_dir / anchor.key_file, env=clean_env, gpg_bin=gpg_bin)
        if info["fingerprint"] != anchor.fingerprint:
            raise PluginTrustError(
                f"trust anchor {anchor.label!r} key_file {anchor.key_file!r} contains fingerprint "
                f"{info['fingerprint']}, expected {anchor.fingerprint}"
            )


def _prepare_ephemeral_gpg_wot(
    gpg_bin: str,
    home: Path,
    keyring_dir: Path,
    key_files: list[Path],
    rev_files: list[Path],
    policy: TrustPolicy,
    *,
    historical: bool,
    as_of: datetime,
    clean_env: dict[str, str],
) -> tuple[list[str], set[str], set[str]]:
    """Populate ephemeral `GNUPGHOME` with keys, active revocations, and root ownertrust."""
    blocked_fprs = _active_revoked_fingerprints(policy, historical=historical, as_of=as_of)

    # Identify soft-revocation cert files that should be deferred in pre-revocation historical mode (L7).
    skip_soft_rev_certs: set[str] = set()
    if historical:
        for rev in policy.revocations:
            if rev.mode == "soft" and rev.cert_file is not None and as_of < rev.revoked_at_dt:
                skip_soft_rev_certs.add(rev.cert_file)

    # 1. Import all public keys first (L7: never fail because a .rev sorted ahead of its key).
    for kf in key_files:
        raw = read_regular_file_bytes(kf, max_bytes=MAX_KEY_FILE_BYTES, label=f"keyring file {kf.name}")
        imp = _run_gpg(gpg_bin, home, ["--import"], env=clean_env, inp=raw)
        if imp.returncode != 0:
            raise PluginTrustError(
                f"failed to import keyring file {kf.name}: {imp.stderr.decode('utf-8', 'replace').strip()}"
            )

    # 2. Import active revocation certificates (all hard certs; soft certs unless historical pre-revocation).
    for rf in rev_files:
        if rf.name in skip_soft_rev_certs:
            continue
        raw = read_regular_file_bytes(rf, max_bytes=MAX_KEY_FILE_BYTES, label=f"revocation cert {rf.name}")
        imp = _run_gpg(gpg_bin, home, ["--import"], env=clean_env, inp=raw)
        if imp.returncode != 0:
            raise PluginTrustError(
                f"failed to import revocation cert {rf.name}: {imp.stderr.decode('utf-8', 'replace').strip()}"
            )

    # 3. Actively remove any key whose primary or subkey fingerprint is blocked by [[trust.revocations]] (M3):
    #    this ensures a revoked root OR intermediate introducer CANNOT vouch for downstream keys
    #    even when no separate OpenPGP revocation certificate was stored!
    if blocked_fprs:
        lst = _run_gpg(gpg_bin, home, ["--with-colons", "--list-keys"], env=clean_env)
        current_primary: str | None = None
        primaries_to_delete: set[str] = set()
        for line in lst.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split(":")
            if parts[0] == "pub":
                current_primary = None
            elif parts[0] == "fpr" and len(parts) > 9:
                fpr = parts[9].upper()
                if current_primary is None:
                    current_primary = fpr
                if fpr in blocked_fprs and current_primary is not None:
                    primaries_to_delete.add(current_primary)
        for del_fpr in sorted(primaries_to_delete):
            _run_gpg(gpg_bin, home, ["--delete-keys", del_fpr], env=clean_env)

    # 4. Separate non-revoked root anchors from direct-signer-only anchors.
    root_anchors = {a.fingerprint for a in policy.anchors if a.role == "root" and a.fingerprint not in blocked_fprs}
    direct_anchors = {a.fingerprint for a in policy.anchors if a.role == "direct" and a.fingerprint not in blocked_fprs}

    gpg_depth = str(policy.max_depth + 1)
    wot_args = [
        "--trust-model",
        "pgp",
        "--max-cert-depth",
        gpg_depth,
        "--completes-needed",
        str(policy.full_threshold),
        "--marginals-needed",
        str(policy.marginal_threshold),
    ]
    if historical:
        wot_args.extend(["--faked-system-time", f"{int(as_of.timestamp())}!"])

    if root_anchors:
        ownertrust_blob = "".join(f"{fpr}:6:\n" for fpr in sorted(root_anchors)).encode("ascii")
        ot = _run_gpg(gpg_bin, home, ["--import-ownertrust"], env=clean_env, inp=ownertrust_blob)
        if ot.returncode != 0:
            raise PluginTrustError(
                f"failed to import ownertrust: {ot.stderr.decode('utf-8', 'replace').strip()}"
            )

    chk = _run_gpg(gpg_bin, home, [*wot_args, "--check-trustdb"], env=clean_env)
    if chk.returncode != 0:
        raise PluginTrustError(
            f"gpg --check-trustdb failed: {chk.stderr.decode('utf-8', 'replace').strip()}"
        )
    return wot_args, root_anchors, direct_anchors


def verify_signer_reachable_in_wot(
    primary_fingerprint: str,
    *,
    signing_subkey_fingerprint: str | None = None,
    site_root: Path,
    policy: TrustPolicy,
    historical: bool = False,
    as_of: datetime | None = None,
    issued_at: datetime | None = None,
    verified_at: datetime | None = None,
    env: Mapping[str, str] | None = None,
    gpg_bin: str | None = None,
) -> tuple[str, tuple[str, ...]]:
    """Verify that a pinned signer key is still valid and reachable from current trust anchors (M3).

    Returns `(trust_level, warnings)` or raises `PluginTrustError`.
    """
    effective_as_of = (as_of if as_of is not None else utc_now()).astimezone(timezone.utc)
    if not historical and as_of is not None:
        raise PluginTrustError("--as-of may only be used with historical verification (--historical)")
    if not policy.anchors:
        raise PluginTrustError("no trust anchors configured in plugins.toml (cannot verify signer reachability)")

    warnings: list[str] = []
    check_fprs = {primary_fingerprint}
    if signing_subkey_fingerprint:
        check_fprs.add(signing_subkey_fingerprint)
    for fpr in sorted(check_fprs):
        warnings.extend(
            evaluate_revocation_policy(
                fpr,
                policy,
                historical=historical,
                as_of=effective_as_of,
                issued_at=issued_at,
                verified_at=verified_at,
            )
        )

    keyring_dir = resolve_keyring_dir(site_root, policy.keyring_dir)
    key_files, rev_files = collect_keyring_files(keyring_dir, policy)
    clean_env = _offline_clean_env(env)
    _, bins = select_wot_backend(policy.backend, env=clean_env, gpg_bin=gpg_bin)
    found_gpg = bins["gpg"]
    _verify_anchor_key_files_match_gpg(found_gpg, keyring_dir, policy.anchors, clean_env)

    with _short_gpg_tempdir() as td:
        home = Path(td) / "g"
        home.mkdir(mode=0o700)
        wot_args, root_anchors, direct_anchors = _prepare_ephemeral_gpg_wot(
            found_gpg,
            home,
            keyring_dir,
            key_files,
            rev_files,
            policy,
            historical=historical,
            as_of=effective_as_of,
            clean_env=clean_env,
        )
        lst = _run_gpg(
            found_gpg,
            home,
            [*wot_args, "--with-colons", "--list-keys", primary_fingerprint],
            env=clean_env,
        )
        if lst.returncode != 0:
            raise PluginTrustError(
                f"pinned signer {primary_fingerprint} is absent or revoked in site-private keyring"
            )
        pub_validity: str | None = None
        for line in lst.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split(":")
            if parts[0] == "pub" and len(parts) > 1:
                pub_validity = parts[1]
                break
        if pub_validity in ("r", "e", "d", "i"):
            raise PluginTrustError(
                f"pinned signer {primary_fingerprint} is revoked/expired/invalid in keyring (status={pub_validity!r})"
            )
        if pub_validity == "u" and primary_fingerprint in root_anchors:
            return "ultimate", tuple(warnings)
        if pub_validity == "f":
            return "full", tuple(warnings)
        if primary_fingerprint in direct_anchors and pub_validity in ("-", "q", "n", "m", "f"):
            return "direct", tuple(warnings)
        raise PluginTrustError(
            f"pinned signer {primary_fingerprint} is no longer reachable from current trust anchors "
            f"(gpg validity={pub_validity!r}, max_depth={policy.max_depth})"
        )


def verify_detached_manifest_signature(
    manifest_path: Path | None,
    sig_path: Path,
    *,
    site_root: Path,
    policy: TrustPolicy,
    manifest_bytes: bytes | None = None,
    historical: bool = False,
    as_of: datetime | None = None,
    issued_at: datetime | None = None,
    verified_at: datetime | None = None,
    env: Mapping[str, str] | None = None,
    gpg_bin: str | None = None,
) -> WoTVerificationResult:
    """Verify detached OpenPGP signature over exact manifest bytes using the site's offline WoT.

    Pass `manifest_bytes` (e.g. `manifest.raw_bytes`) to eliminate verify-then-reopen TOCTOU (M1).
    """
    effective_as_of = (as_of if as_of is not None else utc_now()).astimezone(timezone.utc)
    if not historical and as_of is not None:
        raise PluginTrustError("--as-of may only be used with historical verification (--historical)")
    if not policy.anchors:
        raise PluginTrustError("no trust anchors configured in plugins.toml (cannot establish Web of Trust)")

    if manifest_bytes is None:
        if manifest_path is None:
            raise PluginTrustError("manifest_path or manifest_bytes is required")
        manifest_bytes = read_regular_file_bytes(
            manifest_path, max_bytes=MAX_KEY_FILE_BYTES, label="plugin release manifest"
        )
    sig_bytes = read_regular_file_bytes(sig_path, max_bytes=MAX_SIG_FILE_BYTES, label="detached signature")
    _validate_detached_armored_sig(sig_bytes, str(sig_path))

    keyring_dir = resolve_keyring_dir(site_root, policy.keyring_dir)
    key_files, rev_files = collect_keyring_files(keyring_dir, policy)

    clean_env = _offline_clean_env(env)
    backend, bins = select_wot_backend(policy.backend, env=clean_env, gpg_bin=gpg_bin)
    found_gpg = bins["gpg"]
    _verify_anchor_key_files_match_gpg(found_gpg, keyring_dir, policy.anchors, clean_env)

    with _short_gpg_tempdir() as td:
        td_path = Path(td)
        home = td_path / "g"
        home.mkdir(mode=0o700)

        # Write exact in-memory bytes to private 0700 temp files (zero TOCTOU on caller paths, M1).
        priv_manifest = td_path / "manifest.json"
        priv_sig = td_path / "manifest.json.asc"
        priv_manifest.write_bytes(manifest_bytes)
        priv_sig.write_bytes(sig_bytes)

        wot_args, root_anchors, direct_anchors = _prepare_ephemeral_gpg_wot(
            found_gpg,
            home,
            keyring_dir,
            key_files,
            rev_files,
            policy,
            historical=historical,
            as_of=effective_as_of,
            clean_env=clean_env,
        )

        ver = _run_gpg(
            found_gpg,
            home,
            [*wot_args, "--status-fd", "1", "--verify", str(priv_sig), str(priv_manifest)],
            env=clean_env,
        )

    status_lines = ver.stdout.decode("utf-8", "replace").splitlines()
    validsigs: list[list[str]] = []
    trust_lines: list[str] = []
    bad_statuses: list[str] = []

    for line in status_lines:
        if not line.startswith("[GNUPG:] "):
            continue
        tokens = line.split()
        if len(tokens) < 2:
            continue
        code = tokens[1]
        if code == "VALIDSIG":
            validsigs.append(tokens)
        elif code.startswith("TRUST_"):
            trust_lines.append(code)
        elif code in ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "NODATA"):
            bad_statuses.append(line)

    if bad_statuses:
        # If an ERRSIG/NO_PUBKEY corresponds to a fingerprint we actively stripped because of
        # [[trust.revocations]], surface the clear SOFT-REVOKED / HARD-REVOKED diagnostic!
        for b in bad_statuses:
            parts = b.split()
            if len(parts) >= 9 and parts[1] == "ERRSIG":
                cand_fpr = parts[8].upper()
                try:
                    cand_fpr = validate_fingerprint(cand_fpr, label="ERRSIG fingerprint")
                except PluginManifestError:
                    continue
                evaluate_revocation_policy(
                    cand_fpr,
                    policy,
                    historical=historical,
                    as_of=effective_as_of,
                    issued_at=issued_at,
                    verified_at=verified_at,
                )
        raise PluginTrustError(f"OpenPGP signature verification failed ({'; '.join(bad_statuses)})")
    if ver.returncode != 0 or len(validsigs) != 1:
        detail = ver.stderr.decode("utf-8", "replace").strip()
        raise PluginTrustError(
            f"OpenPGP signature verification failed (exit={ver.returncode}, validsigs={len(validsigs)}): {detail}"
        )

    # VALIDSIG <signing_fpr> <date> <sig_ts> <expire_ts> <sig_ver> <reserved> <pubkey_algo> <hash_algo> <sig_class> [primary_fpr]
    vs = validsigs[0]
    if len(vs) < 11:
        raise PluginTrustError(f"malformed gpg VALIDSIG line: {' '.join(vs)}")
    signing_fpr = validate_fingerprint(vs[2], label="signing key fingerprint")
    try:
        sig_ts = int(vs[4])
        pubkey_algo = int(vs[8])
        hash_algo = int(vs[9])
    except ValueError as exc:
        raise PluginTrustError(f"malformed numeric fields in VALIDSIG: {' '.join(vs)}") from exc

    if hash_algo not in ALLOWED_HASH_ALGOS:
        raise PluginTrustError(
            f"weak or disallowed OpenPGP signature hash algorithm id={hash_algo} "
            f"(required one of {sorted(ALLOWED_HASH_ALGOS)}; SHA-1/MD5 refused)"
        )
    if pubkey_algo not in ALLOWED_PUBKEY_ALGOS:
        raise PluginTrustError(
            f"disallowed OpenPGP signing key algorithm id={pubkey_algo} "
            f"(required one of {sorted(ALLOWED_PUBKEY_ALGOS)})"
        )

    sig_created_dt = datetime.fromtimestamp(sig_ts, tz=timezone.utc)
    primary_fpr = (
        validate_fingerprint(vs[11], label="primary key fingerprint")
        if len(vs) >= 12
        else signing_fpr
    )

    warnings: list[str] = []
    for fpr in sorted({primary_fpr, signing_fpr}):
        warnings.extend(
            evaluate_revocation_policy(
                fpr,
                policy,
                historical=historical,
                as_of=effective_as_of,
                issued_at=issued_at,
                verified_at=verified_at,
                sig_created_at=sig_created_dt,
            )
        )

    if len(trust_lines) != 1:
        raise PluginTrustError(f"ambiguous or missing OpenPGP trust status (got {trust_lines!r})")
    trust_code = trust_lines[0]
    if trust_code == "TRUST_ULTIMATE":
        if primary_fpr not in root_anchors:
            raise PluginTrustError(f"unexpected TRUST_ULTIMATE for non-root key {primary_fpr}")
        trust_level = "ultimate"
    elif trust_code == "TRUST_FULLY":
        trust_level = "full"
    elif primary_fpr in direct_anchors and trust_code in ("TRUST_UNDEFINED", "TRUST_MARGINAL"):
        trust_level = "direct"
    else:
        raise PluginTrustError(
            f"OpenPGP Web-of-Trust check failed for signer {primary_fpr}: "
            f"gpg reported {trust_code} (required TRUST_ULTIMATE/TRUST_FULLY within max_depth={policy.max_depth}, "
            f"or explicit role='direct' anchor)"
        )

    return WoTVerificationResult(
        backend=backend,
        primary_fingerprint=primary_fpr,
        signing_fingerprint=signing_fpr,
        sig_created_at=format_rfc3339_utc(sig_created_dt),
        trust_level=trust_level,
        historical=historical,
        as_of=format_rfc3339_utc(effective_as_of),
        warnings=tuple(warnings),
    )
