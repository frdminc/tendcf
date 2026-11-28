"""Offline OpenPGP Web-of-Trust verifier for third-party tendcf plugins (issue #47).

Implements the 2026-11-28 operator rulings:
- Offline site-private keyring only (never contacts keyservers or WKD; never reads `~/.gnupg`
  or `~/.local/share/sequoia`).
- Bounded Web of Trust: default `max_depth = 1`, configurable `0..2`, with `full_threshold`
  and `marginal_threshold` support.
  - `max_depth = 0`: site trust anchors (`role = "root"`) and keys they directly certify
    (plus `role = "direct"` direct-signer-only anchors, which cannot act as introducers).
  - `max_depth = 1`: anchors + up to 1 intermediate introducer certified via OpenPGP trust sig.
  - `max_depth = 2`: anchors + up to 2 intermediate introducers.
- Pluggable offline backend:
  - `sequoia`: uses Sequoia `sq` + `sq-wot` with ephemeral `--home` and `--network-policy offline`
    (preferred under `backend = "auto"` when both binaries are present).
  - `gpg`: uses GnuPG `gpg` with ephemeral `0700` `GNUPGHOME`, `--batch --no-tty --no-options`,
    `--trust-model pgp`, `--no-auto-key-retrieve`, `--no-auto-key-locate`,
    `--max-cert-depth (max_depth + 1)`, `--completes-needed`, `--marginals-needed`.
- Revocation enforcement:
  - `hard` revocation: always refuses verification (even historical rebuilds).
  - `soft` revocation: refuses new `add`/`update` and current builds; permits historical rebuild
    verification (`historical=True` with `--as-of`) ONLY when `as_of`, `issued_at`, `verified_at`,
    and `sig_created_at` are all strictly before `revoked_at`, returning an explicit warning.
"""

from __future__ import annotations

import json
import os
import re
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
    KeyRevocation,
    PluginManifestError,
    TrustAnchor,
    TrustPolicy,
    format_rfc3339_utc,
    parse_rfc3339_utc,
    read_regular_file_bytes,
    utc_now,
    validate_fingerprint,
)

MAX_KEY_FILE_BYTES = 1024 * 1024
MAX_SIG_FILE_BYTES = 128 * 1024
PGP_COMMAND_TIMEOUT = 30.0

ARMORED_SIG_BEGIN = "-----BEGIN PGP SIGNATURE-----"
ARMORED_SIG_END = "-----END PGP SIGNATURE-----"
ARMORED_KEY_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
KEY_EXTS = frozenset({".asc", ".gpg", ".pgp", ".pub", ".rev"})


class PluginTrustError(Exception):
    """OpenPGP signature, Web-of-Trust path, revocation, or keyring check failed closed."""


@dataclass(frozen=True)
class WoTVerificationResult:
    backend: str  # "sequoia" | "gpg"
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


def resolve_keyring_dir(site_root: Path, keyring_rel: str) -> Path:
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
        except OSError as exc:
            raise PluginTrustError(f"site-private keyring directory missing: {cur} ({exc})") from exc
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise PluginTrustError(f"keyring directory component must be a real non-symlink directory: {cur}")
    resolved_kr = cur.resolve(strict=True)
    if not resolved_kr.is_relative_to(resolved_site):
        raise PluginTrustError(f"keyring directory {resolved_kr} escapes site directory {resolved_site}")
    return resolved_kr


def collect_keyring_files(keyring_dir: Path, policy: TrustPolicy) -> tuple[list[Path], list[Path]]:
    """Collect verified non-symlink key files and revocation cert files inside `keyring_dir`.

    Returns `(all_key_files, anchor_key_files)`. Refuses any symlink inside `keyring_dir`
    and verifies every anchor's `key_file` and every revocation's `cert_file` exists.
    """
    all_files: list[Path] = []
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
        if p.suffix.lower() not in KEY_EXTS:
            continue
        resolved = p.resolve(strict=True)
        if resolved.parent != keyring_dir:
            raise PluginTrustError(f"keyring file {p} resolves outside {keyring_dir}")
        all_files.append(resolved)
        seen_names.add(entry.name)

    anchor_files: list[Path] = []
    for anchor in policy.anchors:
        if anchor.key_file not in seen_names:
            raise PluginTrustError(
                f"trust anchor {anchor.label!r} ({anchor.fingerprint}) key_file {anchor.key_file!r} "
                f"is missing from {keyring_dir}"
            )
        anchor_files.append(keyring_dir / anchor.key_file)

    for rev in policy.revocations:
        if rev.cert_file is not None and rev.cert_file not in seen_names:
            raise PluginTrustError(
                f"revocation cert_file {rev.cert_file!r} for {rev.fingerprint} is missing from {keyring_dir}"
            )

    return all_files, anchor_files


def select_wot_backend(
    preferred: str,
    *,
    env: Mapping[str, str] | None = None,
    sq_bin: str | None = None,
    sq_wot_bin: str | None = None,
    gpg_bin: str | None = None,
) -> tuple[str, dict[str, str]]:
    """Select offline OpenPGP backend ('sequoia' or 'gpg') and return resolved tool paths."""
    path_env = (os.environ if env is None else env).get("PATH")
    found_sq = sq_bin if sq_bin is not None else shutil.which("sq", path=path_env)
    found_sq_wot = sq_wot_bin if sq_wot_bin is not None else shutil.which("sq-wot", path=path_env)
    found_gpg = gpg_bin if gpg_bin is not None else shutil.which("gpg", path=path_env)

    if preferred == "sequoia":
        if not found_sq or not found_sq_wot:
            raise PluginTrustError(
                "trust.backend='sequoia' requires both 'sq' and 'sq-wot' on PATH "
                f"(found sq={found_sq!r}, sq-wot={found_sq_wot!r})"
            )
        return "sequoia", {"sq": found_sq, "sq_wot": found_sq_wot}
    if preferred == "gpg":
        if not found_gpg:
            raise PluginTrustError("trust.backend='gpg' requires 'gpg' on PATH (not found)")
        return "gpg", {"gpg": found_gpg}
    if preferred == "auto":
        if found_sq and found_sq_wot:
            return "sequoia", {"sq": found_sq, "sq_wot": found_sq_wot}
        if found_gpg:
            return "gpg", {"gpg": found_gpg}
        raise PluginTrustError(
            "no offline OpenPGP backend found on PATH (install Sequoia 'sq' + 'sq-wot' or GnuPG 'gpg')"
        )
    raise PluginTrustError(f"unsupported OpenPGP backend {preferred!r}")


def _validate_detached_armored_sig(sig_bytes: bytes, sig_path: Path) -> None:
    """Require an ASCII-armored detached PGP signature (refuse clearsigned/multi-sig blobs)."""
    try:
        text = sig_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PluginTrustError(
            f"detached signature {sig_path} must be ASCII-armored UTF-8 OpenPGP signature: {exc}"
        ) from exc
    if "-----BEGIN PGP SIGNED MESSAGE-----" in text:
        raise PluginTrustError(
            f"clearsigned document refused for {sig_path}; detached ASCII-armored signature required"
        )
    begins = text.count(ARMORED_SIG_BEGIN)
    ends = text.count(ARMORED_SIG_END)
    if begins != 1 or ends != 1:
        raise PluginTrustError(
            f"signature {sig_path} must contain exactly one '{ARMORED_SIG_BEGIN}' block (found {begins}/{ends})"
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
            f"signer key {fingerprint} is HARD-REVOKED as of {rev.revoked_at} ({rev.reason}); "
            "all verification including historical rebuilds is refused"
        )

    # Soft revocation: always blocks non-historical operations (`add`, `update`, current releases).
    if not historical:
        raise PluginTrustError(
            f"signer key {fingerprint} is SOFT-REVOKED as of {rev.revoked_at} ({rev.reason}); "
            "new installs/updates and current releases are refused (historical rebuilds require "
            "--historical --as-of before revoked_at)"
        )

    # Historical rebuild check: every relevant timestamp MUST strictly precede `revoked_at`.
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
                f"signer key {fingerprint} was SOFT-REVOKED at {rev.revoked_at} ({rev.reason}), "
                f"and {label} ({format_rfc3339_utc(ts)}) is not strictly before revocation"
            )

    return (
        f"soft_revoked_after_pin: signer key {fingerprint} was soft-revoked at {rev.revoked_at} "
        f"({rev.reason}); historical verification at {format_rfc3339_utc(as_of)} permitted",
    )


def _offline_clean_env(base_env: Mapping[str, str] | None) -> dict[str, str]:
    src = os.environ if base_env is None else base_env
    clean: dict[str, str] = {"LC_ALL": "C"}
    for keep in ("PATH", "TMPDIR", "TEMP", "TMP"):
        if keep in src:
            clean[keep] = src[keep]
    # Strip proxies & ambient GPG/Sequoia vars so no accidental network/homedir leak is possible.
    return clean


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


def _short_gpg_tempdir() -> tempfile.TemporaryDirectory[str]:
    """Create a short-path temp dir so macOS's 104-byte Unix socket limit never breaks gpg-agent."""
    base = Path("/tmp") if Path("/tmp").is_dir() and len(tempfile.gettempdir()) > 40 else None
    return tempfile.TemporaryDirectory(prefix="tgpg.", dir=str(base) if base is not None else None)


def inspect_openpgp_key(
    key_path: Path,
    *,
    env: Mapping[str, str] | None = None,
    gpg_bin: str | None = None,
    sq_bin: str | None = None,
) -> dict[str, Any]:
    """Inspect a public OpenPGP key file offline and return primary fingerprint + user IDs."""
    key_bytes = read_regular_file_bytes(key_path, max_bytes=MAX_KEY_FILE_BYTES, label="OpenPGP key file")
    clean_env = _offline_clean_env(env)
    found_gpg = gpg_bin if gpg_bin is not None else shutil.which("gpg", path=clean_env.get("PATH"))
    if found_gpg:
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
    raise PluginTrustError("gpg is required to inspect OpenPGP key files offline (not found on PATH)")


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


def _verify_with_gpg(
    gpg_bin: str,
    manifest_path: Path,
    sig_path: Path,
    keyring_dir: Path,
    all_key_files: list[Path],
    policy: TrustPolicy,
    *,
    historical: bool,
    as_of: datetime,
    issued_at: datetime | None,
    verified_at: datetime | None,
    clean_env: dict[str, str],
) -> WoTVerificationResult:
    if not policy.anchors:
        raise PluginTrustError("no trust anchors configured in plugins.toml (cannot establish Web of Trust)")

    _verify_anchor_key_files_match_gpg(gpg_bin, keyring_dir, policy.anchors, clean_env)

    # Separate root anchors (can introduce up to max_depth) from direct-signer-only anchors
    # (trusted to sign plugins directly, NEVER given ultimate ownertrust in gpg).
    root_anchors = {a.fingerprint for a in policy.anchors if a.role == "root"}
    direct_anchors = {a.fingerprint for a in policy.anchors if a.role == "direct"}

    # Empirically verified on GnuPG 2.5.24:
    #   max_depth = 0 (direct anchor / anchor -> author)       => --max-cert-depth 1
    #   max_depth = 1 (anchor -> 1 introducer -> author)       => --max-cert-depth 2
    #   max_depth = 2 (anchor -> 2 introducers -> author)      => --max-cert-depth 3
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
        # Freeze gpg clock at `as_of` strictly for historical rebuild verification.
        wot_args.extend(["--faked-system-time", f"{int(as_of.timestamp())}!"] )

    with _short_gpg_tempdir() as td:
        home = Path(td) / "g"
        home.mkdir(mode=0o700)

        # Import all keyring files offline.
        for kf in all_key_files:
            raw = read_regular_file_bytes(kf, max_bytes=MAX_KEY_FILE_BYTES, label=f"keyring file {kf.name}")
            imp = _run_gpg(gpg_bin, home, ["--import"], env=clean_env, inp=raw)
            if imp.returncode != 0:
                raise PluginTrustError(
                    f"failed to import keyring file {kf.name}: {imp.stderr.decode('utf-8', 'replace').strip()}"
                )

        # Grant ultimate ownertrust ONLY to declared `role = "root"` anchors.
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

        ver = _run_gpg(
            gpg_bin,
            home,
            [*wot_args, "--status-fd", "1", "--verify", str(sig_path), str(manifest_path)],
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
        raise PluginTrustError(
            f"OpenPGP signature verification failed ({'; '.join(bad_statuses)})"
        )
    if ver.returncode != 0 or len(validsigs) != 1:
        detail = ver.stderr.decode("utf-8", "replace").strip()
        raise PluginTrustError(
            f"OpenPGP signature verification failed (exit={ver.returncode}, validsigs={len(validsigs)}): {detail}"
        )

    # VALIDSIG <signing_fpr> <sig_creation_date> <sig_ts> <expire_ts> <sig_ver> <reserved> <pubkey_algo> <hash_algo> <sig_class> [primary_fpr]
    vs = validsigs[0]
    if len(vs) < 5:
        raise PluginTrustError(f"malformed gpg VALIDSIG line: {' '.join(vs)}")
    signing_fpr = validate_fingerprint(vs[2], label="signing key fingerprint")
    try:
        sig_ts = int(vs[4])
    except ValueError as exc:
        raise PluginTrustError(f"invalid signature timestamp in VALIDSIG: {vs[4]!r}") from exc
    sig_created_dt = datetime.fromtimestamp(sig_ts, tz=timezone.utc)
    primary_fpr = (
        validate_fingerprint(vs[11], label="primary key fingerprint")
        if len(vs) >= 12
        else signing_fpr
    )

    # Enforce explicit site-private revocation policy (both soft & hard) for primary and signing keys.
    warnings: list[str] = []
    for fpr in ({primary_fpr, signing_fpr}):
        warnings.extend(
            evaluate_revocation_policy(
                fpr,
                policy,
                historical=historical,
                as_of=as_of,
                issued_at=issued_at,
                verified_at=verified_at,
                sig_created_at=sig_created_dt,
            )
        )

    # Enforce Web-of-Trust validity level.
    if len(trust_lines) != 1:
        raise PluginTrustError(
            f"ambiguous or missing OpenPGP trust status (got {trust_lines!r})"
        )
    trust_code = trust_lines[0]
    if trust_code == "TRUST_ULTIMATE":
        if primary_fpr not in root_anchors:
            raise PluginTrustError(
                f"unexpected TRUST_ULTIMATE for non-root key {primary_fpr}"
            )
        trust_level = "ultimate"
    elif trust_code == "TRUST_FULLY":
        trust_level = "full"
    elif primary_fpr in direct_anchors and trust_code in ("TRUST_UNDEFINED", "TRUST_MARGINAL"):
        # Directly trusted signer-only anchor (explicitly excluded from root introducers).
        trust_level = "direct"
    else:
        raise PluginTrustError(
            f"OpenPGP Web-of-Trust check failed for signer {primary_fpr}: "
            f"gpg reported {trust_code} (required TRUST_ULTIMATE/TRUST_FULLY within max_depth={policy.max_depth}, "
            f"or explicit role='direct' anchor)"
        )

    return WoTVerificationResult(
        backend="gpg",
        primary_fingerprint=primary_fpr,
        signing_fingerprint=signing_fpr,
        sig_created_at=format_rfc3339_utc(sig_created_dt),
        trust_level=trust_level,
        historical=historical,
        as_of=format_rfc3339_utc(as_of),
        warnings=tuple(warnings),
    )


def _verify_with_sequoia(
    sq_bin: str,
    sq_wot_bin: str,
    manifest_path: Path,
    sig_path: Path,
    keyring_dir: Path,
    all_key_files: list[Path],
    policy: TrustPolicy,
    *,
    historical: bool,
    as_of: datetime,
    issued_at: datetime | None,
    verified_at: datetime | None,
    clean_env: dict[str, str],
) -> WoTVerificationResult:
    """Offline verification using Sequoia `sq` (signature check) + `sq-wot` (bounded WoT)."""
    if not policy.anchors:
        raise PluginTrustError("no trust anchors configured in plugins.toml (cannot establish Web of Trust)")

    root_anchors = {a.fingerprint for a in policy.anchors if a.role == "root"}
    direct_anchors = {a.fingerprint for a in policy.anchors if a.role == "direct"}

    with tempfile.TemporaryDirectory(prefix="tendcf-sq-wot.") as td:
        sq_home = Path(td) / "sq-home"
        sq_home.mkdir(mode=0o700)
        combined_keyring = Path(td) / "keyring.pgp"
        chunks: list[bytes] = []
        for kf in all_key_files:
            chunks.append(read_regular_file_bytes(kf, max_bytes=MAX_KEY_FILE_BYTES, label=f"keyring file {kf.name}"))
            chunks.append(b"\n")
        combined_keyring.write_bytes(b"".join(chunks))

        run_env = dict(clean_env)
        run_env["SEQUOIA_HOME"] = str(sq_home)

        # Step 1: Verify detached signature offline against the combined keyring.
        sq_argv = [
            sq_bin,
            "--batch",
            "--home",
            str(sq_home),
            "--network-policy",
            "offline",
            "verify",
            "--signature-file",
            str(sig_path),
            "--signer-file",
            str(combined_keyring),
            "--output-format",
            "json",
        ]
        if historical:
            sq_argv.extend(["--time", format_rfc3339_utc(as_of)])
        sq_argv.append(str(manifest_path))

        try:
            ver = subprocess.run(
                sq_argv,
                capture_output=True,
                env=run_env,
                timeout=PGP_COMMAND_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PluginTrustError(f"sq verify timed out after {PGP_COMMAND_TIMEOUT}s") from exc
        except OSError as exc:
            raise PluginTrustError(f"failed to invoke sq ({sq_bin}): {exc}") from exc

        if ver.returncode != 0:
            raise PluginTrustError(
                f"Sequoia signature verification failed: {ver.stderr.decode('utf-8', 'replace').strip()}"
            )

        try:
            sq_out = json.loads(ver.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PluginTrustError(f"Sequoia verify returned non-JSON output: {exc}") from exc

        sigs = sq_out.get("signatures") if isinstance(sq_out, dict) else None
        if not isinstance(sigs, list) or len(sigs) != 1 or not isinstance(sigs[0], dict):
            raise PluginTrustError(f"Sequoia verify must return exactly one verified signature (got {sq_out!r})")
        sig_rec = sigs[0]
        if sig_rec.get("status") != "good":
            raise PluginTrustError(f"Sequoia signature status is not 'good': {sig_rec!r}")
        primary_fpr = validate_fingerprint(sig_rec.get("primary_fingerprint"), label="Sequoia primary fingerprint")
        signing_fpr = validate_fingerprint(
            sig_rec.get("signing_fingerprint", primary_fpr), label="Sequoia signing fingerprint"
        )
        sig_created_dt = parse_rfc3339_utc(sig_rec.get("created_at"), label="Sequoia signature created_at")

        # Enforce site-private revocation policy before trust path check.
        warnings: list[str] = []
        for fpr in ({primary_fpr, signing_fpr}):
            warnings.extend(
                evaluate_revocation_policy(
                    fpr,
                    policy,
                    historical=historical,
                    as_of=as_of,
                    issued_at=issued_at,
                    verified_at=verified_at,
                    sig_created_at=sig_created_dt,
                )
            )

        # Direct root or direct-signer anchor needs no further WoT path traversal.
        if primary_fpr in root_anchors:
            trust_level = "ultimate"
        elif primary_fpr in direct_anchors:
            trust_level = "direct"
        else:
            if not root_anchors:
                raise PluginTrustError(
                    f"signer {primary_fpr} is not a direct anchor and no role='root' anchors exist for Web of Trust"
                )
            # Step 2: Query sq-wot offline with exact bounded depth & trust roots.
            wot_argv = [
                sq_wot_bin,
                "--keyring",
                str(combined_keyring),
                "--output-format",
                "json",
                "--time",
                format_rfc3339_utc(as_of),
                "--trust-amount",
                "120",
            ]
            for root_fpr in sorted(root_anchors):
                wot_argv.extend(["--trust-root", root_fpr])
            wot_argv.extend(["authenticate", primary_fpr, "--depth", str(policy.max_depth)])
            try:
                wot = subprocess.run(
                    wot_argv,
                    capture_output=True,
                    env=run_env,
                    timeout=PGP_COMMAND_TIMEOUT,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise PluginTrustError(f"sq-wot timed out after {PGP_COMMAND_TIMEOUT}s") from exc
            except OSError as exc:
                raise PluginTrustError(f"failed to invoke sq-wot ({sq_wot_bin}): {exc}") from exc

            if wot.returncode != 0:
                raise PluginTrustError(
                    f"Sequoia Web-of-Trust authentication failed for {primary_fpr} "
                    f"(max_depth={policy.max_depth}): {wot.stderr.decode('utf-8', 'replace').strip()}"
                )
            try:
                wot_out = json.loads(wot.stdout.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise PluginTrustError(f"sq-wot returned non-JSON output: {exc}") from exc
            amount = wot_out.get("trust_amount", 0) if isinstance(wot_out, dict) else 0
            depth_used = wot_out.get("depth") if isinstance(wot_out, dict) else None
            if not isinstance(amount, int) or isinstance(amount, bool) or amount < 120:
                raise PluginTrustError(
                    f"Sequoia WoT trust amount insufficient for {primary_fpr}: {amount!r} (< 120)"
                )
            if isinstance(depth_used, int) and not isinstance(depth_used, bool) and depth_used > policy.max_depth:
                raise PluginTrustError(
                    f"Sequoia WoT path depth {depth_used} exceeds configured max_depth {policy.max_depth}"
                )
            trust_level = "full"

    return WoTVerificationResult(
        backend="sequoia",
        primary_fingerprint=primary_fpr,
        signing_fingerprint=signing_fpr,
        sig_created_at=format_rfc3339_utc(sig_created_dt),
        trust_level=trust_level,
        historical=historical,
        as_of=format_rfc3339_utc(as_of),
        warnings=tuple(warnings),
    )


def verify_detached_manifest_signature(
    manifest_path: Path,
    sig_path: Path,
    *,
    site_root: Path,
    policy: TrustPolicy,
    historical: bool = False,
    as_of: datetime | None = None,
    issued_at: datetime | None = None,
    verified_at: datetime | None = None,
    env: Mapping[str, str] | None = None,
    sq_bin: str | None = None,
    sq_wot_bin: str | None = None,
    gpg_bin: str | None = None,
) -> WoTVerificationResult:
    """Verify detached OpenPGP signature over `manifest_path` using the site's offline WoT."""
    effective_as_of = (as_of if as_of is not None else utc_now()).astimezone(timezone.utc)
    if not historical and as_of is not None:
        raise PluginTrustError("--as-of may only be used with historical verification (--historical)")

    # Verify both files are regular non-symlink files before invoking any crypto binary.
    read_regular_file_bytes(manifest_path, max_bytes=MAX_KEY_FILE_BYTES, label="plugin release manifest")
    sig_bytes = read_regular_file_bytes(sig_path, max_bytes=MAX_SIG_FILE_BYTES, label="detached signature")
    _validate_detached_armored_sig(sig_bytes, sig_path)

    keyring_dir = resolve_keyring_dir(site_root, policy.keyring_dir)
    all_key_files, _ = collect_keyring_files(keyring_dir, policy)

    clean_env = _offline_clean_env(env)
    backend, bins = select_wot_backend(
        policy.backend,
        env=clean_env,
        sq_bin=sq_bin,
        sq_wot_bin=sq_wot_bin,
        gpg_bin=gpg_bin,
    )

    if backend == "sequoia":
        return _verify_with_sequoia(
            bins["sq"],
            bins["sq_wot"],
            manifest_path.resolve(strict=True),
            sig_path.resolve(strict=True),
            keyring_dir,
            all_key_files,
            policy,
            historical=historical,
            as_of=effective_as_of,
            issued_at=issued_at,
            verified_at=verified_at,
            clean_env=clean_env,
        )
    return _verify_with_gpg(
        bins["gpg"],
        manifest_path.resolve(strict=True),
        sig_path.resolve(strict=True),
        keyring_dir,
        all_key_files,
        policy,
        historical=historical,
        as_of=effective_as_of,
        issued_at=issued_at,
        verified_at=verified_at,
        clean_env=clean_env,
    )
