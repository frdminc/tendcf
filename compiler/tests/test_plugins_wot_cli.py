"""Comprehensive tests for issue #47: OpenPGP Web of Trust, wheel verification,
isolated plugin environments, non-deduplicating entry-point loading, and `tendcf plugin` CLI.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import warnings
import zipfile
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from tendcf import cli
from tendcf.plugin_env import (
    PluginEnvError,
    assert_isolated_plugin_env_path,
    discover_env_entry_points,
    stage_plugin_env,
    verify_release_wheels,
    verify_wheel_artifact,
)
from tendcf.plugin_manifest import (
    KeyRevocation,
    PluginManifestError,
    SitePluginsConfig,
    TrustAnchor,
    TrustPolicy,
    format_rfc3339_utc,
    load_release_manifest,
    load_site_plugins_config,
    parse_release_manifest_bytes,
    parse_site_plugins_toml,
    render_site_plugins_toml,
    utc_now,
    write_site_plugins_config,
)
from tendcf.plugin_wot import (
    PluginTrustError,
    select_wot_backend,
    verify_detached_manifest_signature,
)
from tendcf.plugins import PluginError, load_configured_plugin, load_out_of_tree_plugin

COMPILER_DIR = Path(__file__).resolve().parent.parent
TENDCF_ROOT = COMPILER_DIR.parent
SITE_EXAMPLE = COMPILER_DIR / "examples" / "site"
HOST_KEY = "ed25519:" + "b2" * 32


# ---------------------------------------------------------------------------
# Helpers: real GnuPG key/WoT fixture builder + PEP 427 wheel builder
# ---------------------------------------------------------------------------


@pytest.fixture
def gpg_tmp() -> Any:
    """Short temp dir under /tmp so gpg-agent Unix sockets stay below macOS's 104-byte limit."""
    base = "/tmp" if Path("/tmp").is_dir() else None
    with tempfile.TemporaryDirectory(prefix="tg.", dir=base) as td:
        yield Path(td)


def _gpg_run(home: Path, *args: str, inp: str | None = None) -> subprocess.CompletedProcess[str]:
    env = {"PATH": os.environ["PATH"], "GNUPGHOME": str(home), "LC_ALL": "C"}
    return subprocess.run(
        ["gpg", "--batch", "--no-tty", "--yes", "--no-options", "--homedir", str(home), *args],
        input=inp,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _make_gpg_identity(base: Path, name: str) -> tuple[Path, str, str]:
    home = base / f"gpg_{name}"
    home.mkdir(mode=0o700)
    r = _gpg_run(
        home,
        "--passphrase",
        "",
        "--quick-generate-key",
        f"{name} <{name}@tendcf.test>",
        "ed25519",
        "cert,sign",
        "2y",
    )
    assert r.returncode == 0, r.stderr
    lst = _gpg_run(home, "--with-colons", "--list-keys")
    fpr = ""
    for line in lst.stdout.splitlines():
        if line.startswith("fpr:"):
            fpr = line.split(":")[9].upper()
            break
    assert len(fpr) == 40
    pub = _gpg_run(home, "--armor", "--export", fpr).stdout
    return home, fpr, pub


def _gpg_certify(signer_home: Path, target_pub: str, target_fpr: str) -> str:
    assert _gpg_run(signer_home, "--import", inp=target_pub).returncode == 0
    assert _gpg_run(signer_home, "--quick-sign-key", target_fpr).returncode == 0
    return _gpg_run(signer_home, "--armor", "--export", target_fpr).stdout


def _gpg_tsign(
    signer_home: Path,
    target_pub: str,
    target_fpr: str,
    *,
    trust_level: int = 2,  # 1 = marginal, 2 = full
    depth: int = 1,
) -> str:
    assert _gpg_run(signer_home, "--import", inp=target_pub).returncode == 0
    r = _gpg_run(
        signer_home,
        "--command-fd",
        "0",
        "--status-fd",
        "1",
        "--edit-key",
        target_fpr,
        "tsign",
        "save",
        inp=f"{trust_level}\n{depth}\n\n",
    )
    assert r.returncode == 0, r.stderr + r.stdout
    return _gpg_run(signer_home, "--armor", "--export", target_fpr).stdout


def _gpg_detach_sign(signer_home: Path, payload: Path, sig_out: Path) -> Path:
    r = _gpg_run(signer_home, "--armor", "--detach-sign", "-o", str(sig_out), str(payload))
    assert r.returncode == 0, r.stderr
    return sig_out


def _build_wheel(
    out_dir: Path,
    *,
    dist: str,
    version: str,
    files: dict[str, bytes],
    requires_dist: list[str] | None = None,
    entry_points_txt: str | None = None,
    tamper_record: bool = False,
    omit_from_record: str | None = None,
    add_symlink_member: str | None = None,
    duplicate_member: str | None = None,
) -> tuple[Path, str]:
    """Build a valid (or deliberately tampered) PEP 427 `.whl` and return `(path, sha256)`."""
    norm_fn_dist = dist.replace("-", "_")
    filename = f"{norm_fn_dist}-{version}-py3-none-any.whl"
    whl_path = out_dir / filename
    dist_info = f"{norm_fn_dist}-{version}.dist-info"

    meta_lines = [
        "Metadata-Version: 2.1",
        f"Name: {dist}",
        f"Version: {version}",
    ]
    for req in requires_dist or []:
        meta_lines.append(f"Requires-Dist: {req}")
    meta_bytes = ("\n".join(meta_lines) + "\n").encode("utf-8")

    wheel_bytes = (
        "Wheel-Version: 1.0\n"
        "Generator: tendcf-test\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    ).encode("utf-8")

    all_files = dict(files)
    all_files[f"{dist_info}/METADATA"] = meta_bytes
    all_files[f"{dist_info}/WHEEL"] = wheel_bytes
    if entry_points_txt is not None:
        all_files[f"{dist_info}/entry_points.txt"] = entry_points_txt.encode("utf-8")

    record_rows: list[str] = []
    for member, data in sorted(all_files.items()):
        if member == omit_from_record:
            continue
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        if tamper_record and member.endswith(".py"):
            digest = "A" * len(digest)
        record_rows.append(f"{member},sha256={digest},{len(data)}")
    record_rows.append(f"{dist_info}/RECORD,,")
    all_files[f"{dist_info}/RECORD"] = ("\n".join(record_rows) + "\n").encode("utf-8")

    with zipfile.ZipFile(whl_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for member, data in sorted(all_files.items()):
            zf.writestr(member, data)
            if duplicate_member == member:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    zf.writestr(member, data)
        if add_symlink_member is not None:
            zi = zipfile.ZipInfo(add_symlink_member)
            zi.create_system = 3  # Unix
            zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(zi, "/etc/passwd")

    sha = hashlib.sha256(whl_path.read_bytes()).hexdigest()
    return whl_path, sha


def _write_manifest(
    path: Path,
    *,
    name: str,
    kind: str,
    dist: str,
    version: str,
    entry_point: str,
    wheel_filename: str,
    wheel_sha256: str,
    release_seq: int = 1,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    dependencies: list[dict[str, str]] | None = None,
) -> Path:
    now = utc_now()
    iss = issued_at if issued_at is not None else now - timedelta(minutes=5)
    exp = expires_at if expires_at is not None else now + timedelta(days=30)
    doc = {
        "schema_version": 1,
        "plugin": {
            "name": name,
            "kind": kind,
            "distribution": dist,
            "version": version,
            "entry_point_group": "tendcf.frontends" if kind == "frontend" else "tendcf.importers",
            "entry_point": entry_point,
        },
        "release_seq": release_seq,
        "issued_at": format_rfc3339_utc(iss),
        "expires_at": format_rfc3339_utc(exp),
        "wheel": {
            "filename": wheel_filename,
            "sha256": wheel_sha256,
        },
        "dependencies": dependencies or [],
    }
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _run_cli(args: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    run_env = {k: v for k, v in (os.environ if env is None else env).items()}
    run_env["PYTHONPATH"] = str(COMPILER_DIR)
    return subprocess.run(
        [sys.executable, "-m", "tendcf.cli", *args],
        capture_output=True,
        text=True,
        env=run_env,
        check=False,
    )


# ---------------------------------------------------------------------------
# 1. Real GnuPG Web of Trust: depth 0/1/2/3, marginal thresholds, direct anchors
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")
def test_gpg_wot_bounded_depth_marginal_threshold_and_direct_anchor(tmp_path: Path, gpg_tmp: Path) -> None:
    keys_dir = gpg_tmp / "k"
    keys_dir.mkdir()
    root_h, root_fpr, root_pub = _make_gpg_identity(keys_dir, "root")
    direct_h, direct_fpr, direct_pub = _make_gpg_identity(keys_dir, "direct")
    i1_h, i1_fpr, i1_pub = _make_gpg_identity(keys_dir, "intro1")
    i2_h, i2_fpr, i2_pub = _make_gpg_identity(keys_dir, "intro2")
    i3_h, i3_fpr, i3_pub = _make_gpg_identity(keys_dir, "intro3")
    m1_h, m1_fpr, m1_pub = _make_gpg_identity(keys_dir, "marg1")
    m2_h, m2_fpr, m2_pub = _make_gpg_identity(keys_dir, "marg2")
    a0_h, a0_fpr, a0_pub = _make_gpg_identity(keys_dir, "auth0")
    a1_h, a1_fpr, a1_pub = _make_gpg_identity(keys_dir, "auth1")
    a2_h, a2_fpr, a2_pub = _make_gpg_identity(keys_dir, "auth2")
    a3_h, a3_fpr, a3_pub = _make_gpg_identity(keys_dir, "auth3")
    am1_h, am1_fpr, am1_pub = _make_gpg_identity(keys_dir, "auth_marg1")
    am2_h, am2_fpr, am2_pub = _make_gpg_identity(keys_dir, "auth_marg2")
    untrusted_h, _, untrusted_pub = _make_gpg_identity(keys_dir, "untrusted")
    direct_child_h, dc_fpr, dc_pub = _make_gpg_identity(keys_dir, "direct_child")

    # Build certification graph:
    # root -> a0 (direct cert)
    a0_cert = _gpg_certify(root_h, a0_pub, a0_fpr)
    # root --tsign(full, depth=3)--> i1 --cert--> a1
    i1_cert = _gpg_tsign(root_h, i1_pub, i1_fpr, trust_level=2, depth=3)
    a1_cert = _gpg_certify(i1_h, a1_pub, a1_fpr)
    # i1 --tsign(full, depth=2)--> i2 --cert--> a2
    i2_cert = _gpg_tsign(i1_h, i2_pub, i2_fpr, trust_level=2, depth=2)
    a2_cert = _gpg_certify(i2_h, a2_pub, a2_fpr)
    # i2 --tsign(full, depth=1)--> i3 --cert--> a3 (3 intermediate introducers: exceeds max_depth=2!)
    i3_cert = _gpg_tsign(i2_h, i3_pub, i3_fpr, trust_level=2, depth=1)
    a3_cert = _gpg_certify(i3_h, a3_pub, a3_fpr)
    # root --tsign(marginal, depth=1)--> m1, m2; m1 -> am1 (only 1 marginal); m1+m2 -> am2 (2 marginals)
    m1_cert = _gpg_tsign(root_h, m1_pub, m1_fpr, trust_level=1, depth=1)
    m2_cert = _gpg_tsign(root_h, m2_pub, m2_fpr, trust_level=1, depth=1)
    am1_cert = _gpg_certify(m1_h, am1_pub, am1_fpr)
    am2_cert_1 = _gpg_certify(m1_h, am2_pub, am2_fpr)
    am2_cert = _gpg_certify(m2_h, am2_cert_1, am2_fpr)
    # direct_anchor tries to certify direct_child (MUST NOT work: role="direct" cannot introduce!)
    dc_cert = _gpg_certify(direct_h, dc_pub, dc_fpr)

    site_root = tmp_path / "site-private"
    kr = site_root / "plugins" / "keyring"
    kr.mkdir(parents=True)
    (kr / "root.asc").write_text(root_pub, encoding="utf-8")
    (kr / "direct.asc").write_text(direct_pub, encoding="utf-8")
    (kr / "graph.asc").write_text(
        "\n".join(
            [
                i1_cert,
                i2_cert,
                i3_cert,
                m1_cert,
                m2_cert,
                a0_cert,
                a1_cert,
                a2_cert,
                a3_cert,
                am1_cert,
                am2_cert,
                untrusted_pub,
                dc_cert,
            ]
        ),
        encoding="utf-8",
    )

    manifest = tmp_path / "plugin-release.json"
    manifest.write_text('{"schema_version": 1}\n', encoding="utf-8")

    sigs = {
        "root": _gpg_detach_sign(root_h, manifest, tmp_path / "root.asc"),
        "direct": _gpg_detach_sign(direct_h, manifest, tmp_path / "direct.asc"),
        "a0": _gpg_detach_sign(a0_h, manifest, tmp_path / "a0.asc"),
        "a1": _gpg_detach_sign(a1_h, manifest, tmp_path / "a1.asc"),
        "a2": _gpg_detach_sign(a2_h, manifest, tmp_path / "a2.asc"),
        "a3": _gpg_detach_sign(a3_h, manifest, tmp_path / "a3.asc"),
        "am1": _gpg_detach_sign(am1_h, manifest, tmp_path / "am1.asc"),
        "am2": _gpg_detach_sign(am2_h, manifest, tmp_path / "am2.asc"),
        "untrusted": _gpg_detach_sign(untrusted_h, manifest, tmp_path / "untrusted.asc"),
        "dc": _gpg_detach_sign(direct_child_h, manifest, tmp_path / "dc.asc"),
    }

    anchors = (
        TrustAnchor(fingerprint=root_fpr, label="site-root", role="root", key_file="root.asc"),
        TrustAnchor(fingerprint=direct_fpr, label="direct-author", role="direct", key_file="direct.asc"),
    )

    def _policy(depth: int) -> TrustPolicy:
        return TrustPolicy(
            keyring_dir="plugins/keyring",
            max_depth=depth,
            marginal_threshold=2,
            full_threshold=1,
            backend="gpg",
            anchors=anchors,
        )

    # Depth 0: root, direct, and a0 (directly certified by root) pass; a1/a2/a3/untrusted/dc fail.
    res_root = verify_detached_manifest_signature(manifest, sigs["root"], site_root=site_root, policy=_policy(0))
    assert res_root.trust_level == "ultimate" and res_root.primary_fingerprint == root_fpr
    res_direct = verify_detached_manifest_signature(manifest, sigs["direct"], site_root=site_root, policy=_policy(0))
    assert res_direct.trust_level == "direct" and res_direct.primary_fingerprint == direct_fpr
    res_a0 = verify_detached_manifest_signature(manifest, sigs["a0"], site_root=site_root, policy=_policy(0))
    assert res_a0.trust_level == "full" and res_a0.primary_fingerprint == a0_fpr

    for blocked in ("a1", "a2", "a3", "untrusted", "dc"):
        with pytest.raises(PluginTrustError, match="Web-of-Trust check failed"):
            verify_detached_manifest_signature(manifest, sigs[blocked], site_root=site_root, policy=_policy(0))

    # Depth 1 (default): a1 and am2 (2 marginals) pass; am1 (1 marginal), a2, a3, dc fail!
    res_a1 = verify_detached_manifest_signature(manifest, sigs["a1"], site_root=site_root, policy=_policy(1))
    assert res_a1.trust_level == "full" and res_a1.primary_fingerprint == a1_fpr
    res_am2 = verify_detached_manifest_signature(manifest, sigs["am2"], site_root=site_root, policy=_policy(1))
    assert res_am2.trust_level == "full" and res_am2.primary_fingerprint == am2_fpr
    for blocked in ("am1", "a2", "a3", "dc"):
        with pytest.raises(PluginTrustError, match="Web-of-Trust check failed"):
            verify_detached_manifest_signature(manifest, sigs[blocked], site_root=site_root, policy=_policy(1))

    # Depth 2 (max): a2 passes; a3 (3 introducers) and dc (direct anchor cannot introduce) STILL fail!
    res_a2 = verify_detached_manifest_signature(manifest, sigs["a2"], site_root=site_root, policy=_policy(2))
    assert res_a2.trust_level == "full" and res_a2.primary_fingerprint == a2_fpr
    for blocked in ("a3", "dc"):
        with pytest.raises(PluginTrustError, match="Web-of-Trust check failed"):
            verify_detached_manifest_signature(manifest, sigs[blocked], site_root=site_root, policy=_policy(2))

    # Tampered manifest byte -> refused!
    tampered = tmp_path / "tampered.json"
    tampered.write_text('{"schema_version": 2}\n', encoding="utf-8")
    with pytest.raises(PluginTrustError):
        verify_detached_manifest_signature(tampered, sigs["a0"], site_root=site_root, policy=_policy(1))

    # Clearsigned blob & multi-sig blob -> refused!
    clearsigned = tmp_path / "clear.asc"
    clearsigned.write_text("-----BEGIN PGP SIGNED MESSAGE-----\nfoo\n-----BEGIN PGP SIGNATURE-----\n-----END PGP SIGNATURE-----\n", encoding="utf-8")
    with pytest.raises(PluginTrustError, match="clearsigned document refused"):
        verify_detached_manifest_signature(manifest, clearsigned, site_root=site_root, policy=_policy(1))

    multisig = tmp_path / "multi.asc"
    multisig.write_text(sigs["a0"].read_text(encoding="utf-8") + "\n" + sigs["root"].read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(PluginTrustError, match="exactly one"):
        verify_detached_manifest_signature(manifest, multisig, site_root=site_root, policy=_policy(1))


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")
def test_soft_vs_hard_revocation_and_historical_rebuild(tmp_path: Path, gpg_tmp: Path) -> None:
    keys_dir = gpg_tmp / "k"
    keys_dir.mkdir()
    root_h, root_fpr, root_pub = _make_gpg_identity(keys_dir, "root")
    auth_h, auth_fpr, auth_pub = _make_gpg_identity(keys_dir, "auth")
    auth_cert = _gpg_certify(root_h, auth_pub, auth_fpr)

    site_root = tmp_path / "site-private"
    kr = site_root / "plugins" / "keyring"
    kr.mkdir(parents=True)
    (kr / "root.asc").write_text(root_pub, encoding="utf-8")
    (kr / "auth.asc").write_text(auth_cert, encoding="utf-8")

    manifest = tmp_path / "plugin-release.json"
    manifest.write_text('{"schema_version": 1}\n', encoding="utf-8")
    sig = _gpg_detach_sign(auth_h, manifest, tmp_path / "plugin-release.json.asc")

    now = utc_now()
    # Suppose key was soft-revoked 1 hour AFTER the signature/pin (so historical check before revocation passes).
    rev_future = now + timedelta(hours=1)
    soft_policy = TrustPolicy(
        keyring_dir="plugins/keyring",
        max_depth=1,
        backend="gpg",
        anchors=(TrustAnchor(fingerprint=root_fpr, label="root", role="root", key_file="root.asc"),),
        revocations=(
            KeyRevocation(
                fingerprint=auth_fpr,
                mode="soft",
                revoked_at=format_rfc3339_utc(rev_future),
                reason="scheduled rotation",
            ),
        ),
    )

    # Current (non-historical) verification is ALWAYS refused for a soft-revoked key.
    with pytest.raises(PluginTrustError, match="SOFT-REVOKED"):
        verify_detached_manifest_signature(manifest, sig, site_root=site_root, policy=soft_policy, historical=False)

    # Historical verification BEFORE revoked_at succeeds with an explicit warning!
    as_of_before = now + timedelta(seconds=30)
    res_hist = verify_detached_manifest_signature(
        manifest,
        sig,
        site_root=site_root,
        policy=soft_policy,
        historical=True,
        as_of=as_of_before,
        issued_at=now - timedelta(minutes=2),
        verified_at=now + timedelta(seconds=10),
    )
    assert res_hist.historical is True
    assert any("soft_revoked_after_pin" in w for w in res_hist.warnings)

    # Historical verification AT or AFTER revoked_at is REFUSED!
    with pytest.raises(PluginTrustError, match="not strictly before revocation"):
        verify_detached_manifest_signature(
            manifest,
            sig,
            site_root=site_root,
            policy=soft_policy,
            historical=True,
            as_of=rev_future,
            issued_at=now - timedelta(minutes=2),
            verified_at=now + timedelta(seconds=10),
        )

    # Hard revocation refuses EVEN pre-revocation historical rebuilds!
    hard_policy = replace(
        soft_policy,
        revocations=(
            KeyRevocation(
                fingerprint=auth_fpr,
                mode="hard",
                revoked_at=format_rfc3339_utc(rev_future),
                reason="key compromise",
            ),
        ),
    )
    with pytest.raises(PluginTrustError, match="HARD-REVOKED"):
        verify_detached_manifest_signature(
            manifest,
            sig,
            site_root=site_root,
            policy=hard_policy,
            historical=True,
            as_of=as_of_before,
            issued_at=now - timedelta(minutes=2),
            verified_at=now + timedelta(seconds=10),
        )


# ---------------------------------------------------------------------------
# 2. Sequoia sq / sq-wot backend adapter (offline flags, auto preference)
# ---------------------------------------------------------------------------


def test_sequoia_backend_adapter_and_auto_selection(tmp_path: Path) -> None:
    root_fpr = "A" * 40
    auth_fpr = "B" * 40
    site_root = tmp_path / "site-private"
    kr = site_root / "plugins" / "keyring"
    kr.mkdir(parents=True)
    (kr / "root.asc").write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----\n", encoding="utf-8")

    manifest = tmp_path / "plugin-release.json"
    manifest.write_text('{"schema_version": 1}\n', encoding="utf-8")
    sig = tmp_path / "plugin-release.json.asc"
    sig.write_text("-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n", encoding="utf-8")

    now_iso = format_rfc3339_utc(utc_now() - timedelta(minutes=1))
    fake_sq = tmp_path / "sq"
    fake_sq.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "assert '--network-policy' in sys.argv and 'offline' in sys.argv, sys.argv\n"
        f"print(json.dumps({{'signatures': [{{'status': 'good', 'primary_fingerprint': {auth_fpr!r}, 'signing_fingerprint': {auth_fpr!r}, 'created_at': {now_iso!r}}}]}}))\n",
        encoding="utf-8",
    )
    fake_sq.chmod(0o755)

    fake_wot = tmp_path / "sq-wot"
    fake_wot.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "assert '--trust-root' in sys.argv and '--depth' in sys.argv, sys.argv\n"
        "print(json.dumps({'trust_amount': 120, 'depth': 1}))\n",
        encoding="utf-8",
    )
    fake_wot.chmod(0o755)

    backend, bins = select_wot_backend("auto", sq_bin=str(fake_sq), sq_wot_bin=str(fake_wot), gpg_bin="/usr/bin/gpg")
    assert backend == "sequoia" and bins["sq"] == str(fake_sq)

    policy = TrustPolicy(
        keyring_dir="plugins/keyring",
        max_depth=1,
        backend="auto",
        anchors=(TrustAnchor(fingerprint=root_fpr, label="root", role="root", key_file="root.asc"),),
    )
    res = verify_detached_manifest_signature(
        manifest,
        sig,
        site_root=site_root,
        policy=policy,
        sq_bin=str(fake_sq),
        sq_wot_bin=str(fake_wot),
    )
    assert res.backend == "sequoia" and res.primary_fingerprint == auth_fpr and res.trust_level == "full"

    # Insufficient trust_amount (< 120) or excessive depth -> refused!
    fake_wot_low = tmp_path / "sq-wot-low"
    fake_wot_low.write_text(
        f"#!{sys.executable}\nimport json\nprint(json.dumps({{'trust_amount': 60, 'depth': 1}}))\n",
        encoding="utf-8",
    )
    fake_wot_low.chmod(0o755)
    with pytest.raises(PluginTrustError, match="trust amount insufficient"):
        verify_detached_manifest_signature(
            manifest, sig, site_root=site_root, policy=policy, sq_bin=str(fake_sq), sq_wot_bin=str(fake_wot_low)
        )


# ---------------------------------------------------------------------------
# 3. Wheel verification security: .pth, symlinks, RECORD, dep closure, confusion
# ---------------------------------------------------------------------------


def test_wheel_verification_refuses_pth_symlinks_confusion_record_and_missing_deps(tmp_path: Path) -> None:
    wdir = tmp_path / "wheels"
    wdir.mkdir()

    # 1. .pth file inside wheel -> refused BEFORE install!
    pth_whl, pth_sha = _build_wheel(
        wdir,
        dist="bad-pth",
        version="1.0.0",
        files={"bad_pth/__init__.py": b"X=1\n", "evil.pth": b"import os\n"},
        entry_points_txt="[tendcf.frontends]\nbadpth = bad_pth:load\n",
    )
    with pytest.raises(PluginEnvError, match="forbidden startup hook"):
        verify_wheel_artifact(
            pth_whl,
            expected_filename=pth_whl.name,
            expected_sha256=pth_sha,
            expected_distribution="bad-pth",
            expected_version="1.0.0",
            is_plugin_wheel=True,
            expected_entry_point_group="tendcf.frontends",
            expected_plugin_name="badpth",
            expected_entry_point="bad_pth:load",
        )

    # 2. sitecustomize.py -> refused!
    sc_whl, sc_sha = _build_wheel(
        wdir,
        dist="bad-sc",
        version="1.0.0",
        files={"sitecustomize.py": b"1\n"},
        entry_points_txt="[tendcf.frontends]\nbadsc = bad_sc:load\n",
    )
    with pytest.raises(PluginEnvError, match="forbidden startup hook"):
        verify_wheel_artifact(
            sc_whl,
            expected_filename=sc_whl.name,
            expected_sha256=sc_sha,
            expected_distribution="bad-sc",
            expected_version="1.0.0",
            is_plugin_wheel=True,
            expected_entry_point_group="tendcf.frontends",
            expected_plugin_name="badsc",
            expected_entry_point="bad_sc:load",
        )

    # 3. Dependency confusion: wheel shipping top-level tendcf/ -> refused!
    conf_whl, conf_sha = _build_wheel(
        wdir,
        dist="evil-helper",
        version="1.0.0",
        files={"tendcf/__init__.py": b"PWN=1\n"},
    )
    with pytest.raises(PluginEnvError, match="dependency-confusion"):
        verify_wheel_artifact(
            conf_whl,
            expected_filename=conf_whl.name,
            expected_sha256=conf_sha,
            expected_distribution="evil-helper",
            expected_version="1.0.0",
            is_plugin_wheel=False,
        )

    # 4. RECORD hash mismatch, omitted member, symlink member, duplicate member -> ALL refused!
    for label, kwargs, match in (
        ("tamper_record", {"tamper_record": True}, "RECORD SHA-256 mismatch"),
        ("omit_record", {"omit_from_record": "ok_mod/__init__.py"}, "missing from RECORD"),
        ("symlink", {"add_symlink_member": "ok_mod/link.py"}, "symlink ZIP member"),
        ("duplicate", {"duplicate_member": "ok_mod/__init__.py"}, "duplicate ZIP entry"),
    ):
        d = tmp_path / f"w_{label}"
        d.mkdir()
        whl, sha = _build_wheel(
            d,
            dist="ok-mod",
            version="1.0.0",
            files={"ok_mod/__init__.py": b"X=1\n"},
            entry_points_txt="[tendcf.frontends]\nokmod = ok_mod:load\n",
            **kwargs,
        )
        with pytest.raises(PluginEnvError, match=match):
            verify_wheel_artifact(
                whl,
                expected_filename=whl.name,
                expected_sha256=sha,
                expected_distribution="ok-mod",
                expected_version="1.0.0",
                is_plugin_wheel=True,
                expected_entry_point_group="tendcf.frontends",
                expected_plugin_name="okmod",
                expected_entry_point="ok_mod:load",
            )

    # 5. Reserved built-in name & tendcf.supervisors group -> refused!
    sup_whl, sup_sha = _build_wheel(
        wdir,
        dist="bad-sup",
        version="1.0.0",
        files={"bad_sup/__init__.py": b"X=1\n"},
        entry_points_txt="[tendcf.supervisors]\ncustom = bad_sup:render\n[tendcf.frontends]\nbadsup = bad_sup:load\n",
    )
    with pytest.raises(PluginEnvError, match="forbidden entry-point group"):
        verify_wheel_artifact(
            sup_whl,
            expected_filename=sup_whl.name,
            expected_sha256=sup_sha,
            expected_distribution="bad-sup",
            expected_version="1.0.0",
            is_plugin_wheel=True,
            expected_entry_point_group="tendcf.frontends",
            expected_plugin_name="badsup",
            expected_entry_point="bad_sup:load",
        )

    # 6. Incomplete transitive dependency closure -> refused!
    inc_dir = tmp_path / "inc"
    inc_dir.mkdir()
    inc_whl, inc_sha = _build_wheel(
        inc_dir,
        dist="need-dep",
        version="1.0.0",
        files={"need_dep/__init__.py": b"X=1\n"},
        requires_dist=["unpinned-lib>=1.0", "optional-only>=1.0; extra == 'dev'"],
        entry_points_txt="[tendcf.frontends]\nneeddep = need_dep:load\n",
    )
    man_path = _write_manifest(
        tmp_path / "inc.json",
        name="needdep",
        kind="frontend",
        dist="need-dep",
        version="1.0.0",
        entry_point="need_dep:load",
        wheel_filename=inc_whl.name,
        wheel_sha256=inc_sha,
    )
    man = load_release_manifest(man_path)
    with pytest.raises(PluginEnvError, match="incomplete transitive dependency closure"):
        verify_release_wheels(man, inc_dir)


def test_isolated_env_refuses_gate_tools_sys_prefix_and_dedup_bypass(tmp_path: Path) -> None:
    # Refuses sys.prefix, tendcf_root, tendcf_root/tools, site_root
    site_root = tmp_path / "site-private"
    site_root.mkdir()
    for bad in (Path(sys.prefix), TENDCF_ROOT, TENDCF_ROOT / "tools", site_root):
        with pytest.raises(PluginEnvError, match="overlaps forbidden"):
            assert_isolated_plugin_env_path(bad, tendcf_root=TENDCF_ROOT, site_root=site_root)


# ---------------------------------------------------------------------------
# 4. End-to-end CLI workflow: trust add-anchor -> plugin add -> verify ->
#    compile --frontend -> import --importer -> update (anti-rollback) -> remove
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")
def test_end_to_end_cli_add_compile_import_update_rollback_and_tamper_detection(
    tmp_path: Path, gpg_tmp: Path
) -> None:
    keys_dir = gpg_tmp / "k"
    keys_dir.mkdir()
    root_h, root_fpr, root_pub = _make_gpg_identity(keys_dir, "root")
    intro_h, intro_fpr, intro_pub = _make_gpg_identity(keys_dir, "intro")
    auth_h, auth_fpr, auth_pub = _make_gpg_identity(keys_dir, "author")

    intro_cert = _gpg_tsign(root_h, intro_pub, intro_fpr, trust_level=2, depth=1)
    auth_cert = _gpg_certify(intro_h, auth_pub, auth_fpr)

    root_pub_file = tmp_path / "root.asc"
    root_pub_file.write_text(root_pub, encoding="utf-8")

    site_root = tmp_path / "tendcf-private-acme"
    site_root.mkdir()
    # Add introducer + author public certs into offline site-private keyring after add-anchor.
    r_anchor = _run_cli(
        [
            "plugin",
            "trust",
            "add-anchor",
            "--site-dir",
            str(site_root),
            "--key",
            str(root_pub_file),
            "--label",
            "acme-root",
            "--role",
            "root",
            "--json",
        ]
    )
    assert r_anchor.returncode == 0, r_anchor.stderr
    anchor_data = json.loads(r_anchor.stdout)
    assert anchor_data["anchor"]["fingerprint"] == root_fpr
    assert anchor_data["privileged_change"] is True
    assert anchor_data["requires_ceremony_marker"] is True

    (site_root / "plugins" / "keyring" / "delegations.asc").write_text(
        intro_cert + "\n" + auth_cert, encoding="utf-8"
    )

    # Build a real transitive helper wheel + a real out-of-tree frontend plugin wheel!
    wdir_v1 = tmp_path / "wheels-v1"
    wdir_v1.mkdir()
    dep_whl, dep_sha = _build_wheel(
        wdir_v1,
        dist="acme-helper",
        version="0.1.0",
        files={"acme_helper/__init__.py": b"TAG = 'acme-v1'\n"},
    )
    frontend_code = (
        "import acme_helper\n"
        "from tendcf.sitemodel import load_document, load_site_model\n"
        "HELPER_TAG = acme_helper.TAG\n"
        "class Frontend:\n"
        "    def load_site_model(self, services, roles, launchd_writers):\n"
        "        return load_site_model(services, roles, launchd_writers)\n"
        "    def load_document(self, path):\n"
        "        return load_document(path)\n"
        "def get_frontend():\n"
        "    return Frontend()\n"
    ).encode("utf-8")
    fe_whl_v1, fe_sha_v1 = _build_wheel(
        wdir_v1,
        dist="acme-frontend",
        version="1.0.0",
        files={"acme_frontend/__init__.py": frontend_code},
        requires_dist=["acme-helper>=0.1.0", "pyyaml>=6", "tendcf>=0.0.1"],
        entry_points_txt="[tendcf.frontends]\nacme = acme_frontend:get_frontend\n",
    )

    now = utc_now()
    man_v1 = _write_manifest(
        tmp_path / "acme-v1.json",
        name="acme",
        kind="frontend",
        dist="acme-frontend",
        version="1.0.0",
        entry_point="acme_frontend:get_frontend",
        wheel_filename=fe_whl_v1.name,
        wheel_sha256=fe_sha_v1,
        release_seq=1,
        issued_at=now - timedelta(minutes=10),
        expires_at=now + timedelta(days=30),
        dependencies=[
            {
                "distribution": "acme-helper",
                "version": "0.1.0",
                "filename": dep_whl.name,
                "sha256": dep_sha,
            }
        ],
    )
    sig_v1 = _gpg_detach_sign(auth_h, man_v1, tmp_path / "acme-v1.json.asc")

    plugin_env = tmp_path / "isolated-plugin-env"

    # 1. `tendcf plugin add` verifies WoT (root -> intro -> author), verifies wheels & closure, stages env, pins plugins.toml.
    r_add = _run_cli(
        [
            "plugin",
            "add",
            "--site-dir",
            str(site_root),
            "--manifest",
            str(man_v1),
            "--sig",
            str(sig_v1),
            "--wheel-dir",
            str(wdir_v1),
            "--plugin-env",
            str(plugin_env),
            "--json",
        ]
    )
    assert r_add.returncode == 0, r_add.stderr
    add_data = json.loads(r_add.stdout)
    assert add_data["wot"]["primary_fingerprint"] == auth_fpr
    assert add_data["wot"]["trust_level"] == "full"
    assert add_data["privileged_change"] is True
    assert Path(add_data["staged_plugin_env"]).is_dir()

    # 2. `tendcf plugin ls --json`, `inspect --json`, `verify --json` all succeed cleanly.
    r_ls = _run_cli(["plugin", "ls", "--site-dir", str(site_root), "--json"])
    assert r_ls.returncode == 0, r_ls.stderr
    assert any(p["name"] == "acme" and p["source"] == "out-of-tree" for p in json.loads(r_ls.stdout)["plugins"])

    r_ins = _run_cli(["plugin", "inspect", "acme", "--site-dir", str(site_root), "--json"])
    assert r_ins.returncode == 0, r_ins.stderr
    assert json.loads(r_ins.stdout)["plugin"]["release_seq"] == 1

    r_ver = _run_cli(
        [
            "plugin",
            "verify",
            "--site-dir",
            str(site_root),
            "--wheel-dir",
            str(wdir_v1),
            "--plugin-env",
            str(plugin_env),
            "--check-releasable",
            "--json",
        ]
    )
    assert r_ver.returncode == 0, r_ver.stderr + r_ver.stdout
    assert json.loads(r_ver.stdout)["ok"] is True

    # 3. `tendcf compile --frontend acme` loads the verified out-of-tree frontend from isolated env and renders a valid goal file!
    clean_env = {k: v for k, v in os.environ.items() if k != "TENDCF_DIR"}
    r_comp = _run_cli(
        [
            "compile",
            "--host",
            "mac",
            "--platform",
            "macos",
            "--supervisor",
            "launchd",
            "--host-key",
            HOST_KEY,
            "--device-trust",
            str(SITE_EXAMPLE / "device-trust.json"),
            "--site",
            str(SITE_EXAMPLE),
            "--frontend",
            "acme",
            "--plugins-config",
            str(site_root / "plugins.toml"),
            "--plugin-env",
            str(plugin_env),
            "--check-releasable",
        ],
        env=clean_env,
    )
    assert r_comp.returncode == 0, r_comp.stderr
    goal = json.loads(r_comp.stdout)
    assert goal["schema_version"] == 9 and goal["host"] == HOST_KEY

    # Activation rule check: since plugins.toml only names `acme` (not `yaml`), compiling with `--frontend yaml` is REFUSED!
    r_unnamed = _run_cli(
        [
            "compile",
            "--host",
            "mac",
            "--platform",
            "macos",
            "--supervisor",
            "launchd",
            "--host-key",
            HOST_KEY,
            "--device-trust",
            str(SITE_EXAMPLE / "device-trust.json"),
            "--site",
            str(SITE_EXAMPLE),
            "--frontend",
            "yaml",
            "--plugins-config",
            str(site_root / "plugins.toml"),
        ],
        env=clean_env,
    )
    assert r_unnamed.returncode == 2
    assert "not named in site-private plugins.toml" in r_unnamed.stderr

    # 4. Also add a second out-of-tree IMPORTER plugin into the SAME isolated env and execute `tendcf import`!
    wdir_imp = tmp_path / "wheels-imp"
    wdir_imp.mkdir()
    imp_code = (
        "from pathlib import Path\n"
        "def import_site(source: Path, output_dir: Path):\n"
        "    output_dir.mkdir(parents=True, exist_ok=True)\n"
        "    out = output_dir / 'imported.txt'\n"
        "    out.write_text('imported:' + source.read_text(encoding='utf-8'), encoding='utf-8')\n"
        "    return {'written': str(out)}\n"
    ).encode("utf-8")
    imp_whl, imp_sha = _build_wheel(
        wdir_imp,
        dist="acme-importer",
        version="0.2.0",
        files={"acme_importer/__init__.py": imp_code},
        entry_points_txt="[tendcf.importers]\ncustom-imp = acme_importer:import_site\n",
    )
    man_imp = _write_manifest(
        tmp_path / "imp.json",
        name="custom-imp",
        kind="importer",
        dist="acme-importer",
        version="0.2.0",
        entry_point="acme_importer:import_site",
        wheel_filename=imp_whl.name,
        wheel_sha256=imp_sha,
        release_seq=1,
    )
    sig_imp = _gpg_detach_sign(auth_h, man_imp, tmp_path / "imp.json.asc")
    r_add_imp = _run_cli(
        [
            "plugin",
            "add",
            "--site-dir",
            str(site_root),
            "--manifest",
            str(man_imp),
            "--sig",
            str(sig_imp),
            "--wheel-dir",
            str(wdir_imp),
            "--plugin-env",
            str(plugin_env),
            "--json",
        ]
    )
    assert r_add_imp.returncode == 0, r_add_imp.stderr

    src_file = tmp_path / "legacy.cfg"
    src_file.write_text("hello-legacy", encoding="utf-8")
    imp_out = tmp_path / "imported-out"
    r_imp = _run_cli(
        [
            "import",
            "--importer",
            "custom-imp",
            "--source",
            str(src_file),
            "--output-dir",
            str(imp_out),
            "--site-dir",
            str(site_root),
            "--plugin-env",
            str(plugin_env),
            "--check-releasable",
            "--json",
        ],
        env=clean_env,
    )
    assert r_imp.returncode == 0, r_imp.stderr
    assert (imp_out / "imported.txt").read_text(encoding="utf-8") == "imported:hello-legacy"

    # 5. Anti-rollback & anti-freeze on `tendcf plugin update`:
    # Same release_seq=1 -> REFUSED!
    r_replay = _run_cli(
        [
            "plugin",
            "update",
            "acme",
            "--site-dir",
            str(site_root),
            "--manifest",
            str(man_v1),
            "--sig",
            str(sig_v1),
            "--wheel-dir",
            str(wdir_v1),
            "--plugin-env",
            str(plugin_env),
        ]
    )
    assert r_replay.returncode == 1 and "rollback/replay refused" in r_replay.stderr

    # Earlier issued_at (timestamp rollback) -> REFUSED!
    wdir_v2 = tmp_path / "wheels-v2"
    wdir_v2.mkdir()
    fe_whl_v2, fe_sha_v2 = _build_wheel(
        wdir_v2,
        dist="acme-frontend",
        version="1.1.0",
        files={"acme_frontend/__init__.py": frontend_code.replace(b"acme-v1", b"acme-v2")},
        requires_dist=["acme-helper>=0.1.0"],
        entry_points_txt="[tendcf.frontends]\nacme = acme_frontend:get_frontend\n",
    )
    shutil.copyfile(dep_whl, wdir_v2 / dep_whl.name)
    man_backdated = _write_manifest(
        tmp_path / "acme-backdated.json",
        name="acme",
        kind="frontend",
        dist="acme-frontend",
        version="1.1.0",
        entry_point="acme_frontend:get_frontend",
        wheel_filename=fe_whl_v2.name,
        wheel_sha256=fe_sha_v2,
        release_seq=2,
        issued_at=now - timedelta(days=10),
        expires_at=now + timedelta(days=10),
        dependencies=[
            {"distribution": "acme-helper", "version": "0.1.0", "filename": dep_whl.name, "sha256": dep_sha}
        ],
    )
    sig_backdated = _gpg_detach_sign(auth_h, man_backdated, tmp_path / "acme-backdated.json.asc")
    r_backdated = _run_cli(
        [
            "plugin",
            "update",
            "acme",
            "--site-dir",
            str(site_root),
            "--manifest",
            str(man_backdated),
            "--sig",
            str(sig_backdated),
            "--wheel-dir",
            str(wdir_v2),
            "--plugin-env",
            str(plugin_env),
        ]
    )
    assert r_backdated.returncode == 1 and "precedes pinned issued_at" in r_backdated.stderr

    # Expired manifest (freeze attack, newer issued_at & release_seq=2 but expires_at < now) -> REFUSED!
    man_exp = _write_manifest(
        tmp_path / "acme-exp.json",
        name="acme",
        kind="frontend",
        dist="acme-frontend",
        version="1.1.0",
        entry_point="acme_frontend:get_frontend",
        wheel_filename=fe_whl_v2.name,
        wheel_sha256=fe_sha_v2,
        release_seq=2,
        issued_at=now - timedelta(minutes=5),
        expires_at=now - timedelta(minutes=1),
        dependencies=[
            {"distribution": "acme-helper", "version": "0.1.0", "filename": dep_whl.name, "sha256": dep_sha}
        ],
    )
    sig_exp = _gpg_detach_sign(auth_h, man_exp, tmp_path / "acme-exp.json.asc")
    r_exp = _run_cli(
        [
            "plugin",
            "update",
            "acme",
            "--site-dir",
            str(site_root),
            "--manifest",
            str(man_exp),
            "--sig",
            str(sig_exp),
            "--wheel-dir",
            str(wdir_v2),
            "--plugin-env",
            str(plugin_env),
        ]
    )
    assert r_exp.returncode == 1 and "expired" in r_exp.stderr

    # Valid v2 upgrade (release_seq=2, fresh expires_at) -> SUCCEEDS!
    man_v2 = _write_manifest(
        tmp_path / "acme-v2.json",
        name="acme",
        kind="frontend",
        dist="acme-frontend",
        version="1.1.0",
        entry_point="acme_frontend:get_frontend",
        wheel_filename=fe_whl_v2.name,
        wheel_sha256=fe_sha_v2,
        release_seq=2,
        issued_at=now - timedelta(minutes=2),
        expires_at=now + timedelta(days=60),
        dependencies=[
            {"distribution": "acme-helper", "version": "0.1.0", "filename": dep_whl.name, "sha256": dep_sha}
        ],
    )
    sig_v2 = _gpg_detach_sign(auth_h, man_v2, tmp_path / "acme-v2.json.asc")
    r_upd = _run_cli(
        [
            "plugin",
            "update",
            "acme",
            "--site-dir",
            str(site_root),
            "--manifest",
            str(man_v2),
            "--sig",
            str(sig_v2),
            "--wheel-dir",
            str(wdir_v2),
            "--plugin-env",
            str(plugin_env),
            "--json",
        ]
    )
    assert r_upd.returncode == 0, r_upd.stderr
    assert json.loads(r_upd.stdout)["plugin"]["version"] == "1.1.0"

    # 6. Post-staging on-disk tampering in isolated env -> caught by RECORD check!
    (plugin_env / "acme_frontend" / "__init__.py").write_text("# TAMPERED\n", encoding="utf-8")
    r_tamp = _run_cli(
        [
            "plugin",
            "verify",
            "--site-dir",
            str(site_root),
            "--plugin-env",
            str(plugin_env),
            "--check-releasable",
            "--json",
        ]
    )
    assert r_tamp.returncode == 1
    assert any("tampered file detected" in f for f in json.loads(r_tamp.stdout)["findings"])

    # 7. Remove plugin -> updates plugins.toml & re-stages env cleanly without acme!
    r_rm = _run_cli(
        [
            "plugin",
            "remove",
            "acme",
            "--site-dir",
            str(site_root),
            "--plugin-env",
            str(plugin_env),
            "--json",
        ]
    )
    assert r_rm.returncode == 0, r_rm.stderr
    assert not (plugin_env / "acme_frontend").exists()
    assert (plugin_env / "acme_importer").exists()


# ---------------------------------------------------------------------------
# 5. Non-deduplicating dist-info scanner & contrib/ inheritance
# ---------------------------------------------------------------------------


def test_non_dedup_dist_info_detects_duplicate_distributions_and_reserved_impersonation(tmp_path: Path) -> None:
    site_root = tmp_path / "site-private"
    site_root.mkdir()
    cfg = SitePluginsConfig()
    write_site_plugins_config(site_root / "plugins.toml", cfg)

    env_dir = tmp_path / "env"
    env_dir.mkdir()
    (env_dir / ".tendcf-plugin-env.json").write_text(
        json.dumps({"schema_version": 1, "plugin_set_digest": cfg.plugin_set_digest(), "wheels": []}),
        encoding="utf-8",
    )

    def _plant_dist(di_name: str, dist_name: str, version: str, ep_txt: str | None = None) -> None:
        di = env_dir / di_name
        di.mkdir()
        meta = f"Metadata-Version: 2.1\nName: {dist_name}\nVersion: {version}\n".encode("utf-8")
        (di / "METADATA").write_bytes(meta)
        rows = [
            f"{di_name}/METADATA,sha256={base64.urlsafe_b64encode(hashlib.sha256(meta).digest()).rstrip(b'=').decode()},{len(meta)}"
        ]
        if ep_txt is not None:
            ep_b = ep_txt.encode("utf-8")
            (di / "entry_points.txt").write_bytes(ep_b)
            rows.append(
                f"{di_name}/entry_points.txt,sha256={base64.urlsafe_b64encode(hashlib.sha256(ep_b).digest()).rstrip(b'=').decode()},{len(ep_b)}"
            )
        rows.append(f"{di_name}/RECORD,,")
        (di / "RECORD").write_text("\n".join(rows) + "\n", encoding="utf-8")

    # Duplicate distribution name (`foo` 1.0 and 2.0): importlib.metadata would silently drop one; we MUST refuse!
    _plant_dist("foo-1.0.dist-info", "foo", "1.0")
    _plant_dist("foo-2.0.dist-info", "foo", "2.0")
    with pytest.raises(PluginEnvError, match="duplicate distribution"):
        discover_env_entry_points(env_dir, config=cfg, tendcf_root=TENDCF_ROOT, site_root=site_root)

    shutil.rmtree(env_dir / "foo-2.0.dist-info")
    # Reserved name impersonation -> refused even in dev mode!
    _plant_dist("evil-1.0.dist-info", "evil", "1.0", "[tendcf.frontends]\nyaml = evil:load\n")
    with pytest.raises(PluginEnvError, match="reserved built-in plugin name"):
        discover_env_entry_points(env_dir, config=cfg, tendcf_root=TENDCF_ROOT, site_root=site_root)


def test_contrib_plugin_inherits_tendcf_pin_and_refuses_symlinks(tmp_path: Path) -> None:
    fake_root = tmp_path / "tendcf-root"
    (fake_root / "contrib" / "frontends").mkdir(parents=True)
    contrib_file = fake_root / "contrib" / "frontends" / "my_dsl.py"
    contrib_file.write_text(
        "PLUGIN_KIND = 'frontend'\nPLUGIN_NAME = 'my-dsl'\nSENTINEL = 'contrib-ok'\n",
        encoding="utf-8",
    )

    site_root = tmp_path / "site-private"
    site_root.mkdir()
    r = _run_cli(
        [
            "plugin",
            "add",
            "--site-dir",
            str(site_root),
            "--contrib",
            "my-dsl",
            "--kind",
            "frontend",
            "--relpath",
            "contrib/frontends/my_dsl.py",
            "--tendcf",
            str(fake_root),
            "--json",
        ]
    )
    assert r.returncode == 0, r.stderr
    cfg = load_site_plugins_config(site_root / "plugins.toml")
    mod = load_configured_plugin("frontend", "my-dsl", config=cfg, tendcf_root=fake_root)
    assert mod.SENTINEL == "contrib-ok"

    # Symlink replacing contrib plugin -> refused before exec!
    outside = tmp_path / "evil.py"
    outside.write_text("raise AssertionError('MUST_NOT_RUN')\n", encoding="utf-8")
    contrib_file.unlink()
    contrib_file.symlink_to(outside)
    with pytest.raises(PluginError, match="is a symlink"):
        load_configured_plugin("frontend", "my-dsl", config=cfg, tendcf_root=fake_root)


def test_manifest_validation_rejects_supervisor_reserved_and_bad_depth() -> None:
    with pytest.raises(PluginManifestError, match="max_depth"):
        parse_site_plugins_toml(b"[trust]\nmax_depth = 3\n")
    with pytest.raises(PluginManifestError, match="supervisor"):
        parse_site_plugins_toml(b'[[plugins]]\nname = "launchd"\nkind = "supervisor"\nsource = "in-tree"\n')
    with pytest.raises(PluginManifestError, match="reserved"):
        parse_site_plugins_toml(b'[[plugins]]\nname = "yaml"\nkind = "frontend"\nsource = "contrib"\nrelpath = "contrib/y.py"\n')
    with pytest.raises(PluginManifestError, match="tendcf and nix2cf"):
        parse_release_manifest_bytes(
            json.dumps(
                {
                    "schema_version": 1,
                    "plugin": {
                        "name": "evil",
                        "kind": "frontend",
                        "distribution": "tendcf",
                        "version": "1.0.0",
                        "entry_point_group": "tendcf.frontends",
                        "entry_point": "evil:load",
                    },
                    "release_seq": 1,
                    "issued_at": "2026-11-28T00:00:00Z",
                    "expires_at": "2027-01-01T00:00:00Z",
                    "wheel": {"filename": "tendcf-1.0.0-py3-none-any.whl", "sha256": "a" * 64},
                    "dependencies": [],
                }
            ).encode("utf-8")
        )
