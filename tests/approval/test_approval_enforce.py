"""Comprehensive pure-stdlib tests for tools/approval_enforce.py (issue #76).

Runs under `python3 -I -S -m unittest discover -s tests/approval -v` with zero
third-party packages, proving bare-host stdlib execution parity alongside
`tests/projector` and full Python 3.14+ `sys.modules` compatibility.

Covers:
  - Section 0: Official RFC 8032 §7.1 Ed25519 test vectors, strict canonical
    S / R / A rejection, small-order A & small-order R (+ mixed-order A)
    rejection, test-only signing isolation, schema_version floor == ceiling == 9,
    strict JSON, and Python 3.14+ sys.modules registration.
  - Section A (Items 1-7 + PR #75 R4 #1 + Astra Option B): crash-safe two-phase
    durable ReplayStore + independent RollbackAnchor, short-write loop, whole-domain
    directory snapshot restore, zero untrusted leak on anchor mismatch, re-entrant
    locking without self-deadlock, authoritative shared baseline & callback-failure
    preservation, nonce binding, R10 enrollment_nonce, baseline_sha256, monotonic
    application_seq + crash on both sides of anchor commit, Option B zero-write
    idempotent redelivery + equivocation + real contended multi-thread races
    (duplicate/duplicate, duplicate/revocation, owner-removal/enrollment, concurrent
    standing-application baseline race), terminal revocation & tombstone persistence.
  - Section B (Items 8-12): baseline-only signer roles, absent covered-signer,
    no owner/covered-signer crossover, developer_mode scoping & persistent indicator,
    host-key bans, sig_alg/prefix binding, cryptographic nonce entropy & post-loss
    uniqueness.
  - Section C (Items 13-16 + PR #75 R4 #4): R1/R7 default-deny device-trust
    carve-out + replay store carve-out, per-hunk & per-coverage-change derived
    class, empty-domain transitions, migrations (fail-closed default comparability,
    True==1 / False==0 JCS equality anti-smuggling, downward version_bump refusal
    for both standing-application and per-change including re-adoption), R9 briefing.
  - Section D (Items 17-19): not_after strict calendar parsing (end-to-end via
    process_enrollment) + microsecond boundary + non-reversible observed expiry +
    no horizon cap + clock rollback, hold-window confirmed display + boot_epoch
    continuity + NaN/Inf/bool rejection + duplicate hold refusal + stale hold
    pruning + full re-evaluation + owner reject override + revocation cancel,
    covering-grant precedence & DC-2 rejects.
  - Section E (Items 20-26 + PR #75 R4 #2 & #5): generation, covered_signers
    (unsorted/duplicate), R6 developer_mode ceremony, exact ceremony_class &
    device-side authoritative diff (diff=None, version_bump smuggling, missing
    proposed_goal, bootstrap_owner_keys on first adoption, malformed diffs),
    per-target host, exact proposed_sha256 binding, full check-order-before-mark,
    bool-as-int / MAX_SAFE_INT bounds, and PR #75 R4 #5 per-change nonce negatives.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
ENFORCE_PATH = REPO / "tools" / "approval_enforce.py"
SIGNER_PATH = Path(__file__).resolve().with_name("_ed25519_test_signer.py")


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Register in sys.modules BEFORE exec_module (required on Python 3.14+ for dataclasses).
    sys.modules[spec.name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return mod


AE = _load_module("tendcf_approval_enforce_under_test", ENFORCE_PATH)
SIGNER = _load_module("tendcf_ed25519_test_signer", SIGNER_PATH)


# Deterministic 32-byte test seeds (purely synthetic test fixtures).
SEED_HOST = bytes([0x11]) * 32
SEED_OTHER_HOST = bytes([0x22]) * 32
SEED_OWNER = bytes([0x33]) * 32
SEED_OWNER2 = bytes([0x44]) * 32
SEED_COVERED = bytes([0x55]) * 32
SEED_COVERED2 = bytes([0x66]) * 32
SEED_DEV = bytes([0x77]) * 32
SEED_ATTACKER = bytes([0x88]) * 32

KEY_HOST = AE.key_id_from_pubkey(SIGNER.public_key_from_seed(SEED_HOST))
KEY_OTHER_HOST = AE.key_id_from_pubkey(SIGNER.public_key_from_seed(SEED_OTHER_HOST))
KEY_OWNER = AE.key_id_from_pubkey(SIGNER.public_key_from_seed(SEED_OWNER))
KEY_OWNER2 = AE.key_id_from_pubkey(SIGNER.public_key_from_seed(SEED_OWNER2))
KEY_COVERED = AE.key_id_from_pubkey(SIGNER.public_key_from_seed(SEED_COVERED))
KEY_COVERED2 = AE.key_id_from_pubkey(SIGNER.public_key_from_seed(SEED_COVERED2))
KEY_DEV = AE.key_id_from_pubkey(SIGNER.public_key_from_seed(SEED_DEV))
KEY_ATTACKER = AE.key_id_from_pubkey(SIGNER.public_key_from_seed(SEED_ATTACKER))

T0 = datetime.datetime(2026, 11, 26, 12, 0, 0, tzinfo=datetime.timezone.utc)
T1 = datetime.datetime(2026, 11, 26, 12, 5, 0, tzinfo=datetime.timezone.utc)
T_EXP = "2027-12-31T23:59:59Z"
T_AFTER_EXP = datetime.datetime(2028, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
EPOCH_1 = "boot-epoch-1"
EPOCH_2 = "boot-epoch-2"


def make_baseline_goal(
    *,
    host: str = KEY_HOST,
    schema_version: int = 9,
    advisor_keys: dict[str, dict[str, Any]] | None = None,
    extra_domains: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if advisor_keys is None:
        advisor_keys = {
            KEY_OWNER: {"role": "owner", "state": "present"},
            KEY_OWNER2: {"role": "owner", "state": "present"},
            KEY_COVERED: {"role": "covered-signer", "state": "present"},
            KEY_COVERED2: {"role": "covered-signer", "state": "present"},
        }
    domains: dict[str, Any] = {
        "device-trust": {
            "coverage": "comprehensive",
            "entries": {
                "advisor-key": copy.deepcopy(advisor_keys),
                "agent": {
                    "tendcf-agent": {
                        "sha256": "sha256:" + "d4" * 32,
                        "state": "present",
                        "version": "ops-v1.0.0",
                    }
                },
                "policy-tree": {
                    "tree": {
                        "sha256": "sha256:" + "c3" * 32,
                        "state": "present",
                    }
                },
                "supervisor": {
                    "host": {
                        "name": "launchd",
                        "state": "present",
                    }
                },
                "trust-policy": {
                    "consent": {
                        "local_yes_required": True,
                        "state": "present",
                        "tier": "consented",
                    }
                },
            },
        }
    }
    if extra_domains:
        domains.update(copy.deepcopy(extra_domains))
    return {
        "schema_version": schema_version,
        "host": host,
        "domains": domains,
    }


def make_ordinary_service_change(
    baseline: dict[str, Any],
    *,
    service_id: str = "com.tendcf.demo.app",
    cmd: list[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    proposed = copy.deepcopy(baseline)
    entry = {
        "bundle": "demo",
        "command": cmd or ["/usr/bin/true"],
        "run_as": "nobody",
        "state": "present",
        "unit": {"launchd": {"domain": "system", "keep_alive": False, "run_at_load": True}},
        "working_dir": "/",
    }
    had_sup = "supervision" in proposed["domains"]
    sup = proposed["domains"].setdefault(
        "supervision", {"coverage": "comprehensive", "entries": {}}
    )
    old_entry = sup.setdefault("entries", {}).setdefault("service", {}).get(service_id)
    sup["entries"]["service"][service_id] = entry

    hunk: dict[str, Any] = {"new": entry}
    if old_entry is not None:
        hunk["old"] = old_entry
    diff: dict[str, Any] = {
        "schema_version": 9,
        "host": baseline["host"],
        "baseline_sha256": AE.canonical_sha256(baseline),
        "proposed_sha256": AE.canonical_sha256(proposed),
        "hunks": {"supervision": {"service": {service_id: hunk}}},
    }
    if not had_sup:
        diff["coverage_changes"] = {
            "supervision": {"old": "undeclared", "new": "comprehensive"}
        }
    return proposed, diff


def make_supervisor_change(
    baseline: dict[str, Any],
    *,
    new_name: str = "systemd",
) -> tuple[dict[str, Any], dict[str, Any]]:
    proposed = copy.deepcopy(baseline)
    old_entry = copy.deepcopy(baseline["domains"]["device-trust"]["entries"]["supervisor"]["host"])
    new_entry = {"name": new_name, "state": "present"}
    proposed["domains"]["device-trust"]["entries"]["supervisor"]["host"] = new_entry
    diff = {
        "schema_version": 9,
        "host": baseline["host"],
        "baseline_sha256": AE.canonical_sha256(baseline),
        "proposed_sha256": AE.canonical_sha256(proposed),
        "hunks": {
            "device-trust": {
                "supervisor": {
                    "host": {"old": old_entry, "new": new_entry},
                }
            }
        },
    }
    return proposed, diff


def pure_version_bump_migrate(doc: dict[str, Any], target_ver: int) -> dict[str, Any]:
    out = copy.deepcopy(doc)
    out["schema_version"] = target_ver
    return out


def sign_json(record_without_sig: dict[str, Any], seed: bytes) -> bytes:
    signed = SIGNER.sign_approval_record(record_without_sig, seed, AE.jcs_dumps)
    return AE.jcs_dumps(signed)


class _EnforcerTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.baseline = make_baseline_goal()
        self.anchor = AE.InMemoryRollbackAnchor()
        self.store_dir = self.tmp / "replay-store"
        self.store = AE.ReplayStore.provision(
            self.store_dir, KEY_HOST, anchor=self.anchor, baseline_goal=self.baseline
        )
        self.enforcer = AE.ApprovalEnforcer(KEY_HOST, self.store)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _set_store_baseline(self, goal: dict[str, Any]) -> None:
        """Test helper: update the authoritative applied baseline in the store cleanly."""
        with self.store.locked():
            st = self.store.load_verified_unlocked()
            st["applied_baseline_goal"] = copy.deepcopy(goal)
            st["applied_baseline_sha256"] = AE.canonical_sha256(goal)
            self.store.commit_unlocked(st)

    def enroll_active(
        self,
        *,
        grant_id: str = "ci-bot",
        generation: int = 1,
        mode: str = "standing-approval",
        grant_class: str = "ordinary",
        covered_signers: list[str] | None = None,
        developer_mode: bool = False,
        hold_seconds: int | None = None,
        not_after: str | None = T_EXP,
        ceremony_level: str | None = None,
        now_utc: datetime.datetime = T0,
        owner_seed: bytes = SEED_OWNER,
        owner_key: str = KEY_OWNER,
        enforcer: Any = None,
    ) -> tuple[bytes, str, Any]:
        enf = enforcer or self.enforcer
        cs = sorted(covered_signers if covered_signers is not None else [KEY_COVERED])
        if ceremony_level is None:
            ceremony_level = "privileged" if developer_mode else grant_class
        if mode == "hold-window" and hold_seconds is None:
            hold_seconds = 900
        nonce = enf.issue_enrollment_nonce(
            grant_id=grant_id,
            mode=mode,
            covered_signers=cs,
            grant_class=grant_class,
            developer_mode=developer_mode,
            ceremony_level=ceremony_level,
            hold_seconds=hold_seconds,
            not_after=not_after,
            now_utc=now_utc,
        )
        rec: dict[str, Any] = {
            "schema_version": 9,
            "record_kind": "standing-enrollment",
            "host": enf.host,
            "signer": owner_key,
            "sig_alg": "ed25519",
            "grant_id": grant_id,
            "generation": generation,
            "grant_state": "active",
            "nonce": nonce,
            "mode": mode,
            "covered_signers": cs,
            "class": grant_class,
            "developer_mode": developer_mode,
        }
        if hold_seconds is not None:
            rec["hold_seconds"] = hold_seconds
        if not_after is not None:
            rec["not_after"] = not_after
        raw = sign_json(rec, owner_seed)
        receipt = enf.process_enrollment(raw, now_utc=now_utc)
        return raw, nonce, receipt

    def make_app_bytes(
        self,
        *,
        grant_id: str = "ci-bot",
        generation: int = 1,
        application_seq: int = 1,
        enrollment_nonce: str,
        baseline: dict[str, Any] | None = None,
        proposed: dict[str, Any],
        ceremony_class: str = "ordinary",
        signer_seed: bytes = SEED_COVERED,
        signer_key: str = KEY_COVERED,
        host: str = KEY_HOST,
    ) -> bytes:
        base = baseline if baseline is not None else self.enforcer.baseline_goal
        assert base is not None
        rec = {
            "schema_version": 9,
            "record_kind": "standing-application",
            "host": host,
            "signer": signer_key,
            "sig_alg": "ed25519",
            "grant_id": grant_id,
            "generation": generation,
            "application_seq": application_seq,
            "enrollment_nonce": enrollment_nonce,
            "baseline_sha256": AE.canonical_sha256(base),
            "proposed_sha256": AE.canonical_sha256(proposed),
            "ceremony_class": ceremony_class,
        }
        return sign_json(rec, signer_seed)

    def make_revocation_bytes(
        self,
        *,
        grant_id: str = "ci-bot",
        generation: int = 2,
        owner_seed: bytes = SEED_OWNER,
        owner_key: str = KEY_OWNER,
        host: str = KEY_HOST,
    ) -> bytes:
        rec = {
            "schema_version": 9,
            "record_kind": "standing-enrollment",
            "host": host,
            "signer": owner_key,
            "sig_alg": "ed25519",
            "grant_id": grant_id,
            "generation": generation,
            "grant_state": "revoked",
        }
        return sign_json(rec, owner_seed)


# ===========================================================================
# Section 0: RFC 8032 §7.1 Ed25519 Test Vectors, Canonicality & Isolation
# ===========================================================================

class TestSection0Ed25519AndStrictParsing(unittest.TestCase):
    def test_module_registered_in_sys_modules_and_no_signing_exported(self) -> None:
        # Codex #1 / Neon F1 / Adversary H1: Python 3.14 dataclasses requires sys.modules registration.
        self.assertIn("tendcf_approval_enforce_under_test", sys.modules)
        self.assertIn("_tendcf_projector_jcs", sys.modules)
        # Codex Other #1 / Adversary M3: non-constant-time signing helpers NOT exported by tools/approval_enforce.py.
        for forbidden in ("ed25519_sign", "ed25519_public_key_from_seed", "sign_approval_record"):
            self.assertFalse(hasattr(AE, forbidden), f"signing helper {forbidden} must not live in enforcement module")
            self.assertNotIn(forbidden, AE.__all__)

    def test_rfc8032_section7_1_official_vectors(self) -> None:
        vectors = [
            (
                "TEST 1 (empty)",
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "TEST 2 (1 byte)",
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "TEST 3 (2 bytes)",
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
            (
                "TEST SHA(abc) (64 bytes)",
                "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
                "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
                "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
            ),
            (
                "TEST 1024 (1023 bytes)",
                "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
                "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
                (
                    "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
                    "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
                    "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
                    "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
                    "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
                    "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
                    "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
                    "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
                    "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
                    "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
                    "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
                    "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
                    "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
                    "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
                    "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
                    "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
                    "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
                    "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
                    "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
                    "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
                    "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
                    "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
                    "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
                    "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
                    "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
                    "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
                    "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
                    "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
                    "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
                    "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
                    "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
                    "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
                ),
                "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
                "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
            ),
        ]
        for label, sk_hex, pk_hex, msg_hex, sig_hex in vectors:
            with self.subTest(vector=label):
                sk = bytes.fromhex(sk_hex)
                pk = bytes.fromhex(pk_hex)
                msg = bytes.fromhex(msg_hex)
                sig = bytes.fromhex(sig_hex)
                self.assertEqual(SIGNER.public_key_from_seed(sk), pk)
                self.assertEqual(SIGNER.sign(sk, msg), sig)
                self.assertTrue(AE.verify_ed25519(pk, msg, sig))
                bad_sig = bytearray(sig)
                bad_sig[0] ^= 0x01
                self.assertFalse(AE.verify_ed25519(pk, msg, bytes(bad_sig)))

    def test_ed25519_rejects_noncanonical_S_R_A_and_small_order_R(self) -> None:
        sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pk = SIGNER.public_key_from_seed(sk)
        msg = b"tendcf-canonical-ed25519"
        sig = SIGNER.sign(sk, msg)
        self.assertTrue(AE.verify_ed25519(pk, msg, sig))

        # 1. Malleated S >= L.
        s_val = int.from_bytes(sig[32:], "little")
        malleated_s = (s_val + AE.ED25519_L).to_bytes(32, "little")
        self.assertFalse(AE.verify_ed25519(pk, msg, sig[:32] + malleated_s))
        self.assertFalse(AE.verify_ed25519(pk, msg, sig[:32] + AE.ED25519_L.to_bytes(32, "little")))

        # 2. Non-canonical y >= p.
        noncanon_y_p = AE.ED25519_P.to_bytes(32, "little")
        noncanon_y_p1 = (AE.ED25519_P + 1).to_bytes(32, "little")
        self.assertIsNone(AE.ed25519_decompress_point(noncanon_y_p))
        self.assertIsNone(AE.ed25519_decompress_point(noncanon_y_p1))
        self.assertFalse(AE.verify_ed25519(noncanon_y_p, msg, sig))
        self.assertFalse(AE.verify_ed25519(pk, msg, noncanon_y_p + sig[32:]))

        # 3. Non-canonical x == 0 with sign_bit == 1.
        neg_zero_1 = (1 | (1 << 255)).to_bytes(32, "little")
        neg_zero_pm1 = ((AE.ED25519_P - 1) | (1 << 255)).to_bytes(32, "little")
        self.assertIsNone(AE.ed25519_decompress_point(neg_zero_1))
        self.assertIsNone(AE.ed25519_decompress_point(neg_zero_pm1))
        neutral_bytes = (1).to_bytes(32, "little")
        self.assertIsNotNone(AE.ed25519_decompress_point(neutral_bytes))
        self.assertFalse(AE.verify_ed25519(neg_zero_1, msg, sig))
        self.assertFalse(AE.verify_ed25519(pk, msg, neg_zero_1 + sig[32:]))

        # 4. Small-order A (identity point A=(0,1), R=(0,1), S=0) rejected.
        zero_s = (0).to_bytes(32, "little")
        self.assertFalse(AE.verify_ed25519(neutral_bytes, msg, neutral_bytes + zero_s))

        # 5. Adversary M3: Mixed-order A = [a]B + Q_2 with small-order R = O MUST be rejected!
        q2 = AE.ed25519_decompress_point((AE.ED25519_P - 1).to_bytes(32, "little"))
        assert q2 is not None
        a_scalar = 123456789
        pt_mixed = SIGNER._point_add(SIGNER._point_mul(a_scalar, SIGNER.BASE_POINT), q2)
        mixed_pk = SIGNER.compress_point(pt_mixed)
        # Find a message whose challenge k is even so [k]Q_2 == O, giving exact [k*a]B == O + [k]A!
        found = False
        for i in range(100):
            cand_msg = f"mixed-order-{i}".encode("ascii")
            k = int.from_bytes(hashlib.sha512(neutral_bytes + mixed_pk + cand_msg).digest(), "little") % AE.ED25519_L
            if k % 2 == 0:
                s_mixed = (k * a_scalar) % AE.ED25519_L
                forged_sig = neutral_bytes + s_mixed.to_bytes(32, "little")
                # Even though [S]B == O + [k]A holds algebraically, small-order R=O is rejected!
                self.assertFalse(AE.verify_ed25519(mixed_pk, cand_msg, forged_sig))
                found = True
                break
        self.assertTrue(found)

    def test_schema_version_floor_equals_ceiling_strict_json_and_bool_as_int_bounds(self) -> None:
        dup = b'{"schema_version":9,"schema_version":9}'
        with self.assertRaises(AE.MalformedRecordError) as ctx:
            AE.parse_strict_json(dup)
        self.assertEqual(ctx.exception.code, "duplicate_or_invalid_json")

        nfd = '{"note":"cafe\u0301"}'.encode("utf-8")
        with self.assertRaises(AE.MalformedRecordError) as ctx2:
            AE.parse_strict_json(nfd)
        self.assertEqual(ctx2.exception.code, "non_nfc_string")

        for bad_ver in (7, 8, 10, True, "9"):
            with self.assertRaises(AE.MalformedRecordError) as ctx3:
                AE.validate_approval_record_shape({"schema_version": bad_ver})
            self.assertEqual(ctx3.exception.code, "unsupported_schema_version")

        # Neon F8: bool as int on application_seq, approval_seq, generation, hold_seconds & approval_seq > MAX_SAFE_INT.
        base_pc = {
            "schema_version": 9,
            "record_kind": "per-change",
            "host": KEY_HOST,
            "signer": KEY_OWNER,
            "sig_alg": "ed25519",
            "proposed_sha256": "sha256:" + "ab" * 32,
            "nonce": "a" * 32,
            "approval_seq": 0,
            "verdict": "accept",
            "ceremony_class": "ordinary",
            "signature": "ed25519-sig:" + "00" * 64,
        }
        for bad_seq in (True, False, -1, AE.MAX_SAFE_INT + 1):
            with self.assertRaises(AE.MalformedRecordError):
                AE.validate_approval_record_shape(dict(base_pc, approval_seq=bad_seq))

        base_app = {
            "schema_version": 9,
            "record_kind": "standing-application",
            "host": KEY_HOST,
            "signer": KEY_COVERED,
            "sig_alg": "ed25519",
            "grant_id": "g1",
            "generation": 1,
            "application_seq": 1,
            "enrollment_nonce": "b" * 32,
            "baseline_sha256": "sha256:" + "11" * 32,
            "proposed_sha256": "sha256:" + "22" * 32,
            "ceremony_class": "ordinary",
            "signature": "ed25519-sig:" + "00" * 64,
        }
        with self.assertRaises(AE.MalformedRecordError):
            AE.validate_approval_record_shape(dict(base_app, application_seq=True))
        with self.assertRaises(AE.MalformedRecordError):
            AE.validate_approval_record_shape(dict(base_app, generation=True))

        base_enr = {
            "schema_version": 9,
            "record_kind": "standing-enrollment",
            "host": KEY_HOST,
            "signer": KEY_OWNER,
            "sig_alg": "ed25519",
            "grant_id": "g1",
            "generation": 1,
            "grant_state": "active",
            "nonce": "c" * 32,
            "mode": "hold-window",
            "hold_seconds": 60,
            "covered_signers": [KEY_COVERED],
            "class": "ordinary",
            "developer_mode": False,
            "not_after": T_EXP,
            "signature": "ed25519-sig:" + "00" * 64,
        }
        with self.assertRaises(AE.MalformedRecordError):
            AE.validate_approval_record_shape(dict(base_enr, hold_seconds=True))
        with self.assertRaises(AE.MalformedRecordError):
            AE.validate_approval_record_shape(dict(base_enr, generation=True))


# ===========================================================================
# Section A: State, Replay, Freshness, Two-Phase Durability & Races (Items 1-7)
# ===========================================================================

class TestSectionAStateReplayAndFreshness(_EnforcerTestBase):
    def test_item01_rollback_store_loss_corrupt_partial_restore_voids_grants(self) -> None:
        # 1. Explicit independent RollbackAnchor required; co-located FileRollbackAnchor refused!
        with self.assertRaises(TypeError):
            AE.ReplayStore(self.tmp / "no-anchor", KEY_HOST, anchor=None)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            AE.ReplayStore(
                self.tmp / "same-dir",
                KEY_HOST,
                anchor=AE.FileRollbackAnchor(self.tmp / "same-dir" / "adjacent.anchor"),
            )
        # Opening an unprovisioned store fails closed (does not silently provision!).
        unprov = AE.ReplayStore(
            self.tmp / "unprovisioned", KEY_HOST, anchor=AE.InMemoryRollbackAnchor()
        )
        with self.assertRaises(AE.StoreRollbackError) as ctx_unp:
            unprov.snapshot(allow_voided=True)
        self.assertEqual(ctx_unp.exception.code, "store_unprovisioned")

        # 2. Whole-domain directory snapshot restore while independent anchor advances -> fails closed!
        raw_enroll, nonce1, _ = self.enroll_active(grant_id="grant-a")
        dir_snapshot = self.tmp / "store-dir-snapshot-v1"
        shutil.copytree(self.store_dir, dir_snapshot)

        # Revoke grant-a -> independent anchor advances past snapshot!
        rev_bytes = self.make_revocation_bytes(grant_id="grant-a", generation=2)
        self.enforcer.process_enrollment(rev_bytes, now_utc=T0)

        # Restore ENTIRE store directory from tombstone-free snapshot (anchor stays at revoked gen!).
        proposed, diff = make_ordinary_service_change(self.baseline)
        app = self.make_app_bytes(
            grant_id="grant-a", generation=1, application_seq=1, enrollment_nonce=nonce1, baseline=self.baseline, proposed=proposed
        )
        shutil.rmtree(self.store_dir)
        shutil.copytree(dir_snapshot, self.store_dir)
        with self.assertRaises(AE.StoreRollbackError) as ctx_dir:
            self.enforcer.process_standing_application(
                app, proposed_goal=proposed, diff=diff, now_utc=T0, now_mono=10.0
            )
        self.assertEqual(ctx_dir.exception.code, "store_missing_rollback")
        # Stays voided on retry!
        with self.assertRaises(AE.StoreRollbackError) as ctx_void:
            self.enforcer.process_standing_application(
                app, proposed_goal=proposed, diff=diff, now_utc=T0, now_mono=11.0
            )
        self.assertEqual(ctx_void.exception.code, "store_voided")

        # 3. Neon F3 / Adversary C4: Attacker tampers anchored store file with poison
        #    (last_seen_utc="9999-...", approval_seq=MAX_SAFE_INT, fake tombstones, fake rejects)
        #    -> rollback detection MUST NOT copy ANY tampered field into voided state or post-recovery!
        self.store.recover_after_store_loss(baseline_goal=self.baseline)
        self.enroll_active(grant_id="grant-b")
        cur_path = self.store.current_store_path
        assert cur_path is not None
        tampered = json.loads(cur_path.read_text())
        tampered["last_seen_utc"] = "9999-12-31T23:59:59Z"
        tampered["approval_seq"] = AE.MAX_SAFE_INT
        tampered["persisted_rejects"]["sha256:" + "de" * 32] = {"recorded_utc": "2026-11-26T12:00:00Z", "refused": ["x"], "signer": KEY_OWNER}
        tampered["grants"]["fake-tombstone"] = {
            "generation": 99, "grant_state": "revoked", "tombstoned": True,
            "active_payload_jcs_b64": None, "enrollment_nonce": None, "scope": None, "application_seq_mark": 0,
        }
        cur_path.write_bytes(AE.jcs_dumps(tampered))
        with self.assertRaises(AE.StoreRollbackError) as ctx_tamp:
            self.enforcer.process_enrollment(raw_enroll, now_utc=T0)
        self.assertEqual(ctx_tamp.exception.code, "store_rollback_detected")

        self.store.recover_after_store_loss(baseline_goal=self.baseline)
        recovered = self.store.snapshot()
        self.assertIsNone(recovered["last_seen_utc"])
        self.assertEqual(recovered["approval_seq"], -1)
        self.assertEqual(recovered["persisted_rejects"], {})
        self.assertNotIn("fake-tombstone", recovered["grants"])
        # Host is NOT bricked after recovery: fresh enrollment works!
        _, _, r_rec = self.enroll_active(grant_id="fake-tombstone", now_utc=T0)
        self.assertEqual(r_rec.status, "accepted")

        # 4. Separate-directory FileRollbackAnchor detects rollback across reload.
        anchor_dir = self.tmp / "separate-anchor-domain"
        store_dir_fs = self.tmp / "separate-store-domain"
        anchor_fs = AE.FileRollbackAnchor(anchor_dir / "hw.anchor")
        store_fs = AE.ReplayStore.provision(store_dir_fs, KEY_HOST, anchor=anchor_fs, baseline_goal=self.baseline)
        enf_fs = AE.ApprovalEnforcer(KEY_HOST, store_fs)
        self.enroll_active(grant_id="grant-fs", enforcer=enf_fs)
        snap_fs = self.tmp / "snap-fs"
        shutil.copytree(store_dir_fs, snap_fs)
        enf_fs.process_enrollment(self.make_revocation_bytes(grant_id="grant-fs", generation=2), now_utc=T0)
        shutil.rmtree(store_dir_fs)
        shutil.copytree(snap_fs, store_dir_fs)
        reloaded = AE.ReplayStore(store_dir_fs, KEY_HOST, anchor=AE.FileRollbackAnchor(anchor_dir / "hw.anchor"))
        with self.assertRaises(AE.StoreRollbackError):
            reloaded.snapshot(allow_voided=False)

    def test_item01_short_write_loop_and_reentrant_lock_and_callback_failure(self) -> None:
        # 1. Macroscope 4708874407 / Codex #9: short os.write loops until all bytes written!
        real_write = os.write
        calls: list[int] = []

        def short_write(fd: int, data: Any) -> int:
            chunk = bytes(data)[:7]
            calls.append(len(chunk))
            return real_write(fd, chunk)

        out_path = self.tmp / "short-write-target.bin"
        payload = b"0123456789abcdefghijklmnopqrstuvwxyz"
        with mock.patch("os.write", side_effect=short_write):
            AE._atomic_write_file(out_path, payload)
        self.assertEqual(out_path.read_bytes(), payload)
        self.assertGreater(len(calls), 3)

        # Short write returning 0 fails loudly before os.replace.
        with mock.patch("os.write", return_value=0):
            with self.assertRaises(OSError):
                AE._atomic_write_file(self.tmp / "zero-write.bin", b"abc")
        self.assertFalse((self.tmp / "zero-write.bin").exists())

        # 2. Neon F7 / Adversary H3: Re-entrant store.snapshot() & developer_mode_indicator_active()
        #    from inside _apply_callback MUST NOT deadlock!
        cb_observations: list[tuple[bool, int]] = []

        def inspecting_cb(goal: dict[str, Any]) -> None:
            snap = self.store.snapshot()
            ind = self.enforcer.developer_mode_indicator_active(T0)
            cb_observations.append((ind, snap["grants"]["reent-g"]["application_seq_mark"]))

        enf_cb = AE.ApprovalEnforcer(KEY_HOST, self.store, apply_callback=inspecting_cb)
        _, nonce, _ = self.enroll_active(grant_id="reent-g", enforcer=enf_cb)
        prop1, diff1 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.reent")
        app1 = self.make_app_bytes(
            grant_id="reent-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop1
        )
        res = enf_cb.process_standing_application(app1, proposed_goal=prop1, diff=diff1, now_utc=T0)
        self.assertEqual(res.decision, "applied")
        self.assertEqual(cb_observations, [(False, 1)])

        # 3. Codex #8 / Macroscope 4708874409: Callback failure keeps replay mark consumed
        #    while preserving prior authoritative baseline (even across restart!).
        class _ActuateFailed(RuntimeError):
            pass

        def failing_cb(_goal: dict[str, Any]) -> None:
            raise _ActuateFailed("disk full during actuation")

        enf_fail = AE.ApprovalEnforcer(KEY_HOST, self.store, apply_callback=failing_cb)
        prior_hash = AE.canonical_sha256(enf_fail.baseline_goal)
        prop2, diff2 = make_ordinary_service_change(enf_fail.baseline_goal, service_id="com.tendcf.fail")
        app2 = self.make_app_bytes(
            grant_id="reent-g",
            generation=1,
            application_seq=2,
            enrollment_nonce=nonce,
            baseline=enf_fail.baseline_goal,
            proposed=prop2,
        )
        with self.assertRaises(_ActuateFailed):
            enf_fail.process_standing_application(app2, proposed_goal=prop2, diff=diff2, now_utc=T0)
        # Codex R3 #1 / Macroscope 4709558270: callback exception leaves pending_actuation persisted
        # (because callback raising cannot prove device did not change), replay mark consumed (2),
        # actuation_count NOT incremented, prior baseline PRESERVED until reconciled!
        self.assertEqual(enf_fail.actuation_count, 0)
        snap_fail = self.store.snapshot()
        self.assertEqual(snap_fail["grants"]["reent-g"]["application_seq_mark"], 2)
        self.assertEqual(AE.canonical_sha256(enf_fail.baseline_goal), prior_hash)
        self.assertIsNotNone(snap_fail["pending_actuation"])
        fail_act_id = snap_fail["pending_actuation"]["actuation_id"]
        # Fresh reloaded enforcer sees prior baseline & pending_actuation blocking operations!
        reloaded_enf = AE.ApprovalEnforcer(KEY_HOST, AE.ReplayStore(self.store_dir, KEY_HOST, anchor=self.anchor))
        self.assertEqual(AE.canonical_sha256(reloaded_enf.baseline_goal), prior_hash)
        with self.assertRaises(AE.ReplayError) as ctx_pa:
            reloaded_enf.process_standing_application(app2, proposed_goal=prop2, diff=diff2, now_utc=T0)
        self.assertEqual(ctx_pa.exception.code, "pending_actuation_unreconciled")
        # After explicit abort reconciliation, replay mark 2 STILL blocks app2!
        reloaded_enf.reconcile_pending_actuation(fail_act_id, applied_on_device=False)
        with self.assertRaises(AE.ReplayError) as ctx_stale:
            reloaded_enf.process_standing_application(app2, proposed_goal=prop2, diff=diff2, now_utc=T0)
        self.assertEqual(ctx_stale.exception.code, "stale_application_seq")

    def test_item02_enrollment_nonce_bound_to_full_shown_scope(self) -> None:
        # 1. An ordinary per-change nonce offered for a baseline enrollment -> refused.
        pc_nonce = self.enforcer.issue_per_change_nonce(
            proposed_sha256="sha256:" + "12" * 32, ceremony_class="ordinary", now_utc=T0
        )
        rec = {
            "schema_version": 9,
            "record_kind": "standing-enrollment",
            "host": KEY_HOST,
            "signer": KEY_OWNER,
            "sig_alg": "ed25519",
            "grant_id": "base-grant",
            "generation": 1,
            "grant_state": "active",
            "nonce": pc_nonce,
            "mode": "standing-approval",
            "covered_signers": [KEY_COVERED],
            "class": "baseline",
            "developer_mode": False,
            "not_after": T_EXP,
        }
        with self.assertRaises(AE.NonceError) as ctx:
            self.enforcer.process_enrollment(sign_json(rec, SEED_OWNER), now_utc=T0)
        self.assertEqual(ctx.exception.code, "nonce_scope_mismatch")

        # 2. Adversary C2: hold_seconds=True refused in issue_enrollment_nonce!
        with self.assertRaises(AE.MalformedRecordError):
            self.enforcer.issue_enrollment_nonce(
                grant_id="bool-hold",
                mode="hold-window",
                covered_signers=[KEY_COVERED],
                grant_class="ordinary",
                developer_mode=False,
                ceremony_level="ordinary",
                hold_seconds=True,  # type: ignore[arg-type]
                not_after=T_EXP,
                now_utc=T0,
            )

        # 3. A developer-mode enrollment carrying a nonce from an ordinary non-developer ceremony -> refused.
        ord_nonce = self.enforcer.issue_enrollment_nonce(
            grant_id="dev-grant",
            mode="standing-approval",
            covered_signers=[KEY_DEV],
            grant_class="ordinary",
            developer_mode=False,
            ceremony_level="ordinary",
            not_after=T_EXP,
            now_utc=T0,
        )
        dev_rec = dict(
            rec,
            grant_id="dev-grant",
            nonce=ord_nonce,
            covered_signers=[KEY_DEV],
            **{"class": "ordinary", "developer_mode": True},
        )
        with self.assertRaises(AE.NonceError):
            self.enforcer.process_enrollment(sign_json(dev_rec, SEED_OWNER), now_utc=T0)

        # 4. Scope tampering on EVERY field refused.
        base_kwargs = dict(
            grant_id="scoped-grant",
            mode="hold-window",
            covered_signers=[KEY_COVERED],
            grant_class="ordinary",
            developer_mode=False,
            ceremony_level="ordinary",
            hold_seconds=600,
            not_after=T_EXP,
            now_utc=T0,
        )
        mutations = [
            ("mode", {"mode": "standing-approval"}, ["hold_seconds"]),
            ("covered_signers", {"covered_signers": sorted([KEY_COVERED, KEY_COVERED2])}, []),
            ("class", {"class": "privileged"}, []),
            ("hold_seconds", {"hold_seconds": 60}, []),
            ("not_after", {"not_after": "2028-12-31T23:59:59Z"}, []),
            ("grant_id", {"grant_id": "other-grant"}, []),
        ]
        for label, updates, drops in mutations:
            with self.subTest(mutated_field=label):
                n = self.enforcer.issue_enrollment_nonce(**base_kwargs)
                r = {
                    "schema_version": 9,
                    "record_kind": "standing-enrollment",
                    "host": KEY_HOST,
                    "signer": KEY_OWNER,
                    "sig_alg": "ed25519",
                    "grant_id": "scoped-grant",
                    "generation": 1,
                    "grant_state": "active",
                    "nonce": n,
                    "mode": "hold-window",
                    "hold_seconds": 600,
                    "covered_signers": [KEY_COVERED],
                    "class": "ordinary",
                    "developer_mode": False,
                    "not_after": T_EXP,
                }
                r.update(updates)
                for d in drops:
                    r.pop(d, None)
                with self.assertRaises(AE.NonceError):
                    self.enforcer.process_enrollment(sign_json(r, SEED_OWNER), now_utc=T0)

        # 5. Consumed nonce cannot be reused on generation 2.
        _, used_nonce, _ = self.enroll_active(grant_id="single-use", generation=1)
        gen2_reuse = dict(rec, grant_id="single-use", generation=2, nonce=used_nonce, **{"class": "ordinary"})
        with self.assertRaises(AE.NonceError) as ctx_reuse:
            self.enforcer.process_enrollment(sign_json(gen2_reuse, SEED_OWNER), now_utc=T0)
        self.assertEqual(ctx_reuse.exception.code, "unknown_or_consumed_nonce")

    def test_item03_r10_enrollment_nonce_binding_after_store_loss(self) -> None:
        _, old_nonce, _ = self.enroll_active(grant_id="reborn", generation=1)
        proposed, diff = make_ordinary_service_change(self.baseline)
        old_app = self.make_app_bytes(
            grant_id="reborn", generation=1, application_seq=1, enrollment_nonce=old_nonce, proposed=proposed
        )

        # Simulate store loss -> fail closed -> owner recovery -> fresh gen-1 enrollment with NEW nonce.
        cur = self.store.current_store_path
        assert cur is not None
        cur.unlink()
        with self.assertRaises(AE.StoreRollbackError):
            self.store.snapshot(allow_voided=False)
        self.store.recover_after_store_loss(baseline_goal=self.baseline)
        _, new_nonce, _ = self.enroll_active(grant_id="reborn", generation=1)
        self.assertNotEqual(old_nonce, new_nonce)

        with self.assertRaises(AE.NonceError) as ctx:
            self.enforcer.process_standing_application(
                old_app, proposed_goal=proposed, diff=diff, now_utc=T0
            )
        self.assertEqual(ctx.exception.code, "enrollment_nonce_mismatch")

        new_app = self.make_app_bytes(
            grant_id="reborn", generation=1, application_seq=1, enrollment_nonce=new_nonce, proposed=proposed
        )
        res = self.enforcer.process_standing_application(
            new_app, proposed_goal=proposed, diff=diff, now_utc=T0
        )
        self.assertEqual(res.decision, "applied")

    def test_item04_baseline_sha256_binding_and_no_first_adoption(self) -> None:
        fresh_store = AE.ReplayStore.provision(
            self.tmp / "first-adopt", KEY_HOST, anchor=AE.InMemoryRollbackAnchor(), baseline_goal=None
        )
        fresh_enf = AE.ApprovalEnforcer(KEY_HOST, fresh_store)
        proposed0, diff0 = make_ordinary_service_change(self.baseline)
        app0 = self.make_app_bytes(
            grant_id="ci-bot",
            generation=1,
            application_seq=1,
            enrollment_nonce="a" * 32,
            baseline=self.baseline,
            proposed=proposed0,
        )
        with self.assertRaises(AE.ReplayError) as ctx:
            fresh_enf.process_standing_application(app0, proposed_goal=proposed0, diff=diff0, now_utc=T0)
        self.assertEqual(ctx.exception.code, "first_adoption_disallowed")

        _, nonce, _ = self.enroll_active(grant_id="ci-bot")
        held_proposed, held_diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.old.svc")
        held_app = self.make_app_bytes(
            grant_id="ci-bot", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=held_proposed
        )

        later_proposed, later_diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.later.svc")
        pc_nonce = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(later_proposed), ceremony_class="ordinary", now_utc=T0
        )
        pc_rec = {
            "schema_version": 9,
            "record_kind": "per-change",
            "host": KEY_HOST,
            "signer": KEY_OWNER,
            "sig_alg": "ed25519",
            "baseline_sha256": AE.canonical_sha256(self.baseline),
            "proposed_sha256": AE.canonical_sha256(later_proposed),
            "nonce": pc_nonce,
            "approval_seq": 0,
            "verdict": "accept",
            "ceremony_class": "ordinary",
        }
        self.enforcer.process_per_change(
            sign_json(pc_rec, SEED_OWNER), proposed_goal=later_proposed, diff=later_diff, now_utc=T0
        )

        with self.assertRaises(AE.ReplayError) as ctx2:
            self.enforcer.process_standing_application(
                held_app, proposed_goal=held_proposed, diff=held_diff, now_utc=T0
            )
        self.assertEqual(ctx2.exception.code, "baseline_sha256_mismatch")

    def test_item05_application_seq_monotonic_persist_before_apply_and_hold(self) -> None:
        _, nonce1, _ = self.enroll_active(grant_id="seq-grant", generation=1, mode="standing-approval")
        prop1, diff1 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.svc1")
        app7 = self.make_app_bytes(
            grant_id="seq-grant", generation=1, application_seq=7, enrollment_nonce=nonce1, proposed=prop1
        )

        class _Crash(RuntimeError):
            pass

        with self.assertRaises(_Crash):
            self.enforcer.process_standing_application(
                app7,
                proposed_goal=prop1,
                diff=diff1,
                now_utc=T0,
                before_apply_hook=lambda: (_ for _ in ()).throw(_Crash("power loss")),
            )
        self.assertEqual(self.enforcer.actuation_count, 0)
        self.assertEqual(self.store.snapshot()["grants"]["seq-grant"]["application_seq_mark"], 7)
        self.assertIsNotNone(self.store.snapshot()["pending_actuation"])

        # Codex R2 #1: unreconciled pending_actuation blocks further operations until reconciled!
        with self.assertRaises(AE.ReplayError) as ctx_pend:
            self.enforcer.process_standing_application(app7, proposed_goal=prop1, diff=diff1, now_utc=T0)
        self.assertEqual(ctx_pend.exception.code, "pending_actuation_unreconciled")

        act_id_5 = self.store.snapshot()["pending_actuation"]["actuation_id"]
        rec_abort = self.enforcer.reconcile_pending_actuation(act_id_5, applied_on_device=False)
        self.assertEqual(rec_abort["status"], "aborted")
        self.assertIsNone(self.store.snapshot()["pending_actuation"])

        # Replay mark 7 remains durably consumed after abort reconciliation!
        with self.assertRaises(AE.ReplayError) as ctx:
            self.enforcer.process_standing_application(app7, proposed_goal=prop1, diff=diff1, now_utc=T0)
        self.assertEqual(ctx.exception.code, "stale_application_seq")

        _, nonce2, _ = self.enroll_active(grant_id="seq-grant", generation=2, mode="hold-window", hold_seconds=60)
        self.assertEqual(self.store.snapshot()["grants"]["seq-grant"]["application_seq_mark"], 7)
        app7_gen2 = self.make_app_bytes(
            grant_id="seq-grant", generation=2, application_seq=7, enrollment_nonce=nonce2, proposed=prop1
        )
        with self.assertRaises(AE.ReplayError):
            self.enforcer.process_standing_application(app7_gen2, proposed_goal=prop1, diff=diff1, now_utc=T0)

        app8_gen2 = self.make_app_bytes(
            grant_id="seq-grant", generation=2, application_seq=8, enrollment_nonce=nonce2, proposed=prop1
        )
        res = self.enforcer.process_standing_application(
            app8_gen2, proposed_goal=prop1, diff=diff1, now_utc=T0, now_mono=15.0, boot_epoch=EPOCH_1, display_confirmed=True
        )
        self.assertEqual(res.decision, "held")
        self.assertEqual(self.store.snapshot()["grants"]["seq-grant"]["application_seq_mark"], 8)

    def test_item06_option_b_identical_redelivery_zero_writes_and_equivocation(self) -> None:
        raw_enroll, nonce1, receipt1 = self.enroll_active(
            grant_id="optb-grant", generation=1, mode="hold-window", hold_seconds=300
        )
        prop1, diff1 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.optb")
        app7 = self.make_app_bytes(
            grant_id="optb-grant", generation=1, application_seq=7, enrollment_nonce=nonce1, proposed=prop1
        )
        hold_res = self.enforcer.process_standing_application(
            app7, proposed_goal=prop1, diff=diff1, now_utc=T0, now_mono=100.0, boot_epoch=EPOCH_1, display_confirmed=True
        )
        self.assertEqual(hold_res.decision, "held")

        state_before = self.store.snapshot()
        cur_path = self.store.current_store_path
        assert cur_path is not None
        disk_before = cur_path.read_bytes()
        anchor_before = self.anchor.read()
        writes_before = self.store.write_count
        nonce_consumes_before = self.store.nonce_consume_count
        prompts_before = self.enforcer.prompt_count
        actuations_before = self.enforcer.actuation_count

        parsed = json.loads(raw_enroll)
        reordered_wire = json.dumps(parsed, indent=2, sort_keys=False).encode("utf-8")
        receipt2 = self.enforcer.process_enrollment(reordered_wire, now_utc=T1)

        self.assertEqual(receipt1, receipt2)
        self.assertEqual(self.store.write_count, writes_before)
        self.assertEqual(self.store.nonce_consume_count, nonce_consumes_before)
        self.assertEqual(self.enforcer.prompt_count, prompts_before)
        self.assertEqual(self.enforcer.actuation_count, actuations_before)
        self.assertEqual(self.store.snapshot(), state_before)
        self.assertEqual(cur_path.read_bytes(), disk_before)
        self.assertEqual(self.anchor.read(), anchor_before)

        # Replay of application 7 still refused!
        with self.assertRaises(AE.ReplayError) as ctx_rep:
            self.enforcer.process_standing_application(
                app7, proposed_goal=prop1, diff=diff1, now_utc=T1
            )
        self.assertEqual(ctx_rep.exception.code, "duplicate_pending_hold")

        # Equivocation (scope or nonce change at same generation) refused!
        equiv_scope = copy.deepcopy(parsed)
        equiv_scope["hold_seconds"] = 1
        with self.assertRaises(AE.ReplayError) as ctx_eq1:
            self.enforcer.process_enrollment(sign_json(equiv_scope, SEED_OWNER), now_utc=T1)
        self.assertEqual(ctx_eq1.exception.code, "enrollment_equivocation")

        equiv_nonce = copy.deepcopy(parsed)
        equiv_nonce["nonce"] = AE.generate_device_nonce()
        with self.assertRaises(AE.ReplayError) as ctx_eq2:
            self.enforcer.process_enrollment(sign_json(equiv_nonce, SEED_OWNER), now_utc=T1)
        self.assertEqual(ctx_eq2.exception.code, "enrollment_equivocation")

        # Duplicate keys, bad sig, removed owner, missing stored bytes, and expiry all fail closed!
        with self.assertRaises(AE.MalformedRecordError):
            self.enforcer.process_enrollment(raw_enroll[:-1] + b',"generation":1}', now_utc=T1)

        bad_sig = dict(parsed, signature="ed25519-sig:" + "00" * 64)
        with self.assertRaises(AE.SignatureError):
            self.enforcer.process_enrollment(AE.jcs_dumps(bad_sig), now_utc=T1)

        removed_owner_base = copy.deepcopy(self.baseline)
        removed_owner_base["domains"]["device-trust"]["entries"]["advisor-key"][KEY_OWNER]["state"] = "absent"
        self._set_store_baseline(removed_owner_base)
        with self.assertRaises(AE.TrustRootError) as ctx_owner:
            self.enforcer.process_enrollment(raw_enroll, now_utc=T1)
        self.assertEqual(ctx_owner.exception.code, "signer_not_owner")
        self._set_store_baseline(self.baseline)

        st = self.store.snapshot()
        st["grants"]["optb-grant"]["active_payload_jcs_b64"] = None
        raw_st = AE.jcs_dumps(st)
        p = self.store.version_path(st["store_generation"])
        p.write_bytes(raw_st)
        self.anchor.write(AE.AnchorState(st["store_generation"], hashlib.sha256(raw_st).hexdigest()))
        with self.assertRaises(AE.ReplayError) as ctx_missing:
            self.enforcer.process_enrollment(raw_enroll, now_utc=T1)
        self.assertEqual(ctx_missing.exception.code, "missing_stored_payload")

        # Expired identical redelivery fails closed!
        with self.assertRaises(AE.ScopeError) as ctx_exp:
            self.enforcer.process_enrollment(raw_enroll, now_utc=T_AFTER_EXP)
        self.assertEqual(ctx_exp.exception.code, "enrollment_expired")

    def test_item06_option_b_two_phase_crash_boundaries_and_contended_races(self) -> None:
        class _SimCrash(RuntimeError):
            pass

        nonce = self.enforcer.issue_enrollment_nonce(
            grant_id="crash-grant",
            mode="standing-approval",
            covered_signers=[KEY_COVERED],
            grant_class="ordinary",
            developer_mode=False,
            ceremony_level="ordinary",
            not_after=T_EXP,
            now_utc=T0,
        )
        rec = {
            "schema_version": 9,
            "record_kind": "standing-enrollment",
            "host": KEY_HOST,
            "signer": KEY_OWNER,
            "sig_alg": "ed25519",
            "grant_id": "crash-grant",
            "generation": 1,
            "grant_state": "active",
            "nonce": nonce,
            "mode": "standing-approval",
            "covered_signers": [KEY_COVERED],
            "class": "ordinary",
            "developer_mode": False,
            "not_after": T_EXP,
        }
        raw = sign_json(rec, SEED_OWNER)

        # Codex #9: Crash RIGHT BEFORE anchor.write (after v<N> is staged on disk!):
        # v<N-1> stays intact, anchor still points to N-1, retry succeeds as initial install!
        writes0 = self.store.write_count
        with self.assertRaises(_SimCrash):
            self.enforcer.process_enrollment(
                raw,
                now_utc=T0,
                before_anchor_hook=lambda: (_ for _ in ()).throw(_SimCrash("crash before anchor")),
            )
        self.assertEqual(self.store.write_count, writes0)
        self.assertNotIn("crash-grant", self.store.snapshot()["grants"])
        self.assertIn(nonce, self.store.snapshot()["outstanding_nonces"])

        # Codex #9: Retry succeeds and crashes RIGHT AFTER anchor.write (before old-gen cleanup & receipt!):
        # Anchor points to N, v<N> is fsynced -> Option B retry succeeds with ZERO writes!
        with self.assertRaises(_SimCrash):
            self.enforcer.process_enrollment(
                raw,
                now_utc=T0,
                after_commit_hook=lambda: (_ for _ in ()).throw(_SimCrash("crash after anchor")),
            )
        writes_after = self.store.write_count
        self.assertEqual(writes_after, writes0 + 1)
        reordered = json.dumps(json.loads(raw), indent=4).encode("utf-8")
        receipt = self.enforcer.process_enrollment(reordered, now_utc=T0)
        self.assertEqual(receipt.status, "accepted")
        self.assertEqual(self.store.write_count, writes_after)

        # Contended two-thread race 1: identical active enrollments -> 1 install, 1 nonce consume, 2 identical receipts!
        n_race = self.enforcer.issue_enrollment_nonce(
            grant_id="race-dup",
            mode="standing-approval",
            covered_signers=[KEY_COVERED],
            grant_class="ordinary",
            developer_mode=False,
            ceremony_level="ordinary",
            not_after=T_EXP,
            now_utc=T0,
        )
        race_raw = sign_json(dict(rec, grant_id="race-dup", nonce=n_race), SEED_OWNER)
        w0, c0 = self.store.write_count, self.store.nonce_consume_count
        b1 = threading.Barrier(2)
        out1: list[Any] = []
        err1: list[BaseException] = []

        def run_dup(payload: bytes) -> None:
            try:
                b1.wait(timeout=5)
                out1.append(self.enforcer.process_enrollment(payload, now_utc=T0))
            except BaseException as exc:
                err1.append(exc)

        t1 = threading.Thread(target=run_dup, args=(race_raw,))
        t2 = threading.Thread(target=run_dup, args=(json.dumps(json.loads(race_raw), indent=2).encode("utf-8"),))
        t1.start(); t2.start(); t1.join(timeout=10); t2.join(timeout=10)
        self.assertEqual(err1, [])
        self.assertEqual(len(out1), 2)
        self.assertEqual(out1[0], out1[1])
        self.assertEqual(self.store.write_count, w0 + 1)
        self.assertEqual(self.store.nonce_consume_count, c0 + 1)

        # Contended two-thread race 2 (Codex R2 #7): install enrollment FIRST, then race
        # Option B identical redelivery of the ALREADY-INSTALLED enrollment against revocation
        # in BOTH lock orders, verifying exact outcomes and zero-write receipt when redelivery wins!
        # Order A: redelivery wins lock first (zero-write receipt) -> revocation tombstones grant.
        installed_raw_a, _, installed_rcpt_a = self.enroll_active(grant_id="race-optb-a", generation=1)
        redel_wire_a = json.dumps(json.loads(installed_raw_a), indent=2).encode("utf-8")
        rev_raw_a = self.make_revocation_bytes(grant_id="race-optb-a", generation=2)
        writes_before_a = self.store.write_count
        orig_load_a = self.store.load_verified_unlocked
        redel_in_lock = threading.Event()
        rev_ready = threading.Event()
        load_calls_a = [0]

        def gated_load_a(*args: Any, **kwargs: Any) -> Any:
            load_calls_a[0] += 1
            if load_calls_a[0] == 1:
                redel_in_lock.set()
                rev_ready.wait(timeout=5)
            return orig_load_a(*args, **kwargs)

        out_a: dict[str, Any] = {}

        def run_redel_a() -> None:
            out_a["redel"] = self.enforcer.process_enrollment(redel_wire_a, now_utc=T0)

        def run_rev_a() -> None:
            redel_in_lock.wait(timeout=5)
            rev_ready.set()
            out_a["rev"] = self.enforcer.process_enrollment(rev_raw_a, now_utc=T0)

        with mock.patch.object(self.store, "load_verified_unlocked", side_effect=gated_load_a):
            ta1 = threading.Thread(target=run_redel_a)
            ta2 = threading.Thread(target=run_rev_a)
            ta1.start(); ta2.start(); ta1.join(timeout=10); ta2.join(timeout=10)

        # Redelivery returned identical receipt with ZERO writes; revocation performed the single write!
        self.assertEqual(out_a["redel"], installed_rcpt_a)
        self.assertEqual(out_a["rev"].grant_state, "revoked")
        self.assertEqual(self.store.write_count, writes_before_a + 1)
        self.assertTrue(self.store.snapshot()["grants"]["race-optb-a"]["tombstoned"])

        # Order B: revocation wins lock first -> concurrent identical redelivery fails grant_tombstoned!
        installed_raw_b, _, _ = self.enroll_active(grant_id="race-optb-b", generation=1)
        redel_wire_b = json.dumps(json.loads(installed_raw_b), indent=2).encode("utf-8")
        rev_raw_b = self.make_revocation_bytes(grant_id="race-optb-b", generation=2)
        writes_before_b = self.store.write_count
        rev_in_lock = threading.Event()
        redel_waiting = threading.Event()
        out_b: dict[str, Any] = {}

        def run_rev_b() -> None:
            def hold_before_replace() -> None:
                rev_in_lock.set()
                redel_waiting.wait(timeout=5)

            out_b["rev"] = self.enforcer.process_enrollment(
                rev_raw_b, now_utc=T0, before_replace_hook=hold_before_replace
            )

        def run_redel_b() -> None:
            rev_in_lock.wait(timeout=5)
            threading.Timer(0.03, redel_waiting.set).start()
            try:
                out_b["redel"] = ("ok", self.enforcer.process_enrollment(redel_wire_b, now_utc=T0))
            except AE.ReplayError as exc:
                out_b["redel"] = ("err", exc.code)

        tb1 = threading.Thread(target=run_rev_b)
        tb2 = threading.Thread(target=run_redel_b)
        tb1.start(); tb2.start(); tb1.join(timeout=10); tb2.join(timeout=10)
        self.assertEqual(out_b["rev"].grant_state, "revoked")
        self.assertEqual(out_b["redel"], ("err", "grant_tombstoned"))
        self.assertEqual(self.store.write_count, writes_before_b + 1)
        self.assertTrue(self.store.snapshot()["grants"]["race-optb-b"]["tombstoned"])

        # Order C: Free-running barrier race of installed Option B redelivery vs revocation.
        installed_raw_c, _, installed_rcpt_c = self.enroll_active(grant_id="race-optb-c", generation=1)
        rev_raw_c = self.make_revocation_bytes(grant_id="race-optb-c", generation=2)
        writes_before_c = self.store.write_count
        b2 = threading.Barrier(2)
        out_c: dict[str, Any] = {}

        def run_redel_c() -> None:
            b2.wait(timeout=5)
            try:
                out_c["redel"] = ("ok", self.enforcer.process_enrollment(installed_raw_c, now_utc=T0))
            except AE.ReplayError as exc:
                out_c["redel"] = ("err", exc.code)

        def run_rev_c() -> None:
            b2.wait(timeout=5)
            out_c["rev"] = self.enforcer.process_enrollment(rev_raw_c, now_utc=T0)

        t3 = threading.Thread(target=run_redel_c)
        t4 = threading.Thread(target=run_rev_c)
        t3.start(); t4.start(); t3.join(timeout=10); t4.join(timeout=10)
        self.assertEqual(out_c["rev"].grant_state, "revoked")
        self.assertIn(out_c["redel"], [("ok", installed_rcpt_c), ("err", "grant_tombstoned")])
        self.assertEqual(self.store.write_count, writes_before_c + 1)
        self.assertTrue(self.store.snapshot()["grants"]["race-optb-c"]["tombstoned"])
        with self.assertRaises(AE.ReplayError) as ctx_post:
            self.enforcer.process_enrollment(installed_raw_c, now_utc=T0)
        self.assertEqual(ctx_post.exception.code, "grant_tombstoned")

    def test_item06_shared_store_two_enforcers_no_toctou_owner_removal_and_baseline_races(self) -> None:
        # Codex #3 / Adversary C3 / Macroscope 4708874430:
        # Two independent ApprovalEnforcer instances sharing one ReplayStore!
        enf_a = AE.ApprovalEnforcer(KEY_HOST, self.store)
        enf_b = AE.ApprovalEnforcer(KEY_HOST, self.store)

        # 1. Owner 1 removes Owner 2 in enf_a while Owner 2 tries to enroll a rogue grant in enf_b!
        prop_rm = copy.deepcopy(self.baseline)
        prop_rm["domains"]["device-trust"]["entries"]["advisor-key"][KEY_OWNER2]["state"] = "absent"
        diff_rm = AE.compute_authoritative_diff(self.baseline, prop_rm, KEY_HOST)
        pc_n = enf_a.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop_rm), ceremony_class="privileged", now_utc=T0
        )
        pc_rm = sign_json(
            {
                "schema_version": 9,
                "record_kind": "per-change",
                "host": KEY_HOST,
                "signer": KEY_OWNER,
                "sig_alg": "ed25519",
                "baseline_sha256": AE.canonical_sha256(self.baseline),
                "proposed_sha256": AE.canonical_sha256(prop_rm),
                "nonce": pc_n,
                "approval_seq": 0,
                "verdict": "accept",
                "ceremony_class": "privileged",
            },
            SEED_OWNER,
        )
        rogue_n = enf_b.issue_enrollment_nonce(
            grant_id="rogue-g",
            mode="standing-approval",
            covered_signers=[KEY_COVERED],
            grant_class="ordinary",
            developer_mode=False,
            ceremony_level="ordinary",
            not_after=T_EXP,
            now_utc=T0,
        )
        rogue_raw = sign_json(
            {
                "schema_version": 9,
                "record_kind": "standing-enrollment",
                "host": KEY_HOST,
                "signer": KEY_OWNER2,
                "sig_alg": "ed25519",
                "grant_id": "rogue-g",
                "generation": 1,
                "grant_state": "active",
                "nonce": rogue_n,
                "mode": "standing-approval",
                "covered_signers": [KEY_COVERED],
                "class": "ordinary",
                "developer_mode": False,
                "not_after": T_EXP,
            },
            SEED_OWNER2,
        )

        # Force Owner 2 to enter process_enrollment AFTER Owner 1 holds the lock (true TOCTOU test!).
        lock_entered = threading.Event()
        release_owner1 = threading.Event()

        def hold_lock_cb(_goal: dict[str, Any]) -> None:
            lock_entered.set()
            release_owner1.wait(timeout=5)

        enf_a_slow = AE.ApprovalEnforcer(KEY_HOST, self.store, apply_callback=hold_lock_cb)
        owner2_outcome: list[Any] = []

        def run_owner1() -> None:
            enf_a_slow.process_per_change(pc_rm, proposed_goal=prop_rm, diff=diff_rm, now_utc=T0)

        def run_owner2() -> None:
            lock_entered.wait(timeout=5)
            # Release owner1 slightly after owner2 tries to acquire the lock!
            threading.Timer(0.05, release_owner1.set).start()
            try:
                owner2_outcome.append(("accepted", enf_b.process_enrollment(rogue_raw, now_utc=T0)))
            except AE.TrustRootError as exc:
                owner2_outcome.append(("refused", exc.code))

        t1 = threading.Thread(target=run_owner1)
        t2 = threading.Thread(target=run_owner2)
        t1.start(); t2.start(); t1.join(timeout=10); t2.join(timeout=10)
        self.assertEqual(owner2_outcome, [("refused", "signer_not_owner")])
        self.assertNotIn("rogue-g", self.store.snapshot()["grants"])

        # 2. Concurrent standing-application baseline race across two independent enforcers:
        #    Both target the same baseline; EXACTLY ONE applies and the other MUST fail baseline_sha256_mismatch!
        _, g_nonce, _ = self.enroll_active(grant_id="conc-app", enforcer=enf_a)
        cur_base = enf_a.baseline_goal
        assert cur_base is not None
        p_c1, d_c1 = make_ordinary_service_change(cur_base, service_id="com.tendcf.c1")
        p_c2, d_c2 = make_ordinary_service_change(cur_base, service_id="com.tendcf.c2")
        a_c1 = self.make_app_bytes(
            grant_id="conc-app", generation=1, application_seq=1, enrollment_nonce=g_nonce, baseline=cur_base, proposed=p_c1
        )
        a_c2 = self.make_app_bytes(
            grant_id="conc-app", generation=1, application_seq=2, enrollment_nonce=g_nonce, baseline=cur_base, proposed=p_c2
        )
        bar = threading.Barrier(2)
        app_results: list[str] = []

        def run_app(enf: Any, raw: bytes, p: dict[str, Any], d: dict[str, Any]) -> None:
            bar.wait(timeout=5)
            try:
                r = enf.process_standing_application(raw, proposed_goal=p, diff=d, now_utc=T0)
                app_results.append(f"ok:{r.decision}")
            except AE.ReplayError as exc:
                app_results.append(f"err:{exc.code}")

        ta = threading.Thread(target=run_app, args=(enf_a, a_c1, p_c1, d_c1))
        tb = threading.Thread(target=run_app, args=(enf_b, a_c2, p_c2, d_c2))
        ta.start(); tb.start(); ta.join(timeout=10); tb.join(timeout=10)
        self.assertEqual(sorted(app_results), ["err:baseline_sha256_mismatch", "ok:applied"])

    def test_item07_and_r4_01_terminal_revocation_races_and_tombstone_persistence(self) -> None:
        unseen_rev = self.make_revocation_bytes(grant_id="pre-tombstoned", generation=1)
        r_unseen = self.enforcer.process_enrollment(unseen_rev, now_utc=T0)
        self.assertEqual(r_unseen.grant_state, "revoked")
        with self.assertRaises(AE.ReplayError) as ctx_pre:
            self.enroll_active(grant_id="pre-tombstoned", generation=2)
        self.assertEqual(ctx_pre.exception.code, "grant_tombstoned")

        raw_g5, nonce_g5, _ = self.enroll_active(grant_id="rev-any-gen", generation=5, mode="hold-window", hold_seconds=600)
        prop, diff = make_ordinary_service_change(self.baseline)
        app = self.make_app_bytes(
            grant_id="rev-any-gen", generation=5, application_seq=1, enrollment_nonce=nonce_g5, proposed=prop
        )
        self.enforcer.process_standing_application(
            app, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=10.0, boot_epoch=EPOCH_1, display_confirmed=True
        )
        self.assertIn(AE.canonical_sha256(prop), self.store.snapshot()["pending_holds"])

        bad_rev = self.make_revocation_bytes(
            grant_id="rev-any-gen", generation=1, owner_seed=SEED_COVERED, owner_key=KEY_COVERED
        )
        with self.assertRaises(AE.TrustRootError):
            self.enforcer.process_enrollment(bad_rev, now_utc=T0)

        rev_low = self.make_revocation_bytes(grant_id="rev-any-gen", generation=1)
        self.enforcer.process_enrollment(rev_low, now_utc=T0)
        self.assertEqual(self.store.snapshot()["pending_holds"], {})

        with self.assertRaises(AE.ReplayError) as ctx_redel:
            self.enforcer.process_enrollment(raw_g5, now_utc=T0)
        self.assertEqual(ctx_redel.exception.code, "grant_tombstoned")

        # PR #75 R4 #1: Tombstone persists across full ReplayStore reload!
        reloaded_store = AE.ReplayStore(self.store_dir, KEY_HOST, anchor=self.anchor)
        reloaded_enf = AE.ApprovalEnforcer(KEY_HOST, reloaded_store)
        with self.assertRaises(AE.ReplayError) as ctx_reopen:
            self.enroll_active(grant_id="rev-any-gen", generation=6, enforcer=reloaded_enf)
        self.assertEqual(ctx_reopen.exception.code, "grant_tombstoned")

        # Equivocation at exact same generation: revocation wins over active!
        raw_eq, _, _ = self.enroll_active(grant_id="eq-rev", generation=3)
        self.enforcer.process_enrollment(self.make_revocation_bytes(grant_id="eq-rev", generation=3), now_utc=T0)
        with self.assertRaises(AE.ReplayError):
            self.enforcer.process_enrollment(raw_eq, now_utc=T0)


# ===========================================================================
# Section B: Trust and Signers (Items 8-12)
# ===========================================================================

class TestSectionBTrustAndSigners(_EnforcerTestBase):
    def test_item08_baseline_roles_only_absent_covered_signer_and_no_crossover(self) -> None:
        prop_add_owner = copy.deepcopy(self.baseline)
        prop_add_owner["domains"]["device-trust"]["entries"]["advisor-key"][KEY_ATTACKER] = {
            "role": "owner",
            "state": "present",
        }
        diff_add_owner = AE.compute_authoritative_diff(self.baseline, prop_add_owner, KEY_HOST)
        pc_nonce = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop_add_owner), ceremony_class="privileged", now_utc=T0
        )
        attacker_pc = {
            "schema_version": 9,
            "record_kind": "per-change",
            "host": KEY_HOST,
            "signer": KEY_ATTACKER,
            "sig_alg": "ed25519",
            "baseline_sha256": AE.canonical_sha256(self.baseline),
            "proposed_sha256": AE.canonical_sha256(prop_add_owner),
            "nonce": pc_nonce,
            "approval_seq": 0,
            "verdict": "accept",
            "ceremony_class": "privileged",
        }
        with self.assertRaises(AE.TrustRootError) as ctx:
            self.enforcer.process_per_change(
                sign_json(attacker_pc, SEED_ATTACKER),
                proposed_goal=prop_add_owner,
                diff=diff_add_owner,
                now_utc=T0,
            )
        self.assertEqual(ctx.exception.code, "signer_not_owner")

        # covered-signer cannot sign per-change or standing-enrollment.
        with self.assertRaises(AE.TrustRootError):
            self.enforcer.process_per_change(
                sign_json(dict(attacker_pc, signer=KEY_COVERED), SEED_COVERED),
                proposed_goal=prop_add_owner,
                diff=diff_add_owner,
                now_utc=T0,
            )
        with self.assertRaises(AE.TrustRootError):
            self.enroll_active(grant_id="cs-enroll", owner_seed=SEED_COVERED, owner_key=KEY_COVERED)

        # owner NEVER in covered_signers or application signer (even in developer_mode).
        with self.assertRaises(AE.TrustRootError):
            self.enroll_active(grant_id="owner-cov-1", covered_signers=[KEY_OWNER], developer_mode=False)
        with self.assertRaises(AE.TrustRootError):
            self.enroll_active(grant_id="owner-cov-2", covered_signers=[KEY_OWNER], developer_mode=True)

        _, nonce, _ = self.enroll_active(grant_id="dev-g", covered_signers=[KEY_DEV], developer_mode=True)
        prop, diff = make_ordinary_service_change(self.baseline)
        owner_app = self.make_app_bytes(
            grant_id="dev-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop, signer_seed=SEED_OWNER, signer_key=KEY_OWNER
        )
        with self.assertRaises(AE.TrustRootError) as ctx_o:
            self.enforcer.process_standing_application(owner_app, proposed_goal=prop, diff=diff, now_utc=T0)
        self.assertEqual(ctx_o.exception.code, "owner_cannot_sign_application")

        # Neon F8: covered-signer toggled to state == "absent" in baseline refused on enrollment, application, and hold!
        _, nondev_nonce, _ = self.enroll_active(grant_id="nondev-g", covered_signers=[KEY_COVERED])
        absent_cs_base = copy.deepcopy(self.baseline)
        absent_cs_base["domains"]["device-trust"]["entries"]["advisor-key"][KEY_COVERED]["state"] = "absent"
        self._set_store_baseline(absent_cs_base)
        with self.assertRaises(AE.TrustRootError) as ctx_enr_abs:
            self.enroll_active(grant_id="new-absent-cs", covered_signers=[KEY_COVERED])
        self.assertEqual(ctx_enr_abs.exception.code, "untrusted_covered_signer")
        prop_abs, diff_abs = make_ordinary_service_change(absent_cs_base, service_id="com.tendcf.abs")
        app_abs = self.make_app_bytes(
            grant_id="nondev-g", generation=1, application_seq=1, enrollment_nonce=nondev_nonce, baseline=absent_cs_base, proposed=prop_abs
        )
        with self.assertRaises(AE.TrustRootError) as ctx_app_abs:
            self.enforcer.process_standing_application(app_abs, proposed_goal=prop_abs, diff=diff_abs, now_utc=T0)
        self.assertEqual(ctx_app_abs.exception.code, "signer_not_covered_signer_role")

    def test_item09_developer_mode_scope_and_persistent_indicator(self) -> None:
        self.assertFalse(self.enforcer.developer_mode_indicator_active(T0))
        with self.assertRaises(AE.TrustRootError):
            self.enroll_active(grant_id="nondev", covered_signers=[KEY_DEV], developer_mode=False)

        _, dev_nonce, _ = self.enroll_active(
            grant_id="dev-only", generation=1, covered_signers=[KEY_DEV], developer_mode=True, not_after=T_EXP
        )
        self.assertTrue(self.enforcer.developer_mode_indicator_active(T0))

        prop1, diff1 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.dev1")
        app1 = self.make_app_bytes(
            grant_id="dev-only", generation=1, application_seq=1, enrollment_nonce=dev_nonce, proposed=prop1, signer_seed=SEED_DEV, signer_key=KEY_DEV
        )
        self.assertEqual(
            self.enforcer.process_standing_application(app1, proposed_goal=prop1, diff=diff1, now_utc=T0).decision,
            "applied",
        )

        _, other_nonce, _ = self.enroll_active(grant_id="prod-grant", covered_signers=[KEY_COVERED])
        prop2, diff2 = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.dev2")
        bad_app = self.make_app_bytes(
            grant_id="prod-grant", generation=1, application_seq=1, enrollment_nonce=other_nonce, proposed=prop2, signer_seed=SEED_DEV, signer_key=KEY_DEV
        )
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(bad_app, proposed_goal=prop2, diff=diff2, now_utc=T0)

        _, gen2_nonce, _ = self.enroll_active(
            grant_id="dev-only", generation=2, covered_signers=[KEY_COVERED], developer_mode=False
        )
        self.assertFalse(self.enforcer.developer_mode_indicator_active(T0))
        app_old_dev = self.make_app_bytes(
            grant_id="dev-only", generation=2, application_seq=2, enrollment_nonce=gen2_nonce, proposed=prop2, signer_seed=SEED_DEV, signer_key=KEY_DEV
        )
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(app_old_dev, proposed_goal=prop2, diff=diff2, now_utc=T0)

        # Separate active dev grant turns indicator off past not_after (and durably advances last_seen_utc).
        self.enroll_active(
            grant_id="dev-exp", generation=1, covered_signers=[KEY_DEV], developer_mode=True, not_after=T_EXP
        )
        self.assertTrue(self.enforcer.developer_mode_indicator_active(T0))
        self.assertFalse(self.enforcer.developer_mode_indicator_active(T_AFTER_EXP))

    def test_item10_host_key_never_signer_covered_or_advisor_key(self) -> None:
        bad_goal = make_baseline_goal(
            advisor_keys={
                KEY_OWNER: {"role": "owner", "state": "present"},
                KEY_HOST: {"role": "covered-signer", "state": "present"},
            }
        )
        with self.assertRaises(AE.TrustRootError) as ctx_b:
            AE.ReplayStore.provision(
                self.tmp / "bad-base", KEY_HOST, anchor=AE.InMemoryRollbackAnchor(), baseline_goal=bad_goal
            )
        self.assertEqual(ctx_b.exception.code, "host_key_in_trust_root")

        fa_store = AE.ReplayStore.provision(
            self.tmp / "fa-hostkey", KEY_HOST, anchor=AE.InMemoryRollbackAnchor(), baseline_goal=None
        )
        fa_enf = AE.ApprovalEnforcer(KEY_HOST, fa_store)
        fa_nonce = fa_enf.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(bad_goal), ceremony_class="baseline", now_utc=T0
        )
        fa_rec = {
            "schema_version": 9,
            "record_kind": "per-change",
            "host": KEY_HOST,
            "signer": KEY_OWNER,
            "sig_alg": "ed25519",
            "proposed_sha256": AE.canonical_sha256(bad_goal),
            "nonce": fa_nonce,
            "approval_seq": 0,
            "verdict": "accept",
            "ceremony_class": "baseline",
        }
        with self.assertRaises(AE.TrustRootError) as ctx_fa:
            fa_enf.process_per_change(
                sign_json(fa_rec, SEED_OWNER),
                proposed_goal=bad_goal,
                bootstrap_owner_keys={KEY_OWNER},
                now_utc=T0,
            )
        self.assertEqual(ctx_fa.exception.code, "host_key_in_trust_root")

        with self.assertRaises(AE.TrustRootError):
            self.enroll_active(grant_id="host-sign", owner_seed=SEED_HOST, owner_key=KEY_HOST)

        _, nonce, _ = self.enroll_active(grant_id="ok-grant")
        prop, diff = make_ordinary_service_change(self.baseline)
        host_app = self.make_app_bytes(
            grant_id="ok-grant", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop, signer_seed=SEED_HOST, signer_key=KEY_HOST
        )
        with self.assertRaises(AE.TrustRootError):
            self.enforcer.process_standing_application(host_app, proposed_goal=prop, diff=diff, now_utc=T0)

        with self.assertRaises(AE.TrustRootError):
            self.enroll_active(grant_id="host-cov", covered_signers=[KEY_HOST], developer_mode=True)

    def test_item11_sig_alg_prefix_agreement_and_strict_ed25519(self) -> None:
        _, nonce, _ = self.enroll_active(grant_id="alg-grant")
        prop, diff = make_ordinary_service_change(self.baseline)
        base_rec = {
            "schema_version": 9,
            "record_kind": "standing-application",
            "host": KEY_HOST,
            "signer": KEY_COVERED,
            "sig_alg": "ed25519",
            "grant_id": "alg-grant",
            "generation": 1,
            "application_seq": 1,
            "enrollment_nonce": nonce,
            "baseline_sha256": AE.canonical_sha256(self.baseline),
            "proposed_sha256": AE.canonical_sha256(prop),
            "ceremony_class": "ordinary",
        }
        signed = SIGNER.sign_approval_record(base_rec, SEED_COVERED, AE.jcs_dumps)

        with self.assertRaises(AE.SignatureError) as ctx1:
            self.enforcer.process_standing_application(
                AE.jcs_dumps(dict(signed, sig_alg="ed448")), proposed_goal=prop, diff=diff, now_utc=T0
            )
        self.assertEqual(ctx1.exception.code, "unsupported_sig_alg")

        with self.assertRaises(AE.SignatureError) as ctx2:
            self.enforcer.process_standing_application(
                AE.jcs_dumps(dict(signed, signer="ed448:" + "11" * 32)), proposed_goal=prop, diff=diff, now_utc=T0
            )
        self.assertEqual(ctx2.exception.code, "sig_alg_signer_mismatch")

        sig_bytes = bytes.fromhex(signed["signature"].split(":", 1)[1])
        s_mal = (int.from_bytes(sig_bytes[32:], "little") + AE.ED25519_L).to_bytes(32, "little")
        bad_canon = dict(signed, signature="ed25519-sig:" + (sig_bytes[:32] + s_mal).hex())
        with self.assertRaises(AE.SignatureError) as ctx3:
            self.enforcer.process_standing_application(
                AE.jcs_dumps(bad_canon), proposed_goal=prop, diff=diff, now_utc=T0
            )
        self.assertEqual(ctx3.exception.code, "invalid_signature")

    def test_item12_nonce_entropy_randomness_and_post_store_loss_uniqueness(self) -> None:
        issued = {AE.generate_device_nonce() for _ in range(32)}
        self.assertEqual(len(issued), 32)
        for n in issued:
            self.assertIsNotNone(AE.NONCE_RE.match(n))
        with self.assertRaises(ValueError):
            AE.generate_device_nonce(15)
        with self.assertRaises(ValueError):
            AE.generate_device_nonce(True)  # type: ignore[arg-type]

        raw_enroll, old_nonce, _ = self.enroll_active(grant_id="reflash-g")
        prop, diff = make_ordinary_service_change(self.baseline)
        old_app = self.make_app_bytes(
            grant_id="reflash-g", generation=1, application_seq=1, enrollment_nonce=old_nonce, proposed=prop
        )

        store2 = AE.ReplayStore.provision(
            self.tmp / "reflashed", KEY_HOST, anchor=AE.InMemoryRollbackAnchor(), baseline_goal=self.baseline
        )
        enf2 = AE.ApprovalEnforcer(KEY_HOST, store2)
        new_nonce = enf2.issue_enrollment_nonce(
            grant_id="reflash-g",
            mode="standing-approval",
            covered_signers=[KEY_COVERED],
            grant_class="ordinary",
            developer_mode=False,
            ceremony_level="ordinary",
            not_after=T_EXP,
            now_utc=T0,
        )
        self.assertNotEqual(new_nonce, old_nonce)
        with self.assertRaises(AE.NonceError):
            enf2.process_enrollment(raw_enroll, now_utc=T0)
        with self.assertRaises(AE.ReplayError):
            enf2.process_standing_application(old_app, proposed_goal=prop, diff=diff, now_utc=T0)


# ===========================================================================
# Section C: Carve-Out, Class, Migrations & R9 (Items 13-16 + PR #75 R4 #4)
# ===========================================================================

class TestSectionCCarveOutAndClass(_EnforcerTestBase):
    def test_item13_r1_r7_default_deny_device_trust_carve_out_and_replay_store(self) -> None:
        _, priv_nonce, _ = self.enroll_active(
            grant_id="priv-grant", grant_class="privileged", mode="standing-approval"
        )
        carved_kinds = [
            ("advisor-key", KEY_ATTACKER, {"role": "covered-signer", "state": "present"}),
            ("trust-policy", "consent", {"local_yes_required": False, "state": "present", "tier": "consented"}),
            ("agent", "tendcf-agent", {"sha256": "sha256:" + "ee" * 32, "state": "present", "version": "ops-v2.0.0"}),
            ("policy-tree", "tree", {"sha256": "sha256:" + "ff" * 32, "state": "present"}),
            ("peer-allowlist", "default", {"state": "present"}),
            ("device-resource-policy", "limits", {"state": "present"}),
        ]
        for idx, (kind_name, entry_id, new_body) in enumerate(carved_kinds, start=1):
            with self.subTest(carved_kind=kind_name):
                prop = copy.deepcopy(self.baseline)
                prop["domains"]["device-trust"]["entries"].setdefault(kind_name, {})[entry_id] = new_body
                diff = AE.compute_authoritative_diff(self.baseline, prop, KEY_HOST)
                app = self.make_app_bytes(
                    grant_id="priv-grant", generation=1, application_seq=idx, enrollment_nonce=priv_nonce, proposed=prop, ceremony_class="privileged"
                )
                with self.assertRaises(AE.ScopeError) as ctx:
                    self.enforcer.process_standing_application(app, proposed_goal=prop, diff=diff, now_utc=T0)
                self.assertEqual(ctx.exception.code, "carve_out_device_trust")

        prop_sup, diff_sup = make_supervisor_change(self.baseline, new_name="systemd")
        app_rs = self.make_app_bytes(
            grant_id="priv-grant", generation=1, application_seq=1, enrollment_nonce=priv_nonce, proposed=prop_sup, ceremony_class="privileged"
        )
        with self.assertRaises(AE.ScopeError) as ctx_rs:
            self.enforcer.process_standing_application(
                app_rs, proposed_goal=prop_sup, diff=diff_sup, now_utc=T0, touches_replay_store=True
            )
        self.assertEqual(ctx_rs.exception.code, "carve_out_replay_store")

        self.assertEqual(
            self.enforcer.process_standing_application(app_rs, proposed_goal=prop_sup, diff=diff_sup, now_utc=T0).decision,
            "applied",
        )

    def test_item14_and_r4_04_per_hunk_class_mixed_retreat_and_empty_domain(self) -> None:
        _, ord_nonce, _ = self.enroll_active(grant_id="ord-g", grant_class="ordinary")
        _, priv_nonce, _ = self.enroll_active(grant_id="priv-g", grant_class="privileged")

        # 1. Mixed-class diff refused under both privileged and ordinary grants!
        prop_mix, _ = make_ordinary_service_change(self.baseline, service_id="com.tendcf.mix")
        prop_mix["domains"]["device-trust"]["entries"]["supervisor"]["host"] = {"name": "systemd", "state": "present"}
        diff_mix = AE.compute_authoritative_diff(self.baseline, prop_mix, KEY_HOST)
        for gid, gnonce, cc in (("priv-g", priv_nonce, "privileged"), ("ord-g", ord_nonce, "ordinary")):
            app = self.make_app_bytes(
                grant_id=gid, generation=1, application_seq=1, enrollment_nonce=gnonce, proposed=prop_mix, ceremony_class=cc
            )
            with self.assertRaises(AE.ScopeError) as ctx:
                self.enforcer.process_standing_application(app, proposed_goal=prop_mix, diff=diff_mix, now_utc=T0)
            self.assertEqual(ctx.exception.code, "mixed_class_application")

        # 2. Retreating populated domain = mixed -> refused!
        pop_base, _ = make_ordinary_service_change(self.baseline, service_id="com.tendcf.retreat")
        self._set_store_baseline(pop_base)
        retreated = copy.deepcopy(self.baseline)
        retreat_diff = AE.compute_authoritative_diff(pop_base, retreated, KEY_HOST)
        retreat_app = self.make_app_bytes(
            grant_id="priv-g", generation=1, application_seq=1, enrollment_nonce=priv_nonce, baseline=pop_base, proposed=retreated, ceremony_class="privileged"
        )
        with self.assertRaises(AE.ScopeError) as ctx_ret:
            self.enforcer.process_standing_application(retreat_app, proposed_goal=retreated, diff=retreat_diff, now_utc=T0)
        self.assertEqual(ctx_ret.exception.code, "mixed_class_application")

        # 3. PR #75 R4 #4: Empty-domain coverage transitions grantable under derived class!
        empty_base = make_baseline_goal(extra_domains={"supervision": {"coverage": "not-yet-migrated"}})
        empty_comp = make_baseline_goal(extra_domains={"supervision": {"coverage": "comprehensive"}})
        self._set_store_baseline(empty_base)
        diff_ord_cov = AE.compute_authoritative_diff(empty_base, empty_comp, KEY_HOST)
        app_ord_cov = self.make_app_bytes(
            grant_id="ord-g", generation=1, application_seq=1, enrollment_nonce=ord_nonce, baseline=empty_base, proposed=empty_comp, ceremony_class="ordinary"
        )
        self.assertEqual(
            self.enforcer.process_standing_application(app_ord_cov, proposed_goal=empty_comp, diff=diff_ord_cov, now_utc=T0).decision,
            "applied",
        )

        diff_priv_cov = AE.compute_authoritative_diff(empty_comp, empty_base, KEY_HOST)
        app_priv_cov = self.make_app_bytes(
            grant_id="priv-g", generation=1, application_seq=1, enrollment_nonce=priv_nonce, baseline=empty_comp, proposed=empty_base, ceremony_class="privileged"
        )
        self.assertEqual(
            self.enforcer.process_standing_application(app_priv_cov, proposed_goal=empty_base, diff=diff_priv_cov, now_utc=T0).decision,
            "applied",
        )

    def test_item15_migrations_comparability_default_bool_int_smuggling_and_downward_bump(self) -> None:
        _, base_nonce, _ = self.enroll_active(grant_id="base-g", grant_class="baseline")

        # 1. Downward (9 -> 8) & equal (9 -> 9) version_bump refused for BOTH standing-application AND per-change (including is_readoption=True!).
        for new_ver in (8, 9):
            prop_down = copy.deepcopy(self.baseline)
            prop_down["schema_version"] = new_ver
            diff_down = {
                "schema_version": 9,
                "host": KEY_HOST,
                "baseline_sha256": AE.canonical_sha256(self.baseline),
                "proposed_sha256": AE.canonical_sha256(prop_down),
                "version_bump": {"old": 9, "new": new_ver},
            }
            app_down = self.make_app_bytes(
                grant_id="base-g", generation=1, application_seq=1, enrollment_nonce=base_nonce, proposed=prop_down, ceremony_class="baseline"
            )
            with self.assertRaises(AE.ScopeError) as ctx_s:
                self.enforcer.process_standing_application(
                    app_down,
                    proposed_goal=prop_down,
                    diff=diff_down,
                    now_utc=T0,
                    migrate_fn=pure_version_bump_migrate,
                    device_trust_comparable=True,
                )
            self.assertEqual(ctx_s.exception.code, "downward_version_bump")

            pc_n = self.enforcer.issue_per_change_nonce(
                proposed_sha256=AE.canonical_sha256(prop_down), ceremony_class="baseline", now_utc=T0
            )
            pc_down = sign_json(
                {
                    "schema_version": 9,
                    "record_kind": "per-change",
                    "host": KEY_HOST,
                    "signer": KEY_OWNER,
                    "sig_alg": "ed25519",
                    "baseline_sha256": AE.canonical_sha256(self.baseline),
                    "proposed_sha256": AE.canonical_sha256(prop_down),
                    "nonce": pc_n,
                    "approval_seq": 0,
                    "verdict": "accept",
                    "ceremony_class": "baseline",
                },
                SEED_OWNER,
            )
            with self.assertRaises(AE.ScopeError) as ctx_pc:
                self.enforcer.process_per_change(pc_down, proposed_goal=prop_down, diff=diff_down, now_utc=T0)
            self.assertEqual(ctx_pc.exception.code, "downward_version_bump")

            if new_ver < 9:
                # Codex #4 / Macroscope 4708874598: downward schema_version ALSO refused on is_readoption=True!
                with self.assertRaises(AE.ScopeError) as ctx_ra_down:
                    self.enforcer.process_per_change(
                        pc_down, proposed_goal=prop_down, is_readoption=True, now_utc=T0
                    )
                self.assertEqual(ctx_ra_down.exception.code, "downward_version_bump")

        # 2. Codex #10: Default device_trust_comparable=False / migrate_fn=None FAILS CLOSED even when only schema_version differs!
        prop_up = pure_version_bump_migrate(self.baseline, 10)
        diff_up = AE.compute_authoritative_diff(self.baseline, prop_up, KEY_HOST)
        app_up = self.make_app_bytes(
            grant_id="base-g", generation=1, application_seq=1, enrollment_nonce=base_nonce, proposed=prop_up, ceremony_class="baseline"
        )
        with self.assertRaises(AE.ScopeError) as ctx_def:
            self.enforcer.process_standing_application(app_up, proposed_goal=prop_up, diff=diff_up, now_utc=T0)
        self.assertEqual(ctx_def.exception.code, "migration_device_trust_incomparable")

        # 3. Adversary C2: True == 1 / False == 0 R1 device-trust smuggling in baseline migration MUST be refused!
        def bool_to_int_migrate(doc: dict[str, Any], target_ver: int) -> dict[str, Any]:
            out = copy.deepcopy(doc)
            out["schema_version"] = target_ver
            out["domains"]["device-trust"]["entries"]["trust-policy"]["consent"]["local_yes_required"] = 1
            return out

        prop_smuggle = bool_to_int_migrate(self.baseline, 10)
        diff_smuggle = AE.compute_authoritative_diff(self.baseline, prop_smuggle, KEY_HOST)
        app_smuggle = self.make_app_bytes(
            grant_id="base-g", generation=1, application_seq=1, enrollment_nonce=base_nonce, proposed=prop_smuggle, ceremony_class="baseline"
        )
        with self.assertRaises(AE.ScopeError) as ctx_c2:
            self.enforcer.process_standing_application(
                app_smuggle,
                proposed_goal=prop_smuggle,
                diff=diff_smuggle,
                now_utc=T0,
                migrate_fn=bool_to_int_migrate,
                device_trust_comparable=True,
            )
        self.assertEqual(ctx_c2.exception.code, "migration_mutated_device_trust")

        # 4. Re-adoption NEVER by standing-application.
        with self.assertRaises(AE.ScopeError) as ctx_ra:
            self.enforcer.process_standing_application(
                app_up,
                proposed_goal=prop_up,
                diff=diff_up,
                now_utc=T0,
                is_readoption=True,
                migrate_fn=pure_version_bump_migrate,
                device_trust_comparable=True,
            )
        self.assertEqual(ctx_ra.exception.code, "readoption_disallowed")

        # 5. Pure upward schema_version bump WITH explicit migrate_fn + device_trust_comparable=True SUCCEEDS!
        res = self.enforcer.process_standing_application(
            app_up,
            proposed_goal=prop_up,
            diff=diff_up,
            now_utc=T0,
            migrate_fn=pure_version_bump_migrate,
            device_trust_comparable=True,
        )
        self.assertEqual(res.decision, "applied")

    def test_item16_r9_disclosure_in_enrollment_briefing(self) -> None:
        raw, _, _ = self.enroll_active(grant_id="brief-g", covered_signers=[KEY_DEV], developer_mode=True)
        lower = AE.render_enrollment_briefing(json.loads(raw)).lower()
        for phrase in (
            "root-equivalent authority",
            "run as root",
            "trust with root",
            "revocation or expiry stops only future applications and pending holds",
            "never undoes",
            "trust root",
            "replay store",
            "validator",
            "clock",
            "developer mode",
        ):
            self.assertIn(phrase, lower)


# ===========================================================================
# Section D: Time, Hold Window and Precedence (Items 17-19)
# ===========================================================================

class TestSectionDTimeHoldAndPrecedence(_EnforcerTestBase):
    def test_item17_not_after_end_to_end_microsecond_boundary_nonreversible_expiry_and_rollback(self) -> None:
        # 1. Impossible dates refused end-to-end via process_enrollment (including optional-not_after wait-for-user!).
        for bad in (
            "2027-02-30T00:00:00Z",
            "2027-02-29T00:00:00Z",
            "2027-04-31T12:00:00Z",
            "2027-12-31T23:59:59.000Z",
            "2027-12-31T23:59:59+00:00",
            "2027-12-31T23:59:59Z\n",
            "not-a-date",
        ):
            with self.subTest(bad_not_after=bad):
                wfu_rec = {
                    "schema_version": 9,
                    "record_kind": "standing-enrollment",
                    "host": KEY_HOST,
                    "signer": KEY_OWNER,
                    "sig_alg": "ed25519",
                    "grant_id": "bad-date-wfu",
                    "generation": 1,
                    "grant_state": "active",
                    "nonce": AE.generate_device_nonce(),
                    "mode": "wait-for-user",
                    "covered_signers": [KEY_COVERED],
                    "class": "ordinary",
                    "developer_mode": False,
                    "not_after": bad,
                }
                with self.assertRaises(AE.MalformedRecordError):
                    self.enforcer.process_enrollment(sign_json(wfu_rec, SEED_OWNER), now_utc=T0)

        # 2. No hard maximum horizon cap (2026-11-26 ruling).
        _, far_nonce, receipt = self.enroll_active(
            grant_id="far-horizon", not_after="2999-12-31T23:59:59Z", now_utc=T0
        )
        self.assertEqual(receipt.status, "accepted")

        # 3. Neon F6 / Adversary M1: Microsecond expiry boundary!
        #    Exact not_after ACCEPTED; not_after + 1µs REFUSED!
        exact_exp_str = "2026-11-26T12:01:00Z"
        exact_exp_dt = datetime.datetime(2026, 11, 26, 12, 1, 0, tzinfo=datetime.timezone.utc)
        _, exp_nonce, _ = self.enroll_active(
            grant_id="exp-exact", mode="standing-approval", not_after=exact_exp_str, now_utc=T0
        )
        prop_eq, diff_eq = make_ordinary_service_change(self.baseline, service_id="com.tendcf.eq")
        app_eq = self.make_app_bytes(
            grant_id="exp-exact", generation=1, application_seq=1, enrollment_nonce=exp_nonce, proposed=prop_eq
        )
        self.assertEqual(
            self.enforcer.process_standing_application(
                app_eq, proposed_goal=prop_eq, diff=diff_eq, now_utc=exact_exp_dt
            ).decision,
            "applied",
        )

        # Now +1 microsecond strictly past not_after -> REFUSED!
        prop_us, diff_us = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.us")
        app_us = self.make_app_bytes(
            grant_id="exp-exact", generation=1, application_seq=2, enrollment_nonce=exp_nonce, proposed=prop_us
        )
        with self.assertRaises(AE.ScopeError) as ctx_us:
            self.enforcer.process_standing_application(
                app_us,
                proposed_goal=prop_us,
                diff=diff_us,
                now_utc=exact_exp_dt + datetime.timedelta(microseconds=1),
            )
        self.assertEqual(ctx_us.exception.code, "grant_expired")

        # 4. Codex #7: Non-reversible observed expiry!
        #    After observing expiry at exact_exp_dt + 1µs, a backward clock to exact_exp_dt
        #    (even though >= prior successful commit!) MUST fail closed with ClockRollbackError!
        with self.assertRaises(AE.ClockRollbackError) as ctx_nonrev:
            self.enforcer.process_standing_application(
                app_us, proposed_goal=prop_us, diff=diff_us, now_utc=exact_exp_dt
            )
        self.assertEqual(ctx_nonrev.exception.code, "utc_clock_rollback")

        # 5. Also verify backward UTC clock still above prior commit after expiry refusal on a fresh grant.
        t_start = datetime.datetime(2026, 11, 26, 13, 0, 0, tzinfo=datetime.timezone.utc)
        t_grant_exp = "2026-11-26T13:05:00Z"
        _, n_nr, _ = self.enroll_active(
            grant_id="nonrev-g", mode="standing-approval", not_after=t_grant_exp, now_utc=t_start
        )
        prop_nr, diff_nr = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.nr")
        app_nr = self.make_app_bytes(
            grant_id="nonrev-g", generation=1, application_seq=1, enrollment_nonce=n_nr, proposed=prop_nr
        )
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                app_nr,
                proposed_goal=prop_nr,
                diff=diff_nr,
                now_utc=datetime.datetime(2026, 11, 26, 13, 6, 0, tzinfo=datetime.timezone.utc),
            )
        # Clock moves back to 13:04:00 (still > t_start 13:00:00, but < observed 13:06:00) -> REFUSED!
        with self.assertRaises(AE.ClockRollbackError):
            self.enforcer.process_standing_application(
                app_nr,
                proposed_goal=prop_nr,
                diff=diff_nr,
                now_utc=datetime.datetime(2026, 11, 26, 13, 4, 0, tzinfo=datetime.timezone.utc),
            )

    def test_item18_hold_window_confirmed_display_nan_boot_epoch_hygiene_and_reeval(self) -> None:
        _, nonce, _ = self.enroll_active(
            grant_id="hold-g", mode="hold-window", hold_seconds=300, now_utc=T0
        )
        prop, diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.held")
        prop_hash = AE.canonical_sha256(prop)
        app = self.make_app_bytes(
            grant_id="hold-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop
        )

        # 1. Codex #6: Default intake does NOT confirm display -> complete_hold_window fails closed!
        res = self.enforcer.process_standing_application(app, proposed_goal=prop, diff=diff, now_utc=T0)
        self.assertEqual(res.decision, "held")
        self.assertEqual(self.enforcer.prompt_count, 0)
        with self.assertRaises(AE.ScopeError) as ctx_unconf:
            self.enforcer.complete_hold_window(
                prop_hash, proposed_goal=prop, diff=diff, now_utc=T1, now_mono=9999.0, boot_epoch=EPOCH_1
            )
        self.assertEqual(ctx_unconf.exception.code, "hold_display_unconfirmed")

        # 2. Adversary M2: Duplicate overlapping hold for same proposed_sha256 refused BEFORE burning mark!
        app_dup = self.make_app_bytes(
            grant_id="hold-g", generation=1, application_seq=99, enrollment_nonce=nonce, proposed=prop
        )
        with self.assertRaises(AE.ReplayError) as ctx_duphold:
            self.enforcer.process_standing_application(app_dup, proposed_goal=prop, diff=diff, now_utc=T0)
        self.assertEqual(ctx_duphold.exception.code, "duplicate_pending_hold")
        self.assertEqual(self.store.snapshot()["grants"]["hold-g"]["application_seq_mark"], 1)

        # 3. Confirm display at mono=1000.0 in EPOCH_1 -> timer starts from 1000.0!
        self.enforcer.confirm_hold_displayed(prop_hash, now_mono=1000.0, boot_epoch=EPOCH_1)
        self.assertEqual(self.enforcer.prompt_count, 1)

        # 4. Neon F2 / Adversary C1: NaN, +inf, -inf, negative, bool now_mono ALL refused!
        for bad_mono in (float("nan"), float("inf"), float("-inf"), -1.0, True, False):
            with self.subTest(bad_mono=bad_mono):
                with self.assertRaises(AE.ClockRollbackError):
                    self.enforcer.complete_hold_window(
                        prop_hash, proposed_goal=prop, diff=diff, now_utc=T1, now_mono=bad_mono, boot_epoch=EPOCH_1  # type: ignore[arg-type]
                    )

        # 5. Codex #6 & Macroscope 4709254027: Boot epoch change (device rebooted) fails closed
        #    AND resets display state so UI can re-confirm display cleanly!
        with self.assertRaises(AE.ClockRollbackError) as ctx_epoch:
            self.enforcer.complete_hold_window(
                prop_hash, proposed_goal=prop, diff=diff, now_utc=T1, now_mono=2000.0, boot_epoch=EPOCH_2
            )
        self.assertEqual(ctx_epoch.exception.code, "monotonic_boot_epoch_mismatch")
        self.assertFalse(self.store.snapshot()["pending_holds"][prop_hash]["displayed"])
        # Re-confirm display for subsequent monotonic elapsed/rollback checks on EPOCH_1.
        self.enforcer.confirm_hold_displayed(prop_hash, now_mono=1000.0, boot_epoch=EPOCH_1)

        # 6. Wall clock jumps hours ahead, monotonic only +100s (< 300s) -> refused!
        with self.assertRaises(AE.ScopeError) as ctx_early:
            self.enforcer.complete_hold_window(
                prop_hash,
                proposed_goal=prop,
                diff=diff,
                now_utc=T0 + datetime.timedelta(hours=2),
                now_mono=1100.0,
                boot_epoch=EPOCH_1,
            )
        self.assertEqual(ctx_early.exception.code, "hold_window_not_elapsed")

        # 7. Monotonic rollback -> refused!
        with self.assertRaises(AE.ClockRollbackError):
            self.enforcer.complete_hold_window(
                prop_hash,
                proposed_goal=prop,
                diff=diff,
                now_utc=T0 + datetime.timedelta(hours=2),
                now_mono=999.0,
                boot_epoch=EPOCH_1,
            )

        # 8. Owner per-change reject stops hold immediately regardless of ceremony_class/nonce/approval_seq & persists DC-2!
        reject_rec = {
            "schema_version": 9,
            "record_kind": "per-change",
            "host": KEY_HOST,
            "signer": KEY_OWNER,
            "sig_alg": "ed25519",
            "baseline_sha256": AE.canonical_sha256(self.baseline),
            "proposed_sha256": prop_hash,
            "nonce": "stale-unissued-nonce-0000000000",
            "approval_seq": 0,
            "verdict": "reject",
            "refused": ["supervision/service/com.tendcf.held"],
            "ceremony_class": "baseline",
        }
        pc_res = self.enforcer.process_per_change(
            sign_json(reject_rec, SEED_OWNER), now_utc=T0 + datetime.timedelta(hours=2)
        )
        self.assertEqual(pc_res.decision, "rejected")
        self.assertEqual(len(pc_res.cancelled_holds), 1)
        self.assertEqual(self.store.snapshot()["pending_holds"], {})

        # 9. Neon F9: Higher-generation re-enrollment prunes stranded old-generation pending holds!
        prop2, diff2 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.held2")
        app2 = self.make_app_bytes(
            grant_id="hold-g", generation=1, application_seq=2, enrollment_nonce=nonce, proposed=prop2
        )
        self.enforcer.process_standing_application(
            app2, proposed_goal=prop2, diff=diff2, now_utc=T0 + datetime.timedelta(hours=2), now_mono=3000.0, boot_epoch=EPOCH_1, display_confirmed=True
        )
        self.assertIn(AE.canonical_sha256(prop2), self.store.snapshot()["pending_holds"])
        _, nonce2, _ = self.enroll_active(
            grant_id="hold-g", generation=2, mode="hold-window", hold_seconds=300, now_utc=T0 + datetime.timedelta(hours=2, minutes=1)
        )
        self.assertEqual(self.store.snapshot()["pending_holds"], {})

        # 10. Neon F8: Re-evaluation at hold apply — baseline change, covering grant tightening, signer role removal, and dead-hold pruning!
        # (a) Longer hold-window enrolled during hold extends required_hold!
        prop3, diff3 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.held3")
        app3 = self.make_app_bytes(
            grant_id="hold-g", generation=2, application_seq=3, enrollment_nonce=nonce2, proposed=prop3
        )
        self.enforcer.process_standing_application(
            app3, proposed_goal=prop3, diff=diff3, now_utc=T0 + datetime.timedelta(hours=2, minutes=2), now_mono=4000.0, boot_epoch=EPOCH_1, display_confirmed=True
        )
        self.enroll_active(
            grant_id="longer-hw", mode="hold-window", hold_seconds=900, now_utc=T0 + datetime.timedelta(hours=2, minutes=3)
        )
        with self.assertRaises(AE.ScopeError) as ctx_longer:
            self.enforcer.complete_hold_window(
                AE.canonical_sha256(prop3),
                proposed_goal=prop3,
                diff=diff3,
                now_utc=T0 + datetime.timedelta(hours=2, minutes=10),
                now_mono=4400.0,  # +400s >= 300s, but < new 900s!
                boot_epoch=EPOCH_1,
            )
        self.assertEqual(ctx_longer.exception.code, "hold_window_not_elapsed")

        # (b) Baseline changed during hold -> refused AND dead hold pruned!
        other_base, _ = make_ordinary_service_change(self.baseline, service_id="com.tendcf.other")
        self._set_store_baseline(other_base)
        with self.assertRaises(AE.ReplayError) as ctx_basechg:
            self.enforcer.complete_hold_window(
                AE.canonical_sha256(prop3),
                proposed_goal=prop3,
                diff=diff3,
                now_utc=T0 + datetime.timedelta(hours=2, minutes=20),
                now_mono=5000.0,
                boot_epoch=EPOCH_1,
            )
        self.assertEqual(ctx_basechg.exception.code, "baseline_changed_during_hold")
        self.assertNotIn(AE.canonical_sha256(prop3), self.store.snapshot()["pending_holds"])

        # (c) Covering standing-refusal enrolled during hold -> refused AND dead hold pruned!
        self._set_store_baseline(self.baseline)
        prop4, diff4 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.held4")
        app4 = self.make_app_bytes(
            grant_id="hold-g", generation=2, application_seq=4, enrollment_nonce=nonce2, proposed=prop4
        )
        self.enforcer.process_standing_application(
            app4, proposed_goal=prop4, diff=diff4, now_utc=T0 + datetime.timedelta(hours=2, minutes=21), now_mono=6000.0, boot_epoch=EPOCH_1, display_confirmed=True
        )
        self.enroll_active(
            grant_id="ref-during-hold", mode="standing-refusal", not_after=None, now_utc=T0 + datetime.timedelta(hours=2, minutes=22)
        )
        with self.assertRaises(AE.ScopeError) as ctx_ref_hold:
            self.enforcer.complete_hold_window(
                AE.canonical_sha256(prop4),
                proposed_goal=prop4,
                diff=diff4,
                now_utc=T0 + datetime.timedelta(hours=2, minutes=40),
                now_mono=7500.0,
                boot_epoch=EPOCH_1,
            )
        self.assertEqual(ctx_ref_hold.exception.code, "standing_refusal_at_hold_apply")
        self.assertNotIn(AE.canonical_sha256(prop4), self.store.snapshot()["pending_holds"])

        # (d) Expiry during hold -> refused, dead hold pruned, and last_seen_utc durably advanced!
        self.enforcer.process_enrollment(
            self.make_revocation_bytes(grant_id="ref-during-hold", generation=2),
            now_utc=T0 + datetime.timedelta(hours=2, minutes=41),
        )
        self.enforcer.process_enrollment(
            self.make_revocation_bytes(grant_id="longer-hw", generation=2),
            now_utc=T0 + datetime.timedelta(hours=2, minutes=41),
        )
        short_exp = "2026-11-26T15:00:00Z"
        _, n_exp_hw, _ = self.enroll_active(
            grant_id="exp-hw",
            mode="hold-window",
            hold_seconds=300,
            not_after=short_exp,
            now_utc=T0 + datetime.timedelta(hours=2, minutes=50),
        )
        prop5, diff5 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.held5")
        app5 = self.make_app_bytes(
            grant_id="exp-hw", generation=1, application_seq=1, enrollment_nonce=n_exp_hw, proposed=prop5
        )
        self.enforcer.process_standing_application(
            app5,
            proposed_goal=prop5,
            diff=diff5,
            now_utc=T0 + datetime.timedelta(hours=2, minutes=55),
            now_mono=8000.0,
            boot_epoch=EPOCH_1,
            display_confirmed=True,
        )
        with self.assertRaises(AE.ScopeError) as ctx_exp_hw:
            self.enforcer.complete_hold_window(
                AE.canonical_sha256(prop5),
                proposed_goal=prop5,
                diff=diff5,
                now_utc=datetime.datetime(2026, 11, 26, 15, 0, 1, tzinfo=datetime.timezone.utc),
                now_mono=8500.0,
                boot_epoch=EPOCH_1,
            )
        self.assertEqual(ctx_exp_hw.exception.code, "grant_expired_at_hold_apply")
        self.assertNotIn(AE.canonical_sha256(prop5), self.store.snapshot()["pending_holds"])
        self.assertEqual(self.store.snapshot()["last_seen_utc"], "2026-11-26T15:00:01Z")

    def test_item19_precedence_most_restrictive_longest_hold_owner_accept_and_dc2_reject(self) -> None:
        _, sa_nonce, _ = self.enroll_active(grant_id="g-sa", mode="standing-approval")
        _, hw1_nonce, _ = self.enroll_active(grant_id="g-hw1", mode="hold-window", hold_seconds=120)
        self.enroll_active(grant_id="g-hw2", mode="hold-window", hold_seconds=600)
        self.enroll_active(grant_id="g-wfu", mode="wait-for-user", not_after=None)
        self.enroll_active(grant_id="g-ref", mode="standing-refusal", not_after=None)

        prop, diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.prec")
        app_sa = self.make_app_bytes(
            grant_id="g-sa", generation=1, application_seq=1, enrollment_nonce=sa_nonce, proposed=prop
        )
        with self.assertRaises(AE.ScopeError) as ctx_ref:
            self.enforcer.process_standing_application(app_sa, proposed_goal=prop, diff=diff, now_utc=T0)
        self.assertEqual(ctx_ref.exception.code, "standing_refusal")

        # Owner per-change accept stays available against standing-refusal!
        prop_owner, diff_owner = make_ordinary_service_change(self.baseline, service_id="com.tendcf.owner-yes")
        pc_nonce = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop_owner), ceremony_class="ordinary", now_utc=T0
        )
        pc_acc = {
            "schema_version": 9,
            "record_kind": "per-change",
            "host": KEY_HOST,
            "signer": KEY_OWNER,
            "sig_alg": "ed25519",
            "baseline_sha256": AE.canonical_sha256(self.baseline),
            "proposed_sha256": AE.canonical_sha256(prop_owner),
            "nonce": pc_nonce,
            "approval_seq": 0,
            "verdict": "accept",
            "ceremony_class": "ordinary",
        }
        self.assertEqual(
            self.enforcer.process_per_change(
                sign_json(pc_acc, SEED_OWNER), proposed_goal=prop_owner, diff=diff_owner, now_utc=T0
            ).decision,
            "applied",
        )

        prop, diff = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.prec2")
        app_sa = self.make_app_bytes(
            grant_id="g-sa", generation=1, application_seq=1, enrollment_nonce=sa_nonce, proposed=prop
        )
        self.enforcer.process_enrollment(self.make_revocation_bytes(grant_id="g-ref", generation=2), now_utc=T0)
        res_wfu = self.enforcer.process_standing_application(app_sa, proposed_goal=prop, diff=diff, now_utc=T0)
        self.assertEqual(res_wfu.decision, "parked")
        self.assertEqual(res_wfu.effective_mode, "wait-for-user")

        self.enforcer.process_enrollment(self.make_revocation_bytes(grant_id="g-wfu", generation=2), now_utc=T0)
        app_hw = self.make_app_bytes(
            grant_id="g-hw1", generation=1, application_seq=1, enrollment_nonce=hw1_nonce, proposed=prop
        )
        res_hw = self.enforcer.process_standing_application(
            app_hw, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=30.0, boot_epoch=EPOCH_1, display_confirmed=True
        )
        self.assertEqual(res_hw.decision, "held")
        self.assertEqual(res_hw.hold_seconds, 600)

        self.enforcer.process_enrollment(self.make_revocation_bytes(grant_id="g-hw1", generation=2), now_utc=T0)
        self.enforcer.process_enrollment(self.make_revocation_bytes(grant_id="g-hw2", generation=2), now_utc=T0)
        rej_n = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop), ceremony_class="ordinary", now_utc=T0
        )
        pc_rej = {
            "schema_version": 9,
            "record_kind": "per-change",
            "host": KEY_HOST,
            "signer": KEY_OWNER,
            "sig_alg": "ed25519",
            "baseline_sha256": AE.canonical_sha256(self.enforcer.baseline_goal),
            "proposed_sha256": AE.canonical_sha256(prop),
            "nonce": rej_n,
            "approval_seq": 1,
            "verdict": "reject",
            "refused": ["supervision/service/com.tendcf.prec2"],
            "ceremony_class": "ordinary",
        }
        self.enforcer.process_per_change(sign_json(pc_rej, SEED_OWNER), proposed_goal=prop, diff=diff, now_utc=T0)
        with self.assertRaises(AE.ReplayError) as ctx_dc2:
            self.enforcer.process_standing_application(app_sa, proposed_goal=prop, diff=diff, now_utc=T0)
        self.assertEqual(ctx_dc2.exception.code, "persisted_reject_active")

        acc2_n = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop), ceremony_class="ordinary", now_utc=T0
        )
        pc_acc2 = dict(pc_rej, nonce=acc2_n, approval_seq=2, verdict="accept")
        pc_acc2.pop("refused")
        self.assertEqual(
            self.enforcer.process_per_change(
                sign_json(pc_acc2, SEED_OWNER), proposed_goal=prop, diff=diff, now_utc=T0
            ).decision,
            "applied",
        )


# ===========================================================================
# Section E: Further Rules, Authoritative Diff & Check Order (Items 20-26)
# ===========================================================================

class TestSectionEFurtherRulesAndCheckOrder(_EnforcerTestBase):
    def test_item20_generation_rules(self) -> None:
        _, nonce2, _ = self.enroll_active(grant_id="gen-g", generation=2)
        prop, diff = make_ordinary_service_change(self.baseline)
        for bad_gen in (1, 3):
            app = self.make_app_bytes(
                grant_id="gen-g", generation=bad_gen, application_seq=1, enrollment_nonce=nonce2, proposed=prop
            )
            with self.assertRaises(AE.ReplayError) as ctx:
                self.enforcer.process_standing_application(app, proposed_goal=prop, diff=diff, now_utc=T0)
            self.assertEqual(ctx.exception.code, "generation_mismatch")

        with self.assertRaises(AE.ReplayError) as ctx_low:
            self.enroll_active(grant_id="gen-g", generation=1)
        self.assertEqual(ctx_low.exception.code, "stale_generation")

    def test_item21_signer_in_covered_signers_and_unsorted_duplicate_rejection(self) -> None:
        _, nonce, _ = self.enroll_active(grant_id="cov-g", covered_signers=[KEY_COVERED])
        prop, diff = make_ordinary_service_change(self.baseline)
        app = self.make_app_bytes(
            grant_id="cov-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop, signer_seed=SEED_COVERED2, signer_key=KEY_COVERED2
        )
        with self.assertRaises(AE.ScopeError) as ctx:
            self.enforcer.process_standing_application(app, proposed_goal=prop, diff=diff, now_utc=T0)
        self.assertEqual(ctx.exception.code, "signer_not_covered")

        # Neon F8: Unsorted & duplicate covered_signers refused!
        pair_desc = sorted([KEY_COVERED, KEY_COVERED2], reverse=True)
        for bad_list, code in ((pair_desc, "unsorted_covered_signers"), ([KEY_COVERED, KEY_COVERED], "duplicate_covered_signers")):
            enr = {
                "schema_version": 9,
                "record_kind": "standing-enrollment",
                "host": KEY_HOST,
                "signer": KEY_OWNER,
                "sig_alg": "ed25519",
                "grant_id": "bad-cov",
                "generation": 1,
                "grant_state": "active",
                "nonce": AE.generate_device_nonce(),
                "mode": "standing-approval",
                "covered_signers": bad_list,
                "class": "ordinary",
                "developer_mode": False,
                "not_after": T_EXP,
            }
            with self.assertRaises(AE.MalformedRecordError) as ctx_b:
                self.enforcer.process_enrollment(sign_json(enr, SEED_OWNER), now_utc=T0)
            self.assertEqual(ctx_b.exception.code, code)

    def test_item22_r6_developer_mode_requires_privileged_ceremony_ordinary_class_and_not_after(self) -> None:
        with self.assertRaises(AE.NonceError) as ctx_lvl:
            self.enroll_active(
                grant_id="r6-lvl", covered_signers=[KEY_DEV], developer_mode=True, ceremony_level="ordinary", not_after=T_EXP
            )
        self.assertEqual(ctx_lvl.exception.code, "insufficient_ceremony_level")

        with self.assertRaises(AE.MalformedRecordError) as ctx_cls:
            self.enroll_active(
                grant_id="r6-cls", grant_class="privileged", covered_signers=[KEY_DEV], developer_mode=True, ceremony_level="privileged", not_after=T_EXP
            )
        self.assertEqual(ctx_cls.exception.code, "developer_mode_non_ordinary")

        with self.assertRaises(AE.MalformedRecordError) as ctx_na:
            self.enroll_active(
                grant_id="r6-na", mode="wait-for-user", covered_signers=[KEY_DEV], developer_mode=True, ceremony_level="privileged", not_after=None
            )
        self.assertEqual(ctx_na.exception.code, "missing_not_after")

        _, _, r = self.enroll_active(
            grant_id="r6-ok", covered_signers=[KEY_DEV], developer_mode=True, ceremony_level="privileged", not_after=T_EXP
        )
        self.assertEqual(r.status, "accepted")

    def test_item23_ceremony_class_per_change_authoritative_diff_bootstrap_and_malformed_diffs(self) -> None:
        _, priv_nonce, _ = self.enroll_active(grant_id="priv-only", grant_class="privileged")
        prop_ord, diff_ord = make_ordinary_service_change(self.baseline)
        prop_priv, diff_priv = make_supervisor_change(self.baseline)

        # 1. Standing application class mismatch & silent upgrade refused.
        app_ord_on_priv = self.make_app_bytes(
            grant_id="priv-only", generation=1, application_seq=1, enrollment_nonce=priv_nonce, proposed=prop_ord, ceremony_class="ordinary"
        )
        with self.assertRaises(AE.ScopeError) as ctx1:
            self.enforcer.process_standing_application(app_ord_on_priv, proposed_goal=prop_ord, diff=diff_ord, now_utc=T0)
        self.assertEqual(ctx1.exception.code, "grant_class_mismatch")

        app_lied_up = self.make_app_bytes(
            grant_id="priv-only", generation=1, application_seq=1, enrollment_nonce=priv_nonce, proposed=prop_ord, ceremony_class="privileged"
        )
        with self.assertRaises(AE.ScopeError) as ctx2:
            self.enforcer.process_standing_application(app_lied_up, proposed_goal=prop_ord, diff=diff_ord, now_utc=T0)
        self.assertEqual(ctx2.exception.code, "ceremony_class_mismatch")

        # 2. Codex #4 / Adversary C5 / Neon F4: process_per_change with diff=None STILL computes authoritative diff!
        #    Catches silent downgrade (adding owner under ceremony_class="ordinary"), downward version, and wrong goal host!
        prop_add_owner = copy.deepcopy(self.baseline)
        prop_add_owner["domains"]["device-trust"]["entries"]["advisor-key"][KEY_ATTACKER] = {
            "role": "owner", "state": "present"
        }
        n_down = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop_add_owner), ceremony_class="ordinary", now_utc=T0
        )
        pc_downgrade = sign_json(
            {
                "schema_version": 9,
                "record_kind": "per-change",
                "host": KEY_HOST,
                "signer": KEY_OWNER,
                "sig_alg": "ed25519",
                "baseline_sha256": AE.canonical_sha256(self.baseline),
                "proposed_sha256": AE.canonical_sha256(prop_add_owner),
                "nonce": n_down,
                "approval_seq": 0,
                "verdict": "accept",
                "ceremony_class": "ordinary",
            },
            SEED_OWNER,
        )
        with self.assertRaises(AE.ScopeError) as ctx_dg:
            self.enforcer.process_per_change(pc_downgrade, proposed_goal=prop_add_owner, diff=None, now_utc=T0)
        self.assertEqual(ctx_dg.exception.code, "ceremony_class_mismatch")

        # 3. Adversary C5 POC 5b: version_bump trust-root smuggling in per-change refused!
        prop_vb_smuggle = copy.deepcopy(prop_add_owner)
        prop_vb_smuggle["schema_version"] = 10
        diff_vb_smuggle = AE.compute_authoritative_diff(self.baseline, prop_vb_smuggle, KEY_HOST)
        n_vbs = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop_vb_smuggle), ceremony_class="baseline", now_utc=T0
        )
        pc_vbs = sign_json(
            {
                "schema_version": 9,
                "record_kind": "per-change",
                "host": KEY_HOST,
                "signer": KEY_OWNER,
                "sig_alg": "ed25519",
                "baseline_sha256": AE.canonical_sha256(self.baseline),
                "proposed_sha256": AE.canonical_sha256(prop_vb_smuggle),
                "nonce": n_vbs,
                "approval_seq": 0,
                "verdict": "accept",
                "ceremony_class": "baseline",
            },
            SEED_OWNER,
        )
        with self.assertRaises(AE.ScopeError) as ctx_vbs:
            self.enforcer.process_per_change(pc_vbs, proposed_goal=prop_vb_smuggle, diff=diff_vb_smuggle, now_utc=T0)
        self.assertEqual(ctx_vbs.exception.code, "migration_not_version_only")

        # 4. Macroscope 4708874692 / Codex #4: accept with proposed_goal=None refused BEFORE mutating state!
        n_np = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop_ord), ceremony_class="ordinary", now_utc=T0
        )
        pc_np = sign_json(
            {
                "schema_version": 9,
                "record_kind": "per-change",
                "host": KEY_HOST,
                "signer": KEY_OWNER,
                "sig_alg": "ed25519",
                "baseline_sha256": AE.canonical_sha256(self.baseline),
                "proposed_sha256": AE.canonical_sha256(prop_ord),
                "nonce": n_np,
                "approval_seq": 0,
                "verdict": "accept",
                "ceremony_class": "ordinary",
            },
            SEED_OWNER,
        )
        with self.assertRaises(AE.MalformedRecordError) as ctx_np:
            self.enforcer.process_per_change(pc_np, proposed_goal=None, diff=diff_ord, now_utc=T0)
        self.assertEqual(ctx_np.exception.code, "missing_proposed_goal")
        self.assertEqual(self.store.snapshot()["approval_seq"], -1)
        self.assertIn(n_np, self.store.snapshot()["outstanding_nonces"])

        # 5. Codex #5 / Macroscope 4708874405: First adoption requires explicit bootstrap_owner_keys AND matching goal host!
        fa_store = AE.ReplayStore.provision(
            self.tmp / "fa-boot", KEY_HOST, anchor=AE.InMemoryRollbackAnchor(), baseline_goal=None
        )
        fa_enf = AE.ApprovalEnforcer(KEY_HOST, fa_store)
        good_init = make_baseline_goal(host=KEY_HOST)
        bad_host_init = make_baseline_goal(host=KEY_OTHER_HOST)
        n_fa1 = fa_enf.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(good_init), ceremony_class="baseline", now_utc=T0
        )
        pc_fa1 = sign_json(
            {
                "schema_version": 9,
                "record_kind": "per-change",
                "host": KEY_HOST,
                "signer": KEY_OWNER,
                "sig_alg": "ed25519",
                "proposed_sha256": AE.canonical_sha256(good_init),
                "nonce": n_fa1,
                "approval_seq": 0,
                "verdict": "accept",
                "ceremony_class": "baseline",
            },
            SEED_OWNER,
        )
        # Missing bootstrap_owner_keys -> refused BEFORE mutating state!
        with self.assertRaises(AE.TrustRootError) as ctx_noboot:
            fa_enf.process_per_change(pc_fa1, proposed_goal=good_init, now_utc=T0)
        self.assertEqual(ctx_noboot.exception.code, "missing_bootstrap_authority")
        self.assertEqual(fa_store.snapshot()["approval_seq"], -1)

        # Wrong proposed_goal["host"] on first adoption -> refused!
        n_fa2 = fa_enf.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(bad_host_init), ceremony_class="baseline", now_utc=T0
        )
        pc_fa2 = sign_json(
            {
                "schema_version": 9,
                "record_kind": "per-change",
                "host": KEY_HOST,
                "signer": KEY_OWNER,
                "sig_alg": "ed25519",
                "proposed_sha256": AE.canonical_sha256(bad_host_init),
                "nonce": n_fa2,
                "approval_seq": 0,
                "verdict": "accept",
                "ceremony_class": "baseline",
            },
            SEED_OWNER,
        )
        with self.assertRaises(AE.ScopeError) as ctx_badhost:
            fa_enf.process_per_change(
                pc_fa2, proposed_goal=bad_host_init, bootstrap_owner_keys={KEY_OWNER}, now_utc=T0
            )
        self.assertEqual(ctx_badhost.exception.code, "goal_host_mismatch")

        # 6. Adversary H2 / Neon F5 / Macroscope 4708874404: Malformed diffs, phantom {"old": None}, invalid coverage, empty diff!
        malformed_diffs: list[tuple[str, Any, type[Exception]]] = [
            ("version_bump_null", {"schema_version": 9, "host": KEY_HOST, "baseline_sha256": "sha256:" + "11" * 32, "proposed_sha256": "sha256:" + "22" * 32, "version_bump": None}, AE.MalformedRecordError),
            ("version_bump_empty", {"schema_version": 9, "host": KEY_HOST, "baseline_sha256": "sha256:" + "11" * 32, "proposed_sha256": "sha256:" + "22" * 32, "version_bump": {}}, AE.MalformedRecordError),
            ("hunks_null", {"schema_version": 9, "host": KEY_HOST, "baseline_sha256": "sha256:" + "11" * 32, "proposed_sha256": "sha256:" + "22" * 32, "hunks": None}, AE.MalformedRecordError),
            ("phantom_old_none", {"schema_version": 9, "host": KEY_HOST, "baseline_sha256": "sha256:" + "11" * 32, "proposed_sha256": "sha256:" + "22" * 32, "hunks": {"supervision": {"service": {"x": {"old": None}}}}}, AE.MalformedRecordError),
            ("invalid_coverage_enum", {"schema_version": 9, "host": KEY_HOST, "baseline_sha256": "sha256:" + "11" * 32, "proposed_sha256": "sha256:" + "22" * 32, "coverage_changes": {"supervision": {"old": "undeclared", "new": "bogus-cov"}}}, AE.MalformedRecordError),
            ("empty_equal_hashes", {"schema_version": 9, "host": KEY_HOST, "baseline_sha256": "sha256:" + "11" * 32, "proposed_sha256": "sha256:" + "11" * 32, "hunks": {"supervision": {"service": {"x": {"new": {"state": "present"}}}}}}, AE.ScopeError),
        ]
        _, ord_n, _ = self.enroll_active(grant_id="mal-diff-g", grant_class="ordinary")
        app_md = self.make_app_bytes(
            grant_id="mal-diff-g", generation=1, application_seq=1, enrollment_nonce=ord_n, proposed=prop_ord
        )
        for label, bad_d, exc_cls in malformed_diffs:
            with self.subTest(malformed_diff=label):
                with self.assertRaises(exc_cls):
                    self.enforcer.process_standing_application(app_md, proposed_goal=prop_ord, diff=bad_d, now_utc=T0)

        # 7. PR #75 R4 #5 / Neon F8: Per-change nonce negative tests (wrong hash, wrong class, enrollment nonce, reuse, stale approval_seq)!
        prop_b, diff_b = make_ordinary_service_change(self.baseline, service_id="com.tendcf.pc-b")
        # (a) Wrong proposed_sha256
        n_wrong_hash = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop_b), ceremony_class="ordinary", now_utc=T0
        )
        pc_wh = sign_json(
            {
                "schema_version": 9, "record_kind": "per-change", "host": KEY_HOST, "signer": KEY_OWNER,
                "sig_alg": "ed25519", "baseline_sha256": AE.canonical_sha256(self.baseline),
                "proposed_sha256": AE.canonical_sha256(prop_ord), "nonce": n_wrong_hash,
                "approval_seq": 0, "verdict": "accept", "ceremony_class": "ordinary",
            },
            SEED_OWNER,
        )
        with self.assertRaises(AE.NonceError) as ctx_wh:
            self.enforcer.process_per_change(pc_wh, proposed_goal=prop_ord, diff=diff_ord, now_utc=T0)
        self.assertEqual(ctx_wh.exception.code, "nonce_scope_mismatch")

        # (b) Wrong ceremony_class on nonce
        n_wrong_cls = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop_ord), ceremony_class="privileged", now_utc=T0
        )
        with self.assertRaises(AE.NonceError):
            self.enforcer.process_per_change(
                sign_json(dict(json.loads(pc_wh), nonce=n_wrong_cls), SEED_OWNER),
                proposed_goal=prop_ord, diff=diff_ord, now_utc=T0,
            )

        # (c) Enrollment nonce offered for per-change
        enr_n = self.enforcer.issue_enrollment_nonce(
            grant_id="tmp-enr", mode="standing-approval", covered_signers=[KEY_COVERED],
            grant_class="ordinary", developer_mode=False, ceremony_level="ordinary", not_after=T_EXP, now_utc=T0,
        )
        with self.assertRaises(AE.NonceError):
            self.enforcer.process_per_change(
                sign_json(dict(json.loads(pc_wh), nonce=enr_n), SEED_OWNER),
                proposed_goal=prop_ord, diff=diff_ord, now_utc=T0,
            )

        # (d) Valid per-change accept at seq=5, then (e) reused nonce refused & (f) stale approval_seq=5 refused!
        n_ok = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop_ord), ceremony_class="ordinary", now_utc=T0
        )
        pc_ok = sign_json(dict(json.loads(pc_wh), nonce=n_ok, approval_seq=5), SEED_OWNER)
        self.assertEqual(
            self.enforcer.process_per_change(pc_ok, proposed_goal=prop_ord, diff=diff_ord, now_utc=T0).decision,
            "applied",
        )
        prop_next, diff_next = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.pc-next")
        with self.assertRaises(AE.NonceError):
            self.enforcer.process_per_change(
                sign_json(
                    {
                        "schema_version": 9, "record_kind": "per-change", "host": KEY_HOST, "signer": KEY_OWNER,
                        "sig_alg": "ed25519", "baseline_sha256": AE.canonical_sha256(self.enforcer.baseline_goal),
                        "proposed_sha256": AE.canonical_sha256(prop_next), "nonce": n_ok,
                        "approval_seq": 6, "verdict": "accept", "ceremony_class": "ordinary",
                    },
                    SEED_OWNER,
                ),
                proposed_goal=prop_next, diff=diff_next, now_utc=T0,
            )
        n_stale_seq = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop_next), ceremony_class="ordinary", now_utc=T0
        )
        with self.assertRaises(AE.ReplayError) as ctx_stseq:
            self.enforcer.process_per_change(
                sign_json(
                    {
                        "schema_version": 9, "record_kind": "per-change", "host": KEY_HOST, "signer": KEY_OWNER,
                        "sig_alg": "ed25519", "baseline_sha256": AE.canonical_sha256(self.enforcer.baseline_goal),
                        "proposed_sha256": AE.canonical_sha256(prop_next), "nonce": n_stale_seq,
                        "approval_seq": 5, "verdict": "accept", "ceremony_class": "ordinary",
                    },
                    SEED_OWNER,
                ),
                proposed_goal=prop_next, diff=diff_next, now_utc=T0,
            )
        self.assertEqual(ctx_stseq.exception.code, "stale_approval_seq")

    def test_item24_per_target_host_validity(self) -> None:
        _, nonce, _ = self.enroll_active(grant_id="host-g")
        prop, diff = make_ordinary_service_change(self.baseline)

        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_enrollment(self.make_revocation_bytes(grant_id="host-g", generation=2, host=KEY_OTHER_HOST), now_utc=T0)
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="host-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop, host=KEY_OTHER_HOST),
                proposed_goal=prop, diff=diff, now_utc=T0,
            )
        wrong_pc = sign_json(
            {
                "schema_version": 9, "record_kind": "per-change", "host": KEY_OTHER_HOST, "signer": KEY_OWNER,
                "sig_alg": "ed25519", "baseline_sha256": AE.canonical_sha256(self.baseline),
                "proposed_sha256": AE.canonical_sha256(prop), "nonce": AE.generate_device_nonce(),
                "approval_seq": 0, "verdict": "accept", "ceremony_class": "ordinary",
            },
            SEED_OWNER,
        )
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_per_change(wrong_pc, proposed_goal=prop, diff=diff, now_utc=T0)

    def test_item25_exact_proposed_sha256_binding(self) -> None:
        _, nonce, _ = self.enroll_active(grant_id="hash-g")
        prop_approved, _ = make_ordinary_service_change(self.baseline, service_id="com.tendcf.good")
        prop_swapped, diff_swapped = make_ordinary_service_change(self.baseline, service_id="com.tendcf.evil")
        app = self.make_app_bytes(
            grant_id="hash-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop_approved
        )
        with self.assertRaises(AE.ScopeError) as ctx:
            self.enforcer.process_standing_application(app, proposed_goal=prop_swapped, diff=diff_swapped, now_utc=T0)
        self.assertEqual(ctx.exception.code, "proposed_sha256_mismatch")

    def test_item26_and_r4_02_refused_application_never_burns_mark(self) -> None:
        _, nonce, _ = self.enroll_active(grant_id="mark-g", generation=1, mode="standing-approval")
        prop1, diff1 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.m1")
        app1 = self.make_app_bytes(
            grant_id="mark-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop1
        )
        self.assertEqual(
            self.enforcer.process_standing_application(app1, proposed_goal=prop1, diff=diff1, now_utc=T0).decision,
            "applied",
        )
        self.assertEqual(self.store.snapshot()["grants"]["mark-g"]["application_seq_mark"], 1)

        prop2, diff2 = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.m2")
        prop_other, _ = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.m3")

        def assert_mark_unchanged(label: str) -> None:
            self.assertEqual(self.store.snapshot()["grants"]["mark-g"]["application_seq_mark"], 1, label)

        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop2, host=KEY_OTHER_HOST),
                proposed_goal=prop2, diff=diff2, now_utc=T0,
            )
        assert_mark_unchanged("wrong_host")

        bad50 = json.loads(self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop2))
        bad50["signature"] = "ed25519-sig:" + "00" * 64
        with self.assertRaises(AE.SignatureError):
            self.enforcer.process_standing_application(AE.jcs_dumps(bad50), proposed_goal=prop2, diff=diff2, now_utc=T0)
        assert_mark_unchanged("bad_signature")

        with self.assertRaises(AE.ReplayError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=99, application_seq=50, enrollment_nonce=nonce, proposed=prop2),
                proposed_goal=prop2, diff=diff2, now_utc=T0,
            )
        assert_mark_unchanged("wrong_generation")

        with self.assertRaises(AE.NonceError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=AE.generate_device_nonce(), proposed=prop2),
                proposed_goal=prop2, diff=diff2, now_utc=T0,
            )
        assert_mark_unchanged("wrong_enrollment_nonce")

        with self.assertRaises(AE.ReplayError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, baseline=self.baseline, proposed=prop2),
                proposed_goal=prop2, diff=diff2, now_utc=T0,
            )
        assert_mark_unchanged("wrong_baseline_sha256")

        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop_other),
                proposed_goal=prop2, diff=diff2, now_utc=T0,
            )
        assert_mark_unchanged("wrong_proposed_sha256")

        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop2, signer_seed=SEED_COVERED2, signer_key=KEY_COVERED2),
                proposed_goal=prop2, diff=diff2, now_utc=T0,
            )
        assert_mark_unchanged("signer_not_covered")

        # R7 policy-tree carve-out
        prop_pt = copy.deepcopy(self.enforcer.baseline_goal)
        prop_pt["domains"]["device-trust"]["entries"]["policy-tree"]["tree"]["sha256"] = "sha256:" + "99" * 32
        diff_pt = AE.compute_authoritative_diff(self.enforcer.baseline_goal, prop_pt, KEY_HOST)
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop_pt, ceremony_class="privileged"),
                proposed_goal=prop_pt, diff=diff_pt, now_utc=T0,
            )
        assert_mark_unchanged("r7_policy_tree_carve_out")

        # Persisted DC-2 reject
        rej_n = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop2), ceremony_class="ordinary", now_utc=T0
        )
        pc_rej = {
            "schema_version": 9, "record_kind": "per-change", "host": KEY_HOST, "signer": KEY_OWNER,
            "sig_alg": "ed25519", "baseline_sha256": AE.canonical_sha256(self.enforcer.baseline_goal),
            "proposed_sha256": AE.canonical_sha256(prop2), "nonce": rej_n, "approval_seq": 0,
            "verdict": "reject", "refused": ["supervision/service/com.tendcf.m2"], "ceremony_class": "ordinary",
        }
        self.enforcer.process_per_change(sign_json(pc_rej, SEED_OWNER), proposed_goal=prop2, diff=diff2, now_utc=T0)
        with self.assertRaises(AE.ReplayError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop2),
                proposed_goal=prop2, diff=diff2, now_utc=T0,
            )
        assert_mark_unchanged("persisted_dc2_reject")

        # Covering standing-refusal
        self.enroll_active(grant_id="ref-block", mode="standing-refusal", not_after=None)
        prop_ok, diff_ok = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.m4")
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop_ok),
                proposed_goal=prop_ok, diff=diff_ok, now_utc=T0,
            )
        assert_mark_unchanged("covering_standing_refusal")

        # Valid seq=2 STILL succeeds (mark never burned to 50)!
        self.enforcer.process_enrollment(self.make_revocation_bytes(grant_id="ref-block", generation=2), now_utc=T0)
        app2 = self.make_app_bytes(
            grant_id="mark-g", generation=1, application_seq=2, enrollment_nonce=nonce, proposed=prop_ok
        )
        self.assertEqual(
            self.enforcer.process_standing_application(app2, proposed_goal=prop_ok, diff=diff_ok, now_utc=T0).decision,
            "applied",
        )
        self.assertEqual(self.store.snapshot()["grants"]["mark-g"]["application_seq_mark"], 2)


# ===========================================================================
# Section F: Round 2 Security, Crash-Safety & Regression Coverage
# ===========================================================================

class TestSectionFR2SecurityAndCrashSafety(_EnforcerTestBase):
    def test_r2_h1_nfc_refused_before_store_write(self) -> None:
        # 1. NFD string in provision(baseline_goal=...) refused BEFORE writing store!
        nfd_base = make_baseline_goal(
            extra_domains={
                "supervision": {
                    "coverage": "comprehensive",
                    "entries": {
                        "service": {
                            "cafe\u0301": {
                                "bundle": "demo",
                                "command": ["/usr/bin/true"],
                                "run_as": "nobody",
                                "state": "present",
                                "unit": {"launchd": {"domain": "system", "keep_alive": False, "run_at_load": True}},
                                "working_dir": "/",
                            }
                        }
                    },
                }
            }
        )
        nfd_anchor = AE.InMemoryRollbackAnchor()
        nfd_dir = self.tmp / "nfd-prov"
        with self.assertRaises(AE.MalformedRecordError) as ctx_prov:
            AE.ReplayStore.provision(nfd_dir, KEY_HOST, anchor=nfd_anchor, baseline_goal=nfd_base)
        self.assertEqual(ctx_prov.exception.code, "non_nfc_string")
        self.assertIsNone(nfd_anchor.read())

        # 2. NFD string in recover_after_store_loss(baseline_goal=...) refused without corrupting store!
        cur = self.store.current_store_path
        assert cur is not None
        cur.unlink()
        with self.assertRaises(AE.StoreRollbackError):
            self.store.snapshot(allow_voided=False)
        with self.assertRaises(AE.MalformedRecordError) as ctx_rec:
            self.store.recover_after_store_loss(baseline_goal=nfd_base)
        self.assertEqual(ctx_rec.exception.code, "non_nfc_string")
        self.store.recover_after_store_loss(baseline_goal=self.baseline)

        # 3. NFD string in proposed_goal refused BEFORE any store write!
        _, nonce, _ = self.enroll_active(grant_id="nfc-g", mode="hold-window", hold_seconds=60)
        prop_nfd, _ = make_ordinary_service_change(self.baseline, service_id="com.tendcf.cafe\u0301")
        app_nfd = self.make_app_bytes(
            grant_id="nfc-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop_nfd
        )
        writes_before = self.store.write_count
        with self.assertRaises(AE.MalformedRecordError) as ctx_prop:
            self.enforcer.process_standing_application(
                app_nfd, proposed_goal=prop_nfd, diff=None, now_utc=T0
            )
        self.assertEqual(ctx_prop.exception.code, "non_nfc_string")
        self.assertEqual(self.store.write_count, writes_before)
        # Store remains cleanly readable!
        self.assertEqual(self.store.snapshot()["grants"]["nfc-g"]["application_seq_mark"], 0)

        # 4. NFD string in boot_epoch refused BEFORE any store write!
        prop_ok, diff_ok = make_ordinary_service_change(self.baseline, service_id="com.tendcf.ok")
        app_ok = self.make_app_bytes(
            grant_id="nfc-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop_ok
        )
        with self.assertRaises(AE.MalformedRecordError) as ctx_ep1:
            self.enforcer.process_standing_application(
                app_ok,
                proposed_goal=prop_ok,
                diff=diff_ok,
                now_utc=T0,
                now_mono=10.0,
                boot_epoch="epoch-cafe\u0301",
                display_confirmed=True,
            )
        self.assertEqual(ctx_ep1.exception.code, "non_nfc_string")
        self.assertEqual(self.store.write_count, writes_before)

        # Also refused in confirm_hold_displayed()!
        self.enforcer.process_standing_application(app_ok, proposed_goal=prop_ok, diff=diff_ok, now_utc=T0)
        writes_after_hold = self.store.write_count
        with self.assertRaises(AE.MalformedRecordError) as ctx_ep2:
            self.enforcer.confirm_hold_displayed(
                AE.canonical_sha256(prop_ok), now_mono=20.0, boot_epoch="epoch-cafe\u0301"
            )
        self.assertEqual(ctx_ep2.exception.code, "non_nfc_string")
        self.assertEqual(self.store.write_count, writes_after_hold)
        self.assertFalse(self.store.snapshot()["pending_holds"][AE.canonical_sha256(prop_ok)]["displayed"])

    def test_r2_h2_and_codex2_nested_mutation_forbidden_and_cas_anchor_conflict(self) -> None:
        # 1. Nested mutation inside _apply_callback raises nested_mutation_during_actuation,
        #    while read-only store.snapshot() and developer_mode_indicator_active() succeed!
        _, nonce, _ = self.enroll_active(grant_id="nested-g", mode="standing-approval")
        self.enroll_active(
            grant_id="dev-ind-exp", covered_signers=[KEY_DEV], developer_mode=True, not_after=T_EXP
        )
        nested_err: list[str] = []
        readonly_ok: list[bool] = []

        def mutating_cb(_goal: dict[str, Any]) -> None:
            # Non-expired read-only inspection succeeds without mutating or deadlocking!
            snap = self.store.snapshot()
            self.assertIsNotNone(snap["pending_actuation"])
            readonly_ok.append(self.enforcer.developer_mode_indicator_active(T0))
            # Direct store.commit_unlocked inside actuation tx MUST fail closed!
            with self.assertRaises(AE.ReplayError) as raw_c:
                self.store.commit_unlocked(snap)
            self.assertEqual(raw_c.exception.code, "nested_mutation_during_actuation")
            # Reconciling inside actuation tx MUST fail closed!
            with self.assertRaises(AE.ReplayError) as rec_c:
                self.enforcer.reconcile_pending_actuation(
                    snap["pending_actuation"]["actuation_id"], applied_on_device=True
                )
            self.assertEqual(rec_c.exception.code, "nested_mutation_during_actuation")
            # Attempting a nested enforcer mutation MUST fail closed with nested_mutation_during_actuation!
            try:
                self.enforcer.issue_enrollment_nonce(
                    grant_id="illegal-nested",
                    mode="standing-approval",
                    covered_signers=[KEY_COVERED],
                    grant_class="ordinary",
                    developer_mode=False,
                    ceremony_level="ordinary",
                    not_after=T_EXP,
                    now_utc=T0,
                )
            except AE.ReplayError as exc:
                nested_err.append(exc.code)
                raise

        enf_mut = AE.ApprovalEnforcer(KEY_HOST, self.store, apply_callback=mutating_cb)
        prop, diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.nested")
        app = self.make_app_bytes(
            grant_id="nested-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop
        )
        with self.assertRaises(AE.ReplayError) as ctx_nest:
            enf_mut.process_standing_application(app, proposed_goal=prop, diff=diff, now_utc=T0)
        self.assertEqual(ctx_nest.exception.code, "nested_mutation_during_actuation")
        self.assertEqual(nested_err, ["nested_mutation_during_actuation"])
        self.assertEqual(readonly_ok, [True])
        # Codex R3 #1: callback raising preserves pending_actuation until reconciled; mark stays consumed!
        snap_after = self.store.snapshot()
        self.assertIsNotNone(snap_after["pending_actuation"])
        self.assertEqual(snap_after["applied_baseline_sha256"], AE.canonical_sha256(self.baseline))
        self.assertEqual(snap_after["grants"]["nested-g"]["application_seq_mark"], 1)
        enf_mut.reconcile_pending_actuation(
            snap_after["pending_actuation"]["actuation_id"], applied_on_device=False
        )
        self.assertIsNone(self.store.snapshot()["pending_actuation"])

        # 2. CAS anchor generation conflict in commit_unlocked fails closed with StoreRollbackError!
        with self.store.locked():
            st = self.store.load_verified_unlocked()
            # Simulate an external/concurrent writer advancing the anchor between load and commit!
            cur_anc = self.anchor.read()
            assert cur_anc is not None
            self.anchor.write(AE.AnchorState(cur_anc.store_generation + 1, cur_anc.store_sha256))
            with self.assertRaises(AE.StoreRollbackError) as ctx_cas:
                self.store.commit_unlocked(st)
            self.assertEqual(ctx_cas.exception.code, "anchor_generation_conflict")

    def test_r2_codex1_pending_actuation_crash_and_reconcile_promote_and_abort(self) -> None:
        class _PublishCrash(RuntimeError):
            pass

        applied_goals: list[dict[str, Any]] = []
        enf = AE.ApprovalEnforcer(KEY_HOST, self.store, apply_callback=lambda g: applied_goals.append(g))
        _, nonce, _ = self.enroll_active(grant_id="pa-g", mode="standing-approval", enforcer=enf)
        prop1, diff1 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.pa1")
        app1 = self.make_app_bytes(
            grant_id="pa-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop1
        )

        # 1. Callback SUCCEEDS, then crash hits in before_publish_hook before baseline publication commits!
        with self.assertRaises(_PublishCrash):
            enf.process_standing_application(
                app1,
                proposed_goal=prop1,
                diff=diff1,
                now_utc=T0,
                before_publish_hook=lambda: (_ for _ in ()).throw(_PublishCrash("crash before publish")),
            )
        self.assertEqual(len(applied_goals), 1)
        self.assertEqual(enf.actuation_count, 0)

        # 2. Reopen fresh ReplayStore + ApprovalEnforcer: pending_actuation is durably persisted
        #    and blocks ALL mutating entrypoints until reconciled!
        reopened_store = AE.ReplayStore(self.store_dir, KEY_HOST, anchor=self.anchor)
        reopened_enf = AE.ApprovalEnforcer(KEY_HOST, reopened_store)
        snap = reopened_store.snapshot()
        self.assertIsNotNone(snap["pending_actuation"])
        self.assertEqual(snap["pending_actuation"]["proposed_sha256"], AE.canonical_sha256(prop1))
        self.assertEqual(snap["applied_baseline_sha256"], AE.canonical_sha256(self.baseline))

        with self.assertRaises(AE.ReplayError) as c1:
            reopened_enf.issue_enrollment_nonce(
                grant_id="blocked-g", mode="standing-approval", covered_signers=[KEY_COVERED],
                grant_class="ordinary", developer_mode=False, ceremony_level="ordinary", not_after=T_EXP, now_utc=T0,
            )
        self.assertEqual(c1.exception.code, "pending_actuation_unreconciled")
        with self.assertRaises(AE.ReplayError) as c2:
            reopened_enf.issue_per_change_nonce(
                proposed_sha256=AE.canonical_sha256(prop1), ceremony_class="ordinary", now_utc=T0
            )
        self.assertEqual(c2.exception.code, "pending_actuation_unreconciled")
        with self.assertRaises(AE.ReplayError) as c3:
            reopened_enf.process_enrollment(self.make_revocation_bytes(grant_id="pa-g", generation=2), now_utc=T0)
        self.assertEqual(c3.exception.code, "pending_actuation_unreconciled")
        with self.assertRaises(AE.ReplayError) as c4:
            reopened_enf.process_standing_application(app1, proposed_goal=prop1, diff=diff1, now_utc=T0)
        self.assertEqual(c4.exception.code, "pending_actuation_unreconciled")

        # 3. Reconcile with applied_on_device=True -> promotes baseline, clears pending_actuation, increments actuation_count!
        act_id_1 = snap["pending_actuation"]["actuation_id"]
        res_prom = reopened_enf.reconcile_pending_actuation(act_id_1, applied_on_device=True)
        self.assertEqual(res_prom["status"], "promoted")
        self.assertEqual(res_prom["actuation_id"], act_id_1)
        self.assertEqual(res_prom["applied_baseline_sha256"], AE.canonical_sha256(prop1))
        self.assertEqual(reopened_enf.actuation_count, 1)
        self.assertEqual(AE.canonical_sha256(reopened_enf.baseline_goal), AE.canonical_sha256(prop1))
        self.assertIsNone(reopened_store.snapshot()["pending_actuation"])

        # Reconciling again when none pending raises no_pending_actuation.
        with self.assertRaises(AE.ReplayError) as c_none:
            reopened_enf.reconcile_pending_actuation(act_id_1, applied_on_device=False)
        self.assertEqual(c_none.exception.code, "no_pending_actuation")

        # 4. Also verify per-change accept crash before publish + reconcile(applied_on_device=False) preserves prior baseline!
        prop2, diff2 = make_ordinary_service_change(prop1, service_id="com.tendcf.pa2")
        pc_n = reopened_enf.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop2), ceremony_class="ordinary", now_utc=T0
        )
        pc_raw = sign_json(
            {
                "schema_version": 9, "record_kind": "per-change", "host": KEY_HOST, "signer": KEY_OWNER,
                "sig_alg": "ed25519", "baseline_sha256": AE.canonical_sha256(prop1),
                "proposed_sha256": AE.canonical_sha256(prop2), "nonce": pc_n,
                "approval_seq": 0, "verdict": "accept", "ceremony_class": "ordinary",
            },
            SEED_OWNER,
        )
        with self.assertRaises(_PublishCrash):
            reopened_enf.process_per_change(
                pc_raw,
                proposed_goal=prop2,
                diff=diff2,
                now_utc=T0,
                before_publish_hook=lambda: (_ for _ in ()).throw(_PublishCrash("pc crash")),
            )
        act_id_2 = reopened_store.snapshot()["pending_actuation"]["actuation_id"]
        res_ab = reopened_enf.reconcile_pending_actuation(act_id_2, applied_on_device=False)
        self.assertEqual(res_ab["status"], "aborted")
        self.assertEqual(res_ab["actuation_id"], act_id_2)
        self.assertEqual(res_ab["applied_baseline_sha256"], AE.canonical_sha256(prop1))
        self.assertEqual(reopened_store.snapshot()["approval_seq"], 0)

    def test_r2_codex3_observed_expiry_watermark_in_indicator_and_precedence(self) -> None:
        # 1. developer_mode_indicator_active() observing expiry -> restart -> backward clock refuses grant!
        t_start = datetime.datetime(2026, 11, 26, 12, 0, 0, tzinfo=datetime.timezone.utc)
        t_exp = "2026-11-26T12:05:00Z"
        t_past = datetime.datetime(2026, 11, 26, 12, 6, 0, tzinfo=datetime.timezone.utc)
        t_back = datetime.datetime(2026, 11, 26, 12, 4, 0, tzinfo=datetime.timezone.utc)  # > t_start, < t_past!

        raw_dev, dev_nonce, _ = self.enroll_active(
            grant_id="ind-exp", covered_signers=[KEY_DEV], developer_mode=True, not_after=t_exp, now_utc=t_start
        )
        # Live identical Option B redelivery stays strictly zero-write!
        w_before = self.store.write_count
        self.enforcer.process_enrollment(raw_dev, now_utc=t_start)
        self.assertEqual(self.store.write_count, w_before)

        # Observe expiry through developer_mode_indicator_active(t_past).
        self.assertFalse(self.enforcer.developer_mode_indicator_active(t_past))
        self.assertEqual(self.store.snapshot()["last_seen_utc"], "2026-11-26T12:06:00Z")

        # Reopen fresh store + enforcer and rewind clock to t_back (above t_start, before t_exp) -> REFUSED!
        reopened = AE.ApprovalEnforcer(KEY_HOST, AE.ReplayStore(self.store_dir, KEY_HOST, anchor=self.anchor))
        prop, diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.indback")
        app_dev = self.make_app_bytes(
            grant_id="ind-exp", generation=1, application_seq=1, enrollment_nonce=dev_nonce, proposed=prop, signer_seed=SEED_DEV, signer_key=KEY_DEV
        )
        with self.assertRaises(AE.ClockRollbackError) as ctx_rb1:
            reopened.process_standing_application(app_dev, proposed_goal=prop, diff=diff, now_utc=t_back)
        self.assertEqual(ctx_rb1.exception.code, "utc_clock_rollback")

        # 2. Precedence skip observing expiry on parked (wait-for-user) AND refused (standing-refusal) apps persists watermark!
        s2_dir = self.tmp / "prec-wm-store"
        s2_anc = AE.InMemoryRollbackAnchor()
        s2 = AE.ReplayStore.provision(s2_dir, KEY_HOST, anchor=s2_anc, baseline_goal=self.baseline)
        e2 = AE.ApprovalEnforcer(KEY_HOST, s2)
        _, sa_n, _ = self.enroll_active(grant_id="live-sa", mode="standing-approval", not_after=T_EXP, now_utc=t_start, enforcer=e2)
        self.enroll_active(grant_id="exp-hw", mode="hold-window", hold_seconds=600, not_after=t_exp, now_utc=t_start, enforcer=e2)
        self.enroll_active(grant_id="live-wfu", mode="wait-for-user", not_after=None, now_utc=t_start, enforcer=e2)

        prop2, diff2 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.precwm")
        app_sa = self.make_app_bytes(
            grant_id="live-sa", generation=1, application_seq=1, enrollment_nonce=sa_n, proposed=prop2
        )
        # At t_past, exp-hw is skipped as expired during precedence, and live-wfu parks the app!
        parked = e2.process_standing_application(app_sa, proposed_goal=prop2, diff=diff2, now_utc=t_past)
        self.assertEqual(parked.decision, "parked")
        self.assertEqual(s2.snapshot()["last_seen_utc"], "2026-11-26T12:06:00Z")
        with self.assertRaises(AE.ClockRollbackError):
            e2.process_standing_application(app_sa, proposed_goal=prop2, diff=diff2, now_utc=t_back)

        # Also test standing-refusal path persisting observed expiry watermark!
        t_past2 = datetime.datetime(2026, 11, 26, 12, 10, 0, tzinfo=datetime.timezone.utc)
        t_back2 = datetime.datetime(2026, 11, 26, 12, 8, 0, tzinfo=datetime.timezone.utc)
        self.enroll_active(grant_id="live-ref", mode="standing-refusal", not_after=None, now_utc=t_past, enforcer=e2)
        with self.assertRaises(AE.ScopeError) as ctx_ref:
            e2.process_standing_application(app_sa, proposed_goal=prop2, diff=diff2, now_utc=t_past2)
        self.assertEqual(ctx_ref.exception.code, "standing_refusal")
        self.assertEqual(s2.snapshot()["last_seen_utc"], "2026-11-26T12:10:00Z")
        with self.assertRaises(AE.ClockRollbackError):
            e2.process_standing_application(app_sa, proposed_goal=prop2, diff=diff2, now_utc=t_back2)

    def test_r2_codex4_anchor_nested_descendant_rejected(self) -> None:
        base_dir = self.tmp / "nested-anchor-store"
        for rel in (
            base_dir / "anchor.json",
            base_dir / "nested" / "anchor.json",
            base_dir / "a" / "b" / "c" / "anchor.json",
        ):
            with self.subTest(anchor_path=str(rel)):
                with self.assertRaises(ValueError):
                    AE.ReplayStore(base_dir, KEY_HOST, anchor=AE.FileRollbackAnchor(rel))

    def test_r2_codex5_entry_deepcopy_prevents_caller_mutation_during_actuation(self) -> None:
        _, nonce, _ = self.enroll_active(grant_id="mut-g", mode="standing-approval")
        prop, diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.immut")
        signed_hash = AE.canonical_sha256(prop)
        app = self.make_app_bytes(
            grant_id="mut-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop
        )
        observed_hashes: list[str] = []

        def hostile_cb(actuated_goal: dict[str, Any]) -> None:
            # Mutate BOTH caller's original dict AND the callback argument!
            prop["domains"]["supervision"]["entries"]["service"]["com.tendcf.immut"]["command"] = ["/bin/evil"]
            diff["host"] = KEY_OTHER_HOST
            observed_hashes.append(AE.canonical_sha256(actuated_goal))
            actuated_goal["domains"]["supervision"]["entries"]["service"]["com.tendcf.immut"]["command"] = ["/bin/evil2"]

        enf_m = AE.ApprovalEnforcer(KEY_HOST, self.store, apply_callback=hostile_cb)
        res = enf_m.process_standing_application(app, proposed_goal=prop, diff=diff, now_utc=T0)
        self.assertEqual(res.decision, "applied")
        self.assertEqual(observed_hashes, [signed_hash])
        self.assertEqual(AE.canonical_sha256(enf_m.baseline_goal), signed_hash)
        self.assertEqual(
            enf_m.baseline_goal["domains"]["supervision"]["entries"]["service"]["com.tendcf.immut"]["command"],
            ["/usr/bin/true"],
        )

    def test_r2_codex6_and_r2_l1_1_per_change_reject_withdraw_version_bump_requires_proposal(self) -> None:
        prop_up = pure_version_bump_migrate(self.baseline, 10)
        diff_up = AE.compute_authoritative_diff(self.baseline, prop_up, KEY_HOST)
        for idx, verdict in enumerate(("reject", "withdraw")):
            with self.subTest(verdict=verdict):
                pc_n = self.enforcer.issue_per_change_nonce(
                    proposed_sha256=AE.canonical_sha256(prop_up), ceremony_class="baseline", now_utc=T0
                )
                rec: dict[str, Any] = {
                    "schema_version": 9,
                    "record_kind": "per-change",
                    "host": KEY_HOST,
                    "signer": KEY_OWNER,
                    "sig_alg": "ed25519",
                    "baseline_sha256": AE.canonical_sha256(self.baseline),
                    "proposed_sha256": AE.canonical_sha256(prop_up),
                    "nonce": pc_n,
                    "approval_seq": idx,
                    "verdict": verdict,
                    "ceremony_class": "baseline",
                }
                if verdict == "reject":
                    rec["refused"] = ["schema_version"]
                raw = sign_json(rec, SEED_OWNER)
                # Without proposed_goal -> refused BEFORE consuming nonce or approval_seq!
                with self.assertRaises(AE.MalformedRecordError) as ctx_vb:
                    self.enforcer.process_per_change(raw, proposed_goal=None, diff=diff_up, now_utc=T0)
                self.assertEqual(ctx_vb.exception.code, "version_bump_requires_proposal")
                self.assertIn(pc_n, self.store.snapshot()["outstanding_nonces"])

                # With valid proposed_goal -> succeeds cleanly!
                res = self.enforcer.process_per_change(raw, proposed_goal=prop_up, diff=diff_up, now_utc=T0)
                self.assertEqual(res.decision, "rejected" if verdict == "reject" else "withdrawn")

    def test_r2_m1_closed_goal_keys_extra_domain_metadata_and_empty_entries(self) -> None:
        _, nonce, _ = self.enroll_active(grant_id="closed-g", mode="standing-approval")

        # 1. Extra domain metadata on newly added domain with diff=None refused!
        prop_extra_dom, _ = make_ordinary_service_change(self.baseline, service_id="com.tendcf.extra")
        prop_extra_dom["domains"]["supervision"]["rogue_meta"] = {"hidden": True}
        app1 = self.make_app_bytes(
            grant_id="closed-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop_extra_dom
        )
        with self.assertRaises(AE.MalformedRecordError) as ctx1:
            self.enforcer.process_standing_application(app1, proposed_goal=prop_extra_dom, diff=None, now_utc=T0)
        self.assertEqual(ctx1.exception.code, "unexpected_domain_fields")

        # 2. Unknown top-level goal key refused!
        prop_extra_top, _ = make_ordinary_service_change(self.baseline, service_id="com.tendcf.top")
        prop_extra_top["unexpected_top"] = 123
        app2 = self.make_app_bytes(
            grant_id="closed-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop_extra_top
        )
        with self.assertRaises(AE.MalformedRecordError) as ctx2:
            self.enforcer.process_standing_application(app2, proposed_goal=prop_extra_top, diff=None, now_utc=T0)
        self.assertEqual(ctx2.exception.code, "unexpected_goal_fields")

        # 3. "entries" under "deliberately-unmanaged" refused!
        prop_unm = copy.deepcopy(self.baseline)
        prop_unm["domains"]["supervision"] = {
            "coverage": "deliberately-unmanaged",
            "entries": {"service": {"x": {"state": "present"}}},
        }
        with self.assertRaises(AE.MalformedRecordError) as ctx3:
            AE.validate_goal_file_basics(prop_unm, KEY_HOST)
        self.assertEqual(ctx3.exception.code, "entries_in_unmanaged_domain")

        # 4. Empty entries: {} and empty kind map {"service": {}} refused!
        prop_empty_e = copy.deepcopy(self.baseline)
        prop_empty_e["domains"]["supervision"] = {"coverage": "comprehensive", "entries": {}}
        with self.assertRaises(AE.MalformedRecordError) as ctx4:
            AE.validate_goal_file_basics(prop_empty_e, KEY_HOST)
        self.assertEqual(ctx4.exception.code, "invalid_domain_entries")

        prop_empty_k = copy.deepcopy(self.baseline)
        prop_empty_k["domains"]["supervision"] = {"coverage": "comprehensive", "entries": {"service": {}}}
        with self.assertRaises(AE.MalformedRecordError) as ctx5:
            AE.validate_goal_file_basics(prop_empty_k, KEY_HOST)
        self.assertEqual(ctx5.exception.code, "invalid_kind_bucket")

    def test_r2_macroscope_4709254027_reboot_resets_hold_for_redisplay_and_completion(self) -> None:
        _, nonce, _ = self.enroll_active(grant_id="reboot-hw", mode="hold-window", hold_seconds=300)
        prop, diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.reboot")
        prop_hash = AE.canonical_sha256(prop)
        app = self.make_app_bytes(
            grant_id="reboot-hw", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop
        )
        # Hold enters confirmed on EPOCH_1 at mono=1000.0.
        res_h = self.enforcer.process_standing_application(
            app, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=1000.0, boot_epoch=EPOCH_1, display_confirmed=True
        )
        self.assertEqual(res_h.decision, "held")

        # Duplicate confirm on SAME boot_epoch still refused!
        with self.assertRaises(AE.ReplayError) as ctx_dup:
            self.enforcer.confirm_hold_displayed(prop_hash, now_mono=1050.0, boot_epoch=EPOCH_1)
        self.assertEqual(ctx_dup.exception.code, "hold_already_displayed")

        # Device reboots to EPOCH_2: complete_hold_window resets display state and raises monotonic_boot_epoch_mismatch!
        with self.assertRaises(AE.ClockRollbackError) as ctx_boot:
            self.enforcer.complete_hold_window(
                prop_hash, proposed_goal=prop, diff=diff, now_utc=T1, now_mono=500.0, boot_epoch=EPOCH_2
            )
        self.assertEqual(ctx_boot.exception.code, "monotonic_boot_epoch_mismatch")
        hold_after_reset = self.store.snapshot()["pending_holds"][prop_hash]
        self.assertFalse(hold_after_reset["displayed"])
        self.assertIsNone(hold_after_reset["first_shown_mono"])
        self.assertIsNone(hold_after_reset["boot_epoch"])

        # UI re-displays the held change on EPOCH_2 at mono=50.0!
        self.enforcer.confirm_hold_displayed(prop_hash, now_mono=50.0, boot_epoch=EPOCH_2)

        # Partial elapsed time (+100s < 300s) on EPOCH_2 refused!
        with self.assertRaises(AE.ScopeError) as ctx_early:
            self.enforcer.complete_hold_window(
                prop_hash, proposed_goal=prop, diff=diff, now_utc=T1, now_mono=150.0, boot_epoch=EPOCH_2
            )
        self.assertEqual(ctx_early.exception.code, "hold_window_not_elapsed")

        # Full elapsed time (+300s) on EPOCH_2 applies cleanly!
        res_done = self.enforcer.complete_hold_window(
            prop_hash,
            proposed_goal=prop,
            diff=diff,
            now_utc=T1 + datetime.timedelta(minutes=5),
            now_mono=350.0,
            boot_epoch=EPOCH_2,
        )
        self.assertEqual(res_done.decision, "applied")
        self.assertEqual(self.store.snapshot()["pending_holds"], {})

        # Also test direct confirm_hold_displayed() on a NEW boot_epoch without calling complete_hold_window first!
        prop2, diff2 = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.reboot2")
        prop2_hash = AE.canonical_sha256(prop2)
        app2 = self.make_app_bytes(
            grant_id="reboot-hw", generation=1, application_seq=2, enrollment_nonce=nonce, proposed=prop2
        )
        self.enforcer.process_standing_application(
            app2,
            proposed_goal=prop2,
            diff=diff2,
            now_utc=T1 + datetime.timedelta(minutes=6),
            now_mono=400.0,
            boot_epoch=EPOCH_2,
            display_confirmed=True,
        )
        # Reboot directly to boot-epoch-3 -> confirm_hold_displayed succeeds immediately!
        self.enforcer.confirm_hold_displayed(prop2_hash, now_mono=10.0, boot_epoch="boot-epoch-3")
        res_done2 = self.enforcer.complete_hold_window(
            prop2_hash,
            proposed_goal=prop2,
            diff=diff2,
            now_utc=T1 + datetime.timedelta(minutes=12),
            now_mono=310.0,
            boot_epoch="boot-epoch-3",
        )
        self.assertEqual(res_done2.decision, "applied")


# ===========================================================================
# Section G: Round 3 Reconciliation, Recovery, Callback Expiry & Re-adoption
# ===========================================================================

class TestSectionGR3ReconciliationAndEvidence(_EnforcerTestBase):
    def test_r3_codex1_macroscope_callback_apply_then_raise_preserves_pending_actuation(self) -> None:
        # Callback externally applies the goal (e.g. removes Owner 2 on device) and THEN raises TimeoutError!
        device_state: dict[str, Any] = {"applied": None}

        def apply_then_timeout(goal: dict[str, Any]) -> None:
            device_state["applied"] = copy.deepcopy(goal)
            raise TimeoutError("ack lost after device actuation")

        enf = AE.ApprovalEnforcer(KEY_HOST, self.store, apply_callback=apply_then_timeout)
        prop_rm = copy.deepcopy(self.baseline)
        prop_rm["domains"]["device-trust"]["entries"]["advisor-key"][KEY_OWNER2]["state"] = "absent"
        diff_rm = AE.compute_authoritative_diff(self.baseline, prop_rm, KEY_HOST)
        pc_n = enf.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop_rm), ceremony_class="privileged", now_utc=T0
        )
        pc_raw = sign_json(
            {
                "schema_version": 9,
                "record_kind": "per-change",
                "host": KEY_HOST,
                "signer": KEY_OWNER,
                "sig_alg": "ed25519",
                "baseline_sha256": AE.canonical_sha256(self.baseline),
                "proposed_sha256": AE.canonical_sha256(prop_rm),
                "nonce": pc_n,
                "approval_seq": 0,
                "verdict": "accept",
                "ceremony_class": "privileged",
            },
            SEED_OWNER,
        )
        with self.assertRaises(TimeoutError):
            enf.process_per_change(pc_raw, proposed_goal=prop_rm, diff=diff_rm, now_utc=T0)
        self.assertIsNotNone(device_state["applied"])

        # Reopen fresh store + enforcer: pending_actuation MUST remain persisted and block new operations
        # (so removed Owner 2 cannot slip through using the old baseline)!
        reopened_store = AE.ReplayStore(self.store_dir, KEY_HOST, anchor=self.anchor)
        reopened_enf = AE.ApprovalEnforcer(KEY_HOST, reopened_store)
        snap = reopened_store.snapshot()
        self.assertIsNotNone(snap["pending_actuation"])
        act_id = snap["pending_actuation"]["actuation_id"]
        with self.assertRaises(AE.ReplayError) as ctx_blk:
            reopened_enf.process_enrollment(
                self.make_revocation_bytes(grant_id="any-g", generation=1, owner_seed=SEED_OWNER2, owner_key=KEY_OWNER2),
                now_utc=T0,
            )
        self.assertEqual(ctx_blk.exception.code, "pending_actuation_unreconciled")

        # Reconcile against device_state (applied_on_device=True) -> promotes new baseline (Owner 2 absent)!
        res = reopened_enf.reconcile_pending_actuation(act_id, applied_on_device=True)
        self.assertEqual(res["status"], "promoted")
        self.assertEqual(res["applied_baseline_sha256"], AE.canonical_sha256(prop_rm))
        # Now Owner 2 is properly rejected as signer_not_owner!
        with self.assertRaises(AE.TrustRootError) as ctx_o2:
            reopened_enf.process_enrollment(
                self.make_revocation_bytes(grant_id="any-g", generation=1, owner_seed=SEED_OWNER2, owner_key=KEY_OWNER2),
                now_utc=T0,
            )
        self.assertEqual(ctx_o2.exception.code, "signer_not_owner")

    def test_r3_codex2_recover_after_store_loss_requires_voided_and_no_pending_actuation(self) -> None:
        # 1. Healthy store (voided=False) -> refused with store_not_voided, protected bytes bit-for-bit untouched!
        cur_path = self.store.current_store_path
        assert cur_path is not None
        bytes_before = cur_path.read_bytes()
        anchor_before = self.anchor.read()
        writes_before = self.store.write_count
        with self.assertRaises(AE.ReplayError) as ctx_nv:
            self.store.recover_after_store_loss(baseline_goal=self.baseline)
        self.assertEqual(ctx_nv.exception.code, "store_not_voided")
        self.assertEqual(cur_path.read_bytes(), bytes_before)
        self.assertEqual(self.anchor.read(), anchor_before)
        self.assertEqual(self.store.write_count, writes_before)

        # 2. Store with pending_actuation -> refused with pending_actuation_unreconciled, bytes untouched!
        enf_crash = AE.ApprovalEnforcer(
            KEY_HOST, self.store, apply_callback=lambda _g: (_ for _ in ()).throw(RuntimeError("uncertain"))
        )
        _, nonce, _ = self.enroll_active(grant_id="rec-pa", mode="standing-approval", enforcer=enf_crash)
        prop, diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.recpa")
        app = self.make_app_bytes(
            grant_id="rec-pa", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop
        )
        with self.assertRaises(RuntimeError):
            enf_crash.process_standing_application(app, proposed_goal=prop, diff=diff, now_utc=T0)

        pa_path = self.store.current_store_path
        assert pa_path is not None
        pa_bytes_before = pa_path.read_bytes()
        pa_anchor_before = self.anchor.read()
        pa_writes_before = self.store.write_count
        with self.assertRaises(AE.ReplayError) as ctx_pa:
            self.store.recover_after_store_loss(baseline_goal=self.baseline)
        self.assertEqual(ctx_pa.exception.code, "pending_actuation_unreconciled")
        self.assertEqual(pa_path.read_bytes(), pa_bytes_before)
        self.assertEqual(self.anchor.read(), pa_anchor_before)
        self.assertEqual(self.store.write_count, pa_writes_before)

    def test_r3_codex3_stale_actuation_id_cannot_resolve_successor_pending_actuation(self) -> None:
        # Two sequential uncertain actuations for the EXACT SAME proposed_sha256 (e.g. retried with seq 1 then seq 2):
        # Worker A reads act_id_1; Worker B reconciles act_id_1 (aborted); seq 2 becomes pending with act_id_2;
        # Worker A's stale answer for act_id_1 MUST be refused and leave act_id_2 untouched!
        enf = AE.ApprovalEnforcer(
            KEY_HOST, self.store, apply_callback=lambda _g: (_ for _ in ()).throw(TimeoutError("uncertain"))
        )
        _, nonce, _ = self.enroll_active(grant_id="id-bind", mode="standing-approval", enforcer=enf)
        prop, diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.sameprop")

        app1 = self.make_app_bytes(
            grant_id="id-bind", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop
        )
        with self.assertRaises(TimeoutError):
            enf.process_standing_application(app1, proposed_goal=prop, diff=diff, now_utc=T0)
        act_id_1 = self.store.snapshot()["pending_actuation"]["actuation_id"]

        # Worker B resolves intent #1 as aborted.
        enf.reconcile_pending_actuation(act_id_1, applied_on_device=False)

        # Intent #2 arrives for the SAME proposed_sha256 -> gets distinct act_id_2!
        app2 = self.make_app_bytes(
            grant_id="id-bind", generation=1, application_seq=2, enrollment_nonce=nonce, proposed=prop
        )
        with self.assertRaises(TimeoutError):
            enf.process_standing_application(app2, proposed_goal=prop, diff=diff, now_utc=T0)
        act_id_2 = self.store.snapshot()["pending_actuation"]["actuation_id"]
        self.assertNotEqual(act_id_1, act_id_2)

        # Non-ASCII / malformed actuation_id raises MalformedRecordError (never TypeError from hmac.compare_digest)!
        for bad_aid in ("not-hex", "caf\u00e9" + "0" * 28, "A" * 32, "0" * 31):
            with self.assertRaises(AE.MalformedRecordError) as ctx_bad_aid:
                enf.reconcile_pending_actuation(bad_aid, applied_on_device=True)
            self.assertEqual(ctx_bad_aid.exception.code, "invalid_actuation_id")

        # Delayed Worker A sends stale act_id_1 -> REFUSED with actuation_id_mismatch; act_id_2 remains pending!
        writes_before = self.store.write_count
        with self.assertRaises(AE.ReplayError) as ctx_stale:
            enf.reconcile_pending_actuation(act_id_1, applied_on_device=True)
        self.assertEqual(ctx_stale.exception.code, "actuation_id_mismatch")
        self.assertEqual(self.store.write_count, writes_before)
        cur_pa = self.store.snapshot()["pending_actuation"]
        self.assertIsNotNone(cur_pa)
        self.assertEqual(cur_pa["actuation_id"], act_id_2)
        self.assertEqual(AE.canonical_sha256(enf.baseline_goal), AE.canonical_sha256(self.baseline))

        # Reconciling with the exact successor act_id_2 succeeds!
        res2 = enf.reconcile_pending_actuation(act_id_2, applied_on_device=True)
        self.assertEqual(res2["status"], "promoted")
        self.assertEqual(res2["actuation_id"], act_id_2)
        self.assertIsNone(self.store.snapshot()["pending_actuation"])

    def test_r3_codex4_expired_indicator_refused_during_actuation_callback(self) -> None:
        raw_dev, _, _ = self.enroll_active(
            grant_id="dev-cb-exp", covered_signers=[KEY_DEV], developer_mode=True, not_after=T_EXP, now_utc=T0
        )
        _, sa_nonce, _ = self.enroll_active(grant_id="sa-cb", mode="standing-approval", now_utc=T0)

        # Option B identical redelivery of live grant remains strictly zero-write.
        w0 = self.store.write_count
        self.enforcer.process_enrollment(raw_dev, now_utc=T0)
        self.assertEqual(self.store.write_count, w0)

        cb_results: list[Any] = []

        def indicator_cb(_goal: dict[str, Any]) -> None:
            # Non-expired query succeeds read-only during callback.
            cb_results.append(("live", self.enforcer.developer_mode_indicator_active(T0)))
            # Expired query MUST fail closed rather than exposing an unpersisted expiry observation!
            with self.assertRaises(AE.ReplayError) as ctx_exp:
                self.enforcer.developer_mode_indicator_active(T_AFTER_EXP)
            cb_results.append(("expired_err", ctx_exp.exception.code))

        enf_cb = AE.ApprovalEnforcer(KEY_HOST, self.store, apply_callback=indicator_cb)
        prop, diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.indcb")
        app = self.make_app_bytes(
            grant_id="sa-cb", generation=1, application_seq=1, enrollment_nonce=sa_nonce, proposed=prop
        )
        res = enf_cb.process_standing_application(app, proposed_goal=prop, diff=diff, now_utc=T0)
        self.assertEqual(res.decision, "applied")
        self.assertEqual(
            cb_results,
            [("live", True), ("expired_err", "expiry_observation_during_actuation")],
        )

    def test_r3_codex5_readoption_non_hold_reject_and_withdraw_require_proposal(self) -> None:
        prop_up = pure_version_bump_migrate(self.baseline, 10)
        diff_up = AE.compute_authoritative_diff(self.baseline, prop_up, KEY_HOST)

        for idx, verdict in enumerate(("reject", "withdraw")):
            with self.subTest(verdict=verdict):
                pc_n = self.enforcer.issue_per_change_nonce(
                    proposed_sha256=AE.canonical_sha256(prop_up), ceremony_class="baseline", now_utc=T0
                )
                rec: dict[str, Any] = {
                    "schema_version": 9,
                    "record_kind": "per-change",
                    "host": KEY_HOST,
                    "signer": KEY_OWNER,
                    "sig_alg": "ed25519",
                    "baseline_sha256": AE.canonical_sha256(self.baseline),
                    "proposed_sha256": AE.canonical_sha256(prop_up),
                    "nonce": pc_n,
                    "approval_seq": idx,
                    "verdict": verdict,
                    "ceremony_class": "baseline",
                }
                if verdict == "reject":
                    rec["refused"] = ["schema_version"]
                raw = sign_json(rec, SEED_OWNER)
                seq_before = self.store.snapshot()["approval_seq"]

                # Missing proposed_goal with is_readoption=True + version_bump diff -> refused BEFORE nonce/seq!
                with self.assertRaises(AE.MalformedRecordError) as ctx_ra:
                    self.enforcer.process_per_change(
                        raw, proposed_goal=None, diff=diff_up, is_readoption=True, now_utc=T0
                    )
                self.assertEqual(ctx_ra.exception.code, "readoption_requires_proposal")
                self.assertIn(pc_n, self.store.snapshot()["outstanding_nonces"])
                self.assertEqual(self.store.snapshot()["approval_seq"], seq_before)

                # With valid proposed_goal -> succeeds cleanly!
                res = self.enforcer.process_per_change(
                    raw, proposed_goal=prop_up, diff=diff_up, is_readoption=True, now_utc=T0
                )
                self.assertEqual(res.decision, "rejected" if verdict == "reject" else "withdrawn")

    def test_r4_bot_p1_standing_migration_adding_service_content_refused(self) -> None:
        # P1 (4709811340): per schema/goal-diff.schema.json:29, a standalone version_bump
        # migration is valid ONLY when migrated baseline differs in schema_version only.
        # Even if migrate_fn preserves device-trust identically, adding a service requires re-adoption!
        _, base_nonce, _ = self.enroll_active(grant_id="mig-add-g", grant_class="baseline")

        def migrate_adding_service(doc: dict[str, Any], target_ver: int) -> dict[str, Any]:
            out = copy.deepcopy(doc)
            out["schema_version"] = target_ver
            out["domains"]["supervision"] = {
                "coverage": "comprehensive",
                "entries": {
                    "service": {
                        "com.tendcf.smuggled.svc": {
                            "bundle": "demo",
                            "command": ["/usr/bin/true"],
                            "run_as": "nobody",
                            "state": "present",
                            "unit": {"launchd": {"domain": "system", "keep_alive": False, "run_at_load": True}},
                            "working_dir": "/",
                        }
                    }
                },
            }
            return out

        prop_smug = migrate_adding_service(self.baseline, 10)
        diff_smug = AE.compute_authoritative_diff(self.baseline, prop_smug, KEY_HOST)
        app_smug = self.make_app_bytes(
            grant_id="mig-add-g",
            generation=1,
            application_seq=1,
            enrollment_nonce=base_nonce,
            proposed=prop_smug,
            ceremony_class="baseline",
        )
        with self.assertRaises(AE.ScopeError) as ctx_add:
            self.enforcer.process_standing_application(
                app_smug,
                proposed_goal=prop_smug,
                diff=diff_smug,
                now_utc=T0,
                migrate_fn=migrate_adding_service,
                device_trust_comparable=True,
            )
        self.assertEqual(ctx_add.exception.code, "migration_adds_or_changes_content")
        self.assertEqual(self.store.snapshot()["grants"]["mig-add-g"]["application_seq_mark"], 0)

    def test_r4_bot_p2_indicator_advances_utc_watermark_before_expiry_and_flushes_from_callback(self) -> None:
        # P2 (4709811350): Enrolling at 12:00 (expiry 12:10), reading indicator at 12:09
        # (still live!), then rolling clock back to 12:01 MUST fail closed with utc_clock_rollback!
        t_1200 = datetime.datetime(2026, 11, 26, 12, 0, 0, tzinfo=datetime.timezone.utc)
        t_1201 = datetime.datetime(2026, 11, 26, 12, 1, 0, tzinfo=datetime.timezone.utc)
        t_1209 = datetime.datetime(2026, 11, 26, 12, 9, 0, tzinfo=datetime.timezone.utc)
        t_1210_str = "2026-11-26T12:10:00Z"

        raw_dev, dev_nonce, _ = self.enroll_active(
            grant_id="dev-wm",
            covered_signers=[KEY_DEV],
            developer_mode=True,
            not_after=t_1210_str,
            now_utc=t_1200,
        )
        # Option B identical redelivery remains strictly zero-write!
        w_optb = self.store.write_count
        self.enforcer.process_enrollment(raw_dev, now_utc=t_1200)
        self.assertEqual(self.store.write_count, w_optb)

        # Read indicator at 12:09 (before 12:10 expiry): still True AND durably advances last_seen_utc to 12:09!
        self.assertTrue(self.enforcer.developer_mode_indicator_active(t_1209))
        self.assertEqual(self.store.snapshot()["last_seen_utc"], "2026-11-26T12:09:00Z")

        # Rolling clock back to 12:01 (even though > 12:00 enroll and < 12:10 expiry) MUST fail closed!
        prop1, diff1 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.wm1")
        app1 = self.make_app_bytes(
            grant_id="dev-wm",
            generation=1,
            application_seq=1,
            enrollment_nonce=dev_nonce,
            proposed=prop1,
            signer_seed=SEED_DEV,
            signer_key=KEY_DEV,
        )
        with self.assertRaises(AE.ClockRollbackError) as ctx_rb:
            self.enforcer.process_standing_application(
                app1, proposed_goal=prop1, diff=diff1, now_utc=t_1201
            )
        self.assertEqual(ctx_rb.exception.code, "utc_clock_rollback")

        # (2) Inside _apply_callback at same UTC (12:09 == prev_last_dt, non-expired):
        #     read-only indicator succeeds without mutating or deadlocking!
        cb_same_seen: list[bool] = []

        def same_utc_ind_cb(_goal: dict[str, Any]) -> None:
            cb_same_seen.append(self.enforcer.developer_mode_indicator_active(t_1209))

        enf_same = AE.ApprovalEnforcer(KEY_HOST, self.store, apply_callback=same_utc_ind_cb)
        res_same = enf_same.process_standing_application(
            app1, proposed_goal=prop1, diff=diff1, now_utc=t_1209
        )
        self.assertEqual(res_same.decision, "applied")
        self.assertEqual(cb_same_seen, [True])

        # (3) Codex R5 #1: Inside _apply_callback at forward UTC (12:09:30 > 12:09:00):
        #     MUST refuse with ReplayError("time_advance_during_actuation") so an interrupted
        #     callback + reopen + reconcile can NEVER lose an exposed forward UTC observation!
        t_120930 = datetime.datetime(2026, 11, 26, 12, 9, 30, tzinfo=datetime.timezone.utc)
        prop2, diff2 = make_ordinary_service_change(prop1, service_id="com.tendcf.wm2")
        app2 = self.make_app_bytes(
            grant_id="dev-wm",
            generation=1,
            application_seq=2,
            enrollment_nonce=dev_nonce,
            baseline=prop1,
            proposed=prop2,
            signer_seed=SEED_DEV,
            signer_key=KEY_DEV,
        )

        def forward_ind_cb(_goal: dict[str, Any]) -> None:
            self.enforcer.developer_mode_indicator_active(t_120930)

        enf_fwd = AE.ApprovalEnforcer(KEY_HOST, self.store, apply_callback=forward_ind_cb)
        with self.assertRaises(AE.ReplayError) as ctx_fwd:
            enf_fwd.process_standing_application(app2, proposed_goal=prop2, diff=diff2, now_utc=t_1209)
        self.assertEqual(ctx_fwd.exception.code, "time_advance_during_actuation")
        # Pending actuation stays persisted for reconciliation, and no unpersisted forward UTC was exposed!
        snap_fwd = self.store.snapshot()
        self.assertIsNotNone(snap_fwd["pending_actuation"])
        self.assertEqual(snap_fwd["last_seen_utc"], "2026-11-26T12:09:00Z")
        enf_fwd.reconcile_pending_actuation(
            snap_fwd["pending_actuation"]["actuation_id"], applied_on_device=False
        )


if __name__ == "__main__":
    unittest.main()
