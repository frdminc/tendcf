"""Comprehensive pure-stdlib tests for bin/approval_enforce.py (issue #76).

Runs under `python3 -I -S -m unittest discover -s tests/approval -v` with zero
third-party packages, proving bare-host stdlib execution parity alongside
`tests/projector`.

Covers:
  - Section 0: Official RFC 8032 §7.1 Ed25519 test vectors, strict canonical
    S / R / A rejection, schema_version floor == ceiling == 9, strict JSON.
  - Section A (Items 1-7 + PR #75 R4 #1 + Astra Option B): rollback-protected
    durable replay store, partial restore, nonce binding, R10 enrollment_nonce,
    baseline_sha256, monotonic application_seq + crash-before/after-commit,
    Option B zero-write idempotent redelivery + equivocation + concurrent race,
    terminal revocation & tombstone persistence across reload.
  - Section B (Items 8-12): baseline-only signer roles, no owner/covered-signer
    crossover, developer_mode scoping & persistent indicator, host-key bans,
    sig_alg/prefix binding, cryptographic nonce entropy & post-loss uniqueness.
  - Section C (Items 13-16 + PR #75 R4 #4): R1/R7 default-deny device-trust
    carve-out + replay store carve-out, per-hunk & per-coverage-change derived
    class, empty-domain transitions, migrations / downward version_bump refusal
    for both standing-application and per-change / re-adoption, R9 briefing.
  - Section D (Items 17-19): not_after strict calendar parsing + no horizon cap
    + clock rollback, hold-window monotonic clock + re-evaluation + owner reject
    override + revocation cancel, covering-grant precedence & DC-2 rejects.
  - Section E (Items 20-26 + PR #75 R4 #2): generation, covered_signers, R6
    developer_mode ceremony, exact ceremony_class, per-target host, exact
    proposed_sha256 binding, full check-order-before-mark invariant.
"""

from __future__ import annotations

import base64
import copy
import datetime
import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
ENFORCE_PATH = REPO / "bin" / "approval_enforce.py"


def _load_enforce():
    spec = importlib.util.spec_from_file_location("tendcf_approval_enforce_under_test", ENFORCE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


AE = _load_enforce()


# Deterministic 32-byte test seeds (purely synthetic test fixtures).
SEED_HOST = bytes([0x11]) * 32
SEED_OTHER_HOST = bytes([0x22]) * 32
SEED_OWNER = bytes([0x33]) * 32
SEED_OWNER2 = bytes([0x44]) * 32
SEED_COVERED = bytes([0x55]) * 32
SEED_COVERED2 = bytes([0x66]) * 32
SEED_DEV = bytes([0x77]) * 32
SEED_ATTACKER = bytes([0x88]) * 32

KEY_HOST = AE.key_id_from_pubkey(AE.ed25519_public_key_from_seed(SEED_HOST))
KEY_OTHER_HOST = AE.key_id_from_pubkey(AE.ed25519_public_key_from_seed(SEED_OTHER_HOST))
KEY_OWNER = AE.key_id_from_pubkey(AE.ed25519_public_key_from_seed(SEED_OWNER))
KEY_OWNER2 = AE.key_id_from_pubkey(AE.ed25519_public_key_from_seed(SEED_OWNER2))
KEY_COVERED = AE.key_id_from_pubkey(AE.ed25519_public_key_from_seed(SEED_COVERED))
KEY_COVERED2 = AE.key_id_from_pubkey(AE.ed25519_public_key_from_seed(SEED_COVERED2))
KEY_DEV = AE.key_id_from_pubkey(AE.ed25519_public_key_from_seed(SEED_DEV))
KEY_ATTACKER = AE.key_id_from_pubkey(AE.ed25519_public_key_from_seed(SEED_ATTACKER))

T0 = datetime.datetime(2026, 11, 26, 12, 0, 0, tzinfo=datetime.timezone.utc)
T1 = datetime.datetime(2026, 11, 26, 12, 5, 0, tzinfo=datetime.timezone.utc)
T_EXP = "2027-12-31T23:59:59Z"
T_AFTER_EXP = datetime.datetime(2028, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)


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


def sign_json(record_without_sig: dict[str, Any], seed: bytes) -> bytes:
    signed = AE.sign_approval_record(record_without_sig, seed)
    return AE.jcs_dumps(signed)


class _EnforcerTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.baseline = make_baseline_goal()
        self.anchor = AE.InMemoryRollbackAnchor()
        self.store_path = self.tmp / "replay-store.json"
        self.store = AE.ReplayStore(self.store_path, KEY_HOST, anchor=self.anchor)
        self.enforcer = AE.ApprovalEnforcer(KEY_HOST, self.store, self.baseline)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

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
# Section 0: RFC 8032 §7.1 Ed25519 Test Vectors & Canonical Encoding Rules
# ===========================================================================

class TestSection0Ed25519AndStrictParsing(unittest.TestCase):
    def test_rfc8032_section7_1_official_vectors(self) -> None:
        # Official RFC 8032 §7.1 vectors: TEST 1, TEST 2, TEST 3, TEST SHA(abc), TEST 1024
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
                self.assertEqual(AE.ed25519_public_key_from_seed(sk), pk)
                self.assertEqual(AE.ed25519_sign(sk, msg), sig)
                self.assertTrue(AE.verify_ed25519(pk, msg, sig))
                # Bit flip in signature fails verification.
                bad_sig = bytearray(sig)
                bad_sig[0] ^= 0x01
                self.assertFalse(AE.verify_ed25519(pk, msg, bytes(bad_sig)))

    def test_ed25519_rejects_noncanonical_S_R_and_A(self) -> None:
        sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pk = AE.ed25519_public_key_from_seed(sk)
        msg = b"tendcf-canonical-ed25519"
        sig = AE.ed25519_sign(sk, msg)
        self.assertTrue(AE.verify_ed25519(pk, msg, sig))

        # 1. Malleated S >= L (S + L) must be rejected even though [S+L]B == [S]B.
        s_val = int.from_bytes(sig[32:], "little")
        malleated_s = (s_val + AE.ED25519_L).to_bytes(32, "little")
        self.assertFalse(AE.verify_ed25519(pk, msg, sig[:32] + malleated_s))
        self.assertFalse(AE.verify_ed25519(pk, msg, sig[:32] + AE.ED25519_L.to_bytes(32, "little")))

        # 2. Non-canonical y >= p (y = p and y = p + 1) must fail point decoding.
        noncanon_y_p = AE.ED25519_P.to_bytes(32, "little")
        noncanon_y_p1 = (AE.ED25519_P + 1).to_bytes(32, "little")
        self.assertIsNone(AE.ed25519_decompress_point(noncanon_y_p))
        self.assertIsNone(AE.ed25519_decompress_point(noncanon_y_p1))
        self.assertFalse(AE.verify_ed25519(noncanon_y_p, msg, sig))
        self.assertFalse(AE.verify_ed25519(pk, msg, noncanon_y_p + sig[32:]))

        # 3. Non-canonical x == 0 with sign_bit == 1 (for y = 1 and y = p - 1).
        neg_zero_1 = (1 | (1 << 255)).to_bytes(32, "little")
        neg_zero_pm1 = ((AE.ED25519_P - 1) | (1 << 255)).to_bytes(32, "little")
        self.assertIsNone(AE.ed25519_decompress_point(neg_zero_1))
        self.assertIsNone(AE.ed25519_decompress_point(neg_zero_pm1))
        # Canonical neutral point (y=1, sign=0) decodes, while sign=1 fails.
        neutral_bytes = (1).to_bytes(32, "little")
        self.assertIsNotNone(AE.ed25519_decompress_point(neutral_bytes))
        self.assertFalse(AE.verify_ed25519(neg_zero_1, msg, sig))
        self.assertFalse(AE.verify_ed25519(pk, msg, neg_zero_1 + sig[32:]))

        # 4. Small-order public key (identity point A=(0,1), R=(0,1), S=0) MUST be rejected!
        zero_s = (0).to_bytes(32, "little")
        self.assertFalse(AE.verify_ed25519(neutral_bytes, msg, neutral_bytes + zero_s))

    def test_schema_version_floor_equals_ceiling_and_strict_json(self) -> None:
        # Duplicate keys rejected before JCS.
        dup = b'{"schema_version":9,"schema_version":9}'
        with self.assertRaises(AE.MalformedRecordError) as ctx:
            AE.parse_strict_json(dup)
        self.assertEqual(ctx.exception.code, "duplicate_or_invalid_json")

        # Non-NFC string rejected (e + combining acute accent U+0301).
        nfd = '{"note":"cafe\u0301"}'.encode("utf-8")
        with self.assertRaises(AE.MalformedRecordError) as ctx2:
            AE.parse_strict_json(nfd)
        self.assertEqual(ctx2.exception.code, "non_nfc_string")

        # Floor == ceiling == 9 (8, 10, and bool True refused).
        for bad_ver in (7, 8, 10, True, "9"):
            with self.assertRaises(AE.MalformedRecordError) as ctx3:
                AE.validate_approval_record_shape({"schema_version": bad_ver})
            self.assertEqual(ctx3.exception.code, "unsupported_schema_version")


# ===========================================================================
# Section A: State, Replay and Freshness (Items 1-7 + R4 #1 + Option B)
# ===========================================================================

class TestSectionAStateReplayAndFreshness(_EnforcerTestBase):
    def test_item01_rollback_store_loss_corrupt_partial_restore_voids_grants(self) -> None:
        # Enroll active grant and capture pre-revocation snapshot (tombstone-free).
        raw_enroll, nonce1, _ = self.enroll_active(grant_id="grant-a")
        pre_revoke_bytes = self.store_path.read_bytes()

        # Issue another nonce and revoke grant-a -> tombstone created, anchor advances.
        _unused_nonce = self.enforcer.issue_per_change_nonce(
            proposed_sha256="sha256:" + "ab" * 32, ceremony_class="ordinary", now_utc=T0
        )
        rev_bytes = self.make_revocation_bytes(grant_id="grant-a", generation=2)
        self.enforcer.process_enrollment(rev_bytes, now_utc=T0)

        # Case 1a: Restore tombstone-free copy (partial/full rollback) -> fail closed, voids everything!
        self.store_path.write_bytes(pre_revoke_bytes)
        proposed, diff = make_ordinary_service_change(self.baseline)
        app = self.make_app_bytes(
            grant_id="grant-a", generation=1, application_seq=1, enrollment_nonce=nonce1, proposed=proposed
        )
        with self.assertRaises(AE.StoreRollbackError) as ctx:
            self.enforcer.process_standing_application(
                app, proposed_goal=proposed, diff=diff, now_utc=T0, now_mono=10.0
            )
        self.assertEqual(ctx.exception.code, "store_rollback_detected")
        # Subsequent retry stays voided even without further tampering.
        with self.assertRaises(AE.StoreRollbackError) as ctx2:
            self.enforcer.process_standing_application(
                app, proposed_goal=proposed, diff=diff, now_utc=T0, now_mono=11.0
            )
        self.assertEqual(ctx2.exception.code, "store_voided")

        # Recover cleanly, enroll grant-b, then test partial restore of ONLY outstanding_nonces.
        self.store.recover_after_store_loss()
        _, nonce_b, _ = self.enroll_active(grant_id="grant-b")
        cur_doc = json.loads(self.store_path.read_text())
        cur_doc["outstanding_nonces"]["forged-restored-nonce-000000"] = {"record_kind": "per-change"}
        self.store_path.write_bytes(AE.jcs_dumps(cur_doc))
        with self.assertRaises(AE.StoreRollbackError):
            self.enforcer.process_enrollment(raw_enroll, now_utc=T0)

        # Case 1b: Store file deleted while rollback anchor exists -> fail closed.
        self.store.recover_after_store_loss()
        self.enroll_active(grant_id="grant-c")
        self.store_path.unlink()
        with self.assertRaises(AE.StoreRollbackError) as ctx3:
            self.enforcer.process_enrollment(raw_enroll, now_utc=T0)
        self.assertEqual(ctx3.exception.code, "store_missing_rollback")

        # Case 1c: Store file truncated/corrupted -> fail closed.
        self.store.recover_after_store_loss()
        self.enroll_active(grant_id="grant-d")
        self.store_path.write_bytes(b'{"store_version":1,"truncated":')
        with self.assertRaises(AE.StoreRollbackError) as ctx4:
            self.enforcer.process_enrollment(raw_enroll, now_utc=T0)
        self.assertEqual(ctx4.exception.code, "store_corrupt")

        # Case 1d: FileRollbackAnchor detects rollback across fresh ReplayStore instance.
        file_anchor_path = self.tmp / "separate.anchor"
        file_store_path = self.tmp / "file-backed-store.json"
        anchor_fs = AE.FileRollbackAnchor(file_anchor_path)
        store_fs = AE.ReplayStore(file_store_path, KEY_HOST, anchor=anchor_fs)
        enf_fs = AE.ApprovalEnforcer(KEY_HOST, store_fs, self.baseline)
        self.enroll_active(grant_id="grant-fs", enforcer=enf_fs)
        backup_fs = file_store_path.read_bytes()
        enf_fs.process_enrollment(self.make_revocation_bytes(grant_id="grant-fs", generation=2), now_utc=T0)
        file_store_path.write_bytes(backup_fs)
        reloaded_store = AE.ReplayStore(file_store_path, KEY_HOST, anchor=AE.FileRollbackAnchor(file_anchor_path))
        with self.assertRaises(AE.StoreRollbackError):
            reloaded_store.snapshot(allow_voided=False)

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

        # 2. A developer-mode enrollment carrying a nonce from an ordinary non-developer ceremony -> refused.
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
        dev_rec = dict(rec, grant_id="dev-grant", nonce=ord_nonce, covered_signers=[KEY_DEV], **{"class": "ordinary", "developer_mode": True})
        with self.assertRaises(AE.NonceError):
            self.enforcer.process_enrollment(sign_json(dev_rec, SEED_OWNER), now_utc=T0)

        # 3. Scope differs from shown scope on EVERY field (mode, covered_signers, class, hold_seconds, not_after, grant_id).
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

        # 4. Single-use consumption: reusing a consumed nonce on generation 2 is refused.
        _, used_nonce, _ = self.enroll_active(grant_id="single-use", generation=1)
        gen2_reuse = {
            "schema_version": 9,
            "record_kind": "standing-enrollment",
            "host": KEY_HOST,
            "signer": KEY_OWNER,
            "sig_alg": "ed25519",
            "grant_id": "single-use",
            "generation": 2,
            "grant_state": "active",
            "nonce": used_nonce,
            "mode": "standing-approval",
            "covered_signers": [KEY_COVERED],
            "class": "ordinary",
            "developer_mode": False,
            "not_after": T_EXP,
        }
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
        self.store_path.unlink()
        with self.assertRaises(AE.StoreRollbackError):
            self.store.snapshot(allow_voided=False)
        self.store.recover_after_store_loss()
        _, new_nonce, _ = self.enroll_active(grant_id="reborn", generation=1)
        self.assertNotEqual(old_nonce, new_nonce)

        # Old application (same grant_id, same generation 1, seq 1 > 0, WRONG enrollment_nonce) REFUSED!
        with self.assertRaises(AE.NonceError) as ctx:
            self.enforcer.process_standing_application(
                old_app, proposed_goal=proposed, diff=diff, now_utc=T0, now_mono=10.0
            )
        self.assertEqual(ctx.exception.code, "enrollment_nonce_mismatch")

        # Application bound to the new enrollment_nonce succeeds.
        new_app = self.make_app_bytes(
            grant_id="reborn", generation=1, application_seq=1, enrollment_nonce=new_nonce, proposed=proposed
        )
        res = self.enforcer.process_standing_application(
            new_app, proposed_goal=proposed, diff=diff, now_utc=T0, now_mono=11.0
        )
        self.assertEqual(res.decision, "applied")

    def test_item04_baseline_sha256_binding_and_no_first_adoption(self) -> None:
        # 1. First adoption (no applied baseline) is NEVER by standing-application.
        fresh_store = AE.ReplayStore(self.tmp / "first-adopt.json", KEY_HOST, anchor=AE.InMemoryRollbackAnchor())
        fresh_enf = AE.ApprovalEnforcer(KEY_HOST, fresh_store, baseline_goal=None)
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
            fresh_enf.process_standing_application(
                app0, proposed_goal=proposed0, diff=diff0, now_utc=T0, now_mono=1.0
            )
        self.assertEqual(ctx.exception.code, "first_adoption_disallowed")

        # 2. Held-back application released after owner accepted a later change -> refused.
        _, nonce, _ = self.enroll_active(grant_id="ci-bot")
        held_proposed, held_diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.old.svc")
        held_app = self.make_app_bytes(
            grant_id="ci-bot", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=held_proposed
        )

        # Meanwhile, owner accepts a different change advancing baseline.
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

        # Releasing held-back application now fails baseline_sha256 check!
        with self.assertRaises(AE.ReplayError) as ctx2:
            self.enforcer.process_standing_application(
                held_app, proposed_goal=held_proposed, diff=held_diff, now_utc=T0, now_mono=5.0
            )
        self.assertEqual(ctx2.exception.code, "baseline_sha256_mismatch")

    def test_item05_application_seq_monotonic_persist_before_apply_and_hold(self) -> None:
        _, nonce1, _ = self.enroll_active(grant_id="seq-grant", generation=1, mode="standing-approval")
        prop1, diff1 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.svc1")
        app7 = self.make_app_bytes(
            grant_id="seq-grant", generation=1, application_seq=7, enrollment_nonce=nonce1, proposed=prop1
        )

        # Simulate crash AFTER durable persist of application_seq=7 BEFORE actuation.
        class _Crash(RuntimeError):
            pass

        def crash_before_apply() -> None:
            raise _Crash("power loss after durable mark write")

        with self.assertRaises(_Crash):
            self.enforcer.process_standing_application(
                app7,
                proposed_goal=prop1,
                diff=diff1,
                now_utc=T0,
                now_mono=10.0,
                before_apply_hook=crash_before_apply,
            )
        # Baseline NOT updated, actuation did NOT run, mark IS durably 7!
        self.assertEqual(self.enforcer.actuation_count, 0)
        self.assertEqual(self.store.snapshot()["grants"]["seq-grant"]["application_seq_mark"], 7)

        # Replaying application_seq=7 is REFUSED (no double-apply on crash recovery).
        with self.assertRaises(AE.ReplayError) as ctx:
            self.enforcer.process_standing_application(
                app7, proposed_goal=prop1, diff=diff1, now_utc=T0, now_mono=11.0
            )
        self.assertEqual(ctx.exception.code, "stale_application_seq")

        # Re-enroll at generation 2 -> mark MUST NOT decrease across generations!
        _, nonce2, _ = self.enroll_active(grant_id="seq-grant", generation=2, mode="hold-window", hold_seconds=60)
        self.assertEqual(self.store.snapshot()["grants"]["seq-grant"]["application_seq_mark"], 7)
        app7_gen2 = self.make_app_bytes(
            grant_id="seq-grant", generation=2, application_seq=7, enrollment_nonce=nonce2, proposed=prop1
        )
        with self.assertRaises(AE.ReplayError):
            self.enforcer.process_standing_application(
                app7_gen2, proposed_goal=prop1, diff=diff1, now_utc=T0, now_mono=12.0
            )

        # application_seq=8 on hold-window grant persists mark=8 AT INTAKE before hold elapses.
        app8_gen2 = self.make_app_bytes(
            grant_id="seq-grant", generation=2, application_seq=8, enrollment_nonce=nonce2, proposed=prop1
        )
        res = self.enforcer.process_standing_application(
            app8_gen2, proposed_goal=prop1, diff=diff1, now_utc=T0, now_mono=15.0
        )
        self.assertEqual(res.decision, "held")
        self.assertEqual(self.store.snapshot()["grants"]["seq-grant"]["application_seq_mark"], 8)

        # application_seq > 2^53 - 1 refused.
        bad_seq_rec = {
            "schema_version": 9,
            "record_kind": "standing-application",
            "host": KEY_HOST,
            "signer": KEY_COVERED,
            "sig_alg": "ed25519",
            "grant_id": "seq-grant",
            "generation": 2,
            "application_seq": AE.MAX_SAFE_INT + 1,
            "enrollment_nonce": nonce2,
            "baseline_sha256": AE.canonical_sha256(self.baseline),
            "proposed_sha256": AE.canonical_sha256(prop1),
            "ceremony_class": "ordinary",
            "signature": "ed25519-sig:" + "00" * 64,
        }
        with self.assertRaises(AE.MalformedRecordError):
            AE.validate_approval_record_shape(bad_seq_rec)

    def test_item06_option_b_identical_redelivery_zero_writes_and_equivocation(self) -> None:
        raw_enroll, nonce1, receipt1 = self.enroll_active(
            grant_id="optb-grant", generation=1, mode="hold-window", hold_seconds=300
        )
        # Apply seq 7 into a pending hold so state has both mark=7 and an active pending hold.
        prop1, diff1 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.optb")
        app7 = self.make_app_bytes(
            grant_id="optb-grant", generation=1, application_seq=7, enrollment_nonce=nonce1, proposed=prop1
        )
        hold_res = self.enforcer.process_standing_application(
            app7, proposed_goal=prop1, diff=diff1, now_utc=T0, now_mono=100.0
        )
        self.assertEqual(hold_res.decision, "held")

        # Snapshot full protected state & all counters BEFORE identical redelivery.
        state_before = self.store.snapshot()
        disk_before = self.store_path.read_bytes()
        anchor_before = self.anchor.read()
        writes_before = self.store.write_count
        nonce_consumes_before = self.store.nonce_consume_count
        prompts_before = self.enforcer.prompt_count
        actuations_before = self.enforcer.actuation_count

        # Re-deliver identical enrollment with reordered JSON keys & pretty whitespace!
        parsed = json.loads(raw_enroll)
        reordered_wire = json.dumps(parsed, indent=2, sort_keys=False).encode("utf-8")
        self.assertNotEqual(reordered_wire, raw_enroll)

        receipt2 = self.enforcer.process_enrollment(reordered_wire, now_utc=T1)
        # Same success shape as initial acceptance!
        self.assertEqual(receipt1, receipt2)
        # ZERO writes, ZERO nonce/counter mutation, ZERO prompts, ZERO actuation, ZERO state change!
        self.assertEqual(self.store.write_count, writes_before)
        self.assertEqual(self.store.nonce_consume_count, nonce_consumes_before)
        self.assertEqual(self.enforcer.prompt_count, prompts_before)
        self.assertEqual(self.enforcer.actuation_count, actuations_before)
        self.assertEqual(self.store.snapshot(), state_before)
        self.assertEqual(self.store_path.read_bytes(), disk_before)
        self.assertEqual(self.anchor.read(), anchor_before)

        # Replay of application 7 after redelivery is STILL refused!
        with self.assertRaises(AE.ReplayError) as ctx_rep:
            self.enforcer.process_standing_application(
                app7, proposed_goal=prop1, diff=diff1, now_utc=T1, now_mono=101.0
            )
        self.assertEqual(ctx_rep.exception.code, "stale_application_seq")

        # Equivocation 1: validly re-signed same-generation scope change -> refused!
        equiv_scope = copy.deepcopy(parsed)
        equiv_scope["hold_seconds"] = 1
        with self.assertRaises(AE.ReplayError) as ctx_eq1:
            self.enforcer.process_enrollment(sign_json(equiv_scope, SEED_OWNER), now_utc=T1)
        self.assertEqual(ctx_eq1.exception.code, "enrollment_equivocation")

        # Equivocation 2: validly re-signed same-generation nonce change -> refused!
        equiv_nonce = copy.deepcopy(parsed)
        equiv_nonce["nonce"] = AE.generate_device_nonce()
        with self.assertRaises(AE.ReplayError) as ctx_eq2:
            self.enforcer.process_enrollment(sign_json(equiv_nonce, SEED_OWNER), now_utc=T1)
        self.assertEqual(ctx_eq2.exception.code, "enrollment_equivocation")

        # Refusal checks on identical redelivery:
        # (a) Duplicate JSON keys refused.
        dup_wire = raw_enroll[:-1] + b',"generation":1}'
        with self.assertRaises(AE.MalformedRecordError):
            self.enforcer.process_enrollment(dup_wire, now_utc=T1)

        # (b) Invalid signature refused even though JCS-minus-signature matches!
        bad_sig = copy.deepcopy(parsed)
        bad_sig["signature"] = "ed25519-sig:" + "00" * 64
        with self.assertRaises(AE.SignatureError):
            self.enforcer.process_enrollment(AE.jcs_dumps(bad_sig), now_utc=T1)

        # (c) Expired grant refuses identical redelivery!
        with self.assertRaises(AE.ScopeError) as ctx_exp:
            self.enforcer.process_enrollment(raw_enroll, now_utc=T_AFTER_EXP)
        self.assertEqual(ctx_exp.exception.code, "enrollment_expired")

        # (d) Removed owner in baseline refuses identical redelivery!
        removed_owner_base = copy.deepcopy(self.baseline)
        removed_owner_base["domains"]["device-trust"]["entries"]["advisor-key"][KEY_OWNER]["state"] = "absent"
        self.enforcer.baseline_goal = removed_owner_base
        with self.assertRaises(AE.TrustRootError) as ctx_owner:
            self.enforcer.process_enrollment(raw_enroll, now_utc=T1)
        self.assertEqual(ctx_owner.exception.code, "signer_not_owner")
        self.enforcer.baseline_goal = copy.deepcopy(self.baseline)

        # (e) Missing stored canonical JCS-minus-signature bytes fails closed!
        st = self.store.snapshot()
        st["grants"]["optb-grant"]["active_payload_jcs_b64"] = None
        raw_st = AE.jcs_dumps(st)
        self.store_path.write_bytes(raw_st)
        self.anchor.write(AE.AnchorState(st["store_generation"], AE.hashlib.sha256(raw_st).hexdigest()))
        with self.assertRaises(AE.ReplayError) as ctx_missing:
            self.enforcer.process_enrollment(raw_enroll, now_utc=T1)
        self.assertEqual(ctx_missing.exception.code, "missing_stored_payload")

    def test_item06_option_b_crash_both_sides_of_commit_and_concurrent_race(self) -> None:
        class _SimCrash(RuntimeError):
            pass

        # Prepare enrollment record.
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

        # 1. Crash BEFORE durable commit: no receipt, nonce still outstanding, grant NOT installed.
        writes0 = self.store.write_count
        with self.assertRaises(_SimCrash):
            self.enforcer.process_enrollment(
                raw, now_utc=T0, before_replace_hook=lambda: (_ for _ in ()).throw(_SimCrash("before"))
            )
        self.assertEqual(self.store.write_count, writes0)
        self.assertNotIn("crash-grant", self.store.snapshot()["grants"])
        self.assertIn(nonce, self.store.snapshot()["outstanding_nonces"])

        # 2. Retry succeeds and crashes AFTER durable commit (before receipt reaches sender).
        with self.assertRaises(_SimCrash):
            self.enforcer.process_enrollment(
                raw, now_utc=T0, after_commit_hook=lambda: (_ for _ in ()).throw(_SimCrash("after"))
            )
        writes_after_commit = self.store.write_count
        self.assertEqual(writes_after_commit, writes0 + 1)
        self.assertNotIn(nonce, self.store.snapshot()["outstanding_nonces"])

        # 3. Sender retries (with reordered JSON): hits Option B zero-write receipt path!
        reordered = json.dumps(json.loads(raw), indent=4).encode("utf-8")
        receipt = self.enforcer.process_enrollment(reordered, now_utc=T0)
        self.assertEqual(receipt.status, "accepted")
        self.assertEqual(self.store.write_count, writes_after_commit)

        # 4. Concurrent race of two identical deliveries -> 1 install, 1 nonce consumption, 2 identical receipts!
        nonce_race = self.enforcer.issue_enrollment_nonce(
            grant_id="race-grant",
            mode="standing-approval",
            covered_signers=[KEY_COVERED],
            grant_class="ordinary",
            developer_mode=False,
            ceremony_level="ordinary",
            not_after=T_EXP,
            now_utc=T0,
        )
        race_rec = dict(rec, grant_id="race-grant", nonce=nonce_race)
        race_raw = sign_json(race_rec, SEED_OWNER)
        writes_pre_race = self.store.write_count
        consumes_pre_race = self.store.nonce_consume_count

        barrier = threading.Barrier(2)
        results: list[Any] = []
        errors: list[BaseException] = []

        def worker(payload: bytes) -> None:
            try:
                barrier.wait(timeout=5)
                results.append(self.enforcer.process_enrollment(payload, now_utc=T0))
            except BaseException as exc:
                errors.append(exc)

        t1 = threading.Thread(target=worker, args=(race_raw,))
        t2 = threading.Thread(target=worker, args=(json.dumps(json.loads(race_raw), indent=2).encode("utf-8"),))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])
        self.assertEqual(self.store.write_count, writes_pre_race + 1)
        self.assertEqual(self.store.nonce_consume_count, consumes_pre_race + 1)

    def test_item07_and_r4_01_terminal_revocation_races_and_tombstone_persistence(self) -> None:
        # 1. Revocation before first enrollment (unseen grant_id) creates permanent tombstone.
        unseen_rev = self.make_revocation_bytes(grant_id="pre-tombstoned", generation=1)
        r_unseen = self.enforcer.process_enrollment(unseen_rev, now_utc=T0)
        self.assertEqual(r_unseen.grant_state, "revoked")
        with self.assertRaises(AE.ReplayError) as ctx_pre:
            self.enroll_active(grant_id="pre-tombstoned", generation=2)
        self.assertEqual(ctx_pre.exception.code, "grant_tombstoned")

        # 2. Revocation honoured at LOWER generation (< stored) and SAME generation (wins equivocation).
        raw_g5, nonce_g5, _ = self.enroll_active(grant_id="rev-any-gen", generation=5, mode="hold-window", hold_seconds=600)
        prop, diff = make_ordinary_service_change(self.baseline)
        app = self.make_app_bytes(
            grant_id="rev-any-gen", generation=5, application_seq=1, enrollment_nonce=nonce_g5, proposed=prop
        )
        self.enforcer.process_standing_application(
            app, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=10.0
        )
        self.assertIn(AE.canonical_sha256(prop), self.store.snapshot()["pending_holds"])

        # Non-owner cannot revoke.
        bad_rev = self.make_revocation_bytes(
            grant_id="rev-any-gen", generation=1, owner_seed=SEED_COVERED, owner_key=KEY_COVERED
        )
        with self.assertRaises(AE.TrustRootError):
            self.enforcer.process_enrollment(bad_rev, now_utc=T0)

        # Owner revokes at generation 1 (< stored 5) with NO nonce -> honoured & cancels pending hold!
        rev_low = self.make_revocation_bytes(grant_id="rev-any-gen", generation=1)
        self.enforcer.process_enrollment(rev_low, now_utc=T0)
        self.assertEqual(self.store.snapshot()["pending_holds"], {})

        # Identical redelivery at gen 5 is now REFUSED (tombstoned)!
        with self.assertRaises(AE.ReplayError) as ctx_redel:
            self.enforcer.process_enrollment(raw_g5, now_utc=T0)
        self.assertEqual(ctx_redel.exception.code, "grant_tombstoned")

        # PR #75 R4 #1: Later higher generation (gen 6) active enrollment REFUSED even after reload!
        reloaded_store = AE.ReplayStore(self.store_path, KEY_HOST, anchor=self.anchor)
        reloaded_enf = AE.ApprovalEnforcer(KEY_HOST, reloaded_store, self.baseline)
        with self.assertRaises(AE.ReplayError) as ctx_reopen:
            self.enroll_active(grant_id="rev-any-gen", generation=6, enforcer=reloaded_enf)
        self.assertEqual(ctx_reopen.exception.code, "grant_tombstoned")

        # 3. Equivocation at exact same generation: revocation wins over active!
        raw_eq, _, _ = self.enroll_active(grant_id="eq-rev", generation=3)
        rev_same = self.make_revocation_bytes(grant_id="eq-rev", generation=3)
        self.enforcer.process_enrollment(rev_same, now_utc=T0)
        with self.assertRaises(AE.ReplayError):
            self.enforcer.process_enrollment(raw_eq, now_utc=T0)

        # 4. Race duplicate active delivery vs revocation in BOTH commit orders:
        #    Order A: active commits first, then revocation commits -> afterwards
        #    identical and higher-generation active records are both refused!
        raw_ord_a, _, _ = self.enroll_active(grant_id="race-rev-a", generation=1)
        rev_ord_a = self.make_revocation_bytes(grant_id="race-rev-a", generation=1)
        self.enforcer.process_enrollment(rev_ord_a, now_utc=T0)
        with self.assertRaises(AE.ReplayError):
            self.enforcer.process_enrollment(raw_ord_a, now_utc=T0)
        with self.assertRaises(AE.ReplayError):
            self.enroll_active(grant_id="race-rev-a", generation=2)

        #    Order B: revocation commits first -> identical and higher-generation active refused!
        nonce_b = self.enforcer.issue_enrollment_nonce(
            grant_id="race-rev-b",
            mode="standing-approval",
            covered_signers=[KEY_COVERED],
            grant_class="ordinary",
            developer_mode=False,
            ceremony_level="ordinary",
            not_after=T_EXP,
            now_utc=T0,
        )
        raw_ord_b = sign_json(
            {
                "schema_version": 9,
                "record_kind": "standing-enrollment",
                "host": KEY_HOST,
                "signer": KEY_OWNER,
                "sig_alg": "ed25519",
                "grant_id": "race-rev-b",
                "generation": 1,
                "grant_state": "active",
                "nonce": nonce_b,
                "mode": "standing-approval",
                "covered_signers": [KEY_COVERED],
                "class": "ordinary",
                "developer_mode": False,
                "not_after": T_EXP,
            },
            SEED_OWNER,
        )
        rev_ord_b = self.make_revocation_bytes(grant_id="race-rev-b", generation=1)
        self.enforcer.process_enrollment(rev_ord_b, now_utc=T0)
        with self.assertRaises(AE.ReplayError) as ctx_rb:
            self.enforcer.process_enrollment(raw_ord_b, now_utc=T0)
        self.assertEqual(ctx_rb.exception.code, "grant_tombstoned")
        with self.assertRaises(AE.ReplayError) as ctx_rb2:
            self.enroll_active(grant_id="race-rev-b", generation=2)
        self.assertEqual(ctx_rb2.exception.code, "grant_tombstoned")


# ===========================================================================
# Section B: Trust and Signers (Items 8-12)
# ===========================================================================

class TestSectionBTrustAndSigners(_EnforcerTestBase):
    def test_item08_baseline_roles_only_and_no_owner_covered_crossover(self) -> None:
        # 1. Proposed goal file adds attacker as owner -> still refused because baseline governs!
        prop_add_owner = copy.deepcopy(self.baseline)
        prop_add_owner["domains"]["device-trust"]["entries"]["advisor-key"][KEY_ATTACKER] = {
            "role": "owner",
            "state": "present",
        }
        diff_add_owner = {
            "schema_version": 9,
            "host": KEY_HOST,
            "baseline_sha256": AE.canonical_sha256(self.baseline),
            "proposed_sha256": AE.canonical_sha256(prop_add_owner),
            "hunks": {
                "device-trust": {
                    "advisor-key": {
                        KEY_ATTACKER: {"new": {"role": "owner", "state": "present"}}
                    }
                }
            },
        }
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

        # 2. covered-signer cannot sign per-change or standing-enrollment.
        cs_pc = dict(attacker_pc, signer=KEY_COVERED)
        with self.assertRaises(AE.TrustRootError):
            self.enforcer.process_per_change(
                sign_json(cs_pc, SEED_COVERED),
                proposed_goal=prop_add_owner,
                diff=diff_add_owner,
                now_utc=T0,
            )
        with self.assertRaises(AE.TrustRootError):
            self.enroll_active(grant_id="cs-enroll", owner_seed=SEED_COVERED, owner_key=KEY_COVERED)

        # 3. owner key NEVER listed in covered_signers (even in developer_mode) and NEVER signs standing-application.
        with self.assertRaises(AE.TrustRootError) as ctx_o1:
            self.enroll_active(grant_id="owner-covered", covered_signers=[KEY_OWNER], developer_mode=False)
        self.assertEqual(ctx_o1.exception.code, "owner_in_covered_signers")
        with self.assertRaises(AE.TrustRootError) as ctx_o2:
            self.enroll_active(grant_id="owner-covered-dev", covered_signers=[KEY_OWNER], developer_mode=True)
        self.assertEqual(ctx_o2.exception.code, "owner_in_covered_signers")

        _, nonce, _ = self.enroll_active(grant_id="dev-g", covered_signers=[KEY_DEV], developer_mode=True)
        prop, diff = make_ordinary_service_change(self.baseline)
        owner_app = self.make_app_bytes(
            grant_id="dev-g",
            generation=1,
            application_seq=1,
            enrollment_nonce=nonce,
            proposed=prop,
            signer_seed=SEED_OWNER,
            signer_key=KEY_OWNER,
        )
        with self.assertRaises(AE.TrustRootError) as ctx_o3:
            self.enforcer.process_standing_application(
                owner_app, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=1.0
            )
        self.assertEqual(ctx_o3.exception.code, "owner_cannot_sign_application")

    def test_item09_developer_mode_scope_and_persistent_indicator(self) -> None:
        self.assertFalse(self.enforcer.developer_mode_indicator_active(T0))

        # Outside developer_mode, untrusted KEY_DEV cannot be enrolled.
        with self.assertRaises(AE.TrustRootError):
            self.enroll_active(grant_id="nondev", covered_signers=[KEY_DEV], developer_mode=False)

        # Inside developer_mode, KEY_DEV is trusted for THIS host and THIS grant only.
        _, dev_nonce, _ = self.enroll_active(
            grant_id="dev-only",
            generation=1,
            covered_signers=[KEY_DEV],
            developer_mode=True,
            not_after=T_EXP,
        )
        self.assertTrue(self.enforcer.developer_mode_indicator_active(T0))
        # Expired indicator is False.
        self.assertFalse(self.enforcer.developer_mode_indicator_active(T_AFTER_EXP))

        prop1, diff1 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.dev1")
        app1 = self.make_app_bytes(
            grant_id="dev-only",
            generation=1,
            application_seq=1,
            enrollment_nonce=dev_nonce,
            proposed=prop1,
            signer_seed=SEED_DEV,
            signer_key=KEY_DEV,
        )
        res = self.enforcer.process_standing_application(
            app1, proposed_goal=prop1, diff=diff1, now_utc=T0, now_mono=1.0
        )
        self.assertEqual(res.decision, "applied")

        # KEY_DEV is NOT trusted on a second non-developer grant!
        _, other_nonce, _ = self.enroll_active(grant_id="prod-grant", covered_signers=[KEY_COVERED])
        prop2, diff2 = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.dev2")
        bad_app = self.make_app_bytes(
            grant_id="prod-grant",
            generation=1,
            application_seq=1,
            enrollment_nonce=other_nonce,
            proposed=prop2,
            signer_seed=SEED_DEV,
            signer_key=KEY_DEV,
        )
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                bad_app, proposed_goal=prop2, diff=diff2, now_utc=T0, now_mono=2.0
            )

        # Later generation omitting KEY_DEV ends its trust; revocation turns off indicator.
        _, gen2_nonce, _ = self.enroll_active(
            grant_id="dev-only",
            generation=2,
            covered_signers=[KEY_COVERED],
            developer_mode=False,
        )
        self.assertFalse(self.enforcer.developer_mode_indicator_active(T0))
        app_old_dev = self.make_app_bytes(
            grant_id="dev-only",
            generation=2,
            application_seq=2,
            enrollment_nonce=gen2_nonce,
            proposed=prop2,
            signer_seed=SEED_DEV,
            signer_key=KEY_DEV,
        )
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                app_old_dev, proposed_goal=prop2, diff=diff2, now_utc=T0, now_mono=3.0
            )

    def test_item10_host_key_never_signer_covered_or_advisor_key(self) -> None:
        # 1. Host key as advisor-key in baseline / first adoption / re-adoption -> refused.
        bad_goal = make_baseline_goal(
            advisor_keys={
                KEY_OWNER: {"role": "owner", "state": "present"},
                KEY_HOST: {"role": "covered-signer", "state": "present"},
            }
        )
        with self.assertRaises(AE.TrustRootError) as ctx_b:
            AE.ApprovalEnforcer(KEY_HOST, self.store, baseline_goal=bad_goal)
        self.assertEqual(ctx_b.exception.code, "host_key_in_trust_root")

        # First adoption carrying host key as advisor-key -> refused.
        fa_store = AE.ReplayStore(self.tmp / "fa-hostkey.json", KEY_HOST, anchor=AE.InMemoryRollbackAnchor())
        fa_enf = AE.ApprovalEnforcer(KEY_HOST, fa_store, baseline_goal=None)
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
            fa_enf.process_per_change(sign_json(fa_rec, SEED_OWNER), proposed_goal=bad_goal, now_utc=T0)
        self.assertEqual(ctx_fa.exception.code, "host_key_in_trust_root")

        # 2. Host key as signer on standing-enrollment, standing-application, per-change -> refused.
        with self.assertRaises(AE.TrustRootError) as ctx_s1:
            self.enroll_active(grant_id="host-sign", owner_seed=SEED_HOST, owner_key=KEY_HOST)
        self.assertEqual(ctx_s1.exception.code, "host_key_as_signer")

        _, nonce, _ = self.enroll_active(grant_id="ok-grant")
        prop, diff = make_ordinary_service_change(self.baseline)
        host_app = self.make_app_bytes(
            grant_id="ok-grant",
            generation=1,
            application_seq=1,
            enrollment_nonce=nonce,
            proposed=prop,
            signer_seed=SEED_HOST,
            signer_key=KEY_HOST,
        )
        with self.assertRaises(AE.TrustRootError) as ctx_s2:
            self.enforcer.process_standing_application(
                host_app, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=1.0
            )
        self.assertEqual(ctx_s2.exception.code, "host_key_as_signer")

        # 3. Host key in covered_signers (even in developer_mode) -> refused.
        with self.assertRaises(AE.TrustRootError) as ctx_c:
            self.enroll_active(grant_id="host-cov", covered_signers=[KEY_HOST], developer_mode=True)
        self.assertEqual(ctx_c.exception.code, "host_key_in_covered_signers")

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
        signed = AE.sign_approval_record(base_rec, SEED_COVERED)

        # 1. Unknown sig_alg refused.
        bad_alg = dict(signed, sig_alg="ed448")
        with self.assertRaises(AE.SignatureError) as ctx1:
            self.enforcer.process_standing_application(
                AE.jcs_dumps(bad_alg), proposed_goal=prop, diff=diff, now_utc=T0, now_mono=1.0
            )
        self.assertEqual(ctx1.exception.code, "unsupported_sig_alg")

        # 2. Mismatched signer prefix refused.
        bad_signer = dict(signed, signer="ed448:" + "11" * 32)
        with self.assertRaises(AE.SignatureError) as ctx2:
            self.enforcer.process_standing_application(
                AE.jcs_dumps(bad_signer), proposed_goal=prop, diff=diff, now_utc=T0, now_mono=1.0
            )
        self.assertEqual(ctx2.exception.code, "sig_alg_signer_mismatch")

        # 3. Non-canonical malleated S (+ L) on approval record refused.
        sig_bytes = bytes.fromhex(signed["signature"].split(":", 1)[1])
        s_malleated = (int.from_bytes(sig_bytes[32:], "little") + AE.ED25519_L).to_bytes(32, "little")
        bad_canon = dict(signed, signature="ed25519-sig:" + (sig_bytes[:32] + s_malleated).hex())
        with self.assertRaises(AE.SignatureError) as ctx3:
            self.enforcer.process_standing_application(
                AE.jcs_dumps(bad_canon), proposed_goal=prop, diff=diff, now_utc=T0, now_mono=1.0
            )
        self.assertEqual(ctx3.exception.code, "invalid_signature")

    def test_item12_nonce_entropy_randomness_and_post_store_loss_uniqueness(self) -> None:
        issued: set[str] = set()
        for _ in range(32):
            n = AE.generate_device_nonce()
            self.assertGreaterEqual(len(n), 22)
            self.assertLessEqual(len(n), 128)
            self.assertNotIn("\n", n)
            self.assertIsNotNone(AE.NONCE_RE.match(n))
            issued.add(n)
        self.assertEqual(len(issued), 32)

        # Rejects < 16 bytes (< 128 bits).
        with self.assertRaises(ValueError):
            AE.generate_device_nonce(15)

        # Simulate store loss / reflash: fresh ReplayStore issues no previously issued nonce,
        # and both the old enrollment AND old application are refused.
        raw_enroll, old_nonce, _ = self.enroll_active(grant_id="reflash-g")
        prop, diff = make_ordinary_service_change(self.baseline)
        old_app = self.make_app_bytes(
            grant_id="reflash-g", generation=1, application_seq=1, enrollment_nonce=old_nonce, proposed=prop
        )

        # Reflash (fresh store + fresh anchor, same host key).
        store2 = AE.ReplayStore(self.tmp / "reflashed.json", KEY_HOST, anchor=AE.InMemoryRollbackAnchor())
        enf2 = AE.ApprovalEnforcer(KEY_HOST, store2, self.baseline)
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
            enf2.process_standing_application(
                old_app, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=1.0
            )


# ===========================================================================
# Section C: Carve-Out and Class (Items 13-16 + PR #75 R4 #4)
# ===========================================================================

class TestSectionCCarveOutAndClass(_EnforcerTestBase):
    def test_item13_r1_r7_default_deny_device_trust_carve_out_and_replay_store(self) -> None:
        _, priv_nonce, _ = self.enroll_active(
            grant_id="priv-grant", grant_class="privileged", mode="standing-approval"
        )

        # 1. Every carved-out device-trust kind (including policy-tree R7 and future unknown kinds!) is REFUSED.
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
                entries = prop["domains"]["device-trust"]["entries"]
                old_body = entries.get(kind_name, {}).get(entry_id)
                entries.setdefault(kind_name, {})[entry_id] = new_body
                hunk: dict[str, Any] = {"new": new_body}
                if old_body is not None:
                    hunk["old"] = old_body
                diff = {
                    "schema_version": 9,
                    "host": KEY_HOST,
                    "baseline_sha256": AE.canonical_sha256(self.baseline),
                    "proposed_sha256": AE.canonical_sha256(prop),
                    "hunks": {"device-trust": {kind_name: {entry_id: hunk}}},
                }
                app = self.make_app_bytes(
                    grant_id="priv-grant",
                    generation=1,
                    application_seq=idx,
                    enrollment_nonce=priv_nonce,
                    proposed=prop,
                    ceremony_class="privileged",
                )
                with self.assertRaises(AE.ScopeError) as ctx:
                    self.enforcer.process_standing_application(
                        app, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=1.0
                    )
                self.assertEqual(ctx.exception.code, "carve_out_device_trust")

        # 2. Replay-store reset is carved out even on an otherwise valid supervisor hunk!
        prop_sup, diff_sup = make_supervisor_change(self.baseline, new_name="systemd")
        app_rs = self.make_app_bytes(
            grant_id="priv-grant",
            generation=1,
            application_seq=1,
            enrollment_nonce=priv_nonce,
            proposed=prop_sup,
            ceremony_class="privileged",
        )
        with self.assertRaises(AE.ScopeError) as ctx_rs:
            self.enforcer.process_standing_application(
                app_rs,
                proposed_goal=prop_sup,
                diff=diff_sup,
                now_utc=T0,
                now_mono=1.0,
                touches_replay_store=True,
            )
        self.assertEqual(ctx_rs.exception.code, "carve_out_replay_store")

        # 3. device-trust/supervisor IS allowed under a privileged standing grant!
        res = self.enforcer.process_standing_application(
            app_rs, proposed_goal=prop_sup, diff=diff_sup, now_utc=T0, now_mono=2.0
        )
        self.assertEqual(res.decision, "applied")

    def test_item14_and_r4_04_per_hunk_class_mixed_retreat_and_empty_domain(self) -> None:
        _, ord_nonce, _ = self.enroll_active(grant_id="ord-g", grant_class="ordinary")
        _, priv_nonce, _ = self.enroll_active(grant_id="priv-g", grant_class="privileged")

        # 1. Mixed-class diff (device-trust/supervisor [privileged] + supervision/service [ordinary]) -> REFUSED!
        prop_mix, diff_mix = make_ordinary_service_change(self.baseline, service_id="com.tendcf.mix")
        old_sup = copy.deepcopy(self.baseline["domains"]["device-trust"]["entries"]["supervisor"]["host"])
        new_sup = {"name": "systemd", "state": "present"}
        prop_mix["domains"]["device-trust"]["entries"]["supervisor"]["host"] = new_sup
        diff_mix["proposed_sha256"] = AE.canonical_sha256(prop_mix)
        diff_mix["hunks"]["device-trust"] = {"supervisor": {"host": {"old": old_sup, "new": new_sup}}}
        for gid, gnonce, cc in (("priv-g", priv_nonce, "privileged"), ("ord-g", ord_nonce, "ordinary")):
            app = self.make_app_bytes(
                grant_id=gid, generation=1, application_seq=1, enrollment_nonce=gnonce, proposed=prop_mix, ceremony_class=cc
            )
            with self.assertRaises(AE.ScopeError) as ctx:
                self.enforcer.process_standing_application(
                    app, proposed_goal=prop_mix, diff=diff_mix, now_utc=T0, now_mono=1.0
                )
            self.assertEqual(ctx.exception.code, "mixed_class_application")

        # 2. Retreating a populated domain (comprehensive -> undeclared [privileged] + entry delete [ordinary]) -> MIXED -> REFUSED!
        pop_base, _ = make_ordinary_service_change(self.baseline, service_id="com.tendcf.retreat")
        self.enforcer.baseline_goal = copy.deepcopy(pop_base)
        retreated = copy.deepcopy(self.baseline)
        old_svc = pop_base["domains"]["supervision"]["entries"]["service"]["com.tendcf.retreat"]
        retreat_diff = {
            "schema_version": 9,
            "host": KEY_HOST,
            "baseline_sha256": AE.canonical_sha256(pop_base),
            "proposed_sha256": AE.canonical_sha256(retreated),
            "coverage_changes": {"supervision": {"old": "comprehensive", "new": "undeclared"}},
            "hunks": {"supervision": {"service": {"com.tendcf.retreat": {"old": old_svc}}}},
        }
        retreat_app = self.make_app_bytes(
            grant_id="priv-g",
            generation=1,
            application_seq=1,
            enrollment_nonce=priv_nonce,
            baseline=pop_base,
            proposed=retreated,
            ceremony_class="privileged",
        )
        with self.assertRaises(AE.ScopeError) as ctx_ret:
            self.enforcer.process_standing_application(
                retreat_app, proposed_goal=retreated, diff=retreat_diff, now_utc=T0, now_mono=2.0
            )
        self.assertEqual(ctx_ret.exception.code, "mixed_class_application")

        # 3. PR #75 R4 #4: Empty-domain coverage transitions are grantable under the class they derive!
        # (a) not-yet-migrated -> comprehensive derives `ordinary` -> grantable under `ordinary` grant!
        empty_base = make_baseline_goal(extra_domains={"supervision": {"coverage": "not-yet-migrated"}})
        empty_comp = make_baseline_goal(extra_domains={"supervision": {"coverage": "comprehensive"}})
        self.enforcer.baseline_goal = copy.deepcopy(empty_base)
        diff_ord_cov = {
            "schema_version": 9,
            "host": KEY_HOST,
            "baseline_sha256": AE.canonical_sha256(empty_base),
            "proposed_sha256": AE.canonical_sha256(empty_comp),
            "coverage_changes": {"supervision": {"old": "not-yet-migrated", "new": "comprehensive"}},
        }
        # Refused under privileged grant (wrong class).
        app_wrong_cls = self.make_app_bytes(
            grant_id="priv-g",
            generation=1,
            application_seq=1,
            enrollment_nonce=priv_nonce,
            baseline=empty_base,
            proposed=empty_comp,
            ceremony_class="ordinary",
        )
        with self.assertRaises(AE.ScopeError) as ctx_wc:
            self.enforcer.process_standing_application(
                app_wrong_cls, proposed_goal=empty_comp, diff=diff_ord_cov, now_utc=T0, now_mono=3.0
            )
        self.assertEqual(ctx_wc.exception.code, "grant_class_mismatch")

        # Accepted under ordinary grant!
        app_ord_cov = self.make_app_bytes(
            grant_id="ord-g",
            generation=1,
            application_seq=1,
            enrollment_nonce=ord_nonce,
            baseline=empty_base,
            proposed=empty_comp,
            ceremony_class="ordinary",
        )
        res_ord = self.enforcer.process_standing_application(
            app_ord_cov, proposed_goal=empty_comp, diff=diff_ord_cov, now_utc=T0, now_mono=4.0
        )
        self.assertEqual(res_ord.decision, "applied")

        # (b) comprehensive -> not-yet-migrated (empty domain) derives `privileged` -> grantable under `privileged` grant!
        diff_priv_cov = {
            "schema_version": 9,
            "host": KEY_HOST,
            "baseline_sha256": AE.canonical_sha256(empty_comp),
            "proposed_sha256": AE.canonical_sha256(empty_base),
            "coverage_changes": {"supervision": {"old": "comprehensive", "new": "not-yet-migrated"}},
        }
        app_priv_cov = self.make_app_bytes(
            grant_id="priv-g",
            generation=1,
            application_seq=1,
            enrollment_nonce=priv_nonce,
            baseline=empty_comp,
            proposed=empty_base,
            ceremony_class="privileged",
        )
        res_priv = self.enforcer.process_standing_application(
            app_priv_cov, proposed_goal=empty_base, diff=diff_priv_cov, now_utc=T0, now_mono=5.0
        )
        self.assertEqual(res_priv.decision, "applied")

    def test_item15_migrations_downward_bump_and_readoption(self) -> None:
        _, base_nonce, _ = self.enroll_active(grant_id="base-g", grant_class="baseline")

        # 1. Downward version_bump (9 -> 8) and equal (9 -> 9) REFUSED for BOTH standing-application AND per-change!
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
                grant_id="base-g",
                generation=1,
                application_seq=1,
                enrollment_nonce=base_nonce,
                proposed=prop_down,
                ceremony_class="baseline",
            )
            with self.assertRaises(AE.ScopeError) as ctx_s:
                self.enforcer.process_standing_application(
                    app_down, proposed_goal=prop_down, diff=diff_down, now_utc=T0, now_mono=1.0
                )
            self.assertEqual(ctx_s.exception.code, "downward_version_bump")

            # Operator ruling 2026-11-26: per-change owner record ALSO refuses downward/equal version_bump!
            pc_nonce = self.enforcer.issue_per_change_nonce(
                proposed_sha256=AE.canonical_sha256(prop_down), ceremony_class="baseline", now_utc=T0
            )
            pc_down = {
                "schema_version": 9,
                "record_kind": "per-change",
                "host": KEY_HOST,
                "signer": KEY_OWNER,
                "sig_alg": "ed25519",
                "baseline_sha256": AE.canonical_sha256(self.baseline),
                "proposed_sha256": AE.canonical_sha256(prop_down),
                "nonce": pc_nonce,
                "approval_seq": 0,
                "verdict": "accept",
                "ceremony_class": "baseline",
            }
            with self.assertRaises(AE.ScopeError) as ctx_pc:
                self.enforcer.process_per_change(
                    sign_json(pc_down, SEED_OWNER), proposed_goal=prop_down, diff=diff_down, now_utc=T0
                )
            self.assertEqual(ctx_pc.exception.code, "downward_version_bump")

        # 2. Upward migration whose device-trust is incomparable -> refused.
        prop_up = copy.deepcopy(self.baseline)
        prop_up["schema_version"] = 10
        diff_up = {
            "schema_version": 9,
            "host": KEY_HOST,
            "baseline_sha256": AE.canonical_sha256(self.baseline),
            "proposed_sha256": AE.canonical_sha256(prop_up),
            "version_bump": {"old": 9, "new": 10},
        }
        app_up = self.make_app_bytes(
            grant_id="base-g",
            generation=1,
            application_seq=1,
            enrollment_nonce=base_nonce,
            proposed=prop_up,
            ceremony_class="baseline",
        )
        with self.assertRaises(AE.ScopeError) as ctx_inc:
            self.enforcer.process_standing_application(
                app_up,
                proposed_goal=prop_up,
                diff=diff_up,
                now_utc=T0,
                now_mono=2.0,
                device_trust_comparable=False,
            )
        self.assertEqual(ctx_inc.exception.code, "migration_device_trust_incomparable")

        # 3. Migration whose migrate() mutates any device-trust entry (e.g. role default) -> refused!
        def mutating_migrate(doc: dict[str, Any], target_ver: int) -> dict[str, Any]:
            out = copy.deepcopy(doc)
            out["schema_version"] = target_ver
            out["domains"]["device-trust"]["entries"]["advisor-key"][KEY_COVERED]["role"] = "owner"
            return out

        prop_mut = mutating_migrate(self.baseline, 10)
        diff_mut = {
            "schema_version": 9,
            "host": KEY_HOST,
            "baseline_sha256": AE.canonical_sha256(self.baseline),
            "proposed_sha256": AE.canonical_sha256(prop_mut),
            "version_bump": {"old": 9, "new": 10},
        }
        app_mut = self.make_app_bytes(
            grant_id="base-g",
            generation=1,
            application_seq=1,
            enrollment_nonce=base_nonce,
            proposed=prop_mut,
            ceremony_class="baseline",
        )
        with self.assertRaises(AE.ScopeError) as ctx_mut:
            self.enforcer.process_standing_application(
                app_mut,
                proposed_goal=prop_mut,
                diff=diff_mut,
                now_utc=T0,
                now_mono=3.0,
                migrate_fn=mutating_migrate,
            )
        self.assertEqual(ctx_mut.exception.code, "migration_mutated_device_trust")

        # 4. Re-adoption NEVER by standing-application!
        with self.assertRaises(AE.ScopeError) as ctx_ra:
            self.enforcer.process_standing_application(
                app_up,
                proposed_goal=prop_up,
                diff=diff_up,
                now_utc=T0,
                now_mono=4.0,
                is_readoption=True,
            )
        self.assertEqual(ctx_ra.exception.code, "readoption_disallowed")

        # 5. Pure upward schema_version bump with identical device-trust SUCCEEDS under baseline grant!
        res = self.enforcer.process_standing_application(
            app_up, proposed_goal=prop_up, diff=diff_up, now_utc=T0, now_mono=5.0
        )
        self.assertEqual(res.decision, "applied")

    def test_item16_r9_disclosure_in_enrollment_briefing(self) -> None:
        raw, _, _ = self.enroll_active(grant_id="brief-g", covered_signers=[KEY_DEV], developer_mode=True)
        briefing = AE.render_enrollment_briefing(json.loads(raw))
        lower = briefing.lower()
        self.assertIn("root-equivalent authority", lower)
        self.assertIn("run as root", lower)
        self.assertIn("trust with root", lower)
        self.assertIn("revocation or expiry stops only future applications and pending holds", lower)
        self.assertIn("never undoes", lower)
        self.assertIn("trust root", lower)
        self.assertIn("replay store", lower)
        self.assertIn("validator", lower)
        self.assertIn("clock", lower)
        self.assertIn("developer mode", lower)


# ===========================================================================
# Section D: Time, Hold Window and Precedence (Items 17-19)
# ===========================================================================

class TestSectionDTimeHoldAndPrecedence(_EnforcerTestBase):
    def test_item17_not_after_strict_calendar_no_horizon_cap_and_clock_rollback(self) -> None:
        # 1. Impossible calendar dates & malformed formats REFUSED (never treated as absent!).
        bad_dates = [
            "2027-02-30T00:00:00Z",
            "2027-02-29T00:00:00Z",  # 2027 is not a leap year
            "2027-04-31T12:00:00Z",
            "2027-12-31T23:59:59.000Z",
            "2027-12-31T23:59:59+00:00",
            "2027-12-31T23:59:59Z\n",
            "not-a-date",
        ]
        for bad in bad_dates:
            with self.subTest(bad_not_after=bad):
                with self.assertRaises(AE.MalformedRecordError):
                    AE.parse_utc_timestamp(bad)

        # 2. Operator ruling 2026-11-26: NO hard maximum horizon cap (far-future valid date accepted).
        _, far_nonce, receipt = self.enroll_active(
            grant_id="far-horizon", not_after="2999-12-31T23:59:59Z", now_utc=T0
        )
        self.assertEqual(receipt.status, "accepted")

        # 3. Expiry checked at intake AND rechecked at hold-window apply time.
        short_exp = "2026-11-26T12:01:00Z"
        _, short_nonce, _ = self.enroll_active(
            grant_id="short-hold", mode="hold-window", hold_seconds=120, not_after=short_exp, now_utc=T0
        )
        prop, diff = make_ordinary_service_change(self.baseline)
        app = self.make_app_bytes(
            grant_id="short-hold", generation=1, application_seq=1, enrollment_nonce=short_nonce, proposed=prop
        )
        res = self.enforcer.process_standing_application(
            app, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=10.0
        )
        self.assertEqual(res.decision, "held")
        # Hold elapses monotonically, but grant expired in UTC before apply -> REFUSED!
        after_short_exp = datetime.datetime(2026, 11, 26, 12, 2, 0, tzinfo=datetime.timezone.utc)
        with self.assertRaises(AE.ScopeError) as ctx_exp:
            self.enforcer.complete_hold_window(
                AE.canonical_sha256(prop),
                proposed_goal=prop,
                diff=diff,
                now_utc=after_short_exp,
                now_mono=200.0,
            )
        self.assertEqual(ctx_exp.exception.code, "grant_expired_at_hold_apply")

        # 4. UTC clock rollback fails closed!
        earlier_utc = T0 - datetime.timedelta(seconds=30)
        app2 = self.make_app_bytes(
            grant_id="far-horizon", generation=1, application_seq=1, enrollment_nonce=far_nonce, proposed=prop
        )
        with self.assertRaises(AE.ClockRollbackError) as ctx_clk:
            self.enforcer.process_standing_application(
                app2, proposed_goal=prop, diff=diff, now_utc=earlier_utc, now_mono=201.0
            )
        self.assertEqual(ctx_clk.exception.code, "utc_clock_rollback")

    def test_item18_hold_window_monotonic_recheck_owner_reject_and_revocation(self) -> None:
        _, nonce, _ = self.enroll_active(
            grant_id="hold-g", mode="hold-window", hold_seconds=300, now_utc=T0
        )
        prop, diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.held")
        prop_hash = AE.canonical_sha256(prop)
        app = self.make_app_bytes(
            grant_id="hold-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop
        )
        res = self.enforcer.process_standing_application(
            app, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=1000.0
        )
        self.assertEqual(res.decision, "held")

        # 1. Wall clock jumps 2 hours ahead while device slept, monotonic clock only +100s (< 300s) -> REFUSED!
        with self.assertRaises(AE.ScopeError) as ctx_early:
            self.enforcer.complete_hold_window(
                prop_hash,
                proposed_goal=prop,
                diff=diff,
                now_utc=T0 + datetime.timedelta(hours=2),
                now_mono=1100.0,
            )
        self.assertEqual(ctx_early.exception.code, "hold_window_not_elapsed")

        # 2. Monotonic clock rollback -> fail closed!
        with self.assertRaises(AE.ClockRollbackError):
            self.enforcer.complete_hold_window(
                prop_hash,
                proposed_goal=prop,
                diff=diff,
                now_utc=T0 + datetime.timedelta(hours=2),
                now_mono=999.0,
            )

        # 3. Owner per-change reject during hold window stops hold IMMEDIATELY regardless of
        #    ceremony_class, bogus/unissued nonce, or stale approval_seq, and persists as DC-2 reject!
        reject_rec = {
            "schema_version": 9,
            "record_kind": "per-change",
            "host": KEY_HOST,
            "signer": KEY_OWNER,
            "sig_alg": "ed25519",
            "baseline_sha256": AE.canonical_sha256(self.baseline),
            "proposed_sha256": prop_hash,
            "nonce": "stale-unissued-nonce-0000000000",
            "approval_seq": 0,  # even if stale
            "verdict": "reject",
            "refused": ["supervision/service/com.tendcf.held"],
            "ceremony_class": "baseline",  # deliberately mismatched class
        }
        pc_res = self.enforcer.process_per_change(
            sign_json(reject_rec, SEED_OWNER), now_utc=T0 + datetime.timedelta(hours=2)
        )
        self.assertEqual(pc_res.decision, "rejected")
        self.assertEqual(len(pc_res.cancelled_holds), 1)

        # Attempting to complete the cancelled hold fails!
        with self.assertRaises(AE.ReplayError) as ctx_gone:
            self.enforcer.complete_hold_window(
                prop_hash,
                proposed_goal=prop,
                diff=diff,
                now_utc=T0 + datetime.timedelta(hours=3),
                now_mono=2000.0,
            )
        self.assertEqual(ctx_gone.exception.code, "no_pending_hold")

        # Persisted DC-2 reject outlives the hold window and blocks a fresh standing application!
        app2 = self.make_app_bytes(
            grant_id="hold-g", generation=1, application_seq=2, enrollment_nonce=nonce, proposed=prop
        )
        with self.assertRaises(AE.ReplayError) as ctx_dc2:
            self.enforcer.process_standing_application(
                app2,
                proposed_goal=prop,
                diff=diff,
                now_utc=T0 + datetime.timedelta(hours=3),
                now_mono=2001.0,
            )
        self.assertEqual(ctx_dc2.exception.code, "persisted_reject_active")

        # 4. Re-evaluation at apply: grant re-enrolled at gen 2 during hold -> hold refused on generation/nonce change!
        prop2, diff2 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.held2")
        app3 = self.make_app_bytes(
            grant_id="hold-g", generation=1, application_seq=3, enrollment_nonce=nonce, proposed=prop2
        )
        self.enforcer.process_standing_application(
            app3,
            proposed_goal=prop2,
            diff=diff2,
            now_utc=T0 + datetime.timedelta(hours=3),
            now_mono=3000.0,
        )
        self.enroll_active(
            grant_id="hold-g",
            generation=2,
            mode="hold-window",
            hold_seconds=300,
            now_utc=T0 + datetime.timedelta(hours=3, minutes=1),
        )
        with self.assertRaises(AE.ReplayError) as ctx_gen:
            self.enforcer.complete_hold_window(
                AE.canonical_sha256(prop2),
                proposed_goal=prop2,
                diff=diff2,
                now_utc=T0 + datetime.timedelta(hours=3, minutes=10),
                now_mono=3500.0,
            )
        self.assertEqual(ctx_gen.exception.code, "generation_changed_during_hold")

    def test_item19_precedence_most_restrictive_longest_hold_owner_accept_and_dc2_reject(self) -> None:
        # Enroll standing-approval, hold-window(120), hold-window(600), wait-for-user, standing-refusal!
        _, sa_nonce, _ = self.enroll_active(grant_id="g-sa", mode="standing-approval")
        _, hw1_nonce, _ = self.enroll_active(grant_id="g-hw1", mode="hold-window", hold_seconds=120)
        self.enroll_active(grant_id="g-hw2", mode="hold-window", hold_seconds=600)
        self.enroll_active(grant_id="g-wfu", mode="wait-for-user", not_after=None)
        self.enroll_active(grant_id="g-ref", mode="standing-refusal", not_after=None)

        prop, diff = make_ordinary_service_change(self.baseline, service_id="com.tendcf.prec")
        app_sa = self.make_app_bytes(
            grant_id="g-sa", generation=1, application_seq=1, enrollment_nonce=sa_nonce, proposed=prop
        )

        # 1. standing-refusal wins over everything (even when app names g-sa!).
        with self.assertRaises(AE.ScopeError) as ctx_ref:
            self.enforcer.process_standing_application(
                app_sa, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=10.0
            )
        self.assertEqual(ctx_ref.exception.code, "standing_refusal")

        # 2. Owner's own per-change accept of exact proposed_sha256 STILL succeeds against standing-refusal!
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
        pc_res = self.enforcer.process_per_change(
            sign_json(pc_acc, SEED_OWNER), proposed_goal=prop_owner, diff=diff_owner, now_utc=T0
        )
        self.assertEqual(pc_res.decision, "applied")

        # Recompute prop against updated baseline.
        prop, diff = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.prec2")
        app_sa = self.make_app_bytes(
            grant_id="g-sa", generation=1, application_seq=1, enrollment_nonce=sa_nonce, proposed=prop
        )

        # 3. Revoke standing-refusal -> wait-for-user now wins -> PARKED (not applied!).
        self.enforcer.process_enrollment(self.make_revocation_bytes(grant_id="g-ref", generation=2), now_utc=T0)
        res_wfu = self.enforcer.process_standing_application(
            app_sa, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=20.0
        )
        self.assertEqual(res_wfu.decision, "parked")
        self.assertEqual(res_wfu.effective_mode, "wait-for-user")

        # 4. Revoke wait-for-user -> hold-window wins over standing-approval, and LONGEST hold_seconds (600) wins!
        self.enforcer.process_enrollment(self.make_revocation_bytes(grant_id="g-wfu", generation=2), now_utc=T0)
        app_hw = self.make_app_bytes(
            grant_id="g-hw1", generation=1, application_seq=1, enrollment_nonce=hw1_nonce, proposed=prop
        )
        res_hw = self.enforcer.process_standing_application(
            app_hw, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=30.0
        )
        self.assertEqual(res_hw.decision, "held")
        self.assertEqual(res_hw.hold_seconds, 600)  # longest hold won over 120!

        # 5. Revoke both hold-windows -> standing-approval wins!
        self.enforcer.process_enrollment(self.make_revocation_bytes(grant_id="g-hw1", generation=2), now_utc=T0)
        self.enforcer.process_enrollment(self.make_revocation_bytes(grant_id="g-hw2", generation=2), now_utc=T0)
        # First test DC-2 reject wins over standing-approval until owner per-change accept!
        rej_nonce = self.enforcer.issue_per_change_nonce(
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
            "nonce": rej_nonce,
            "approval_seq": 1,
            "verdict": "reject",
            "refused": ["supervision/service/com.tendcf.prec2"],
            "ceremony_class": "ordinary",
        }
        self.enforcer.process_per_change(
            sign_json(pc_rej, SEED_OWNER), proposed_goal=prop, diff=diff, now_utc=T0
        )
        with self.assertRaises(AE.ReplayError) as ctx_dc2:
            self.enforcer.process_standing_application(
                app_sa, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=40.0
            )
        self.assertEqual(ctx_dc2.exception.code, "persisted_reject_active")

        # Later owner per-change accept clears persisted reject and applies!
        acc2_nonce = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop), ceremony_class="ordinary", now_utc=T0
        )
        pc_acc2 = dict(pc_rej, nonce=acc2_nonce, approval_seq=2, verdict="accept")
        pc_acc2.pop("refused")
        res_acc2 = self.enforcer.process_per_change(
            sign_json(pc_acc2, SEED_OWNER), proposed_goal=prop, diff=diff, now_utc=T0
        )
        self.assertEqual(res_acc2.decision, "applied")


# ===========================================================================
# Section E: Further Rules & Full Check-Order-Before-Mark (Items 20-26 + R4 #2)
# ===========================================================================

class TestSectionEFurtherRulesAndCheckOrder(_EnforcerTestBase):
    def test_item20_generation_rules(self) -> None:
        _, nonce2, _ = self.enroll_active(grant_id="gen-g", generation=2)
        prop, diff = make_ordinary_service_change(self.baseline)

        # Application at gen 1 (< 2) and gen 3 (> 2) refused.
        for bad_gen in (1, 3):
            app = self.make_app_bytes(
                grant_id="gen-g", generation=bad_gen, application_seq=1, enrollment_nonce=nonce2, proposed=prop
            )
            with self.assertRaises(AE.ReplayError) as ctx:
                self.enforcer.process_standing_application(
                    app, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=1.0
                )
            self.assertEqual(ctx.exception.code, "generation_mismatch")

        # Active enrollment at generation 1 (< stored 2) refused.
        with self.assertRaises(AE.ReplayError) as ctx_low:
            self.enroll_active(grant_id="gen-g", generation=1)
        self.assertEqual(ctx_low.exception.code, "stale_generation")

    def test_item21_signer_in_covered_signers(self) -> None:
        _, nonce, _ = self.enroll_active(grant_id="cov-g", covered_signers=[KEY_COVERED])
        prop, diff = make_ordinary_service_change(self.baseline)
        # KEY_COVERED2 is a valid baseline covered-signer, but NOT listed in cov-g's covered_signers!
        app = self.make_app_bytes(
            grant_id="cov-g",
            generation=1,
            application_seq=1,
            enrollment_nonce=nonce,
            proposed=prop,
            signer_seed=SEED_COVERED2,
            signer_key=KEY_COVERED2,
        )
        with self.assertRaises(AE.ScopeError) as ctx:
            self.enforcer.process_standing_application(
                app, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=1.0
            )
        self.assertEqual(ctx.exception.code, "signer_not_covered")

    def test_item22_r6_developer_mode_requires_privileged_ceremony_ordinary_class_and_not_after(self) -> None:
        # 1. developer_mode with ordinary-level ceremony -> refused (requires >= privileged!).
        with self.assertRaises(AE.NonceError) as ctx_lvl:
            self.enroll_active(
                grant_id="r6-lvl",
                covered_signers=[KEY_DEV],
                developer_mode=True,
                ceremony_level="ordinary",
                not_after=T_EXP,
            )
        self.assertEqual(ctx_lvl.exception.code, "insufficient_ceremony_level")

        # 2. developer_mode with class != ordinary -> refused.
        with self.assertRaises(AE.MalformedRecordError) as ctx_cls:
            self.enroll_active(
                grant_id="r6-cls",
                grant_class="privileged",
                covered_signers=[KEY_DEV],
                developer_mode=True,
                ceremony_level="privileged",
                not_after=T_EXP,
            )
        self.assertEqual(ctx_cls.exception.code, "developer_mode_non_ordinary")

        # 3. developer_mode without not_after -> refused (even for wait-for-user!).
        with self.assertRaises(AE.MalformedRecordError) as ctx_na:
            self.enroll_active(
                grant_id="r6-na",
                mode="wait-for-user",
                covered_signers=[KEY_DEV],
                developer_mode=True,
                ceremony_level="privileged",
                not_after=None,
            )
        self.assertEqual(ctx_na.exception.code, "missing_not_after")

        # 4. developer_mode with class=ordinary, not_after, privileged ceremony -> accepted!
        _, _, r = self.enroll_active(
            grant_id="r6-ok",
            covered_signers=[KEY_DEV],
            developer_mode=True,
            ceremony_level="privileged",
            not_after=T_EXP,
        )
        self.assertEqual(r.status, "accepted")

    def test_item23_ceremony_class_exact_match_no_upgrade_or_downgrade(self) -> None:
        _, priv_nonce, _ = self.enroll_active(grant_id="priv-only", grant_class="privileged")
        prop_ord, diff_ord = make_ordinary_service_change(self.baseline)
        prop_priv, diff_priv = make_supervisor_change(self.baseline)

        # 1. Standing application: privileged grant cannot cover ordinary change (no implicit hierarchy!).
        app_ord_on_priv = self.make_app_bytes(
            grant_id="priv-only",
            generation=1,
            application_seq=1,
            enrollment_nonce=priv_nonce,
            proposed=prop_ord,
            ceremony_class="ordinary",
        )
        with self.assertRaises(AE.ScopeError) as ctx1:
            self.enforcer.process_standing_application(
                app_ord_on_priv, proposed_goal=prop_ord, diff=diff_ord, now_utc=T0, now_mono=1.0
            )
        self.assertEqual(ctx1.exception.code, "grant_class_mismatch")

        # 2. Standing application: asserting privileged for an ordinary change refused (no silent upgrade!).
        app_lied_up = self.make_app_bytes(
            grant_id="priv-only",
            generation=1,
            application_seq=1,
            enrollment_nonce=priv_nonce,
            proposed=prop_ord,
            ceremony_class="privileged",
        )
        with self.assertRaises(AE.ScopeError) as ctx2:
            self.enforcer.process_standing_application(
                app_lied_up, proposed_goal=prop_ord, diff=diff_ord, now_utc=T0, now_mono=1.0
            )
        self.assertEqual(ctx2.exception.code, "ceremony_class_mismatch")

        # 3. Per-change: silent upgrade (privileged asserted for ordinary) AND silent downgrade (ordinary for privileged) refused!
        for prop, diff, asserted in ((prop_ord, diff_ord, "privileged"), (prop_priv, diff_priv, "ordinary")):
            n = self.enforcer.issue_per_change_nonce(
                proposed_sha256=AE.canonical_sha256(prop), ceremony_class=asserted, now_utc=T0
            )
            pc = {
                "schema_version": 9,
                "record_kind": "per-change",
                "host": KEY_HOST,
                "signer": KEY_OWNER,
                "sig_alg": "ed25519",
                "baseline_sha256": AE.canonical_sha256(self.baseline),
                "proposed_sha256": AE.canonical_sha256(prop),
                "nonce": n,
                "approval_seq": 0,
                "verdict": "accept",
                "ceremony_class": asserted,
            }
            with self.assertRaises(AE.ScopeError) as ctx3:
                self.enforcer.process_per_change(
                    sign_json(pc, SEED_OWNER), proposed_goal=prop, diff=diff, now_utc=T0
                )
            self.assertEqual(ctx3.exception.code, "ceremony_class_mismatch")

    def test_item24_per_target_host_validity(self) -> None:
        _, nonce, _ = self.enroll_active(grant_id="host-g")
        prop, diff = make_ordinary_service_change(self.baseline)

        # Wrong host on standing-enrollment (active and revoked).
        wrong_rev = self.make_revocation_bytes(grant_id="host-g", generation=2, host=KEY_OTHER_HOST)
        with self.assertRaises(AE.ScopeError) as ctx1:
            self.enforcer.process_enrollment(wrong_rev, now_utc=T0)
        self.assertEqual(ctx1.exception.code, "wrong_host")

        # Wrong host on standing-application.
        wrong_app = self.make_app_bytes(
            grant_id="host-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop, host=KEY_OTHER_HOST
        )
        with self.assertRaises(AE.ScopeError) as ctx2:
            self.enforcer.process_standing_application(
                wrong_app, proposed_goal=prop, diff=diff, now_utc=T0, now_mono=1.0
            )
        self.assertEqual(ctx2.exception.code, "wrong_host")

        # Wrong host on per-change.
        wrong_pc = {
            "schema_version": 9,
            "record_kind": "per-change",
            "host": KEY_OTHER_HOST,
            "signer": KEY_OWNER,
            "sig_alg": "ed25519",
            "baseline_sha256": AE.canonical_sha256(self.baseline),
            "proposed_sha256": AE.canonical_sha256(prop),
            "nonce": AE.generate_device_nonce(),
            "approval_seq": 0,
            "verdict": "accept",
            "ceremony_class": "ordinary",
        }
        with self.assertRaises(AE.ScopeError) as ctx3:
            self.enforcer.process_per_change(
                sign_json(wrong_pc, SEED_OWNER), proposed_goal=prop, diff=diff, now_utc=T0
            )
        self.assertEqual(ctx3.exception.code, "wrong_host")

    def test_item25_exact_proposed_sha256_binding(self) -> None:
        _, nonce, _ = self.enroll_active(grant_id="hash-g")
        prop_approved, diff_approved = make_ordinary_service_change(self.baseline, service_id="com.tendcf.good")
        prop_swapped, diff_swapped = make_ordinary_service_change(self.baseline, service_id="com.tendcf.evil")

        # Signed for prop_approved, delivered with prop_swapped -> REFUSED!
        app = self.make_app_bytes(
            grant_id="hash-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop_approved
        )
        with self.assertRaises(AE.ScopeError) as ctx:
            self.enforcer.process_standing_application(
                app, proposed_goal=prop_swapped, diff=diff_swapped, now_utc=T0, now_mono=1.0
            )
        self.assertEqual(ctx.exception.code, "proposed_sha256_mismatch")

    def test_item26_and_r4_02_refused_application_never_burns_mark(self) -> None:
        # Enroll ordinary grant and apply seq=1 so initial stored mark is 1.
        _, nonce, _ = self.enroll_active(grant_id="mark-g", generation=1, mode="standing-approval")
        prop1, diff1 = make_ordinary_service_change(self.baseline, service_id="com.tendcf.m1")
        app1 = self.make_app_bytes(
            grant_id="mark-g", generation=1, application_seq=1, enrollment_nonce=nonce, proposed=prop1
        )
        self.assertEqual(
            self.enforcer.process_standing_application(
                app1, proposed_goal=prop1, diff=diff1, now_utc=T0, now_mono=1.0
            ).decision,
            "applied",
        )
        self.assertEqual(self.store.snapshot()["grants"]["mark-g"]["application_seq_mark"], 1)

        prop2, diff2 = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.m2")
        prop_other, _ = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.m3")

        # Every single refusal below carries application_seq=50; NONE may burn or raise the mark!
        def assert_mark_unchanged(label: str) -> None:
            self.assertEqual(
                self.store.snapshot()["grants"]["mark-g"]["application_seq_mark"],
                1,
                f"application_seq_mark was burned by refused case: {label}",
            )

        # (a) Wrong host
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop2, host=KEY_OTHER_HOST),
                proposed_goal=prop2, diff=diff2, now_utc=T0, now_mono=2.0,
            )
        assert_mark_unchanged("wrong_host")

        # (b) Bad signature
        good_50 = json.loads(self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop2))
        good_50["signature"] = "ed25519-sig:" + "00" * 64
        with self.assertRaises(AE.SignatureError):
            self.enforcer.process_standing_application(
                AE.jcs_dumps(good_50), proposed_goal=prop2, diff=diff2, now_utc=T0, now_mono=2.0,
            )
        assert_mark_unchanged("bad_signature")

        # (c) Wrong generation
        with self.assertRaises(AE.ReplayError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=99, application_seq=50, enrollment_nonce=nonce, proposed=prop2),
                proposed_goal=prop2, diff=diff2, now_utc=T0, now_mono=2.0,
            )
        assert_mark_unchanged("wrong_generation")

        # (d) Wrong enrollment_nonce (R10)
        with self.assertRaises(AE.NonceError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=AE.generate_device_nonce(), proposed=prop2),
                proposed_goal=prop2, diff=diff2, now_utc=T0, now_mono=2.0,
            )
        assert_mark_unchanged("wrong_enrollment_nonce")

        # (e) Wrong baseline_sha256
        with self.assertRaises(AE.ReplayError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, baseline=self.baseline, proposed=prop2),
                proposed_goal=prop2, diff=diff2, now_utc=T0, now_mono=2.0,
            )
        assert_mark_unchanged("wrong_baseline_sha256")

        # (f) Wrong proposed_sha256
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop_other),
                proposed_goal=prop2, diff=diff2, now_utc=T0, now_mono=2.0,
            )
        assert_mark_unchanged("wrong_proposed_sha256")

        # (g) Signer not in covered_signers
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop2, signer_seed=SEED_COVERED2, signer_key=KEY_COVERED2),
                proposed_goal=prop2, diff=diff2, now_utc=T0, now_mono=2.0,
            )
        assert_mark_unchanged("signer_not_covered")

        # (h) Expired not_after
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop2),
                proposed_goal=prop2, diff=diff2, now_utc=T_AFTER_EXP, now_mono=2.0,
            )
        assert_mark_unchanged("grant_expired")

        # (i) R1/R7 carve-out (policy-tree)
        prop_pt = copy.deepcopy(self.enforcer.baseline_goal)
        prop_pt["domains"]["device-trust"]["entries"]["policy-tree"]["tree"]["sha256"] = "sha256:" + "99" * 32
        diff_pt = {
            "schema_version": 9,
            "host": KEY_HOST,
            "baseline_sha256": AE.canonical_sha256(self.enforcer.baseline_goal),
            "proposed_sha256": AE.canonical_sha256(prop_pt),
            "hunks": {
                "device-trust": {
                    "policy-tree": {
                        "tree": {
                            "old": self.enforcer.baseline_goal["domains"]["device-trust"]["entries"]["policy-tree"]["tree"],
                            "new": prop_pt["domains"]["device-trust"]["entries"]["policy-tree"]["tree"],
                        }
                    }
                }
            },
        }
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop_pt, ceremony_class="privileged"),
                proposed_goal=prop_pt, diff=diff_pt, now_utc=T0, now_mono=2.0,
            )
        assert_mark_unchanged("r7_policy_tree_carve_out")

        # (j) Persisted DC-2 reject
        rej_n = self.enforcer.issue_per_change_nonce(
            proposed_sha256=AE.canonical_sha256(prop2), ceremony_class="ordinary", now_utc=T0
        )
        pc_rej = {
            "schema_version": 9,
            "record_kind": "per-change",
            "host": KEY_HOST,
            "signer": KEY_OWNER,
            "sig_alg": "ed25519",
            "baseline_sha256": AE.canonical_sha256(self.enforcer.baseline_goal),
            "proposed_sha256": AE.canonical_sha256(prop2),
            "nonce": rej_n,
            "approval_seq": 0,
            "verdict": "reject",
            "refused": ["supervision/service/com.tendcf.m2"],
            "ceremony_class": "ordinary",
        }
        self.enforcer.process_per_change(sign_json(pc_rej, SEED_OWNER), proposed_goal=prop2, diff=diff2, now_utc=T0)
        with self.assertRaises(AE.ReplayError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop2),
                proposed_goal=prop2, diff=diff2, now_utc=T0, now_mono=2.0,
            )
        assert_mark_unchanged("persisted_dc2_reject")

        # (k) Covering standing-refusal
        self.enroll_active(grant_id="ref-block", mode="standing-refusal", not_after=None)
        prop_ok, diff_ok = make_ordinary_service_change(self.enforcer.baseline_goal, service_id="com.tendcf.m4")
        with self.assertRaises(AE.ScopeError):
            self.enforcer.process_standing_application(
                self.make_app_bytes(grant_id="mark-g", generation=1, application_seq=50, enrollment_nonce=nonce, proposed=prop_ok),
                proposed_goal=prop_ok, diff=diff_ok, now_utc=T0, now_mono=2.0,
            )
        assert_mark_unchanged("covering_standing_refusal")

        # Finally revoke ref-block and confirm valid seq=2 STILL succeeds (mark was never burned to 50)!
        self.enforcer.process_enrollment(self.make_revocation_bytes(grant_id="ref-block", generation=2), now_utc=T0)
        app2 = self.make_app_bytes(
            grant_id="mark-g", generation=1, application_seq=2, enrollment_nonce=nonce, proposed=prop_ok
        )
        res2 = self.enforcer.process_standing_application(
            app2, proposed_goal=prop_ok, diff=diff_ok, now_utc=T0, now_mono=3.0
        )
        self.assertEqual(res2.decision, "applied")
        self.assertEqual(self.store.snapshot()["grants"]["mark-g"]["application_seq_mark"], 2)


if __name__ == "__main__":
    unittest.main()
