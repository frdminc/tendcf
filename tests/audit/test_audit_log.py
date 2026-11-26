"""Hermetic unit and security contract tests for tools/audit_log.py (issue #119).

Runs under isolated stdlib-only `python3 -I -S -m unittest discover -s tests/audit -v`
with zero third-party dependencies.

Directly proves the issue #119 acceptance criteria:
  1. Hash-chained local JSONL matches the off-device sink copy line-for-line
     after an offline period (including multi-batch reconnect and idempotent retry).
  2. A host with deleted, tail-truncated, mid-log-deleted, or edited local JSONL
     is flagged immediately when verified against the sink copy.
  3. The append-only SSH forced-command boundary refuses read, list, rename,
     truncate, delete, and cross-host/cross-src spoofing; client key can append
     only and sink never echoes log contents.
  4. Local capture completes normally and queues records when the sink is
     unreachable, never blocking `cf-agent`.
  5. Redaction tests prove CMDB values, goal-file contents, command output,
     environment variables, secrets, private keys, and consent free-text are
     blocked structurally and never reach the local log or sink.
  6. Intermittent/silent hosts report status `"unknown"`, never `"fine"`.
  7. Symlink, FIFO, path-traversal, duplicate-key, non-canonical JCS, fork,
     gap, and crash-recovery negative/edge tests.
"""

from __future__ import annotations

import datetime
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AUDIT_TOOL = REPO_ROOT / "tools" / "audit_log.py"
EXAMPLES_YML = REPO_ROOT / "examples" / "audit-envelopes.yml"


def _load_audit_module():
    spec = importlib.util.spec_from_file_location("_tendcf_audit_log_test", AUDIT_TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


audit = _load_audit_module()

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64
H4 = "sha256:" + "4" * 64
KID = "ed25519:" + "a" * 64


def _hb_data(converged: bool = True, unshipped: int = 0) -> dict:
    return {
        "running_release": "release-1.0.0",
        "goal_sha256": H1,
        "projection_sha256": H2,
        "converged": converged,
        "unshipped_count": unshipped,
    }


def _promise_data(entry: str = "tendcf.canary.service", outcome: str = "repaired") -> dict:
    return {
        "release": "release-1.0.0",
        "domain": "linux-systemd-services",
        "bundle": "edge-http",
        "entry": entry,
        "mode": "enforce",
        "outcome": outcome,
    }


class TestHashChainAndOfflineShipping(unittest.TestCase):
    def test_offline_queue_then_reconnect_matches_line_for_line(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool = audit.AuditSpool(
                root / "spool", host="pastebin", src="tendcf", boot_id="boot-aaa-1"
            )
            sink_root = root / "sink"
            online = False

            def transport(batch_bytes: bytes) -> dict:
                if not online:
                    raise audit.TransportError("sink unreachable: connection refused")
                return audit.run_forced_command(
                    sink_root=sink_root,
                    expected_host="pastebin",
                    expected_src="tendcf",
                    stdin_bytes=batch_bytes,
                    original_command="audit-append tendcf",
                    receive_ts="2026-11-26T15:00:00Z",
                )

            shipper = audit.AuditShipper(spool, transport, batch_size=2)

            # Emit 5 records while sink is unreachable; local emit succeeds without blocking.
            emitted = []
            emitted.append(
                spool.append(
                    "release_decision",
                    {
                        "release": "release-1.0.0",
                        "release_sha256": H1,
                        "goal_sha256": H2,
                        "projection_sha256": H3,
                        "verdict": "pass",
                    },
                    ts="2026-11-26T14:00:01Z",
                    mono_ms=100,
                )
            )
            emitted.append(
                spool.append(
                    "consent_decision",
                    {
                        "verdict": "accept",
                        "key_id": KID,
                        "decided_at": "2026-11-26T14:00:02Z",
                        "decision_sha256": H4,
                        "ceremony_class": "privileged",
                    },
                    ts="2026-11-26T14:00:02Z",
                    mono_ms=200,
                )
            )
            emitted.append(
                spool.append(
                    "promise_outcome",
                    _promise_data("tendcf.canary.service", "repaired"),
                    ts="2026-11-26T14:00:03Z",
                    mono_ms=300,
                )
            )
            emitted.append(
                spool.append(
                    "service_change",
                    {
                        "action": "install",
                        "supervisor": "systemd",
                        "unit": "tendcf.canary.service",
                        "path": "/etc/systemd/system/tendcf.canary.service",
                        "new_sha256": H1,
                    },
                    ts="2026-11-26T14:00:04Z",
                    mono_ms=400,
                )
            )
            emitted.append(
                spool.append(
                    "heartbeat",
                    _hb_data(converged=True, unshipped=4),
                    ts="2026-11-26T14:00:05Z",
                    mono_ms=500,
                )
            )

            # Attempt to ship while offline: does not raise, loses 0 lines, keeps all 5 queued.
            res_offline = shipper.ship()
            self.assertFalse(res_offline.ok)
            self.assertEqual(res_offline.shipped, 0)
            self.assertEqual(res_offline.remaining, 5)
            self.assertEqual(res_offline.last_acked_seq, 0)
            self.assertIn("unreachable", res_offline.error or "")

            # Sink comes back online: drains across 3 batches (2 + 2 + 1).
            online = True
            res_online = shipper.ship()
            self.assertTrue(res_online.ok)
            self.assertEqual(res_online.shipped, 5)
            self.assertEqual(res_online.remaining, 0)
            self.assertEqual(res_online.last_acked_seq, 5)
            self.assertEqual(res_online.last_acked_h, emitted[-1]["h"])

            # Verify line-for-line byte identity between local JSONL and sink copy.
            sink_file = sink_root / "pastebin" / "tendcf" / "2026-11-26.jsonl"
            self.assertEqual(spool.log_path.read_bytes(), sink_file.read_bytes())

            # Forensic verification passes with zero findings.
            ver = audit.verify_local_against_sink(
                spool.log_path,
                sink_root / "pastebin" / "tendcf",
                expected_host="pastebin",
                expected_src="tendcf",
            )
            self.assertTrue(ver.ok, f"unexpected findings: {ver.findings}")
            self.assertEqual(ver.local_count, 5)
            self.assertEqual(ver.sink_count, 5)
            self.assertEqual(ver.quarantine_count, 0)

    def test_idempotent_retry_after_dropped_ack_produces_no_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool = audit.AuditSpool(root / "spool", host="pastebin", boot_id="boot-1")
            sink_root = root / "sink"
            spool.append("heartbeat", _hb_data(), ts="2026-11-26T14:00:01Z", mono_ms=10)
            spool.append("heartbeat", _hb_data(), ts="2026-11-26T14:00:02Z", mono_ms=20)

            drop_first_ack = True

            def flaky_transport(batch_bytes: bytes) -> dict:
                nonlocal drop_first_ack
                ack = audit.run_forced_command(
                    sink_root=sink_root,
                    expected_host="pastebin",
                    expected_src="tendcf",
                    stdin_bytes=batch_bytes,
                    receive_ts="2026-11-26T14:00:03Z",
                )
                if drop_first_ack:
                    drop_first_ack = False
                    raise audit.TransportError("network reset before ack arrived")
                return ack

            shipper = audit.AuditShipper(spool, flaky_transport)
            first = shipper.ship()
            self.assertFalse(first.ok)
            self.assertEqual(first.last_acked_seq, 0)

            second = shipper.ship()
            self.assertTrue(second.ok)
            self.assertEqual(second.shipped, 0)
            self.assertEqual(second.duplicates, 2)
            self.assertEqual(second.quarantined, 0)
            self.assertEqual(second.last_acked_seq, 2)
            self.assertEqual(second.remaining, 0)

            sink_file = sink_root / "pastebin" / "tendcf" / "2026-11-26.jsonl"
            self.assertEqual(len(sink_file.read_bytes().splitlines()), 2)

    def test_spool_and_sink_enforce_private_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool = audit.AuditSpool(root / "spool", host="pastebin", boot_id="boot-1")
            spool.append("heartbeat", _hb_data(), ts="2026-11-26T14:00:01Z", mono_ms=1)
            self.assertEqual(stat.S_IMODE(os.lstat(spool.spool_dir).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.lstat(spool.log_path).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.lstat(spool.cursor_path).st_mode), 0o600)

            sink_root = root / "sink"
            audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=spool.log_path.read_bytes(),
                receive_ts="2026-11-26T14:00:02Z",
            )
            stream_dir = sink_root / "pastebin" / "tendcf"
            self.assertEqual(stat.S_IMODE(os.lstat(stream_dir).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.lstat(stream_dir / "2026-11-26.jsonl").st_mode), 0o600)


class TestTamperDetectionAgainstSink(unittest.TestCase):
    def _setup_shipped_pair(self, root: Path, count: int = 4):
        spool = audit.AuditSpool(root / "spool", host="pastebin", boot_id="boot-1")
        sink_root = root / "sink"
        for i in range(1, count + 1):
            spool.append(
                "promise_outcome",
                _promise_data(f"svc-{i}.service", "repaired"),
                ts=f"2026-11-26T12:00:{i:02d}Z",
                mono_ms=i * 100,
            )
        shipper = audit.AuditShipper(
            spool,
            lambda b: audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=b,
                receive_ts="2026-11-26T12:01:00Z",
            ),
        )
        res = shipper.ship()
        self.assertTrue(res.ok)
        return spool, sink_root / "pastebin" / "tendcf"

    def test_deleted_local_log_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            spool, sink_dir = self._setup_shipped_pair(Path(td), 3)
            spool.log_path.unlink()
            report = audit.verify_local_against_sink(
                spool.log_path, sink_dir, expected_host="pastebin"
            )
            self.assertFalse(report.ok)
            codes = {f.code for f in report.findings}
            self.assertIn("LOCAL_MISSING", codes)

    def test_tail_truncated_local_log_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            spool, sink_dir = self._setup_shipped_pair(Path(td), 4)
            lines = spool.log_path.read_bytes().splitlines(keepends=True)
            spool.log_path.write_bytes(b"".join(lines[:2]))
            report = audit.verify_local_against_sink(
                spool.log_path, sink_dir, expected_host="pastebin"
            )
            self.assertFalse(report.ok)
            codes = {f.code for f in report.findings}
            self.assertIn("LOCAL_TRUNCATED", codes)

            # Spool itself also refuses to silently restart/append after truncation.
            with self.assertRaises(audit.ChainTamperError):
                spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:02:00Z", mono_ms=999)

    def test_mid_log_deleted_line_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            spool, sink_dir = self._setup_shipped_pair(Path(td), 4)
            lines = spool.log_path.read_bytes().splitlines(keepends=True)
            spool.log_path.write_bytes(lines[0] + lines[2] + lines[3])
            report = audit.verify_local_against_sink(
                spool.log_path, sink_dir, expected_host="pastebin"
            )
            self.assertFalse(report.ok)
            codes = {f.code for f in report.findings}
            self.assertIn("LOCAL_LINE_DELETED", codes)
            self.assertIn("LOCAL_CHAIN_SEQ_GAP", codes)

    def test_edited_local_line_even_with_recomputed_chain_is_flagged(self) -> None:
        """Even a root attacker who rewrites local history & recomputes every hash is caught by the sink."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool, sink_dir = self._setup_shipped_pair(root, 3)

            # Attacker rebuilds a completely valid-looking alternate chain from seq 1..3.
            forged = audit.AuditSpool(root / "forged", host="pastebin", boot_id="boot-1")
            forged.append(
                "promise_outcome",
                _promise_data("svc-1.service", "success"),  # changed repaired -> success
                ts="2026-11-26T12:00:01Z",
                mono_ms=100,
            )
            forged.append(
                "promise_outcome",
                _promise_data("svc-2.service", "repaired"),
                ts="2026-11-26T12:00:02Z",
                mono_ms=200,
            )
            forged.append(
                "promise_outcome",
                _promise_data("svc-3.service", "repaired"),
                ts="2026-11-26T12:00:03Z",
                mono_ms=300,
            )
            spool.log_path.write_bytes(forged.log_path.read_bytes())

            report = audit.verify_local_against_sink(
                spool.log_path, sink_dir, expected_host="pastebin"
            )
            self.assertFalse(report.ok)
            edited_seqs = [f.seq for f in report.findings if f.code == "LOCAL_EDITED"]
            self.assertEqual(edited_seqs, [1, 2, 3])


class TestAppendOnlySinkBoundary(unittest.TestCase):
    def test_forced_command_blocks_read_list_rename_truncate_delete(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sink_root = Path(td) / "sink"
            env = audit.build_envelope(
                host="pastebin",
                src="tendcf",
                boot_id="boot-1",
                seq=1,
                prev=audit.GENESIS_PREV,
                event_type="heartbeat",
                data=_hb_data(),
                ts="2026-11-26T12:00:01Z",
                mono_ms=10,
            )
            ack = audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=audit.jcs_dumps(env) + b"\n",
                original_command="audit-append tendcf",
                receive_ts="2026-11-26T12:00:02Z",
            )
            self.assertTrue(ack["ok"])
            self.assertEqual(ack["last_seq"], 1)
            # Ack never leaks file paths or event contents.
            self.assertNotIn("data", ack)
            self.assertNotIn("path", ack)

            disallowed = [
                "cat /srv/audit/pastebin/tendcf/2026-11-26.jsonl",
                "ls -la /srv/audit",
                "rm -rf /srv/audit/pastebin",
                "mv 2026-11-26.jsonl evil.jsonl",
                "truncate -s 0 2026-11-26.jsonl",
                "audit-append other-src",
                "audit-append tendcf; rm -rf /",
                "sh -c id",
                "read",
                "list",
                "delete",
            ]
            for bad_cmd in disallowed:
                with self.subTest(cmd=bad_cmd):
                    with self.assertRaises(audit.ForcedCommandError):
                        audit.run_forced_command(
                            sink_root=sink_root,
                            expected_host="pastebin",
                            expected_src="tendcf",
                            stdin_bytes=b"",
                            original_command=bad_cmd,
                        )

            # Original committed file is untouched.
            day_file = sink_root / "pastebin" / "tendcf" / "2026-11-26.jsonl"
            self.assertEqual(day_file.read_bytes(), audit.jcs_dumps(env) + b"\n")

    def test_cross_host_and_cross_src_spoofing_quarantined_not_committed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sink_root = Path(td) / "sink"
            wrong_host = audit.build_envelope(
                host="other-host",
                src="tendcf",
                boot_id="boot-1",
                seq=1,
                prev=audit.GENESIS_PREV,
                event_type="heartbeat",
                data=_hb_data(),
                ts="2026-11-26T12:00:01Z",
                mono_ms=10,
            )
            ack = audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=audit.jcs_dumps(wrong_host) + b"\n",
                receive_ts="2026-11-26T12:00:02Z",
            )
            self.assertEqual(ack["accepted"], 0)
            self.assertEqual(ack["quarantined"], 1)
            self.assertEqual(ack["last_seq"], 0)
            self.assertFalse((sink_root / "other-host").exists())

    def test_gap_and_fork_are_quarantined_not_silently_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sink_root = Path(td) / "sink"
            e1 = audit.build_envelope(
                host="pastebin",
                boot_id="boot-1",
                seq=1,
                prev=audit.GENESIS_PREV,
                event_type="heartbeat",
                data=_hb_data(converged=True),
                ts="2026-11-26T12:00:01Z",
                mono_ms=10,
            )
            e1_fork = audit.build_envelope(
                host="pastebin",
                boot_id="boot-1",
                seq=1,
                prev=audit.GENESIS_PREV,
                event_type="heartbeat",
                data=_hb_data(converged=False),
                ts="2026-11-26T12:00:01Z",
                mono_ms=10,
            )
            e3_gap = audit.build_envelope(
                host="pastebin",
                boot_id="boot-1",
                seq=3,
                prev=e1["h"],
                event_type="heartbeat",
                data=_hb_data(),
                ts="2026-11-26T12:00:03Z",
                mono_ms=30,
            )

            ack1 = audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=audit.jcs_dumps(e1) + b"\n",
                receive_ts="2026-11-26T12:00:02Z",
            )
            self.assertEqual(ack1["accepted"], 1)

            ack2 = audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=audit.jcs_dumps(e1_fork) + b"\n" + audit.jcs_dumps(e3_gap) + b"\n",
                receive_ts="2026-11-26T12:00:04Z",
            )
            self.assertEqual(ack2["accepted"], 0)
            self.assertEqual(ack2["quarantined"], 2)
            self.assertEqual(ack2["last_seq"], 1)

            q_lines = [
                json.loads(ln)
                for ln in (sink_root / "pastebin" / "tendcf" / "quarantine.jsonl").read_text().splitlines()
            ]
            self.assertEqual([q["reason"] for q in q_lines], ["fork", "gap"])

    def test_sink_uses_receive_date_preventing_client_filename_spraying(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sink_root = Path(td) / "sink"
            env = audit.build_envelope(
                host="pastebin",
                boot_id="boot-1",
                seq=1,
                prev=audit.GENESIS_PREV,
                event_type="heartbeat",
                data=_hb_data(),
                ts="1999-01-01T00:00:00Z",  # wild client clock
                mono_ms=10,
            )
            audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=audit.jcs_dumps(env) + b"\n",
                receive_ts="2026-11-26T15:30:00Z",
            )
            stream_dir = sink_root / "pastebin" / "tendcf"
            self.assertTrue((stream_dir / "2026-11-26.jsonl").is_file())
            self.assertFalse((stream_dir / "1999-01-01.jsonl").exists())


class TestRedactionGate(unittest.TestCase):
    def test_cmdb_goal_file_secrets_env_output_and_consent_freetext_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            spool = audit.AuditSpool(Path(td) / "spool", host="pastebin", boot_id="boot-1")
            forbidden_cases = [
                ("cmdb_vars", "promise_outcome", {**_promise_data(), "vars": {"secret_port": 8080}}),
                ("goal_file_content", "release_decision", {
                    "release": "release-1.0.0",
                    "release_sha256": H1,
                    "goal_sha256": H2,
                    "projection_sha256": H3,
                    "verdict": "pass",
                    "goal_file": '{"schema_version":9}',
                }),
                ("command_output", "promise_outcome", {**_promise_data(), "stdout": "root:x:0:0"}),
                ("message_field", "promise_outcome", {**_promise_data(), "message": "raw output"}),
                ("env_vars", "service_change", {
                    "action": "install",
                    "supervisor": "systemd",
                    "unit": "app.service",
                    "path": "/etc/systemd/system/app.service",
                    "new_sha256": H1,
                    "env": {"API_KEY": "supersecret"},
                }),
                ("consent_typed_text", "consent_decision", {
                    "verdict": "accept",
                    "key_id": KID,
                    "decided_at": "2026-11-26T12:00:00Z",
                    "decision_sha256": H1,
                    "ceremony_class": "ordinary",
                    "typed_text": "my private operator note",
                }),
                ("pem_key_in_entry", "promise_outcome", _promise_data("-----BEGIN PRIVATE KEY-----")),
                ("gh_token_in_entry", "promise_outcome", _promise_data("ghp_1234567890abcdef")),
                ("newline_injection", "promise_outcome", _promise_data("svc\n{\"injected\":1}")),
            ]
            for name, etype, data in forbidden_cases:
                with self.subTest(case=name):
                    with self.assertRaises(audit.AuditRedactionError):
                        spool.append(etype, data, ts="2026-11-26T12:00:01Z", mono_ms=1)

            # Nothing was written to the local log.
            self.assertFalse(spool.log_path.exists())

    def test_sink_quarantine_never_persists_raw_secret_payload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sink_root = Path(td) / "sink"
            secret_canary = "SUPER_SECRET_CMDB_VALUE_987654321"
            poison = json.dumps(
                {
                    "v": 1,
                    "src": "tendcf",
                    "host": "pastebin",
                    "boot_id": "boot-1",
                    "seq": 1,
                    "ts": "2026-11-26T12:00:01Z",
                    "mono_ms": 1,
                    "prev": audit.GENESIS_PREV,
                    "type": "promise_outcome",
                    "data": {**_promise_data(), "vars": secret_canary},
                    "h": H1,
                }
            ).encode("utf-8") + b"\n"

            ack = audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=poison,
                receive_ts="2026-11-26T12:00:02Z",
            )
            self.assertEqual(ack["accepted"], 0)
            self.assertEqual(ack["quarantined"], 1)

            q_bytes = (sink_root / "pastebin" / "tendcf" / "quarantine.jsonl").read_bytes()
            self.assertNotIn(secret_canary.encode("utf-8"), q_bytes)
            q_obj = json.loads(q_bytes.decode("utf-8").strip())
            self.assertEqual(q_obj["reason"], "redaction_blocked")
            self.assertTrue(q_obj["raw_sha256"].startswith("sha256:"))


class TestSilentHostLivenessAndSecurityEdges(unittest.TestCase):
    def test_silent_and_unseen_host_reports_unknown_never_fine(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sink_root = Path(td) / "sink"
            now = datetime.datetime(2026, 11, 26, 15, 0, 0, tzinfo=datetime.timezone.utc)

            # Unseen host -> unknown.
            rep_unseen = audit.check_host_liveness(
                sink_root / "ghost" / "tendcf", host="ghost", now_utc=now, max_silence_seconds=300
            )
            self.assertEqual(rep_unseen.status, "unknown")

            # Host sends heartbeat at 14:58:00Z -> ok at 15:00:00Z (120s <= 300s).
            hb = audit.build_envelope(
                host="pastebin",
                boot_id="boot-1",
                seq=1,
                prev=audit.GENESIS_PREV,
                event_type="heartbeat",
                data=_hb_data(),
                ts="2026-11-26T14:58:00Z",
                mono_ms=10,
            )
            audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=audit.jcs_dumps(hb) + b"\n",
                receive_ts="2026-11-26T14:58:00Z",
            )
            rep_ok = audit.check_host_liveness(
                sink_root / "pastebin" / "tendcf", host="pastebin", now_utc=now, max_silence_seconds=300
            )
            self.assertEqual(rep_ok.status, "ok")

            # 10 minutes later (15:08:01Z) -> silent host is "unknown", never "fine"/"ok".
            later = datetime.datetime(2026, 11, 26, 15, 8, 1, tzinfo=datetime.timezone.utc)
            rep_silent = audit.check_host_liveness(
                sink_root / "pastebin" / "tendcf", host="pastebin", now_utc=later, max_silence_seconds=300
            )
            self.assertEqual(rep_silent.status, "unknown")
            self.assertIn("silent", rep_silent.reason)

    def test_symlink_and_fifo_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool_dir = root / "spool"
            spool_dir.mkdir(mode=0o700)
            target = root / "outside.txt"
            target.write_text("do-not-touch", encoding="utf-8")
            (spool_dir / "audit.jsonl").symlink_to(target)

            spool = audit.AuditSpool(spool_dir, host="pastebin", boot_id="boot-1")
            with self.assertRaises(audit.AuditFileSecurityError):
                spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:01Z", mono_ms=1)
            self.assertEqual(target.read_text(encoding="utf-8"), "do-not-touch")

            # FIFO refusal (must never block).
            fifo_dir = root / "fifo_spool"
            fifo_dir.mkdir(mode=0o700)
            os.mkfifo(fifo_dir / "audit.jsonl")
            fifo_spool = audit.AuditSpool(fifo_dir, host="pastebin", boot_id="boot-1")
            with self.assertRaises(audit.AuditFileSecurityError):
                fifo_spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:01Z", mono_ms=1)

    def test_ssh_transport_argv_hardening(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            key = root / "id_ed25519"
            kh = root / "known_hosts"
            key.write_text("dummy", encoding="utf-8")
            os.chmod(key, 0o600)
            kh.write_text("dummy", encoding="utf-8")

            argv = audit.build_ssh_append_argv(
                target="audit@sink.example.org",
                identity_file=key,
                known_hosts_file=kh,
                src="tendcf",
            )
            self.assertIn("-F", argv)
            self.assertIn("/dev/null", argv)
            self.assertIn("BatchMode=yes", argv)
            self.assertIn("IdentitiesOnly=yes", argv)
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("GlobalKnownHostsFile=/dev/null", argv)
            self.assertIn("ProxyCommand=none", argv)
            self.assertIn("ProxyJump=none", argv)
            self.assertIn("ControlPath=none", argv)
            self.assertIn("KnownHostsCommand=none", argv)
            self.assertIn("ClearAllForwardings=yes", argv)
            self.assertIn("ForwardAgent=no", argv)
            self.assertEqual(argv[-3:], ["--", "audit@sink.example.org", "audit-append tendcf"])

            # Option-injection target and leading-dash host after @ refused (H5).
            for bad_target in ("-oProxyCommand=evil", "audit@-oProxyCommand=evil", "audit@host:22"):
                with self.subTest(bad_target=bad_target):
                    with self.assertRaises(audit.TransportError):
                        audit.build_ssh_append_argv(
                            target=bad_target,
                            identity_file=key,
                            known_hosts_file=kh,
                        )

            # Group/world-readable key refused (H5).
            os.chmod(key, 0o644)
            with self.assertRaises(audit.AuditFileSecurityError):
                audit.build_ssh_append_argv(
                    target="audit@sink.example.org",
                    identity_file=key,
                    known_hosts_file=kh,
                )
            os.chmod(key, 0o600)

            # Percent/whitespace injection in known_hosts path refused (H5).
            bad_kh = root / "known %h hosts"
            bad_kh.write_text("dummy", encoding="utf-8")
            with self.assertRaises(audit.AuditFileSecurityError):
                audit.build_ssh_append_argv(
                    target="audit@sink.example.org",
                    identity_file=key,
                    known_hosts_file=bad_kh,
                )

            # Bad io_timeout_s refused (H5).
            for bad_to in (0, -5, True, "10"):
                with self.assertRaises(audit.TransportError):
                    audit.make_ssh_append_transport(
                        target="audit@sink.example.org",
                        identity_file=key,
                        known_hosts_file=kh,
                        io_timeout_s=bad_to,  # type: ignore[arg-type]
                    )


class TestR1AdversaryRegressions(unittest.TestCase):
    def test_h1_deeply_nested_json_does_not_crash_sink_or_verifier(self) -> None:
        deep = (b'{"a":' * 1500) + b"1" + (b"}" * 1500)
        with self.assertRaises(audit.AuditValidationError):
            audit.strict_json_loads(deep)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sink_root = root / "sink"
            ack = audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=deep + b"\n",
                receive_ts="2026-11-26T15:00:00Z",
            )
            self.assertEqual(ack["quarantined"], 1)

            local_log = root / "audit.jsonl"
            local_log.write_bytes(deep + b"\n")
            ver = audit.verify_local_against_sink(
                local_log, sink_root / "pastebin" / "tendcf", expected_host="pastebin"
            )
            self.assertFalse(ver.ok)
            self.assertIn("LOCAL_PARSE_ERROR", {f.code for f in ver.findings})

    def test_h2_batch_line_cap_and_quarantine_cap_prevent_amplification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sink_root = Path(td) / "sink"
            # Exceeding MAX_BATCH_LINES is rejected before looping.
            too_many = b"x\n" * (audit.MAX_BATCH_LINES + 1)
            with self.assertRaises(audit.AuditValidationError):
                audit.run_forced_command(
                    sink_root=sink_root,
                    expected_host="pastebin",
                    expected_src="tendcf",
                    stdin_bytes=too_many,
                    receive_ts="2026-11-26T15:00:00Z",
                )

            # 200 invalid lines within MAX_BATCH_LINES caps quarantine disk writes to MAX_QUARANTINE_PER_BATCH + 1 summary.
            ack = audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=b"x\n" * 200,
                receive_ts="2026-11-26T15:00:00Z",
            )
            self.assertEqual(ack["quarantined"], 200)
            q_lines = (sink_root / "pastebin" / "tendcf" / "quarantine.jsonl").read_text().splitlines()
            self.assertEqual(len(q_lines), audit.MAX_QUARANTINE_PER_BATCH + 1)
            self.assertEqual(json.loads(q_lines[-1])["reason"], "quarantine_batch_cap_reached")
            self.assertEqual(
                json.loads(q_lines[-1])["suppressed_count"],
                200 - audit.MAX_QUARANTINE_PER_BATCH,
            )

    def test_h3_shipper_unwedges_when_sink_ahead_of_batch_or_cursor_rebuilt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool = audit.AuditSpool(root / "spool", host="pastebin", boot_id="boot-1")
            sink_root = root / "sink"
            for i in range(1, 7):
                spool.append(
                    "heartbeat", _hb_data(), ts=f"2026-11-26T12:00:{i:02d}Z", mono_ms=i * 10
                )

            # Ship first 4 records to sink directly (simulating lost ack / rebuilt cursor.json).
            pending_all, _ = spool.unshipped()
            audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=b"".join(raw + b"\n" for _, raw in pending_all[:4]),
                receive_ts="2026-11-26T12:01:00Z",
            )
            # Delete cursor.json so spool recovers with acked_seq=0, then ship with batch_size=2.
            spool.cursor_path.unlink()
            shipper = audit.AuditShipper(
                spool,
                lambda b: audit.run_forced_command(
                    sink_root=sink_root,
                    expected_host="pastebin",
                    expected_src="tendcf",
                    stdin_bytes=b,
                    receive_ts="2026-11-26T12:02:00Z",
                ),
                batch_size=2,
            )
            res = shipper.ship()
            self.assertTrue(res.ok, f"shipper wedged: {res}")
            self.assertEqual(res.last_acked_seq, 6)
            self.assertEqual(res.remaining, 0)
            self.assertEqual(res.shipped, 2)
            self.assertEqual(res.duplicates, 2)

    def test_h4_append_skips_redundant_fchmod_for_chattr_a_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "s"
            d.mkdir(mode=0o700)
            orig_fchmod = os.fchmod
            calls = []

            def spy_fchmod(fd: int, mode: int) -> None:
                calls.append(mode)
                return orig_fchmod(fd, mode)

            os.fchmod = spy_fchmod  # type: ignore[assignment]
            try:
                with audit._open_dir_fd(d, require_private=True) as dfd:
                    audit._append_bytes_durable_in_dir(dfd, "2026-11-26.jsonl", b'{"a":1}\n', mode=0o600)
                    calls.clear()
                    # Second append on an already-0600 file must NOT invoke fchmod (would EPERM on chattr +a).
                    audit._append_bytes_durable_in_dir(dfd, "2026-11-26.jsonl", b'{"a":2}\n', mode=0o600)
                    self.assertEqual(calls, [])
            finally:
                os.fchmod = orig_fchmod  # type: ignore[assignment]

    def test_m1_verify_is_readonly_flags_missing_sink_and_enforces_0700_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            missing_sink = root / "does-not-exist" / "tendcf"
            local_log = root / "missing-local.jsonl"
            rep = audit.verify_local_against_sink(local_log, missing_sink, expected_host="pastebin")
            self.assertFalse(rep.ok)
            self.assertIn("SINK_MISSING", {f.code for f in rep.findings})
            # Must NEVER create the missing directory!
            self.assertFalse(missing_sink.exists())
            self.assertFalse((root / "does-not-exist").exists())

            # Pre-existing 0755 spool dir rejected (M1).
            wide_dir = root / "wide_spool"
            wide_dir.mkdir(mode=0o755)
            os.chmod(wide_dir, 0o755)
            with self.assertRaises(audit.AuditFileSecurityError):
                audit.AuditSpool(wide_dir, host="pastebin", boot_id="boot-1")

            # Symlinked ancestor directory rejected (M1).
            real_base = root / "real_base"
            real_base.mkdir(mode=0o700)
            link_base = root / "link_base"
            link_base.symlink_to(real_base)
            with self.assertRaises(audit.AuditFileSecurityError):
                audit.AuditSpool(link_base / "spool", host="pastebin", boot_id="boot-1")

    def test_m2_sink_crash_recovery_persists_state_without_fabricating_liveness(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sink_root = Path(td) / "sink"
            hb = audit.build_envelope(
                host="pastebin",
                boot_id="boot-1",
                seq=1,
                prev=audit.GENESIS_PREV,
                event_type="heartbeat",
                data=_hb_data(),
                ts="2026-11-26T10:00:00Z",
                mono_ms=10,
            )
            audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=audit.jcs_dumps(hb) + b"\n",
                receive_ts="2026-11-26T10:00:01Z",
            )
            # Simulate crash where state.json was lost after daily file fsync.
            state_file = sink_root / "pastebin" / "tendcf" / "state.json"
            state_file.unlink()

            # Retry 10 hours later (duplicate): must persist recovered state.json,
            # but MUST NOT fabricate a fresh 20:00:00Z heartbeat receive timestamp!
            ack = audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=audit.jcs_dumps(hb) + b"\n",
                receive_ts="2026-11-26T20:00:00Z",
            )
            self.assertEqual(ack["duplicates"], 1)
            self.assertTrue(state_file.is_file())
            rep = audit.check_host_liveness(
                sink_root / "pastebin" / "tendcf",
                host="pastebin",
                now_utc=datetime.datetime(2026, 11, 26, 20, 0, 5, tzinfo=datetime.timezone.utc),
                max_silence_seconds=300,
            )
            self.assertEqual(rep.status, "unknown")

    def test_m3_torn_transport_stream_does_not_poison_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sink_root = Path(td) / "sink"
            env = audit.build_envelope(
                host="pastebin",
                boot_id="boot-1",
                seq=1,
                prev=audit.GENESIS_PREV,
                event_type="heartbeat",
                data=_hb_data(),
                ts="2026-11-26T12:00:01Z",
                mono_ms=10,
            )
            torn = audit.jcs_dumps(env)[:-10]  # missing tail & newline
            with self.assertRaises(audit.AuditValidationError):
                audit.run_forced_command(
                    sink_root=sink_root,
                    expected_host="pastebin",
                    expected_src="tendcf",
                    stdin_bytes=torn,
                    receive_ts="2026-11-26T12:00:02Z",
                )
            self.assertFalse((sink_root / "pastebin" / "tendcf" / "quarantine.jsonl").exists())

    def test_m4_path_and_akia_and_genesis_parity(self) -> None:
        # Non-normalized paths rejected; /opt/AKIA/svc allowed while real AWS key blocked.
        for bad_path in ("/etc/./passwd", "/etc/.", "/etc/systemd/", "/etc/foo/../bar"):
            with self.assertRaises(audit.AuditValidationError):
                audit.validate_event_data(
                    "tripwire", {"tool": "aide", "event": "modified", "path": bad_path}
                )
        # Normal path containing AKIA passes; 20-char AWS key blocked.
        audit.validate_event_data("tripwire", {"tool": "aide", "event": "modified", "path": "/opt/AKIA/svc"})
        with self.assertRaises(audit.AuditRedactionError):
            audit.validate_event_data(
                "tripwire",
                {"tool": "aide", "event": "modified", "path": "/opt/AKIAIOSFODNN7EXAMPLE/svc"},
            )

    def test_m5_l3_l4_cross_host_splice_liveness_mismatch_sink_truncation_and_quarantine(self) -> None:
        # Cross-host chain splicing caught even when expected_host=None.
        e1 = audit.build_envelope(
            host="host-a", boot_id="b1", seq=1, prev=audit.GENESIS_PREV,
            event_type="heartbeat", data=_hb_data(), ts="2026-11-26T12:00:01Z", mono_ms=1,
        )
        e2 = audit.build_envelope(
            host="host-b", boot_id="b2", seq=2, prev=e1["h"],
            event_type="heartbeat", data=_hb_data(), ts="2026-11-26T12:00:02Z", mono_ms=2,
        )
        findings = audit.verify_chain_records([e1, e2])
        self.assertIn("CHAIN_HOST_MISMATCH", {f.code for f in findings})

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sink_root = root / "sink"
            audit.run_forced_command(
                sink_root=sink_root,
                expected_host="host-a",
                expected_src="tendcf",
                stdin_bytes=audit.jcs_dumps(e1) + b"\n",
                receive_ts="2026-11-26T12:00:02Z",
            )
            stream_a = sink_root / "host-a" / "tendcf"
            now = datetime.datetime(2026, 11, 26, 12, 0, 10, tzinfo=datetime.timezone.utc)
            # Wrong host pointed at host-a's stream -> unknown (M5).
            rep_wrong = audit.check_host_liveness(stream_a, host="host-b", now_utc=now)
            self.assertEqual(rep_wrong.status, "unknown")
            self.assertIn("mismatch", rep_wrong.reason)

            # Quarantine present makes liveness "unknown" (L4).
            audit.run_forced_command(
                sink_root=sink_root,
                expected_host="host-a",
                expected_src="tendcf",
                stdin_bytes=b"bad\n",
                receive_ts="2026-11-26T12:00:05Z",
            )
            rep_q = audit.check_host_liveness(stream_a, host="host-a", now_utc=now)
            self.assertEqual(rep_q.status, "unknown")
            self.assertEqual(rep_q.quarantine_count, 1)

            # Deleting sink daily file while state.json survives -> SINK_TRUNCATED (M5).
            (stream_a / "2026-11-26.jsonl").unlink()
            local_log = root / "audit.jsonl"
            local_log.write_bytes(b"")
            ver_trunc = audit.verify_local_against_sink(local_log, stream_a, expected_host="host-a")
            self.assertFalse(ver_trunc.ok)
            self.assertIn("SINK_TRUNCATED", {f.code for f in ver_trunc.findings})

            # Symlinked local log classified as LOCAL_UNSAFE_FILE (L3).
            sym_local = root / "sym.jsonl"
            sym_local.symlink_to(local_log)
            ver_sym = audit.verify_local_against_sink(sym_local, stream_a, expected_host="host-a")
            self.assertIn("LOCAL_UNSAFE_FILE", {f.code for f in ver_sym.findings})

    def test_l1_redaction_errors_omit_raw_values_and_catch_forbidden_key_with_list(self) -> None:
        secret = "my_secret_value_should_not_echo_12345"
        with self.assertRaises(audit.AuditValidationError) as ctx:
            audit.validate_event_data(
                "promise_outcome", _promise_data(entry=f"bad {secret}")
            )
        self.assertNotIn(secret, str(ctx.exception))

        # Forbidden key carrying a list/None must raise AuditRedactionError (not AuditValidationError).
        with self.assertRaises(audit.AuditRedactionError):
            audit.validate_event_data("promise_outcome", {**_promise_data(), "vars": ["secret"]})
        with self.assertRaises(audit.AuditRedactionError):
            audit.validate_event_data("promise_outcome", {**_promise_data(), "env": None})

    def test_pr123_bot_extra_key_names_never_echoed_in_errors(self) -> None:
        # Macroscope #4712891391: rejected extra JSON keys must not echo attacker-controlled names.
        secret_key = "password=hunter2_do_not_leak"
        with self.assertRaises(audit.AuditRedactionError) as ctx1:
            audit.validate_event_data("promise_outcome", {**_promise_data(), secret_key: "x"})
        self.assertNotIn(secret_key, str(ctx1.exception))

        env = audit.build_envelope(
            host="pastebin", boot_id="boot-1", seq=1, prev=audit.GENESIS_PREV,
            event_type="heartbeat", data=_hb_data(), ts="2026-11-26T12:00:01Z", mono_ms=1,
        )
        env[secret_key] = "x"
        with self.assertRaises(audit.AuditRedactionError) as ctx2:
            audit.validate_envelope(env)
        self.assertNotIn(secret_key, str(ctx2.exception))

    def test_pr123_bot_non_ascii_hash_in_local_and_sink_state_does_not_crash(self) -> None:
        # Macroscope #4712891399 & Codex #4712897474: non-ASCII h must yield findings, never TypeError.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool = audit.AuditSpool(root / "spool", host="pastebin", boot_id="boot-1")
            sink_root = root / "sink"
            env = spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:01Z", mono_ms=1)
            audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=spool.log_path.read_bytes(),
                receive_ts="2026-11-26T12:00:02Z",
            )
            stream_dir = sink_root / "pastebin" / "tendcf"

            # Corrupt local record with non-ASCII 'h'.
            bad_local = dict(env)
            bad_local["h"] = "é"
            spool.log_path.write_bytes(json.dumps(bad_local, ensure_ascii=False).encode("utf-8") + b"\n")
            rep1 = audit.verify_local_against_sink(spool.log_path, stream_dir, expected_host="pastebin")
            self.assertFalse(rep1.ok)
            codes1 = {f.code for f in rep1.findings}
            self.assertIn("LOCAL_EDITED", codes1)

            # Corrupt sink state.json last_h with non-ASCII 'é'.
            st = json.loads((stream_dir / "state.json").read_text(encoding="utf-8"))
            st["last_h"] = "é"
            (stream_dir / "state.json").write_text(json.dumps(st, ensure_ascii=False) + "\n", encoding="utf-8")
            rep2 = audit.verify_local_against_sink(spool.log_path, stream_dir, expected_host="pastebin")
            self.assertFalse(rep2.ok)
            self.assertIn("SINK_STATE_MISMATCH", {f.code for f in rep2.findings})

    def test_pr123_bot_spool_o1_append_does_not_rescan_full_history(self) -> None:
        # Codex #4712897460: append() uses cursor byte offsets (O(1)) instead of scanning seq 1..N.
        with tempfile.TemporaryDirectory() as td:
            spool = audit.AuditSpool(Path(td) / "spool", host="pastebin", boot_id="boot-1")
            for i in range(1, 25):
                spool.append("heartbeat", _hb_data(), ts=f"2026-11-26T12:00:{i:02d}Z", mono_ms=i)

            orig_iter = audit._iter_regular_lines_in_dir
            calls = []

            def spy_iter(*args, **kwargs):
                calls.append((args, kwargs))
                return orig_iter(*args, **kwargs)

            audit._iter_regular_lines_in_dir = spy_iter
            try:
                spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:30Z", mono_ms=30)
                # Steady-state append must NOT invoke full-file line iteration at all.
                self.assertEqual(calls, [])
            finally:
                audit._iter_regular_lines_in_dir = orig_iter

            cur = json.loads(spool.cursor_path.read_text(encoding="utf-8"))
            self.assertEqual(cur["local_seq"], 25)
            self.assertEqual(cur["local_offset"], spool.log_path.stat().st_size)

    def test_pr123_bot_sink_recovers_incomplete_partial_write_before_retry(self) -> None:
        # Codex #4712897466: unterminated 100-byte partial write on daily file must recover
        # append-only (chattr +a compatible) so subsequent batch retries succeed cleanly.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool = audit.AuditSpool(root / "spool", host="pastebin", boot_id="boot-1")
            sink_root = root / "sink"
            e1 = spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:01Z", mono_ms=10)
            e2 = spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:02Z", mono_ms=20)
            e1_bytes = audit.jcs_dumps(e1) + b"\n"
            e2_bytes = audit.jcs_dumps(e2) + b"\n"

            # Commit e1 normally, then simulate interrupted partial write of 100 bytes of e2.
            ack1 = audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=e1_bytes,
                receive_ts="2026-11-26T12:00:05Z",
            )
            self.assertEqual(ack1["last_seq"], 1)
            day_file = sink_root / "pastebin" / "tendcf" / "2026-11-26.jsonl"
            with open(day_file, "ab") as fh:
                fh.write(e2_bytes[:100])

            # Retry full batch [e1, e2]: sink must seal torn fragment append-only, dedup e1,
            # commit e2 cleanly, and record recovery witness in quarantine.jsonl & state.json.
            ack2 = audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=e1_bytes + e2_bytes,
                receive_ts="2026-11-26T12:00:10Z",
            )
            self.assertTrue(ack2["ok"])
            self.assertEqual(ack2["duplicates"], 1)
            self.assertEqual(ack2["accepted"], 1)
            self.assertEqual(ack2["last_seq"], 2)
            self.assertEqual(ack2["last_h"], e2["h"])

            # Subsequent verification sees both committed records (no SINK_CORRUPT) plus quarantine witness.
            ver = audit.verify_local_against_sink(
                spool.log_path, sink_root / "pastebin" / "tendcf", expected_host="pastebin"
            )
            self.assertEqual(ver.sink_count, 2)
            codes = {f.code for f in ver.findings}
            self.assertNotIn("SINK_CORRUPT", codes)
            self.assertNotIn("LOCAL_EDITED", codes)
            self.assertIn("SINK_QUARANTINE_PRESENT", codes)

    def test_r3_h1_write_ahead_partial_recovery_survives_crash_before_newline_seal(self) -> None:
        # H1-R3 + Macroscope 4712973914/4713174933: atomic per-pin files in recovered_partials/
        # are persisted BEFORE sealing '\n' on the daily file, without growing state.json.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool = audit.AuditSpool(root / "spool", host="pastebin", boot_id="boot-1")
            sink_root = root / "sink"
            e1 = spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:01Z", mono_ms=10)
            e2 = spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:02Z", mono_ms=20)
            e1_bytes = audit.jcs_dumps(e1) + b"\n"
            e2_bytes = audit.jcs_dumps(e2) + b"\n"

            audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=e1_bytes,
                receive_ts="2026-11-26T12:00:05Z",
            )
            day_file = sink_root / "pastebin" / "tendcf" / "2026-11-26.jsonl"
            with open(day_file, "ab") as fh:
                fh.write(e2_bytes[:100])

            # Simulate crash right after atomic pin write, BEFORE '\n' seal on daily file.
            orig_append = audit._append_bytes_durable_in_dir
            orig_write_json = audit._write_json_atomic_in_dir
            call_order: list[str] = []

            def spy_write_json(dfd, name, payload, mode=0o600):
                call_order.append(f"atomic:{name}")
                return orig_write_json(dfd, name, payload, mode=mode)

            def crash_on_newline_seal(dfd, name, payload, mode=0o600):
                call_order.append(f"append:{name}:{len(payload)}")
                if name == "2026-11-26.jsonl" and payload == b"\n":
                    raise OSError("simulated power loss before newline seal")
                return orig_append(dfd, name, payload, mode=mode)

            audit._write_json_atomic_in_dir = spy_write_json
            audit._append_bytes_durable_in_dir = crash_on_newline_seal
            try:
                with self.assertRaises(OSError):
                    audit.run_forced_command(
                        sink_root=sink_root,
                        expected_host="pastebin",
                        expected_src="tendcf",
                        stdin_bytes=e1_bytes + e2_bytes,
                        receive_ts="2026-11-26T12:00:10Z",
                    )
                # Confirm atomic pin file was persisted BEFORE attempting '\n' seal.
                pin_idx = call_order.index("atomic:2026-11-26.jsonl.2.json")
                seal_idx = call_order.index("append:2026-11-26.jsonl:1")
                self.assertLess(pin_idx, seal_idx)
            finally:
                audit._write_json_atomic_in_dir = orig_write_json
                audit._append_bytes_durable_in_dir = orig_append

            # Next retry completes the '\n' seal without duplicating pin/witness and commits e2.
            ack = audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=e1_bytes + e2_bytes,
                receive_ts="2026-11-26T12:00:15Z",
            )
            self.assertTrue(ack["ok"])
            self.assertEqual(ack["last_seq"], 2)
            self.assertEqual(ack["accepted"], 1)
            q_lines = (sink_root / "pastebin" / "tendcf" / "quarantine.jsonl").read_text().splitlines()
            self.assertEqual(len(q_lines), 1)
            pin_dir = sink_root / "pastebin" / "tendcf" / "recovered_partials"
            pin_files = sorted(p.name for p in pin_dir.iterdir())
            self.assertEqual(pin_files, ["2026-11-26.jsonl.2.json"])
            st = json.loads((sink_root / "pastebin" / "tendcf" / "state.json").read_text())
            self.assertNotIn("recovered_partials", st)

    def test_private_dir_rejects_foreign_uid_owner(self) -> None:
        # Macroscope 4712973907: _verify_private_dir_mode must enforce st_uid == os.geteuid().
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "priv"
            p.mkdir(mode=0o700)
            real_st = os.stat(p)
            # Build a fake stat_result with mode 0700 but a different uid.
            foreign_uid = real_st.st_uid + 1
            fake_fields = list(real_st)
            fake_fields[4] = foreign_uid  # st_uid
            fake_st = os.stat_result(fake_fields)
            with self.assertRaises(audit.AuditFileSecurityError):
                audit._verify_private_dir_mode(fake_st, p)

    def test_shipper_error_and_max_batches_use_o1_watermark_without_unshipped_scan(self) -> None:
        # Macroscope 4712973929: error/no-progress/max_batches paths use O(1) watermark(), not unshipped().
        with tempfile.TemporaryDirectory() as td:
            spool = audit.AuditSpool(Path(td) / "spool", host="pastebin", boot_id="boot-1")
            for i in range(1, 6):
                spool.append("heartbeat", _hb_data(), ts=f"2026-11-26T12:00:0{i}Z", mono_ms=i * 10)

            orig_unshipped = spool.unshipped
            unbounded_calls = 0

            def spy_unshipped(*, limit=None):
                nonlocal unbounded_calls
                if limit is None:
                    unbounded_calls += 1
                return orig_unshipped(limit=limit)

            spool.unshipped = spy_unshipped  # type: ignore[method-assign]

            # 1) Transport failure path.
            def failing_transport(_batch: bytes) -> dict:
                raise audit.TransportError("network down")

            shipper = audit.AuditShipper(spool, failing_transport, batch_size=2, max_batches=2)
            res_err = shipper.ship()
            self.assertFalse(res_err.ok)
            self.assertEqual(res_err.remaining, 5)
            self.assertEqual(unbounded_calls, 0)

            # 2) max_batches exhaustion path.
            sink_root = Path(td) / "sink"

            def ok_transport(batch: bytes) -> dict:
                return audit.run_forced_command(
                    sink_root=sink_root,
                    expected_host="pastebin",
                    expected_src="tendcf",
                    stdin_bytes=batch,
                    receive_ts="2026-11-26T12:00:10Z",
                )

            shipper_cap = audit.AuditShipper(spool, ok_transport, batch_size=2, max_batches=1)
            res_cap = shipper_cap.ship()
            self.assertFalse(res_cap.ok)
            self.assertEqual(res_cap.shipped, 2)
            self.assertEqual(res_cap.remaining, 3)
            self.assertEqual(unbounded_calls, 0)

    def test_recovered_partials_dir_scales_and_survives_interrupted_multi_pin_crash(self) -> None:
        # Macroscope 4712973914 + 4713174933:
        # 1. Atomic per-pin files scale past 64 KiB total without growing state.json.
        # 2. A crash midway through writing multiple pins (leaving a torn .tmp file and only
        #    a subset of pins renamed) recovers cleanly on the next ingest without wedging.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool = audit.AuditSpool(root / "spool", host="pastebin", boot_id="boot-1")
            sink_root = root / "sink"
            e1 = spool.append("heartbeat", _hb_data(), ts="2026-11-25T12:00:01Z", mono_ms=10)
            e2 = spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:02Z", mono_ms=20)
            e3 = spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:03Z", mono_ms=30)
            e1_bytes = audit.jcs_dumps(e1) + b"\n"
            e2_bytes = audit.jcs_dumps(e2) + b"\n"
            e3_bytes = audit.jcs_dumps(e3) + b"\n"

            audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=e1_bytes,
                receive_ts="2026-11-25T12:00:05Z",
            )
            audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=e2_bytes,
                receive_ts="2026-11-26T12:00:05Z",
            )
            sink_dir = sink_root / "pastebin" / "tendcf"
            # Leave unterminated partial tails on BOTH daily files simultaneously.
            with open(sink_dir / "2026-11-25.jsonl", "ab") as fh:
                fh.write(e3_bytes[:80])
            with open(sink_dir / "2026-11-26.jsonl", "ab") as fh:
                fh.write(e3_bytes[:90])

            # Pre-populate >64 KiB worth of historical atomic pins + a leftover torn .tmp file.
            rp_dir = sink_dir / "recovered_partials"
            rp_dir.mkdir(mode=0o700)
            dummy_sha = "sha256:" + ("a" * 64)
            total_pin_bytes = 0
            for i in range(1, 650):
                p = rp_dir / f"2026-11-24.jsonl.{i}.json"
                blob = audit.jcs_dumps(
                    {
                        "file": "2026-11-24.jsonl",
                        "line": i,
                        "raw_sha256": dummy_sha,
                        "raw_len": 42,
                    }
                ) + b"\n"
                p.write_bytes(blob)
                os.chmod(p, 0o600)
                total_pin_bytes += len(blob)
            self.assertGreater(total_pin_bytes, audit.MAX_LINE_BYTES)
            # Simulate a torn pre-rename temp file left by an earlier power loss.
            torn_tmp = rp_dir / ".2026-11-26.jsonl.2.json.tmp.99999.0123456789abcdef"
            torn_tmp.write_bytes(b'{"file":"2026-11-26.jsonl","line":2')
            os.chmod(torn_tmp, 0o600)

            # Simulate crash AFTER writing the first pin (2026-11-25) and BEFORE writing the second (2026-11-26).
            orig_write_json = audit._write_json_atomic_in_dir

            def crash_on_second_pin(dfd, name, payload, mode=0o600):
                if name == "2026-11-26.jsonl.2.json":
                    raise OSError("simulated power loss between multi-pin writes")
                return orig_write_json(dfd, name, payload, mode=mode)

            audit._write_json_atomic_in_dir = crash_on_second_pin
            try:
                with self.assertRaises(OSError):
                    audit.run_forced_command(
                        sink_root=sink_root,
                        expected_host="pastebin",
                        expected_src="tendcf",
                        stdin_bytes=e3_bytes,
                        receive_ts="2026-11-26T12:00:10Z",
                    )
                self.assertTrue((rp_dir / "2026-11-25.jsonl.2.json").exists())
                self.assertFalse((rp_dir / "2026-11-26.jsonl.2.json").exists())
            finally:
                audit._write_json_atomic_in_dir = orig_write_json

            # Next retry tolerates the leftover torn .tmp file, reuses the first pin idempotently,
            # persists the second pin, seals both daily files, and commits e3 cleanly.
            ack = audit.run_forced_command(
                sink_root=sink_root,
                expected_host="pastebin",
                expected_src="tendcf",
                stdin_bytes=e3_bytes,
                receive_ts="2026-11-26T12:00:15Z",
            )
            self.assertTrue(ack["ok"])
            self.assertEqual(ack["last_seq"], 3)
            self.assertTrue((rp_dir / "2026-11-26.jsonl.2.json").exists())
            self.assertLess((sink_dir / "state.json").stat().st_size, 512)
            ver = audit.verify_local_against_sink(spool.log_path, sink_dir, expected_host="pastebin")
            codes = {f.code for f in ver.findings}
            self.assertNotIn("SINK_CORRUPT", codes)
            self.assertNotIn("SINK_STATE_MISMATCH", codes)
            self.assertIn("SINK_QUARANTINE_PRESENT", codes)

    def test_r3_m1_cursor_zero_seq_nonzero_offset_and_advance_ack_chain_check(self) -> None:
        # M1-R3 (1): acked_seq == 0 with nonzero acked_offset must raise ChainTamperError.
        with tempfile.TemporaryDirectory() as td:
            spool = audit.AuditSpool(Path(td) / "spool", host="pastebin", boot_id="boot-1")
            e1 = spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:01Z", mono_ms=10)
            e2 = spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:02Z", mono_ms=20)
            cur = json.loads(spool.cursor_path.read_text(encoding="utf-8"))
            cur["acked_offset"] = cur["local_offset"]
            spool.cursor_path.write_text(json.dumps(cur) + "\n", encoding="utf-8")
            with self.assertRaises(audit.ChainTamperError):
                spool.unshipped()

        # M1-R3 (2): advance_ack() checks JCS canonical bytes and chain continuity.
        with tempfile.TemporaryDirectory() as td:
            spool = audit.AuditSpool(Path(td) / "spool", host="pastebin", boot_id="boot-1")
            e1 = spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:01Z", mono_ms=10)
            e2 = spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:02Z", mono_ms=20)
            # Rewrite e1 as non-canonical JSON (extra whitespace) while keeping e2 intact.
            lines = spool.log_path.read_bytes().splitlines(keepends=True)
            non_canon_e1 = json.dumps(e1, indent=None, separators=(", ", ": ")).encode("utf-8") + b"\n"
            cur = json.loads(spool.cursor_path.read_text(encoding="utf-8"))
            spool.log_path.write_bytes(non_canon_e1 + lines[1])
            cur["local_offset"] = len(non_canon_e1) + len(lines[1])
            spool.cursor_path.write_text(json.dumps(cur) + "\n", encoding="utf-8")
            with self.assertRaises(audit.ChainTamperError):
                spool.advance_ack(2, e2["h"])

    def test_cli_end_to_end_via_isolated_python(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool_dir = root / "spool"
            sink_root = root / "sink"
            p1 = subprocess.run(
                [
                    sys.executable, "-I", "-S", str(AUDIT_TOOL),
                    "emit",
                    "--spool-dir", str(spool_dir),
                    "--host", "pastebin",
                    "--boot-id", "boot-cli-1",
                    "--type", "heartbeat",
                    "--data-json", json.dumps(_hb_data()),
                ],
                capture_output=True,
                check=False,
            )
            self.assertEqual(p1.returncode, 0, p1.stderr.decode())

            p2 = subprocess.run(
                [
                    sys.executable, "-I", "-S", str(AUDIT_TOOL),
                    "sink-append",
                    "--sink-root", str(sink_root),
                    "--host", "pastebin",
                    "--src", "tendcf",
                ],
                input=p1.stdout,
                capture_output=True,
                env={"PATH": "/usr/bin:/bin", "SSH_ORIGINAL_COMMAND": "audit-append tendcf"},
                check=False,
            )
            self.assertEqual(p2.returncode, 0, p2.stderr.decode())
            ack = json.loads(p2.stdout.decode())
            self.assertTrue(ack["ok"])
            self.assertEqual(ack["last_seq"], 1)

            # Disallowed SSH_ORIGINAL_COMMAND exits 2.
            p_deny = subprocess.run(
                [
                    sys.executable, "-I", "-S", str(AUDIT_TOOL),
                    "sink-append",
                    "--sink-root", str(sink_root),
                    "--host", "pastebin",
                    "--src", "tendcf",
                ],
                input=b"",
                capture_output=True,
                env={"PATH": "/usr/bin:/bin", "SSH_ORIGINAL_COMMAND": "rm -rf /"},
                check=False,
            )
            self.assertEqual(p_deny.returncode, 2)

            # Verify CLI exits 0 when intact, 1 when local log deleted.
            p_ver_ok = subprocess.run(
                [
                    sys.executable, "-I", "-S", str(AUDIT_TOOL),
                    "verify",
                    "--local", str(spool_dir / "audit.jsonl"),
                    "--sink-dir", str(sink_root / "pastebin" / "tendcf"),
                    "--host", "pastebin",
                ],
                capture_output=True,
                check=False,
            )
            self.assertEqual(p_ver_ok.returncode, 0, p_ver_ok.stdout.decode())

            (spool_dir / "audit.jsonl").unlink()
            p_ver_fail = subprocess.run(
                [
                    sys.executable, "-I", "-S", str(AUDIT_TOOL),
                    "verify",
                    "--local", str(spool_dir / "audit.jsonl"),
                    "--sink-dir", str(sink_root / "pastebin" / "tendcf"),
                    "--host", "pastebin",
                ],
                capture_output=True,
                check=False,
            )
            self.assertEqual(p_ver_fail.returncode, 1)

    def test_checked_in_example_envelopes_form_valid_chain(self) -> None:
        """Verify examples/audit-envelopes.yml parses cleanly and verifies cryptographically."""
        # Minimal stdlib parser for our simple checked-in YAML list fixture (no PyYAML under -I -S).
        records: list[dict] = []
        cur: dict | None = None
        in_data = False
        for raw_line in EXAMPLES_YML.read_text(encoding="utf-8").splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if raw_line.startswith("- "):
                if cur is not None:
                    records.append(cur)
                cur = {}
                in_data = False
                k, v = raw_line[2:].split(":", 1)
                cur[k.strip()] = _parse_yaml_scalar(v.strip())
            elif raw_line.startswith("  data:"):
                assert cur is not None
                cur["data"] = {}
                in_data = True
            elif raw_line.startswith("    ") and in_data:
                assert cur is not None
                k, v = stripped.split(":", 1)
                cur["data"][k.strip()] = _parse_yaml_scalar(v.strip())
            elif raw_line.startswith("  "):
                assert cur is not None
                in_data = False
                k, v = stripped.split(":", 1)
                cur[k.strip()] = _parse_yaml_scalar(v.strip())
        if cur is not None:
            records.append(cur)

        self.assertEqual(len(records), 9)
        self.assertEqual({r["type"] for r in records}, audit.EVENT_TYPES)
        findings = audit.verify_chain_records(records, expected_host="pastebin", expected_src="tendcf")
        self.assertEqual(findings, [], f"example chain findings: {findings}")

    def test_ship_config_disabled_exits_zero_and_enforces_private_mode(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            etc = root / "etc"
            etc.mkdir(mode=0o700)
            cfg = etc / "audit-shipper.json"
            cfg.write_text(
                json.dumps(
                    {
                        "enabled": False,
                        "host": "pastebin",
                        "spool_dir": str(root / "spool"),
                        "src": "tendcf",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            os.chmod(cfg, 0o600)

            p = subprocess.run(
                [sys.executable, "-I", "-S", str(AUDIT_TOOL), "ship", "--config", str(cfg)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(p.returncode, 0, p.stderr)
            out = json.loads(p.stdout)
            self.assertTrue(out["ok"])
            self.assertTrue(out["skipped"])

            # Mixing --config with explicit target/defaulted flags fails closed (L1).
            for extra_flag in (
                ["--host", "pastebin"],
                ["--src", "tendcf"],
                ["--ssh-bin", "/usr/bin/ssh"],
                ["--batch-size", "10"],
            ):
                p_mix = subprocess.run(
                    [
                        sys.executable, "-I", "-S", str(AUDIT_TOOL),
                        "ship", "--config", str(cfg), *extra_flag,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(p_mix.returncode, 0, f"expected refusal for {extra_flag}")
                self.assertIn("--config cannot be combined", p_mix.stderr)

            # Group-readable (0640) and owner-exec (0700) config files both rejected (L1: exact 0600).
            for bad_mode in (0o640, 0o700, 0o1600):
                os.chmod(cfg, bad_mode)
                with self.assertRaises(audit.AuditFileSecurityError):
                    audit.load_shipper_config(cfg)

            # Hardlinked config file rejected (H1/L1: nlink == 1).
            os.chmod(cfg, 0o600)
            hardlink = etc / "audit-shipper.hardlink"
            os.link(cfg, hardlink)
            try:
                with self.assertRaises(audit.AuditFileSecurityError):
                    audit.load_shipper_config(cfg)
            finally:
                hardlink.unlink()

            # Unknown key rejected even when 0600.
            os.chmod(cfg, 0o600)
            cfg.write_text(json.dumps({"enabled": False, "rogue": 1}) + "\n", encoding="utf-8")
            with self.assertRaises(audit.AuditValidationError):
                audit.load_shipper_config(cfg)

            # Enabled config validates required paths, expected_spool_dir & host/target cleanly.
            cfg.write_text(
                json.dumps(
                    {
                        "enabled": True,
                        "host": "pastebin",
                        "spool_dir": str(root / "spool"),
                        "src": "tendcf",
                        "target": "audit@nixncus.internal",
                        "identity": str(root / "id_ed25519"),
                        "known_hosts": str(root / "known_hosts"),
                        "port": 2222,
                        "batch_size": 50,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            loaded = audit.load_shipper_config(cfg, expected_spool_dir=root / "spool")
            self.assertTrue(loaded["enabled"])
            self.assertEqual(loaded["port"], 2222)
            self.assertEqual(loaded["batch_size"], 50)
            with self.assertRaises(audit.AuditValidationError):
                audit.load_shipper_config(cfg, expected_spool_dir=root / "other-spool")

    def test_h2_projector_source_loader_ignores_poisoned_pycache_pyc(self) -> None:
        # H2: _load_projector_module reads raw projector.py source via O_NOFOLLOW, never __pycache__/*.pyc.
        import importlib.util as _ilu

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bin_dir = root / "bin"
            bin_dir.mkdir(mode=0o755)
            shutil.copy2(REPO_ROOT / "tools" / "projector.py", bin_dir / "projector.py")
            shutil.copy2(AUDIT_TOOL, bin_dir / "audit_log.py")
            # Plant a poisoned .pyc matching projector.py's cache path that would create a marker if executed!
            marker = root / "pyc_pwned.marker"
            pyc_path = Path(_ilu.cache_from_source(str(bin_dir / "projector.py")))
            pyc_path.parent.mkdir(parents=True, exist_ok=True)
            evil_src = f"import pathlib; pathlib.Path({str(marker)!r}).write_text('pwned')\n"
            import py_compile
            evil_py = root / "evil.py"
            evil_py.write_text(evil_src, encoding="utf-8")
            py_compile.compile(str(evil_py), cfile=str(pyc_path), doraise=True)
            # Match mtime/size header to projector.py so normal importlib WOULD have loaded evil .pyc.
            st_proj = (bin_dir / "projector.py").stat()
            raw_pyc = bytearray(pyc_path.read_bytes())
            import struct
            raw_pyc[8:16] = struct.pack("<II", int(st_proj.st_mtime) & 0xFFFFFFFF, st_proj.st_size & 0xFFFFFFFF)
            pyc_path.write_bytes(bytes(raw_pyc))

            etc = root / "etc"
            etc.mkdir(mode=0o700)
            cfg = etc / "audit-shipper.json"
            cfg.write_text(json.dumps({"enabled": False}) + "\n", encoding="utf-8")
            os.chmod(cfg, 0o600)

            p = subprocess.run(
                [sys.executable, "-I", "-S", str(bin_dir / "audit_log.py"), "ship", "--config", str(cfg)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertFalse(marker.exists(), "poisoned __pycache__ .pyc was executed!")

            # Also verify standalone execution without sibling projector.py at all, exercising JCS via append,
            # and verify exact JCS byte-for-byte parity with tools/projector.py::_stdlib_jcs_dumps.
            (bin_dir / "projector.py").unlink()
            spool_dir = root / "spool"
            spool_dir.mkdir(mode=0o700)
            p2 = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    str(bin_dir / "audit_log.py"),
                    "emit",
                    "--spool-dir",
                    str(spool_dir),
                    "--host",
                    "pastebin",
                    "--boot-id",
                    "boot-1",
                    "--type",
                    "heartbeat",
                    "--data-json",
                    json.dumps(_hb_data()),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(p2.returncode, 0, p2.stderr)
            self.assertFalse(marker.exists(), "poisoned __pycache__ .pyc was executed on append!")
            proj_spec = importlib.util.spec_from_file_location("_tendcf_proj_parity", REPO_ROOT / "tools" / "projector.py")
            assert proj_spec is not None and proj_spec.loader is not None
            proj_mod = importlib.util.module_from_spec(proj_spec)
            proj_spec.loader.exec_module(proj_mod)
            sample = {"z": 1, "a": [True, False, None, 0.0, -0.0, 1e-6, 1e20, "x\n\t\x01\"\\"], "\ue000": 1, "\U00010000": 2}
            self.assertEqual(audit.jcs_dumps(sample), proj_mod._stdlib_jcs_dumps(sample))

    def test_m6_ssh_stderr_sentinel_never_leaks_to_ship_output(self) -> None:
        # M6: remote-influenced SSH stderr must never appear in TransportError, ShipResult, stdout, or stderr.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spool = audit.AuditSpool(root / "spool", host="pastebin", boot_id="boot-1")
            spool.append("heartbeat", _hb_data(), ts="2026-11-26T12:00:01Z", mono_ms=10)
            sentinel = "REMOTE_SECRET_BANNER_SENTINEL_999"
            fake_ssh = root / "fake-ssh"
            fake_ssh.write_text(f"#!/bin/sh\necho '{sentinel}' >&2\nexit 255\n", encoding="utf-8")
            fake_ssh.chmod(0o755)
            id_file = root / "id_ed25519"
            id_file.write_text("dummy\n", encoding="utf-8")
            id_file.chmod(0o600)
            kh_file = root / "known_hosts"
            kh_file.write_text("example ssh-ed25519 AAAA\n", encoding="utf-8")
            kh_file.chmod(0o644)

            transport = audit.make_ssh_append_transport(
                target="audit@nixncus.internal",
                identity_file=id_file,
                known_hosts_file=kh_file,
                ssh_bin=str(fake_ssh),
            )
            res = audit.AuditShipper(spool, transport).ship()
            self.assertFalse(res.ok)
            self.assertEqual(res.error, "ssh_exit_255")
            self.assertNotIn(sentinel, res.error or "")

    def test_recovered_partials_regex_rejects_trailing_newline(self) -> None:
        # N1-R6: \Z anchor rejects trailing newline filenames inside recovered_partials/.
        self.assertIsNone(audit.RECOVERED_PARTIAL_FILE_RE.match("2026-11-26.jsonl.1.json\n"))
        self.assertIsNone(
            audit.RECOVERED_PARTIAL_TMP_RE.match(".2026-11-26.jsonl.1.json.tmp.123.0123456789abcdef\n")
        )


def _parse_yaml_scalar(val: str):
    if val.startswith('"') and val.endswith('"'):
        return val[1:-1]
    if val == "true":
        return True
    if val == "false":
        return False
    if val.isdigit():
        return int(val)
    return val


if __name__ == "__main__":
    unittest.main()
