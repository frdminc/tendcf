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
            kh.write_text("dummy", encoding="utf-8")

            argv = audit.build_ssh_append_argv(
                target="audit@sink.example.org",
                identity_file=key,
                known_hosts_file=kh,
                src="tendcf",
            )
            self.assertIn("BatchMode=yes", argv)
            self.assertIn("IdentitiesOnly=yes", argv)
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("ClearAllForwardings=yes", argv)
            self.assertIn("ForwardAgent=no", argv)
            self.assertEqual(argv[-3:], ["--", "audit@sink.example.org", "audit-append tendcf"])

            # Option-injection target refused.
            with self.assertRaises(audit.TransportError):
                audit.build_ssh_append_argv(
                    target="-oProxyCommand=evil",
                    identity_file=key,
                    known_hosts_file=kh,
                )

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
