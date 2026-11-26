# Android Tamper-Evident Audit Push Path (Issue #119)

**Status:** Design specified; implementation **explicitly deferred** pending
(1) provisioning of the shared append-only sink host (`nixncus`,
[djbclark-ade #1013](https://github.com/djbclark/djbclark-ade/issues/1013)) and
(2) construction of the thin Kotlin `tendcf-agent` prototype (see
[`../review-2026-11-13/07-android-landscape.md`](../review-2026-11-13/07-android-landscape.md)
§5).

This note closes acceptance criterion 7 of
[frdminc/tendcf#119](https://github.com/frdminc/tendcf/issues/119) by pinning
the wire contract, privilege boundary, offline-queue semantics, and tripwire
limits for Android devices so the later Kotlin/Termux implementation reuses
[`../../schema/audit-envelope.schema.json`](../../schema/audit-envelope.schema.json)
and [`../../tools/audit_log.py`](../../tools/audit_log.py) unchanged.

## 1. Privilege and UID Boundary (Preserved)

Per the 2026-11-14 operator rulings recorded in
[`../review-2026-11-13/07-android-landscape.md`](../review-2026-11-13/07-android-landscape.md)
§5 (`B3` Termux CFEngine + thin Kotlin agent; `Q3` Kotlin agent owns device
JSONL and index):

1. **No UID collapse:** Termux (`com.termux` UID) runs CFEngine convergence and
   `tendcf-validate`, while `tendcf-agent` (its own Android app UID) owns the
   trust anchor, consent decisions, and the device's canonical audit JSONL +
   index in app-private storage (`/data/user/0/<agent-pkg>/files/audit/`).
2. **No inbound listener or cross-profile localhost socket:** Android 17 blocks
   cross-profile loopback traffic by default (`07-android-landscape.md` §3.4),
   and `cf-serverd` in Termux dies when backgrounded. Audit shipping is strictly
   **device-initiated outbound push**, never a host-to-phone pull.
3. **Never blocks convergence:** Mirroring the Linux and macOS contract, a
   missing network or unreachable sink only delays shipping. Local append to the
   hash-chained spool succeeds offline; `cf-agent` in Termux never waits on the
   sink.

## 2. Shared Wire Contract and Transport Order

Android emits the exact v1 envelope defined by
[`../../schema/audit-envelope.schema.json`](../../schema/audit-envelope.schema.json)
(`v=1`, `src="tendcf"`, `host`, `boot_id`, `seq`, `ts`, `mono_ms`, `prev`,
`type`, `data`, `h = sha256(ascii(prev) || jcs(entry_without_h))`) and enforces
the identical redaction allowlist (no CMDB values, no goal-file contents, no
command output, no env vars, no secrets/keys, no free-text consent notes).

| Phase | Owner | Transport | Key storage | Trigger |
| --- | --- | --- | --- | --- |
| **State 1 (Termux prototype)** | Termux userland (`tools/audit_log.py ship`) | Hardened OpenSSH forced-command drop (`audit-append tendcf`) to `nixncus` | Per-device write-only Ed25519 key in Termux private dir (`0700`/`0600`), pinned `known_hosts` | `Termux:Boot` / periodic `runit` or `crond` job when network is up |
| **State 2 (thin Kotlin `tendcf-agent`)** | `tendcf-agent` app UID | Primary: SSH append-only drop (`audit-append tendcf`) via embedded SSH client; Fallback: HTTPS mTLS / Ed25519-signed POST bridge to the same append-only sink contract if SSH is constrained by network or sandbox | Hardware-backed Android Keystore key (non-exportable) or app-private `0600` write-only SSH key | Android `WorkManager` periodic job (`NetworkType.CONNECTED`, backoff on failure; respects Android 16 JobScheduler quotas) |

Both phases target the exact same per-host append-only sink stream
(`<sink_root>/<host>/tendcf/YYYY-MM-DD.jsonl`) enforced by
`tools/audit_log.py sink-append`, where the device's credential can only append
(no read, list, rename, truncate, or delete).

## 3. Intermittent Connectivity and Privilege-Degradation Semantics

1. **Reconnect resume:** The sink tracks `last_seq` and `last_h` per host. On
   reconnect, the device ships from its durable local cursor and reconciles
   idempotently against the sink's JSON ack (`last_seq`, `last_h`), matching
   `AuditShipper` in [`../../tools/audit_log.py`](../../tools/audit_log.py).
2. **Silent host = `"unknown"`, never `"fine"`:** A sleeping or offline phone
   past the liveness window is reported by `tools/audit_log.py status` as
   `"unknown"` (never silently treated as compliant).
3. **Shizuku/helper reboot drop:** When an unrooted phone reboots and loses its
   wireless-debugging Shizuku helper until Wi-Fi + unattended boot start recover
   it (`07-android-landscape.md` §2, §5.4), `tendcf-agent` records a `lifecycle`
   or `promise_outcome` event (`not_kept`, `privilege-unavailable`) rather than
   silently skipping shell-tier promises.

## 4. Tripwire Boundary on Unrooted Android

Kernel `auditd` (`auditctl -e 2`), AIDE, and Endpoint Security (`eslogger`) are
unavailable on unrooted Android. Instead, tamper resistance relies on four
controls matching the Android threat model:

1. **App-private storage isolation:** SELinux and Android UID separation isolate
   `tendcf-agent`'s trust anchor, approval ledger, and audit spool from Termux
   and other apps.
2. **Trusted-signer allowlist:** `ShizukuTendCF` restricts privileged helper
   access to pinned signer fingerprints.
3. **Dual verification:** Every goal bundle is checked by `tendcf-validate` in
   Termux and independently re-verified (Ed25519 signature + monotonic
   high-water mark) by `tendcf-agent` before consent or execution.
4. **Off-device append-only witness:** Once shipped to `nixncus`, any local
   truncation, wipe, or rewrite of the device's audit log is detected by
   `tools/audit_log.py verify` against the sink copy.

## 5. Exit Criteria to Un-Defer Implementation

Implementation moves from deferred to active once:

1. `nixncus` append-only sink host is provisioned and accepting per-host
   write-only SSH keys ([djbclark-ade #1013](https://github.com/djbclark/djbclark-ade/issues/1013)).
2. The State 1 Termux + thin Kotlin `tendcf-agent` workspace exists in the repo,
   providing a concrete build/test harness for the `WorkManager` shipper and
   local spool integration.
