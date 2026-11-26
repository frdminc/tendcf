#!/usr/bin/env bash
# The root-owned install of deploy/linux/tendcf-install.sh, end to end, on a
# systemd host (the ubuntu VM jobs). Run as root, or let it re-run itself under
# passwordless sudo. Needs the CI build at /opt/tendcf (the build-fork action
# with prefix /opt/tendcf).
#
# It proves the canonical shape linux-targets.md step 7 settled on, with the
# canary service (deploy/linux/canary/):
#
#   1. install: the tree and the policy are root-owned and not group/other
#      writable, the CMDB data is root-only;
#   2. run-once: the canary unit is rendered, enabled and running as `nobody`;
#   3. enable: a root cf-execd service is running; and cf-execd's own path
#      (executor control -> cf-agent -> the installed promises.cf) puts a
#      stopped canary back, which is what the timer will do on a host;
#   4. the tombstone: new data, one run, and the unit is gone from the manager.
#
# Writes /etc/systemd/system/{tendcf.canary.service,tendcf-execd.service},
# /opt/tendcf (including its work directory), and removes the units again on
# exit. It takes over /opt/tendcf: run it on a CI VM, not on a host.
set -euo pipefail

if [ "$(id -u)" != 0 ]; then
    exec sudo -n "$0" "$@"
fi

repo="$(cd "$(dirname "$0")/../.." && pwd)"
installer="$repo/deploy/linux/tendcf-install.sh"
canary="$repo/deploy/linux/canary"
unit=tendcf.canary.service
fail=0

cleanup() {
    "$installer" uninstall --purge-spool >/dev/null 2>&1 || true
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$unit"
    systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

check() {  # check NAME COND...
    local name="$1"; shift
    if "$@"; then echo "ok   $name"; else echo "FAIL $name"; fail=1; fi
}
owned_by_root_unwritable() {  # no entry under PATH is non-root or group/other-writable
    [ -z "$(find "$1" \( ! -user root -o ! -group root -o -perm /022 \) ! -type l -print -quit)" ]
}
unit_prop() { systemctl show -p "$1" --value "$unit"; }

echo "# 1. install"
proj_sha="$(sha256sum "$repo/tools/projector.py" | awk '{print $1}')"
audit_sha="$(sha256sum "$repo/tools/audit_log.py" | awk '{print $1}')"
"$installer" install \
    --projector-src "$repo/tools/projector.py" --projector-sha256 "$proj_sha" \
    --audit-log-src "$repo/tools/audit_log.py" --audit-log-sha256 "$audit_sha" \
    --data "$canary/host_specific.json"
wd="$("$installer" workdir)"
check "/opt/tendcf is root-owned and not group/other-writable" owned_by_root_unwritable /opt/tendcf
check "installed policy is root-owned and not group/other-writable" \
    owned_by_root_unwritable "$wd/inputs"
check "projector.py is installed root:root 0644 (non-symlink)" \
    bash -c "[ -f /opt/tendcf/share/tendcf/bin/projector.py ] && [ ! -L /opt/tendcf/share/tendcf/bin/projector.py ] && [ \"\$(stat -c '%U:%G %a' /opt/tendcf/share/tendcf/bin/projector.py)\" = 'root:root 644' ]"
check "audit_log.py is installed root:root 0644 (non-symlink)" \
    bash -c "[ -f /opt/tendcf/share/tendcf/bin/audit_log.py ] && [ ! -L /opt/tendcf/share/tendcf/bin/audit_log.py ] && [ \"\$(stat -c '%U:%G %a' /opt/tendcf/share/tendcf/bin/audit_log.py)\" = 'root:root 644' ]"
check "audit-shipper.json is installed root:root 0600" \
    bash -c "[ -f /opt/tendcf/etc/audit-shipper.json ] && [ ! -L /opt/tendcf/etc/audit-shipper.json ] && [ \"\$(stat -c '%U:%G %a' /opt/tendcf/etc/audit-shipper.json)\" = 'root:root 600' ]"
check "auditd tripwire rules installed root:root 0640" \
    bash -c "[ -f /etc/audit/rules.d/99-tendcf-tripwire.rules ] && [ \"\$(stat -c '%U:%G %a' /etc/audit/rules.d/99-tendcf-tripwire.rules)\" = 'root:root 640' ]"
check "AIDE tripwire rules installed root:root 0644" \
    bash -c "[ -f /etc/aide/aide.conf.d/99-tendcf-tripwire ] && [ \"\$(stat -c '%U:%G %a' /etc/aide/aide.conf.d/99-tendcf-tripwire)\" = 'root:root 644' ]"
check "CMDB data is root:root 0600" \
    bash -c "[ \"\$(stat -c '%U:%G %a' $wd/data/host_specific.json)\" = 'root:root 600' ]"

echo "# 2. run-once"
"$installer" run-once
check "canary unit file rendered" test -f "/etc/systemd/system/$unit"
check "canary active" systemctl is-active --quiet "$unit"
check "canary enabled" systemctl is-enabled --quiet "$unit"
check "canary runs as nobody" bash -c "[ \"\$(systemctl show -p User --value $unit)\" = nobody ]"
check "canary has the entry's Restart=on-failure" bash -c "[ \"\$(systemctl show -p Restart --value $unit)\" = on-failure ]"

echo "# 3. cf-execd"
"$installer" enable
check "tendcf-execd.service active" systemctl is-active --quiet tendcf-execd.service
check "cf-execd runs as root" bash -c "[ \"\$(ps -o user= -C cf-execd | sort -u | tr -d ' ')\" = root ]"
systemctl stop tendcf-execd.service
systemctl stop "$unit"
check "canary stopped for the drift test" bash -c "! systemctl is-active --quiet $unit"
timeout 300 /opt/tendcf/bin/cf-execd --once >/tmp/tendcf-execd-once.out 2>&1 || true
check "cf-execd's own run restored the canary" systemctl is-active --quiet "$unit"
if [ "$fail" != 0 ]; then echo "--- cf-execd --once output ---"; cat /tmp/tendcf-execd-once.out; fi

echo "# 4. tombstone"
"$installer" data "$canary/host_specific-absent.json"
"$installer" run-once
check "tombstone removed the unit file" bash -c "[ ! -e /etc/systemd/system/$unit ]"
check "tombstone stopped the canary" bash -c "! systemctl is-active --quiet $unit"
check "manager forgot the unit (not-found)" bash -c "[ \"\$(systemctl show -p LoadState --value $unit)\" = not-found ]"

echo "# 5. installer hardening (#53, #57, #58)"
scratch="$(mktemp -d)"
cleanup_all() {
    rm -rf "$scratch" "$wd/inputs/def.json"
    cleanup
}
trap cleanup_all EXIT

live_data="$wd/data/host_specific.json"
orig_snap="$scratch/orig.json"
cp -p "$live_data" "$orig_snap"
orig_ino="$(stat -c '%i' "$live_data")"
orig_mtime="$(stat -c '%Y.%y' "$live_data")"

# #53: non-canonical JCS (trailing newline) and forbidden pre_action argv refused without touching live data
bad_nl="$scratch/noncanonical.json"
printf '%s\n' "$(cat "$canary/host_specific.json")" > "$bad_nl"
check "#53 non-canonical projection (trailing newline) refused" \
    bash -c "! \"$installer\" data \"$bad_nl\" >/dev/null 2>&1"
check "#53 live data unchanged (bytes, inode, mtime) after non-canonical refusal" \
    bash -c "cmp -s \"$orig_snap\" \"$live_data\" && [ \"\$(stat -c '%i' \"$live_data\")\" = \"$orig_ino\" ] && [ \"\$(stat -c '%Y.%y' \"$live_data\")\" = \"$orig_mtime\" ]"

bad_argv="$scratch/bad-argv.json"
printf '%s' '{"vars":{"tendcf_interlock":{"bad-check":{"blocks":"enclosing-bundle","bundle":"demo","defines_class":"demo_ok","pre_action":{"command":["/usr/bin/true","has space"],"expect_exit":0,"timeout_seconds":5},"report":true,"state":"present"}}}}' > "$bad_argv"
check "#53 forbidden pre_action argv refused by projector gate" \
    bash -c "! \"$installer\" data \"$bad_argv\" >/dev/null 2>&1"
check "#53 live data unchanged after forbidden argv refusal" \
    bash -c "cmp -s \"$orig_snap\" \"$live_data\" && [ \"\$(stat -c '%i' \"$live_data\")\" = \"$orig_ino\" ]"

# #57: CMDB refusal fixture rejected before touching live data
check "#57 cmdb-classes-section fixture refused without touching live data" \
    bash -c "! \"$installer\" data \"$repo/tests/policy/fixtures/cmdb-classes-section.json\" >/dev/null 2>&1 && cmp -s \"$orig_snap\" \"$live_data\" && [ \"\$(stat -c '%i' \"$live_data\")\" = \"$orig_ino\" ]"

# #57 Gate 2 direct check against real cf-promises --show-classes (valid vs tendcf_cmdb_refused)
gate2_wd="$scratch/gate2-wd"
install -d -m 0755 "$gate2_wd/bin" "$gate2_wd/outputs" "$gate2_wd/modules" "$gate2_wd/state"
install -d -m 0700 "$gate2_wd/ppkeys" "$gate2_wd/data"
cp -pRP "$wd/inputs" "$gate2_wd/inputs"
printf '%s' '{"vars":{}}' > "$gate2_wd/data/host_specific.json"
chmod 0600 "$gate2_wd/data/host_specific.json"
check "#57 real cf-promises accepts empty vars projection with no tendcf_cmdb_refused" \
    bash -c "out=\"\$(LD_LIBRARY_PATH=/opt/tendcf/lib /opt/tendcf/bin/cf-promises --workdir \"$gate2_wd\" -f \"$gate2_wd/inputs/promises.cf\" --show-classes)\" && [ -n \"\$out\" ] && ! printf '%s\n' \"\$out\" | awk '\$1 == \"tendcf_cmdb_refused\" || \$1 ~ /^tendcf_cmdb_problem_/ { found=1 } END { exit !found }'"
cp "$repo/tests/policy/fixtures/cmdb-classes-section.json" "$gate2_wd/data/host_specific.json"
chmod 0600 "$gate2_wd/data/host_specific.json"
check "#57 real cf-promises flags tendcf_cmdb_refused on cmdb-classes-section" \
    bash -c "out=\"\$(LD_LIBRARY_PATH=/opt/tendcf/lib /opt/tendcf/bin/cf-promises --workdir \"$gate2_wd\" -f \"$gate2_wd/inputs/promises.cf\" --show-classes)\" && printf '%s\n' \"\$out\" | awk '\$1 == \"tendcf_cmdb_refused\" { found=1 } END { exit !found }'"

# #57 Gate 2 end-to-end pre-publish refusal on a projector-valid projection:
# plant a rogue augments file at $wd/inputs/def.json (where CFEngine loads
# augments from). Gate 1 (projector.py --check) passes on the valid canary
# projection, then Gate 2 copies $wd/inputs into the staged workdir, sees
# tendcf_cmdb_problem_foreign_class / tendcf_cmdb_refused, and refuses BEFORE
# live host_specific.json is ever touched (bytes, inode, and mtime unchanged).
printf '%s' '{"classes":{"rogue_augments_class":["any"]}}' > "$wd/inputs/def.json"
chmod 0600 "$wd/inputs/def.json"
check "#57 Gate 2 pre-publish tendcf_cmdb_refused rejects projector-valid data with zero live exposure" \
    bash -c "! \"$installer\" data \"$canary/host_specific.json\" >/dev/null 2>&1 && cmp -s \"$orig_snap\" \"$live_data\" && [ \"\$(stat -c '%i' \"$live_data\")\" = \"$orig_ino\" ] && [ \"\$(stat -c '%Y.%y' \"$live_data\")\" = \"$orig_mtime\" ]"
rm -f "$wd/inputs/def.json"

# #58: concurrent publishers serialize cleanly with zero collisions and zero temp leftovers
pids=()
for i in 1 2 3 4 5 6; do
    if [ $((i % 2)) -eq 0 ]; then
        "$installer" data "$canary/host_specific.json" >/dev/null &
    else
        "$installer" data "$canary/host_specific-absent.json" >/dev/null &
    fi
    pids+=("$!")
done
conc_ok=1
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then conc_ok=0; fi
done
check "#58 all 6 concurrent publishers exited 0" test "$conc_ok" -eq 1
check "#58 final live data matches one of the two valid projections byte-for-byte" \
    bash -c "cmp -s \"$canary/host_specific.json\" \"$live_data\" || cmp -s \"$canary/host_specific-absent.json\" \"$live_data\""
check "#58 final live data passes cf-promises --show-classes without tendcf_cmdb_refused" \
    bash -c "out=\"\$(LD_LIBRARY_PATH=/opt/tendcf/lib /opt/tendcf/bin/cf-promises --workdir \"$wd\" -f \"$wd/inputs/promises.cf\" --show-classes)\" && [ -n \"\$out\" ] && ! printf '%s\n' \"\$out\" | awk '\$1 == \"tendcf_cmdb_refused\" || \$1 ~ /^tendcf_cmdb_problem_/ { found=1 } END { exit !found }'"
check "#58 zero leftover staging/backup temp files in workdir/data" \
    bash -c "[ -z \"\$(find \"$wd/data\" -maxdepth 1 -mindepth 1 ! -name host_specific.json ! -name .publish.lock -print)\" ]"

echo "# 6. audit shipper & uninstall (#119 Slice 2)"
check "#119 tendcf-audit-shipper.timer enabled and active" \
    bash -c "systemctl is-enabled --quiet tendcf-audit-shipper.timer && systemctl is-active --quiet tendcf-audit-shipper.timer"
check "#119 tendcf-audit-shipper.service runs cleanly with disabled default config" \
    systemctl start tendcf-audit-shipper.service
"$installer" uninstall --purge-spool
check "#119 uninstall removes tendcf-execd.service and shipper units" \
    bash -c "[ ! -e /etc/systemd/system/tendcf-execd.service ] && [ ! -e /etc/systemd/system/tendcf-audit-shipper.service ] && [ ! -e /etc/systemd/system/tendcf-audit-shipper.timer ]"
check "#119 uninstall removes auditd and AIDE tripwire rules" \
    bash -c "[ ! -e /etc/audit/rules.d/99-tendcf-tripwire.rules ] && [ ! -e /etc/aide/aide.conf.d/99-tendcf-tripwire ]"
check "#119 uninstall removes audit_log.py, shipper config, tripwire templates, and purged spool" \
    bash -c "[ ! -e /opt/tendcf/share/tendcf/bin/audit_log.py ] && [ ! -e /opt/tendcf/etc/audit-shipper.json ] && [ ! -e /opt/tendcf/share/tendcf/tripwire ] && [ ! -e /opt/tendcf/var/audit-spool ]"

if [ "$fail" != 0 ]; then exit 1; fi
echo; echo "all install tests passed"
