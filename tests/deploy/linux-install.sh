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
# /var/cfengine and /opt/tendcf, and removes the units again on exit. Never run
# it on a machine that has a real /var/cfengine.
set -euo pipefail

if [ "$(id -u)" != 0 ]; then
    exec sudo -n "$0" "$@"
fi

repo="$(cd "$(dirname "$0")/../.." && pwd)"
installer="$repo/deploy/linux/tendcf-install.sh"
canary="$repo/deploy/linux/canary"
unit=tendcf.canary.service
fail=0

if [ -e /var/cfengine/ppkeys ]; then
    echo "refusing to run: /var/cfengine already exists on this host" >&2
    exit 2
fi

cleanup() {
    "$installer" disable >/dev/null 2>&1 || true
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
"$installer" install --data "$canary/host_specific.json"
check "/opt/tendcf is root-owned and not group/other-writable" owned_by_root_unwritable /opt/tendcf
check "installed policy is root-owned and not group/other-writable" \
    owned_by_root_unwritable /var/cfengine/inputs
check "CMDB data is root:root 0600" \
    bash -c "[ \"\$(stat -c '%U:%G %a' /var/cfengine/data/host_specific.json)\" = 'root:root 600' ]"

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

if [ "$fail" != 0 ]; then exit 1; fi
echo; echo "all install tests passed"
