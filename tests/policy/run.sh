#!/usr/bin/env bash
# Generic-bundle tests for policy/tendcf_services.cf against a real cf-agent.
#
# Platform-independent on purpose: nothing here touches launchd or
# /Library/LaunchDaemons, so the same run passes on a Linux CI runner and on
# the Mac dev build. Three checks:
#
#   1. wiring: cf-promises parses the bundle with the example projection
#      (examples/host_specific.json) installed as CMDB data, so every
#      data:variables.* reference resolves the way the bundle assumes.
#   2. interlock refusal, enforce mode: an interlock whose pre_action fails
#      blocks every service tagged with its bundle (bundle-scoped refusal,
#      architecture-DEFINITIVE-v3.md S7/D16). The fixture has two present
#      services under the blocked bundle and nothing else, so a correct run
#      renders no unit and runs no launchctl; an incorrect one would, which
#      is exactly the actuation a Linux host must never see.
#   3. interlock satisfied, enforce mode: the same interlock with a passing
#      pre_action and no services. The command must run and no refusal may
#      be reported. This is the twin that found the 2026-10-29 ordering
#      defect (verdict fixed before the command ran); without it, check 2
#      passes on a bundle that refuses everything. Services are left out so
#      the satisfied path never reaches the launchd promises on Linux; the
#      render itself is Mac-only until the systemd branch exists.
#   4. flavour guard, enforce mode: a satisfied interlock and a present
#      service whose unit flavour is runit. Implemented adapters are launchd
#      (darwin) and systemd (Linux booted by systemd), so the entry must be
#      refused by name and nothing rendered, on every host (linux-targets.md
#      step 3: the fail-closed guard, with this as its negative test).
#   5. host guard, enforce mode, non-Darwin only: a satisfied interlock and
#      two present launchd services. launchd exists only on darwin, so a
#      Linux host must refuse both, write nothing under /Library and run no
#      launchctl. This is the wrong-platform actuation the Opus review
#      ranked highest (F1). Skipped on Darwin, where the same fixture is the
#      real render path and needs root.
#   6. systemd adapter, enforce mode. Where the host is not booted by
#      systemd (Darwin, a container), a systemd entry must be refused and
#      nothing run. On a systemd host the full lifecycle runs against the
#      real manager, only when TENDCF_TEST_SYSTEMD=1 because it writes
#      /etc/systemd/system and needs root (root, or passwordless sudo):
#      install (unit rendered, enabled, started), a second run that does
#      nothing, a changed unit (re-rendered, restarted, disabled), and the
#      tombstone (stopped, disabled, removed, manager reloaded) with its own
#      second run that does nothing.
#
# The pre_action commands are /usr/bin/true and /usr/bin/false, which exist
# on Linux and macOS alike; /bin/true does not exist on macOS, and a missing
# executable is a failed promise, which looks like a refusal.
#
# Usage: tests/policy/run.sh [--bindir DIR]
#   DIR holds cf-agent and cf-promises (default: $PATH). Exit 0 on pass.
#   Prints the agent version first: every result names the build it ran on.
set -euo pipefail
# cf-agent refuses a workdir, state dir or policy file that others can
# write; a host with umask 002 (pastebin, 2026-10-29) would hand it exactly
# that. The scratch tree is ours, so its mode is ours too.
umask 077

bindir=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bindir) bindir="$2"; shift 2 ;;
        *) echo "usage: $0 [--bindir DIR]" >&2; exit 2 ;;
    esac
done
if [ -n "$bindir" ]; then
    cf_agent="$bindir/cf-agent"; cf_promises="$bindir/cf-promises"
else
    cf_agent="$(command -v cf-agent)"; cf_promises="$(command -v cf-promises)"
fi

repo="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/tendcf-policy.XXXXXX")"
mkdir -p "$work/data" "$work/inputs" "$work/state" "$work/ppkeys" "$work/tmp" "$work/bin"
chmod 700 "$work/ppkeys"   # cf-agent refuses a world-readable key directory
# cf-agent pre-validates policy with $(sys.workdir)/bin/cf-promises and falls
# back to the built-in failsafe (a policy-hub fetch) when it is missing.
ln -s "$(dirname "$cf_promises")"/cf-* "$work/bin/"

"$cf_agent" --version
echo

# cf-agent refuses to run without its host key pair; generate one into the
# scratch workdir (CFENGINE_TEST_OVERRIDE_WORKDIR is how core's own
# tests/acceptance/testall points every tool at a throwaway workdir).
export CFENGINE_TEST_OVERRIDE_WORKDIR="$work"
"$bindir${bindir:+/}cf-key" >/dev/null 2>&1 || true

cat > "$work/inputs/entry.cf" <<EOF
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_services" };
}
EOF

fail=0
check() {  # check NAME COND...
    local name="$1"; shift
    if "$@"; then echo "ok   $name"; else echo "FAIL $name"; fail=1; fi
}

echo "# 1. wiring: cf-promises with examples/host_specific.json"
cp "$repo/examples/host_specific.json" "$work/data/host_specific.json"
check "cf-promises parses the bundle with the example projection" \
    "$cf_promises" -f "$work/inputs/entry.cf"

echo "# 2. interlock refusal, enforce mode (-K, no -n)"
cp "$repo/tests/policy/fixtures/interlock-refused.json" "$work/data/host_specific.json"
out="$work/refused.out"
# -I logs every command cf-agent executes, which is what the negative
# assertions below read. Exit status is not asserted: a failed pre_action is
# a failed commands: promise, so cf-agent may exit non-zero and still be
# correct; the assertions are about what it did and did not do.
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "refusal reported for the failing interlock" \
    grep -q "tendcf: interlock 'demo-check' not satisfied, bundle 'demo' refused" "$out"
check "no launchctl invocation" \
    bash -c "! grep -q launchctl '$out'"
check "no unit rendered for a blocked service" \
    bash -c "! grep -q 'LaunchDaemons/com.tendcf.demo' '$out'"
check "refusal reported exactly once (interlock-scoped, not per service)" \
    bash -c "[ \"\$(grep -c \"bundle 'demo' refused\" '$out')\" = 1 ]"

echo "# 3. interlock satisfied, enforce mode"
cp "$repo/tests/policy/fixtures/interlock-satisfied.json" "$work/data/host_specific.json"
out="$work/satisfied.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "pre_action executed" \
    grep -q "Executing .*'/usr/bin/true'" "$out"
check "no refusal reported for the satisfied interlock" \
    bash -c "! grep -q \"bundle 'demo' refused\" '$out'"

echo "# 4. flavour guard: runit entry refused on every host"
cp "$repo/tests/policy/fixtures/flavour-refused.json" "$work/data/host_specific.json"
out="$work/flavour.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "runit entry refused by name" \
    grep -q "tendcf: service 'demo-runit' refused: unit flavour 'runit' is not implemented on this host" "$out"
check "no interlock refusal (the interlock passed)" \
    bash -c "! grep -q \"bundle 'demo' refused\" '$out'"
check "nothing rendered for the runit entry" \
    bash -c "! grep -q 'Created file' '$out'"
check "no launchctl invocation" \
    bash -c "! grep -q launchctl '$out'"

if [ "$(uname)" != Darwin ]; then
    echo "# 5. host guard: launchd entries refused on $(uname)"
    cp "$repo/tests/policy/fixtures/launchd-present.json" "$work/data/host_specific.json"
    out="$work/host.out"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "both launchd entries refused by name" \
        bash -c "[ \"\$(grep -c \"refused: unit flavour 'launchd' is not implemented on this host\" '$out')\" = 2 ]"
    check "nothing rendered under /Library" \
        bash -c "! grep -q 'LaunchDaemons/com.tendcf.demo' '$out'"
    check "no launchctl invocation" \
        bash -c "! grep -q launchctl '$out'"
else
    echo "# 5. host guard: skipped on Darwin (launchd fixture is the real render path there)"
fi

echo "# 6. systemd adapter"
unit=tendcf-test-demo.service
unit_path=/etc/systemd/system/$unit
no_systemctl() { ! grep -Eq "Executing .*systemctl" "$1"; }
if [ "$(uname)" = Linux ] && [ -d /run/systemd/system ]; then
    if [ "${TENDCF_TEST_SYSTEMD:-}" != 1 ]; then
        echo "skip systemd lifecycle: set TENDCF_TEST_SYSTEMD=1 (writes /etc/systemd/system, needs root)"
    elif [ "$(id -u)" = 0 ]; then
        as_root() { "$@"; }
    elif sudo -n true 2>/dev/null; then
        as_root() { sudo -n "$@"; }
    else
        check "root or passwordless sudo available for the systemd lifecycle" false
    fi
    if declare -F as_root >/dev/null; then
        cleanup_unit() {
            as_root systemctl disable --now "$unit" >/dev/null 2>&1 || true
            as_root rm -f "$unit_path"
            as_root systemctl daemon-reload >/dev/null 2>&1 || true
        }
        trap cleanup_unit EXIT
        sysd_run() {  # sysd_run FIXTURE OUT
            cp "$repo/tests/policy/fixtures/$1" "$work/data/host_specific.json"
            as_root env CFENGINE_TEST_OVERRIDE_WORKDIR="$work" \
                "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$2" 2>&1 || true
        }
        unit_active() { as_root systemctl is-active --quiet "$unit"; }
        unit_enabled() { as_root systemctl is-enabled --quiet "$unit"; }
        main_pid() { systemctl show -p MainPID --value "$unit"; }

        sysd_run systemd-present.json "$work/sysd1.out"
        check "unit rendered" \
            grep -q 'ExecStart="/usr/bin/sleep" "3600"' "$unit_path"
        check "unit passes systemd-analyze verify" \
            systemd-analyze verify "$unit_path"
        check "unit active after the first run" unit_active
        check "unit enabled after the first run" unit_enabled
        pid1="$(main_pid)"

        sysd_run systemd-present.json "$work/sysd2.out"
        check "second run issues no systemctl command" no_systemctl "$work/sysd2.out"
        check "second run leaves the same process" \
            bash -c "[ \"\$(systemctl show -p MainPID --value $unit)\" = '$pid1' ]"

        sysd_run systemd-changed.json "$work/sysd3.out"
        check "changed unit re-rendered" \
            grep -q 'ExecStart="/usr/bin/sleep" "3601"' "$unit_path"
        check "changed unit restarted onto a new process" \
            bash -c "[ \"\$(systemctl show -p MainPID --value $unit)\" != '$pid1' ]"
        check "changed unit still active" unit_active
        check "enabled:false removed the boot link" bash -c "! systemctl is-enabled --quiet $unit"

        sysd_run systemd-absent.json "$work/sysd4.out"
        check "tombstone removed the unit file" bash -c "[ ! -e '$unit_path' ]"
        check "tombstone stopped the unit" bash -c "! systemctl is-active --quiet $unit"
        check "tombstone reloaded the manager (unit not found)" \
            bash -c "[ \"\$(systemctl show -p LoadState --value $unit)\" = not-found ]"

        sysd_run systemd-absent.json "$work/sysd5.out"
        check "second tombstone run issues no systemctl command" no_systemctl "$work/sysd5.out"
    fi
elif [ "${TENDCF_TEST_SYSTEMD:-}" = 1 ]; then
    check "TENDCF_TEST_SYSTEMD=1 needs a host booted by systemd" false
else
    cp "$repo/tests/policy/fixtures/systemd-present.json" "$work/data/host_specific.json"
    out="$work/sysd-host.out"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "systemd entry refused by name on a host not booted by systemd" \
        grep -q "tendcf: service '$unit' refused: unit flavour 'systemd' is not implemented on this host" "$out"
    check "nothing rendered under /etc/systemd/system" bash -c "[ ! -e '$unit_path' ]"
    check "no systemctl invocation" no_systemctl "$out"
fi

if [ "$fail" != 0 ]; then
    for f in refused satisfied flavour host sysd-host sysd1 sysd2 sysd3 sysd4 sysd5; do
        [ -f "$work/$f.out" ] || continue
        echo; echo "--- cf-agent output ($f) ---"; cat "$work/$f.out"
    done
    exit 1
fi
echo; echo "all policy tests passed"
