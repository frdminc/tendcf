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
#
# The pre_action commands are /usr/bin/true and /usr/bin/false, which exist
# on Linux and macOS alike; /bin/true does not exist on macOS, and a missing
# executable is a failed promise, which looks like a refusal.
#
# Usage: tests/policy/run.sh [--bindir DIR]
#   DIR holds cf-agent and cf-promises (default: $PATH). Exit 0 on pass.
#   Prints the agent version first: every result names the build it ran on.
set -euo pipefail

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

if [ "$fail" != 0 ]; then
    echo; echo "--- cf-agent output (refused) ---"; cat "$work/refused.out"
    echo; echo "--- cf-agent output (satisfied) ---"; cat "$work/satisfied.out"
    exit 1
fi
echo; echo "all policy tests passed"
