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
#      second run that does nothing; then a tombstone naming an alias link, a
#      mask (link to /dev/null) and a dangling link in /etc/systemd/system,
#      none of which it may touch: reported, no systemctl, links left as found.
#   8. no shell on the interlock pre_action: `/usr/bin/false || /usr/bin/true`
#      must be refused and `/usr/bin/true ; /usr/bin/false` satisfied, the
#      opposite of what a shell would do (C-policy-01; numbered 8 because 7 is
#      the opt-in NixOS-shape check, which runs first). 8c records the argv a
#      program receives (element-for-element: every punctuation character the
#      schema alphabet admits plus a sample of letters and digits, and a
#      metacharacter set); 8d refuses a relative command[0] from a projection
#      that skipped the schema.
#   9. CMDB cross-check against the agent's real loader (tendcf_cmdb in
#      policy/tendcf_services.cf, proposal 2026-11-03 section 13 option 3): a
#      file the loader cannot install whole is refused and reported and
#      actuates nothing; the consistent files of checks 2-4 raise no report; no
#      file at all, and a file with no vars, are the normal empty case. Also
#      refused and reported, each actuating nothing: a `variables` section that
#      replaces a container under the same ids with another command (the
#      comparison is of the whole container, not of key names and ids), a
#      `classes` section, and a `vars` key that is not a plain identifier, which
#      the loader would file under another scope (a preset of the policy's own
#      id lists), and a `vars` value that is not an object (not comparable as
#      JSON text with the file's). Also refused, each actuating nothing: a CMDB
#      `vars` key that presets a variable of the checker itself (`doc`,
#      `bad_keys`, `missing_keys`) or of a gate (`interlock_ids`), which the
#      engine would otherwise keep because a vars promise with a function-call
#      rvalue is skipped when the variable exists; a `classes` section that is
#      hidden from the file-based checks by such a preset; and an augments file
#      (`def.json` in inputs/) that defines a class and a variable. A `vars`
#      container that is a list of strings is the positive control: accepted,
#      actuates. A plain-identifier key longer than 64 characters is refused and
#      its report line shows only the first 64. Every file of checks 2-8 and 6 is also a no-report control.
#      NB: the fork's loader skips a bad entry and installs the rest, but the
#      Mac dev build rejects the whole `vars` instead (the same fixture refuses
#      on both, as "nothing loaded"), so only the fork's CI legs see the
#      per-entry skip.
#  10. the same cross-check against a loader that skips ONE container, which
#      the Mac dev build cannot do: tests/policy/sim-loader.cf installs
#      data:variables.* in the loader's place (cf-agent --no-host-specific-data)
#      from the very file the policy reads. Each case must report what differs
#      and run nothing; the control case (everything installed) must run as
#      before, so the others cannot pass because the stand-in installed nothing.
#      A skipped interlock container with the services loaded is the 2026-11-02
#      fail-open; a skipped service container with the interlock loaded shows
#      the first bundle (tendcf_interlocks, which runs pre_action commands) is
#      gated too. Same ids with a changed value (a service's command, or an
#      interlock's pre_action) are refused as a content difference, which no
#      key-and-id comparison could see. Under TENDCF_TEST_SYSTEMD=1 the same stand-in is run against
#      the real manager (6b): no unit rendered, a tombstone leaves the unit alone.
#  11. the engine's evaluation of tendcf_cmdb, measured on a real
#      cf-agent with -d: how often the checker's variables and classes are
#      visited, with the file replaced (same keys and ids, another pre_action)
#      by a common bundle, in two deterministic timings: before the check's read
#      (refused, "content differs", nothing runs) and after it (the policy reads
#      the file once, so not refused, the loaded pre_action runs and the replaced
#      one does not); a debug run counts the reads (the doc promise is evaluated
#      once) and prints the other counts (`info:`). A third case swaps in a file
#      whose pre_action element holds `$(` (strcmp() is skipped, so the comparison
#      has no verdict): refused as "reached no verdict", nothing runs.
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
# Same two bundles, with the stand-in loader first (see tests/policy/sim-loader.cf).
cat > "$work/inputs/sim-entry.cf" <<EOF
body common control
{
      inputs => { "$repo/tests/policy/sim-loader.cf", "$repo/policy/tendcf_services.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_services" };
}
EOF

fail=0
check() {  # check NAME COND...
    local name="$1"; shift
    if "$@"; then echo "ok   $name"; else echo "FAIL $name"; fail=1; fi
}

# The cross-check's report. "refusing to actuate anything" is the summary line
# tendcf_interlocks prints once; no_actuation is what a refused run must not do:
# run any command (-I logs every one, pre_action included), render, or process
# a service or an interlock entry at all (each prints a "tendcf: service|interlock"
# report when it is processed, and `*_ids` are empty under a refusal).
refusal_reported() { grep -q "tendcf: CMDB cross-check failed: refusing to actuate anything" "$1"; }
refusal_once() { [ "$(grep -c "CMDB cross-check failed" "$1")" = 1 ]; }
no_crosscheck() { ! grep -q "CMDB cross-check" "$1"; }
no_actuation() { ! grep -Eq "Executing|Created file|launchctl|systemctl|tendcf: (service|interlock) '" "$1"; }
foreign_var_reported() { grep -q "tendcf: CMDB cross-check: the CMDB or an augments file installed a variable outside" "$1"; }
foreign_class_reported() { grep -q "tendcf: CMDB cross-check: the CMDB or an augments file defined a class" "$1"; }
key_not_loaded() { grep -q "key '$2' is under 'vars' in .* but CFEngine did not load data:variables.$2" "$1"; }

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
check "no reason line for an absolute command[0]" \
    bash -c "! grep -q 'is not an absolute path' '$out'"

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
alias_path=/etc/systemd/system/tendcf-test-alias.service
mask_path=/etc/systemd/system/tendcf-test-mask.service
dangling_path=/etc/systemd/system/tendcf-test-dangling.service
# A command promise logs "Executing ..." at inform level; a returnszero() probe
# logs "returnszero ran '<cmd>' ..." only at verbose level, so a check that must
# also rule out probes reads verbose output (sysd_run_verbose).
no_systemctl() { ! grep -Eq "Executing .*systemctl|returnszero ran '[^']*systemctl" "$1"; }
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
            as_root rm -f "$unit_path" "$alias_path" "$mask_path" "$dangling_path"
            as_root systemctl daemon-reload >/dev/null 2>&1 || true
        }
        trap cleanup_unit EXIT
        sysd_run() {  # sysd_run FIXTURE OUT
            cp "$repo/tests/policy/fixtures/$1" "$work/data/host_specific.json"
            as_root env CFENGINE_TEST_OVERRIDE_WORKDIR="$work" \
                "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$2" 2>&1 || true
            # cf-agent run as root takes the workdir over (found in CI,
            # 2026-10-31: the next cp got "Permission denied"); give it back.
            as_root chown -R "$(id -u):$(id -g)" "$work"
        }
        sysd_run_verbose() {  # as sysd_run, with -v so returnszero probes are logged
            cp "$repo/tests/policy/fixtures/$1" "$work/data/host_specific.json"
            as_root env CFENGINE_TEST_OVERRIDE_WORKDIR="$work" \
                "$cf_agent" -K -v -f "$work/inputs/entry.cf" >"$2" 2>&1 || true
            as_root chown -R "$(id -u):$(id -g)" "$work"
        }
        unit_active() { as_root systemctl is-active --quiet "$unit"; }
        unit_enabled() { as_root systemctl is-enabled --quiet "$unit"; }
        main_pid() { systemctl show -p MainPID --value "$unit"; }

        sysd_run_sim() {  # sysd_run_sim FIXTURE CLASSES OUT: stand-in loader, run as root
            cp "$repo/tests/policy/fixtures/$1" "$work/data/host_specific.json"
            as_root env CFENGINE_TEST_OVERRIDE_WORKDIR="$work" \
                "$cf_agent" -K -v --no-host-specific-data -D "$2" -f "$work/inputs/sim-entry.cf" >"$3" 2>&1 || true
            as_root chown -R "$(id -u):$(id -g)" "$work"
        }

        # 6b. Refused by the CMDB cross-check (check 10): the interlock container
        #     was skipped, the service loaded. Nothing may be rendered or started.
        sysd_run_sim systemd-present.json sim_service "$work/sysd-sim-present.out"
        check "cross-check refusal on a real systemd host: reported" \
            refusal_reported "$work/sysd-sim-present.out"
        check "cross-check refusal: no unit rendered" bash -c "[ ! -e '$unit_path' ]"
        check "cross-check refusal: no systemctl command or probe" \
            no_systemctl "$work/sysd-sim-present.out"

        sysd_run systemd-present.json "$work/sysd1.out"
        check "no refusal reported on a normal systemd host" \
            bash -c "! grep -q \"'$unit' refused\" '$work/sysd1.out'"
        check "unit rendered" \
            grep -q 'ExecStart="/usr/bin/sleep" "3600"' "$unit_path"
        check "Restart and WantedBy rendered from the entry" \
            bash -c "grep -qx 'Restart=on-failure' '$unit_path' && grep -qx 'WantedBy=multi-user.target' '$unit_path'"
        check "manager loaded Restart=on-failure" \
            bash -c "[ \"\$(systemctl show -p Restart --value $unit)\" = on-failure ]"
        check "unit passes systemd-analyze verify" \
            systemd-analyze verify "$unit_path"
        check "unit active after the first run" unit_active
        check "unit enabled after the first run" unit_enabled
        pid1="$(main_pid)"

        # 6b, tombstone: the unit is live; a refused run must leave it alone.
        sysd_run_sim systemd-absent.json sim_service "$work/sysd-sim-tomb.out"
        check "cross-check refusal (tombstone): reported" \
            refusal_reported "$work/sysd-sim-tomb.out"
        check "cross-check refusal (tombstone): unit file left in place" \
            bash -c "[ -f '$unit_path' ]"
        check "cross-check refusal (tombstone): unit still active" unit_active
        check "cross-check refusal (tombstone): no systemctl command or probe" \
            no_systemctl "$work/sysd-sim-tomb.out"

        sysd_run systemd-present.json "$work/sysd2.out"
        check "second run issues no systemctl command" no_systemctl "$work/sysd2.out"
        check "second run leaves the same process" \
            bash -c "[ \"\$(systemctl show -p MainPID --value $unit)\" = '$pid1' ]"

        sysd_run systemd-changed.json "$work/sysd3.out"
        check "changed unit re-rendered" \
            grep -q 'ExecStart="/usr/bin/sleep" "3601"' "$unit_path"
        check "manager loaded the changed Restart=always" \
            bash -c "[ \"\$(systemctl show -p Restart --value $unit)\" = always ]"
        check "changed unit restarted onto a new process" \
            bash -c "[ \"\$(systemctl show -p MainPID --value $unit)\" != '$pid1' ]"
        check "changed unit still active" unit_active
        check "enabled:false removed the boot link" bash -c "! systemctl is-enabled --quiet $unit"

        sysd_run systemd-absent.json "$work/sysd4.out"
        check "tombstone_elsewhere report absent on a normal systemd host" \
            bash -c "! grep -q 'tombstone not actuated' '$work/sysd4.out'"
        check "tombstone removed the unit file" bash -c "[ ! -e '$unit_path' ]"
        check "tombstone stopped the unit" bash -c "! systemctl is-active --quiet $unit"
        check "tombstone reloaded the manager (unit not found)" \
            bash -c "[ \"\$(systemctl show -p LoadState --value $unit)\" = not-found ]"

        sysd_run systemd-absent.json "$work/sysd5.out"
        check "second tombstone run issues no systemctl command" no_systemctl "$work/sysd5.out"

        # Refusal: a tombstone must never tear down a path this adapter did
        # not render. `fileexists` is true for a link, a mask and a dangling
        # link, so a teardown gated on it would `systemctl disable --now` and
        # delete each of these (schema-v5-dpkg-reconciliation-2026-11-02.md
        # section 2.2(4); pastebin's sshd.service is such an alias link).
        # Created after the regular-file lifecycle above; the EXIT trap
        # removes them whatever fails. Refusal also means no systemctl at all.
        alias_target="$work/alias-target.service"
        : >"$alias_target"
        as_root ln -s "$alias_target" "$alias_path"
        as_root ln -s /dev/null "$mask_path"
        as_root ln -s /nonexistent/tendcf-test "$dangling_path"
        sysd_run_verbose systemd-absent-links.json "$work/sysd6.out"
        for n in alias mask dangling; do
            check "tombstone on a $n link reported as not actuated" \
                grep -q "tendcf: service 'tendcf-test-$n.service' tombstone not actuated: /etc/systemd/system/tendcf-test-$n.service is not a regular file" "$work/sysd6.out"
        done
        check "no systemctl command or probe for the link tombstones" no_systemctl "$work/sysd6.out"
        check "alias link left in place" \
            bash -c "[ \"\$(readlink '$alias_path')\" = '$alias_target' ]"
        check "alias target left in place" bash -c "[ -f '$alias_target' ]"
        check "mask link left in place" bash -c "[ \"\$(readlink '$mask_path')\" = /dev/null ]"
        check "dangling link left in place" \
            bash -c "[ \"\$(readlink '$dangling_path')\" = /nonexistent/tendcf-test ]"
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

    # A tombstone on a host that is not booted by systemd (Darwin, a
    # container) is not the NixOS layout: no report, nothing run.
    cp "$repo/tests/policy/fixtures/systemd-absent.json" "$work/data/host_specific.json"
    out="$work/sysd-host-tomb.out"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "tombstone_elsewhere report absent on a host not booted by systemd" \
        bash -c "! grep -q 'tombstone not actuated' '$out'"
    check "no systemctl invocation for the tombstone" no_systemctl "$out"
fi

# 7. NixOS shape: booted by systemd but /etc/systemd/system is a symlink into a
#    read-only tree (nixos-passthrough-plan.md section 1). The adapter must refuse
#    by policy, naming the supervisor, and run no systemctl. Reshapes the host,
#    so only on request and as root (the debian-13 container in CI); restored on exit.
if [ "${TENDCF_TEST_NIXOS_SHAPE:-}" = 1 ]; then
    echo "# 7. NixOS shape: /etc/systemd/system a read-only store symlink"
    [ "$(id -u)" = 0 ] || { echo "FAIL TENDCF_TEST_NIXOS_SHAPE=1 needs root"; fail=1; }
    if [ "$(id -u)" = 0 ]; then
        shape="$(mktemp -d /tmp/tendcf-nixos-shape.XXXXXX)"
        mkdir -p "$shape/static/systemd/system"
        had_run=1; [ -d /run/systemd/system ] || { had_run=0; mkdir -p /run/systemd/system; }
        [ -e /etc/systemd/system ] && mv /etc/systemd/system "$shape/real"
        ln -s "$shape/static/systemd/system" /etc/systemd/system
        chmod -R a-w "$shape/static"
        unshape() {
            rm -f /etc/systemd/system
            [ -e "$shape/real" ] && mv "$shape/real" /etc/systemd/system
            [ "$had_run" = 1 ] || rmdir /run/systemd/system /run/systemd 2>/dev/null || true
            chmod -R u+w "$shape"; rm -rf "$shape"
        }
        trap unshape EXIT
        cp "$repo/tests/policy/fixtures/systemd-present.json" "$work/data/host_specific.json"
        out="$work/nixos-shape.out"
        "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
        check "systemd entry refused naming the nixos supervisor" \
            grep -q "tendcf: service '$unit' refused: /etc/systemd/system is not a writable directory on this host .*supervisor nixos" "$out"
        check "generic flavour refusal not also reported" \
            bash -c "! grep -q \"'$unit' refused: unit flavour\" '$out'"
        check "nothing written into the store-like unit directory" \
            bash -c "[ -z \"\$(ls -A '$shape/static/systemd/system')\" ]"
        check "no systemctl invocation" no_systemctl "$out"

        # 7b. A tombstone has no unit and no flavour, so the refusal above
        #     cannot see it: it must be reported and never actuated (D3). A unit
        #     file stands in the store-like tree first, as if the Nix configuration
        #     declared it, so a teardown that wrongly ran would have something to
        #     remove (root ignores the a-w bits; the symlink is what the policy reads).
        echo "# 7b. NixOS shape: tombstone reported, not actuated"
        printf '[Unit]\nDescription=declared by the system configuration\n' \
            >"$shape/static/systemd/system/$unit"
        cp "$repo/tests/policy/fixtures/systemd-absent.json" "$work/data/host_specific.json"
        out="$work/nixos-tombstone.out"
        "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
        check "tombstone reported as not actuated, naming the nixos supervisor" \
            grep -q "tendcf: service '$unit' tombstone not actuated: /etc/systemd/system is not a writable directory on this host .*supervisor nixos" "$out"
        check "tombstone is not reported as a refusal" \
            bash -c "! grep -q \"'$unit' refused\" '$out'"
        check "the configuration's unit file is left in place (tombstone)" \
            bash -c "[ -f '$shape/static/systemd/system/$unit' ]"
        check "no systemctl invocation (tombstone)" no_systemctl "$out"
        unshape; trap - EXIT
    fi
fi

# 8. no shell on the interlock pre_action (C-policy-01). The argv is joined
#    with spaces and exec'd by cf-agent itself (useshell => "noshell"), so a
#    shell operator is a plain argument. The two fixtures give opposite
#    answers under a shell, and neither has a service, so both reach the
#    refusal report on every host (Linux CI included):
#      or:   `/usr/bin/false || /usr/bin/true`, expect_exit 0. A shell runs
#            the right-hand side and exits 0 (satisfied). Without one,
#            /usr/bin/false gets the arguments `||` and `/usr/bin/true`, exits
#            1, and the bundle must be refused.
#      semi: `/usr/bin/true ; /usr/bin/false`, expect_exit 0. A shell exits
#            with the last command's 1 (refused). Without one,
#            /usr/bin/true ignores its arguments and exits 0: satisfied.
echo "# 8. pre_action runs without a shell"
cp "$repo/tests/policy/fixtures/interlock-noshell-or.json" "$work/data/host_specific.json"
out="$work/noshell-or.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "'false || true' ran as one command line" \
    grep -q "Executing .*'/usr/bin/false || /usr/bin/true'" "$out"
check "'||' was an argument, not an operator: interlock refused" \
    grep -q "tendcf: interlock 'demo-check' not satisfied, bundle 'demo' refused" "$out"
cp "$repo/tests/policy/fixtures/interlock-noshell-semi.json" "$work/data/host_specific.json"
out="$work/noshell-semi.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "'true ; false' ran as one command line" \
    grep -q "Executing .*'/usr/bin/true ; /usr/bin/false'" "$out"
check "';' was an argument, not an operator: interlock satisfied" \
    bash -c "! grep -q \"bundle 'demo' refused\" '$out'"

# 8c. argv fidelity. A recorder executable writes the argv it was handed, one
#     element per line, to a file it only renames into place after the last
#     write, so the file's existence is the evidence that it ran to the end
#     (the `Executing` log line is emitted before the exec, and /usr/bin/true
#     ignores its arguments, so neither shows what arrived). Exit 0 with
#     expect_exit 0 means the interlock must not be refused.
#       alphabet: every punctuation character the schema's interlock_argv
#                 alphabet admits (`. _ + @ : = , / -`) and a sample of
#                 letters and digits must arrive element for element.
#       meta:     shell metacharacters, which the schema refuses but a
#                 projection that skipped it could carry, must arrive as the
#                 plain arguments they are.
#     Neither path may contain a space (the join would split it); mktemp's
#     does not.
recorder="$work/argv-recorder"
case "$recorder" in *[[:space:]]*) check "scratch path has no whitespace" false ;; esac
cat > "$recorder" <<'RECORDER'
#!/bin/sh
: > "$0.tmp"
for a in "$@"; do printf '%s\n' "$a" >> "$0.tmp"; done
mv "$0.tmp" "$0.out"
RECORDER
chmod 700 "$recorder"
argv_case() {  # argv_case NAME ELEMENT...  (writes the fixture, runs cf-agent, compares)
    local name="$1"; shift
    local json="" el
    for el in "$@"; do json="$json,\"$el\""; done
    printf '{"vars":{"tendcf_interlock":{"demo-check":{"blocks":"enclosing-bundle","bundle":"demo","defines_class":"demo_ok","pre_action":{"command":["%s"%s],"expect_exit":0,"timeout_seconds":5},"report":true,"state":"present"}},"tendcf_service":{}}}\n' \
        "$recorder" "$json" > "$work/data/host_specific.json"
    rm -f "$recorder.out" "$recorder.tmp"
    out="$work/argv-$name.out"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    printf '%s\n' "$@" > "$work/argv-$name.want"
    check "$name: the recorder ran to the end" test -s "$recorder.out"
    check "$name: argv arrived element for element" cmp -s "$recorder.out" "$work/argv-$name.want"
    check "$name: exit 0 satisfied the interlock" \
        bash -c "! grep -q \"bundle 'demo' refused\" '$out'"
    check "$name: no reason line for an absolute command[0]" \
        bash -c "! grep -q 'is not an absolute path' '$out'"
}
argv_case alphabet 'a,b=c:d@e+f' '--k=v,w:/p@h+1._-' '-' 'A0z9' '/x/y'
argv_case meta ';' '/usr/bin/false' '||' '>' '/dev/null' '&' '*' '~' '#'

# 8d. a relative command[0] (a projection that skipped the schema) is refused
#     by the policy itself. Without the guard cf-agent stats and execv()s the
#     name against its own working directory, so a `true` placed there would
#     run and satisfy the interlock; with it the promise is skipped, the
#     marker file is never written and the bundle is refused and reported.
mkdir -p "$work/rel"
cat > "$work/rel/true" <<'RELTRUE'
#!/bin/sh
: > ran
RELTRUE
chmod 700 "$work/rel/true"
rm -f "$work/rel/ran"
printf '%s\n' '{"vars":{"tendcf_interlock":{"demo-check":{"blocks":"enclosing-bundle","bundle":"demo","defines_class":"demo_ok","pre_action":{"command":["true"],"expect_exit":0,"timeout_seconds":5},"report":true,"state":"present"}},"tendcf_service":{}}}' > "$work/data/host_specific.json"
out="$work/relative.out"
cf_agent_abs="$(cd "$(dirname "$cf_agent")" && pwd)/$(basename "$cf_agent")"
( cd "$work/rel" && "$cf_agent_abs" -K -I -f "$work/inputs/entry.cf" ) >"$out" 2>&1 || true
check "relative command[0]: interlock refused" \
    grep -q "tendcf: interlock 'demo-check' not satisfied, bundle 'demo' refused" "$out"
check "relative command[0]: the reason is reported" \
    grep -q "^R: tendcf: interlock 'demo-check' pre_action command\\[0\\] is not an absolute path; refused" "$out"
check "relative command[0]: nothing was run" \
    bash -c "[ ! -e '$work/rel/ran' ]"

echo "# 9. CMDB cross-check, the agent's real loader"
cp "$repo/tests/policy/fixtures/interlock-malformed.json" "$work/data/host_specific.json"
out="$work/xc-malformed.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "malformed interlock: refusal reported" refusal_reported "$out"
check "malformed interlock: the container the loader did not install is named" \
    key_not_loaded "$out" tendcf_interlock
check "malformed interlock: refusal reported once" refusal_once "$out"
check "malformed interlock: nothing actuated, no pre_action run, no service processed" \
    no_actuation "$out"
for f in refused satisfied flavour; do
    check "consistent file of the $f run (checks 2-4): no cross-check report" no_crosscheck "$work/$f.out"
done
rm -f "$work/data/host_specific.json"
out="$work/xc-nofile.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "no host_specific.json at all: no report" no_crosscheck "$out"
check "no host_specific.json at all: no error logged" bash -c "! grep -q 'error:' '$out'"
check "no host_specific.json at all: nothing actuated" no_actuation "$out"
printf '%s\n' '{"vars":{}}' >"$work/data/host_specific.json"
out="$work/xc-novars.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "empty vars: no report" no_crosscheck "$out"
check "empty vars: nothing actuated" no_actuation "$out"
printf '%s\n' '{bad' >"$work/data/host_specific.json"
out="$work/xc-garbage.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "unparseable file: refusal reported" refusal_reported "$out"
check "unparseable file: reported as unreadable" \
    grep -q "host_specific.json exists but cannot be read as JSON" "$out"
check "unparseable file: refusal reported once" refusal_once "$out"
check "unparseable file: nothing actuated" no_actuation "$out"

# Consistent files from the other checks (8, 8c, 8d, and the systemd lifecycle
# when it ran): the whole-container comparison must not refuse a normal file, so
# key order and number formatting do not make a false refusal.
for f in noshell-or noshell-semi argv-alphabet argv-meta relative sysd1 sysd2 sysd3 sysd4 sysd5; do
    [ -f "$work/$f.out" ] || continue
    check "consistent file of the $f run: no cross-check report" no_crosscheck "$work/$f.out"
done

# A `variables` section replaces `vars.tendcf_interlock` under the same id with
# a pre_action that passes (the file's own vars say /usr/bin/false). The loader
# applies `variables` after `vars` (cmdb.c LoadCMDBData), so the ids match and
# only the content differs.
cp "$repo/tests/policy/fixtures/cmdb-variables-collision.json" "$work/data/host_specific.json"
out="$work/xc-collision.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "variables-section collision: refusal reported" refusal_reported "$out"
check "variables-section collision: the content difference is named" \
    grep -q "key 'tendcf_interlock' content differs between" "$out"
check "variables-section collision: not an id difference" \
    bash -c "! grep -q 'loaded differently' '$out'"
check "variables-section collision: the section is named" \
    grep -q "has top-level section 'variables' besides 'vars'" "$out"
check "variables-section collision: refusal reported once" refusal_once "$out"
check "variables-section collision: the replacement pre_action did not run" no_actuation "$out"

# A `classes` section can define interlock_ok_demo_check, which would unblock the
# bundle whatever the pre_action returns (it is /usr/bin/false here).
cp "$repo/tests/policy/fixtures/cmdb-classes-section.json" "$work/data/host_specific.json"
out="$work/xc-classes.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "classes section: refusal reported" refusal_reported "$out"
check "classes section: the section is named" \
    grep -q "has top-level section 'classes' besides 'vars'" "$out"
check "classes section: nothing actuated (no pre_action, no service processed)" no_actuation "$out"

# `vars` keys that name a variable of the policy's own bundles preset the id
# lists before the policy loads; a refusal must overwrite them, not leave them.
cp "$repo/tests/policy/fixtures/cmdb-scoped-preset.json" "$work/data/host_specific.json"
out="$work/xc-preset.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "scoped-key preset: refusal reported" refusal_reported "$out"
for k in default:tendcf_interlocks.interlock_ids default:tendcf_services.interlock_ids default:tendcf_services.service_ids; do
    check "scoped-key preset: '$k' refused as not a plain identifier" \
        grep -q "key '$k' under 'vars' in .* is not a plain identifier" "$out"
done
check "scoped-key preset: refusal reported once" refusal_once "$out"
check "scoped-key preset: the preset id lists did not actuate" no_actuation "$out"
# The control that gives the case above its teeth: with no tendcf policy at all,
# the loader really does preset the policy's own variable from such a key (so the
# refusal had to overwrite it, not merely find it absent).
printf 'bundle agent main\n{\n}\n' > "$work/inputs/empty.cf"
"$cf_promises" --show-vars -f "$work/inputs/empty.cf" >"$work/xc-preset-vars.out" 2>&1 || true
check "scoped-key preset (control): the loader installed default:tendcf_services.service_ids" \
    bash -c "grep 'default:tendcf_services.service_ids' '$work/xc-preset-vars.out' | grep -q demo-runit"

# A `vars` value that is not an object is installed as a scalar (not
# comparable: storejson() fails) or, for a list of primitives, as an slist of
# strings, so numbers read back as "1","2" and differ from the file's [1,2]:
# either way a problem (a difference, or one side that cannot be serialised),
# refused and named. (A list of strings compares equal and passes, below.)
printf '%s\n' '{"vars":{"tendcf_interlock":{},"tendcf_service":{},"scalar":"x","plain_list":[1,2]}}' >"$work/data/host_specific.json"
out="$work/xc-uncomparable.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "uncomparable vars values: refusal reported" refusal_reported "$out"
for k in scalar plain_list; do
    check "uncomparable vars value '$k': named (differs or could not be compared)" \
        grep -Eq "key '$k' content (differs|could not be compared) between" "$out"
done
check "uncomparable vars values: the object containers are not blamed" \
    bash -c "! grep -Eq \"key 'tendcf_(interlock|service)' content (differs|could not be compared)\" '$out'"

# A key that is a plain identifier but longer than the 64 characters a report
# may show (Astra round 3, A2): refused as before, and the report line shows at
# most its first 64 characters. The 70-character key is the loader's own scalar
# case again, so it is refused for the same reason as 'scalar' above.
long_key="$(printf 'k%.0s' $(seq 1 70))"
long_head="${long_key:0:64}"
printf '{"vars":{"tendcf_interlock":{},"tendcf_service":{},"%s":"x"}}\n' "$long_key" >"$work/data/host_specific.json"
out="$work/xc-longkey.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "long key: refusal reported" refusal_reported "$out"
check "long key: the report line shows its first 64 characters" \
    grep -Eq "key '$long_head' content (differs|could not be compared) between" "$out"
check "long key: no report line shows more than 64 characters of it" \
    bash -c "! grep -q 'key .${long_head}[A-Za-z0-9_]' '$out'"

# A `vars` key can preset any variable of the policy, the checker's own included
# (adversary M1): a vars promise whose rvalue is a function call is skipped when
# the variable already exists (verify_vars.c, "Already did this"), so a preset
# `doc`, `bad_keys` or `missing_keys` of tendcf_cmdb, or an id list of the gates,
# stays. The policy refuses any CMDB-installed variable that is not
# data:variables.<identifier> and any CMDB-installed class, read from the loaded
# state, so there is no variable of the checker's to preset.
for fx in checker-preset checker-preset-keys classes-hidden; do
    cp "$repo/tests/policy/fixtures/cmdb-$fx.json" "$work/data/host_specific.json"
    out="$work/xc-$fx.out"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "$fx: refusal reported" refusal_reported "$out"
    if [ "$fx" != classes-hidden ]; then
        check "$fx: the foreign variable is reported" foreign_var_reported "$out"
    fi
    check "$fx: refusal reported once" refusal_once "$out"
    check "$fx: nothing actuated (no pre_action, no service processed)" no_actuation "$out"
done
# Its presets of the checker's variables are replaced by the policy's own values
# (check 11 shows function-call vars are re-evaluated), so the section and the
# class are what the policy sees; the foreign class is the loaded-state evidence.
check "classes-hidden: the foreign class is reported" foreign_class_reported "$work/xc-classes-hidden.out"
check "classes-hidden: the section is reported too" \
    grep -q "has top-level section 'classes' besides 'vars'" "$work/xc-classes-hidden.out"

# Augments (def.json in inputs/) are loaded after the CMDB and can define classes
# and variables just the same. tendcf ships none, so any is refused.
cp "$repo/tests/policy/fixtures/interlock-refused.json" "$work/data/host_specific.json"
printf '%s\n' '{"classes":{"interlock_ok_demo_check":["any"]},"vars":{"probe":"x"}}' >"$work/inputs/def.json"
out="$work/xc-augments.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
rm -f "$work/inputs/def.json"
check "augments: refusal reported" refusal_reported "$out"
check "augments: the foreign variable is reported" foreign_var_reported "$out"
check "augments: the foreign class is reported" foreign_class_reported "$out"
check "augments: nothing actuated (the class would have unblocked the bundle)" no_actuation "$out"

# Positive control (review B3): a `vars` container that is a list of strings
# round-trips through the loader's slist, so it is accepted and the run actuates.
printf '%s\n' '{"vars":{"tendcf_interlock":{"demo-check":{"blocks":"enclosing-bundle","bundle":"demo","defines_class":"demo_ok","pre_action":{"command":["/usr/bin/true"],"expect_exit":0,"timeout_seconds":5},"report":true,"state":"present"}},"tendcf_service":{},"plain_strings":["a","b"]}}' >"$work/data/host_specific.json"
out="$work/xc-strlist.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "list of strings in vars: no cross-check report" no_crosscheck "$out"
check "list of strings in vars: actuates normally (the pre_action ran)" \
    grep -q "Executing .*'/usr/bin/true'" "$out"

echo "# 10. CMDB cross-check, a loader that skips one container (tests/policy/sim-loader.cf)"
sim_run() {  # sim_run FIXTURE|none CLASSES OUT
    if [ "$1" = none ]; then rm -f "$work/data/host_specific.json"
    else cp "$repo/tests/policy/fixtures/$1" "$work/data/host_specific.json"; fi
    "$cf_agent" -K -I --no-host-specific-data -D "$2" -f "$work/inputs/sim-entry.cf" >"$3" 2>&1 || true
}
out="$work/xc-sim-control.out"
sim_run flavour-refused.json sim_interlock,sim_service "$out"
check "control (everything installed): no cross-check report" no_crosscheck "$out"
check "control: the pre_action ran" grep -q "Executing .*'/usr/bin/true'" "$out"
check "control: the service was processed" \
    grep -q "tendcf: service 'demo-runit' refused: unit flavour 'runit'" "$out"

# The 2026-11-02 fail-open: the services loaded, their interlock did not.
out="$work/xc-sim-nointerlock.out"
sim_run flavour-refused.json sim_service "$out"
check "interlock container skipped: refusal reported" refusal_reported "$out"
check "interlock container skipped: tendcf_interlock named" key_not_loaded "$out" tendcf_interlock
check "interlock container skipped: tendcf_service not blamed" \
    bash -c "! grep -q \"key 'tendcf_service'\" '$out'"
check "interlock container skipped: no service processed, nothing actuated" no_actuation "$out"

# The reverse, which also proves the FIRST bundle is gated: the interlock
# loaded, so tendcf_interlocks would run its pre_action.
out="$work/xc-sim-noservice.out"
sim_run flavour-refused.json sim_interlock "$out"
check "service container skipped: refusal reported" refusal_reported "$out"
check "service container skipped: tendcf_service named" key_not_loaded "$out" tendcf_service
check "service container skipped: the pre_action did not run (first bundle gated)" no_actuation "$out"

out="$work/xc-sim-partial.out"
sim_run runit-pair.json sim_interlock,sim_service_partial "$out"
check "half-loaded container: refusal reported" refusal_reported "$out"
check "half-loaded container: the entry the loader lost is named" \
    grep -q "key 'tendcf_service' loaded differently from .*: in the file only: \[demo-runit-two\]; loaded only: \[\]" "$out"
check "half-loaded container: the whole key is not reported as missing" \
    bash -c "! grep -q 'did not load data:variables' '$out'"
check "half-loaded container: nothing actuated (the loaded entry is not processed either)" \
    no_actuation "$out"

out="$work/xc-sim-stray.out"
sim_run runit-pair.json sim_interlock,sim_service,sim_stray "$out"
check "extra loaded variable: refusal reported" refusal_reported "$out"
check "extra loaded variable: named" \
    grep -q "CFEngine loaded data:variables.stray, which is not a key under 'vars'" "$out"
check "extra loaded variable: nothing actuated" no_actuation "$out"

# Same ids, a changed value: what a loader that replaced an entry's value (or a
# file replaced between the loader's read and the policy's) would leave. Ids and
# keys match, so only the whole-container comparison can see it.
out="$work/xc-sim-changed-service.out"
sim_run flavour-refused.json sim_interlock,sim_service_changed "$out"
check "service value changed under the same id: refusal reported" refusal_reported "$out"
check "service value changed under the same id: the container is named" \
    grep -q "key 'tendcf_service' content differs between" "$out"
check "service value changed under the same id: not an id difference" \
    bash -c "! grep -q 'loaded differently' '$out'"
check "service value changed under the same id: tendcf_interlock not blamed" \
    bash -c "! grep -q \"key 'tendcf_interlock'\" '$out'"
check "service value changed under the same id: nothing actuated" no_actuation "$out"

out="$work/xc-sim-changed-interlock.out"
sim_run interlock-refused.json sim_interlock_changed,sim_service "$out"
check "interlock value changed under the same id: refusal reported" refusal_reported "$out"
check "interlock value changed under the same id: the container is named" \
    grep -q "key 'tendcf_interlock' content differs between" "$out"
check "interlock value changed under the same id: tendcf_service not blamed" \
    bash -c "! grep -q \"key 'tendcf_service'\" '$out'"
check "interlock value changed under the same id: the passing pre_action did not run" no_actuation "$out"

out="$work/xc-sim-nofile.out"
sim_run none sim_stray "$out"
check "data loaded with no file: refusal reported" refusal_reported "$out"
check "data loaded with no file: reported" \
    grep -q "host_specific.json does not exist but CFEngine loaded data:variables.stray" "$out"
check "data loaded with no file: nothing actuated" no_actuation "$out"

echo "# 11. a file replaced during the run (tests/policy/probe-mutate.cf)"
# A (interlock-satisfied.json) is consistent with what the loader installed. A
# common bundle replaces it with B: same keys and ids, pre_action /usr/bin/false.
# Two timings, each with one expected outcome:
#   before: B is on disk before the check reads the file. The check compares B
#     with the loaded A and refuses ("content differs"); nothing runs.
#   after: B appears only once tendcf_cmdb.doc exists (the probe's own guard), so
#     after the check's read. The policy reads the file once (the `doc` promise
#     is skipped once `doc` exists), so it never sees B: not refused, the loaded
#     pre_action (true) runs, B's (false) never does, and doc is evaluated once.
# Ordering is evidenced by the outcome itself (a refusal naming a content
# difference only follows a read of B; the true/false split only a read of A) and
# by the probe's guard, not by text of a debug log: a debug log (-d) echoes the
# policy's own report strings, so it is only used for the visit counts.
cat > "$work/inputs/probe-before.cf" <<EOF2
body common control
{
      inputs => { "$repo/tests/policy/probe-mutate.cf", "$repo/policy/tendcf_services.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_services" };
}
EOF2
cat > "$work/inputs/probe-after.cf" <<EOF2
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf", "$repo/tests/policy/probe-mutate.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_services" };
}
EOF2
cat > "$work/probe-mutate.sh" <<EOF2
#!/bin/sh
echo ran >> "$work/probe-count"
cp "$work/probe-B.json" "$work/data/host_specific.json"
EOF2
chmod 700 "$work/probe-mutate.sh"
probe_a="$(cat "$repo/tests/policy/fixtures/interlock-satisfied.json")"
printf '%s\n' "${probe_a//\"\/usr\/bin\/true\"/\"\/usr\/bin\/false\"}" > "$work/probe-B.json"
probe_replaced() { [ "$(cat "$work/data/host_specific.json")" = "$(cat "$work/probe-B.json")" ]; }
probe_start() { cp "$repo/tests/policy/fixtures/interlock-satisfied.json" "$work/data/host_specific.json"; rm -f "$work/probe-count"; }

probe_start
out="$work/xc-probe-before.out"
"$cf_agent" -K -I -D probe_before -f "$work/inputs/probe-before.cf" >"$out" 2>&1 || true
check "probe before the read: the file was replaced" probe_replaced
check "probe before the read: refused" refusal_reported "$out"
check "probe before the read: the content difference is named" \
    grep -q "key 'tendcf_interlock' content differs between" "$out"
check "probe before the read: nothing ran (neither the loaded nor the replaced pre_action)" no_actuation "$out"

probe_start
out="$work/xc-probe-after.out"
"$cf_agent" -K -I -D probe_after -f "$work/inputs/probe-after.cf" >"$out" 2>&1 || true
check "probe after the read: the file was replaced" probe_replaced
check "probe after the read: not refused (the policy never saw the replacement)" no_crosscheck "$out"
check "probe after the read: the loaded pre_action (true) ran" \
    grep -q "info: Executing .*'/usr/bin/true'" "$out"
check "probe after the read: the replaced pre_action (false) did not" \
    bash -c "! grep -q \"info: Executing .*'/usr/bin/false'\" '$out'"

# Visit counts, from a debug run of the after case.
probe_start
dbg="$work/xc-probe-debug.out"
"$cf_agent" -K -I -d -D probe_after -f "$work/inputs/probe-after.cf" >"$dbg" 2>&1 || true
n_doc="$(grep -c 'Evaluating vars promise: doc$' "$dbg" || true)"
n_json="$(grep -c 'Evaluating vars promise: file_json\[' "$dbg" || true)"
n_cls="$(grep -c 'Evaluating classes promise: tendcf_cmdb_refused$' "$dbg" || true)"
n_res="$(grep -c "Resolving classes and variables in 'bundle common tendcf_cmdb'" "$dbg" || true)"
n_mut="$(wc -l < "$work/probe-count" 2>/dev/null || echo 0)"
echo "info: tendcf_cmdb resolved $n_res times; vars 'doc' visited $n_doc times, 'file_json[..]' $n_json times; class 'tendcf_cmdb_refused' visited $n_cls times; mutation script ran $n_mut times"
check "probe (debug run): the mutation script ran" [ "$n_mut" -ge 1 ]
check "probe (debug run): the file is read once (doc promise evaluated once)" [ "$n_doc" = 1 ]

# A comparison that has no verdict (adversary round 3, L1): B is A with one
# pre_action element changed to `/usr/bin/true$(nonexistent)`, swapped in before
# the check's read. strcmp() is skipped when an argument still holds `$(`, so
# neither a difference nor an equality is computed; the check must refuse anyway,
# name the key and run nothing. (The loader refuses `$(` in a value, so this can
# only be a file replaced after the loader's read, which is what the probe does.)
printf '%s\n' "${probe_a//\"\/usr\/bin\/true\"/\"\/usr\/bin\/true\$(nonexistent)\"}" > "$work/probe-B.json"
probe_start
out="$work/xc-probe-noverdict.out"
"$cf_agent" -K -I -D probe_before -f "$work/inputs/probe-before.cf" >"$out" 2>&1 || true
check "probe no verdict: the file was replaced" probe_replaced
check "probe no verdict: the replacement really holds a \$( element" \
    grep -qF "true\$(nonexistent)" "$work/data/host_specific.json"
check "probe no verdict: refused" refusal_reported "$out"
check "probe no verdict: the key is named" \
    grep -q "key 'tendcf_interlock' content comparison reached no verdict between" "$out"
check "probe no verdict: nothing ran (neither the loaded nor the replaced pre_action)" no_actuation "$out"

if [ "$fail" != 0 ]; then
    for f in refused satisfied noshell-or noshell-semi argv-alphabet argv-meta relative flavour host sysd-host sysd-host-tomb sysd1 sysd2 sysd3 sysd4 sysd5 sysd6 nixos-shape nixos-tombstone \
             xc-malformed xc-nofile xc-novars xc-garbage xc-collision xc-classes xc-preset xc-preset-vars xc-uncomparable xc-checker-preset xc-checker-preset-keys xc-classes-hidden xc-augments xc-strlist xc-probe-before xc-probe-after xc-probe-noverdict xc-longkey \
             xc-sim-control xc-sim-nointerlock xc-sim-noservice xc-sim-partial xc-sim-stray xc-sim-nofile xc-sim-changed-service xc-sim-changed-interlock \
             sysd-sim-present sysd-sim-tomb; do
        [ -f "$work/$f.out" ] || continue
        echo; echo "--- cf-agent output ($f) ---"; cat "$work/$f.out"
    done
    exit 1
fi
echo; echo "all policy tests passed"
