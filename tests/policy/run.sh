#!/usr/bin/env bash
# Generic-bundle tests for policy/tendcf_services.cf against a real cf-agent.
#
# Nothing here touches real launchd (/bin/launchctl) or /Library/LaunchDaemons:
# check 5m exercises the darwin launchd adapter against a scratch directory and
# an argv-recording launchctl stub without root. Two kinds of
# assertion hold only with the pinned fork's all-or-nothing, strict-parse loader
# (overlay/fork.json), and go through fork_only():
#   - loader assertions: its log strings, the duplicate-variable message, "this
#     container was not installed", the probe-absent lines;
#   - loader+policy integration assertions: the cross-check's refusal and the
#     absence of actuation for a repeated member, a repeated `vars` and trailing
#     input (9b dup-member, dup-vars, trailing). A lenient loader and the lenient
#     readjson see the same surviving data, so the cross-check has no difference
#     to refuse and the interlock or service guard acts instead. For these
#     cases two plain `check`s hold on any loader: the test-only completion
#     marker (policy_completed: entry.cf runs tests/policy/fixtures/test-done.cf
#     after the two tendcf bundles, so the SAME output shows that invocation
#     evaluated the policy to the end) and no_render_start (no `Created file`,
#     no launchctl, no systemctl). The marker is what makes the negative grep
#     mean something; a separate probe process proves only what the data loaded
#     as. On a non-fork run lenient_only also asserts the line a lenient loader's
#     data makes the policy print (derived from policy source, never run there).
# Everything else is policy-layer and holds on any cf-agent (the Linux CI
# legs, the Mac dev build). A one-time capability probe in check 4b (a file with
# a repeated member of `vars`) decides whether the loader is the fork's; on a
# non-fork run (the Mac dev build, retained as a target by the operator,
# 2026-11-14) each fork_only assertion prints `SKIP (loader not all-or-nothing):
# <name>` and the run is expected to pass with those SKIP lines and a final
# count, never a silent pass. The Linux CI legs set TENDCF_REQUIRE_FORK_LOADER=1,
# which turns a non-fork loader (so, any skip) into a failure; so does the
# overlay-build leg, which runs this script on upstream plus overlay/ (its
# loader, overlay/core/0002, is the fork's, so check 4b passes unchanged). The non-fork
# outcome has been derived from the parser behaviour, not yet run on the Mac.
# Checks:
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
#   4b. malformed CMDB entries, enforce mode: a host_specific.json with one
#      malformed entry (an unresolved variable reference in the interlock;
#      then a key 'tendcf_interlock[' that the variable parser reads as the
#      interlock container) beside a valid interlock and a present service.
#      The policy layer must refuse and report it (refusal_reported,
#      refusal_once) and actuate nothing on any loader. On the pinned fork's
#      all-or-nothing loader the file also installs nothing (loader log
#      strings; a probe policy finds neither data:variables.tendcf_interlock
#      nor ...tendcf_service): those assertions are fork_only. A loader that
#      skipped only the bad entry would let the service through unguarded,
#      which the policy-layer assertions would catch.
#      The same block holds the capability probe (fork_loader) and the
#      TENDCF_REQUIRE_FORK_LOADER=1 assertion.
#   5. host guard, enforce mode, non-Darwin only: a satisfied interlock and
#      two present launchd services. launchd exists only on darwin, so a
#      Linux host must refuse both, write nothing under /Library and run no
#      launchctl. This is the wrong-platform actuation the Opus review
#      ranked highest (F1). On Darwin this prints an explicit counted SKIP.
#  5m. launchd adapter, per-domain system golden and lifecycle (C-policy-03,
#      C-policy-04, C-policy-05, issue 70 steps 4, 7 and 8): cross-platform
#      checks validate the committed per-domain golden plists
#      (tests/policy/golden/launchd/system/<id>.plist) with Python plistlib,
#      run `plutil -lint` where plutil exists (explicit counted SKIP where not),
#      and prove that CMDB and def.json presets targeting tendcf_services_apply's
#      override parameters are refused on every host (with a --show-vars control).
#      On Darwin, a non-root harness invokes tendcf_services_apply() against a
#      scratch daemon directory and an argv-recording launchctl stub (never
#      touching /Library or real /bin/launchctl) for: first render (byte-identical
#      to golden, plutil -lint, mode 0644, no *.cf-*-edit backup, bootstrap),
#      unchanged re-run (plist hash unchanged, zero launchctl write calls),
#      one-key drift (repaired to golden, no backup, bootout then bootstrap for
#      drifted service only), perms drift (0600 -> 0644, reload), failed bootout
#      + persisted reload-pending recovery on the next run (M1) + post-recovery
#      settle, failed bootstrap, read-only dir render failure (no 0-byte plist),
#      present non-regular refusal (symlink, dangling link, directory), tombstone
#      (print error exit 5 fails closed and keeps plist, bootout strictly before
#      delete, second run zero launchctl calls, failed bootout keeps plist,
#      unloaded exit 113 and exit 3 regular plist deleted, C-policy-04
#      non-regular files refused with zero launchctl calls), bad-id refusal
#      (traversal, spaces, quotes, leading ./-, 129-char vs 128-char accepted),
#      canonify() and darwin APFS case-insensitive id collision refusals plus
#      single-tombstone APFS case-mismatch refusal, dry-run (`cf-agent -n`) on
#      missing/converged/drifted/loaded-tombstone cases (zero false failures and
#      zero mutations), XML escaping round-trip (`<>&"`), tombstone refusal on
#      `!tendcf_launchd_host`, and CMDB refusal on direct tendcf_services_apply.
#      On non-Darwin the darwin lifecycle checks print explicit counted SKIPs.
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
#      names a container of `vars` again (the fork at the pin refuses the file
#      as a duplicate variable and installs none of it; the whole-container
#      comparison that would catch the same ids with another command is tested
#      in checks 10 and 11), a
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
#      NB: the fork at the pin (overlay/fork.json, core 4443504) loads
#      all-or-nothing (PR #41, operator ruling R13): a file in which an entry is
#      invalid, a class cannot be inserted, a `vars` member or section is
#      repeated, or non-whitespace follows the document, installs none of its
#      contents (libpromises/cmdb.c, strict libntech parse; the strict parse is
#      the CMDB loader's alone, readjson and def.json stay lenient). On the
#      Linux legs this check sees every `vars` key missing, as the Mac dev build
#      does when it rejects the whole `vars`. The same fixture refuses the same
#      way on both ("nothing loaded"). No loader this check runs against skips
#      one entry and installs the rest; the fork did before R13 (`8f0076b81`,
#      B-5b), which is the 2026-11-02 fail-open.
#  9b. the loader's strict-parse and class refusals, one fixture each in
#      tests/policy/fixtures/loader-*.json, each beside a valid interlock and a
#      present service: a repeated member of `vars` (dup-member), a repeated
#      top-level `vars` whose later section drops the interlock (dup-vars),
#      non-whitespace after a valid document (trailing), a whitespace-only
#      default-namespace class name (class-space). Each must be refused and
#      reported once by PR 42's cross-check and actuate nothing (fork_only for
#      the first three, the integration assertions above; unconditional for
#      class-space, whose `classes` section the cross-check refuses on any
#      loader); on the fork each also loads nothing, logs the loader's reason and
#      reports each key as not loaded (fork_only). A class that already exists (class-exists,
#      the host's own hard class) is not an error: the fork leaves it as it is
#      and installs the rest, so no refusal is expected; the case asserts that
#      `classes` beside good vars is still refused by the cross-check's own
#      `classes` rule. In dup-vars the lenient readjson sees only the last
#      `vars` section, so the report names only what that section holds
#      (tendcf_service), not the interlock the loader dropped: the
#      cross-check's independence from the loader is limited (proposal 13).
#      Two empty-view controls (empty-dup-vars `{"vars":{},"vars":{}}`,
#      empty-trailing `{"vars":{}}` plus trailing input) are refused by the
#      strict loader but read as an empty `vars` by readjson: nothing installs,
#      nothing actuates and no cross-check report is made (asserted on any
#      loader; only the loader's refusal is fork_only). No actuation is not a
#      refusal report.
#  10. the same cross-check against a loader that skips ONE container, which
#      neither the Mac dev build nor the pinned fork does: tests/policy/sim-loader.cf
#      installs data:variables.* in the loader's place (cf-agent
#      --no-host-specific-data) from the very file the policy reads. It stays
#      valid after R13: the check compares the file with what is installed
#      whatever the loader's policy, and this is the only way to test the
#      partial states (a fork before the pin, another engine, a gap in the
#      loader's validation). Each case must report what differs
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

# The test-only marker bundle (tests/policy/fixtures/test-done.cf) runs last, so
# a negative-only case can require it in the same output as the run it asserts
# about (policy_completed below).
cat > "$work/inputs/entry.cf" <<EOF
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf", "$repo/tests/policy/fixtures/test-done.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_services", "tendcf_test_done" };
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

# Assertions that hold only on the pinned fork's CMDB loader (overlay/fork.json:
# all-or-nothing, strict parse): its log strings, "this container was not
# installed", and the loader+policy integration assertions of 9b (the
# cross-check's refusal and no actuation for a repeated member, a repeated
# `vars`, trailing input). Policy-layer assertions that hold on every loader
# stay on `check`. fork_loader is set once, by the
# probe in check 4b. A loader that is not the fork's makes fork_only print a
# SKIP line, never pass silently; TENDCF_REQUIRE_FORK_LOADER=1, which the Linux
# CI legs set because they build the pinned fork, turns "not the fork's loader"
# into a failure, so CI cannot pass by skipping.
fork_loader=unknown
skipped=0
platform_skipped=0
fork_only() {  # fork_only NAME COND...
    if [ "$fork_loader" = 1 ]; then check "$@"; return 0; fi
    echo "SKIP (loader not all-or-nothing): $1"
    skipped=$((skipped + 1))
}
platform_skip() {  # platform_skip REASON NAME
    echo "SKIP ($1): $2"
    platform_skipped=$((platform_skipped + 1))
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
# Narrower than no_actuation: nothing rendered and nothing started. It holds on a
# lenient loader too for the strict-parse fixtures (the interlock's pre_action
# fails and blocks the bundle, or only the runit service is left and its flavour
# is refused by name on every host), where no_actuation does not, because it also
# matches the interlock's own `Executing` and the `tendcf: service|interlock '`
# report lines a lenient run legitimately prints. (Adversary r4 I4.)
no_render_start() { ! grep -Eq "Created file|launchctl|systemctl" "$1"; }
# Positive evidence about the SAME cf-agent invocation whose output is asserted:
# the test-only bundle that entry.cf runs after tendcf_interlocks and
# tendcf_services reported. A run that failed validation or died before its
# policy, or whose loader refusal ended it, has no such line, so a negative
# grep over its output cannot pass for the wrong reason. cf-agent does go on to
# evaluate policy after the CMDB loader refuses a file: generic_agent.c:1234
# (4443504) only logs "Failed to load CMDB data" at ERR and returns to
# evaluation, and CI shows the policy's own refusal after the strict loader's
# on the fork (Linux legs, run 43649349555). The separate probe policy
# (probe()) runs a second process and proves only what the data loaded as.
policy_completed() { grep -q "^R: tendcf-test-done: the entry policy evaluated tendcf_interlocks and tendcf_services" "$1"; }
# Lenient-path assertions apply only where the loader is NOT the fork's (a
# repeated member, a repeated `vars` or trailing input is read leniently and
# the data it keeps is acted on). Not a skip: on the fork the same file is
# refused, which the fork_only assertions cover. Derived from the policy source
# and the fixtures, never run on a lenient build.
lenient_only() {  # lenient_only NAME COND...
    [ "$fork_loader" = 0 ] && check "$@"
    return 0
}
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

echo "# 4b. malformed CMDB entries: the loader fails closed"
# Each fixture is a host_specific.json with one malformed entry next to a
# valid interlock and a present service. The interlock's pre_action would
# fail if it ran, so a loader that dropped only the bad entry (or let it take
# the place of another) would let the service through unguarded: the service
# would be processed and reported (the runit flavour is refused by name on
# every host, check 4). The fork's all-or-nothing CMDB loader installs
# nothing from a file it finds invalid (this one is), so no service and no
# interlock exists to act on.
# Besides what the agent did, the probe policy asks it directly whether either
# container exists, which a service-only or interlock-only leftover cannot hide
# from; its positive control is a file that loads.
cp "$repo/tests/policy/fixtures/cmdb-probe.cf" "$work/inputs/cmdb-probe.cf"
probe() {  # probe FIXTURE OUT: run the probe policy over FIXTURE as CMDB data
    cp "$repo/tests/policy/fixtures/$1" "$work/data/host_specific.json"
    "$cf_agent" -K -f "$work/inputs/cmdb-probe.cf" >"$2" 2>&1 || true
}
probe interlock-refused.json "$work/probe-control.out"
check "probe control: a file that loads has tendcf_interlock" \
    grep -q "cmdb-probe: tendcf_interlock present" "$work/probe-control.out"
check "probe control: a file that loads has tendcf_service" \
    grep -q "cmdb-probe: tendcf_service present" "$work/probe-control.out"

# Loader capability, once: a repeated object member in `vars` must install
# nothing (the fork's strict parse, LoadCMDBData reading with JsonParseFileStrict,
# cmdb.c:1187 at 4443504), where a lenient loader keeps the last member and
# installs both containers. Positive evidence only: both "absent" lines.
probe loader-dup-member.json "$work/probe-capability.out"
if grep -q "cmdb-probe: tendcf_interlock absent" "$work/probe-capability.out" &&
   grep -q "cmdb-probe: tendcf_service absent" "$work/probe-capability.out"; then
    fork_loader=1
    echo "# loader capability: all-or-nothing with strict parse (the pinned fork)"
else
    fork_loader=0
    echo "# loader capability: NOT the pinned fork's loader; fork-only assertions print SKIP"
fi
if [ "${TENDCF_REQUIRE_FORK_LOADER:-0}" = 1 ]; then
    check "TENDCF_REQUIRE_FORK_LOADER=1: the loader is the pinned fork's (no skipping)" \
        test "$fork_loader" = 1
fi

malformed_case() {  # malformed_case NAME FIXTURE ERROR-PATTERN
    local name="$1" fixture="$2" pattern="$3"
    out="$work/malformed-$name.out"
    cp "$repo/tests/policy/fixtures/$fixture" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "$name: the policy refuses and reports it" refusal_reported "$out"
    check "$name: the policy reports it once" refusal_once "$out"
    fork_only "$name: malformed entry named in the CMDB error" grep -q "$pattern" "$out"
    fork_only "$name: loader reports that it installed none of the file" \
        grep -q "installing none of its contents" "$out"
    check "$name: no service processed (the sibling service entry was not installed)" \
        bash -c "! grep -q \"tendcf: service 'demo-runit'\" '$out'"
    check "$name: no interlock command executed" \
        bash -c "! grep -q \"Executing .*'/usr/bin/false'\" '$out'"
    check "$name: nothing rendered" \
        bash -c "! grep -q 'Created file' '$out'"
    check "$name: no launchctl or systemctl invocation" \
        bash -c "! grep -Eq 'launchctl|systemctl' '$out'"
    probe "$fixture" "$work/probe-$name.out"
    fork_only "$name: no tendcf_interlock variable" \
        grep -q "cmdb-probe: tendcf_interlock absent" "$work/probe-$name.out"
    fork_only "$name: no tendcf_service variable" \
        grep -q "cmdb-probe: tendcf_service absent" "$work/probe-$name.out"
}
# an unresolved variable reference in the interlock's pre_action
malformed_case unresolved interlock-malformed.json \
    "offending value in entry 'tendcf_interlock'"
# a key the variable parser reads as the interlock container itself
# ('tendcf_interlock[' is 'tendcf_interlock' to it, with only a log message)
malformed_case index-key interlock-malformed-key.json \
    "Invalid variable specification in CMDB data: 'tendcf_interlock\\['"

echo "# 4c. installer-owned unit guard (issue #102): refused on every host"
reserved_cross_case() {  # reserved_cross_case NAME FIXTURE EXPECTED-MSG
    local name="$1" fx="$2" expected="$3"
    out="$work/reserved-$name.out"
    cp "$repo/tests/policy/fixtures/$fx" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "reserved ($name): policy completed" policy_completed "$out"
    check "reserved ($name): no CMDB cross-check refusal" no_crosscheck "$out"
    check "reserved ($name): dedicated refusal reported" grep -qF "$expected" "$out"
    check "reserved ($name): no generic flavour/host/domain refusal" \
        bash -c "! grep -Eq \"refused: (unit flavour|launchd domain|missing or invalid|system-domain|user-domain|/etc/systemd/system)|tombstone not actuated\" '$out'"
    check "reserved ($name): nothing rendered and no launchctl/systemctl" no_render_start "$out"
}
reserved_cross_case launchd-present reserved-launchd-present.json \
    "tendcf: service 'org.tendcf.execd' refused: installer-owned unit (tendcf-install) cannot be actuated by cfengine"
reserved_cross_case launchd-case-present reserved-launchd-case-present.json \
    "tendcf: service 'ORG.TENDCF.EXECD' refused: installer-owned unit (tendcf-install) cannot be actuated by cfengine"
reserved_cross_case systemd-present reserved-systemd-present.json \
    "tendcf: service 'tendcf-execd.service' refused: installer-owned unit (tendcf-install) cannot be actuated by cfengine"
reserved_cross_case launchd-absent reserved-launchd-absent.json \
    "tendcf: service 'org.tendcf.execd' tombstone refused: installer-owned unit (tendcf-install) cannot be removed by cfengine"
reserved_cross_case launchd-case-absent reserved-launchd-case-absent.json \
    "tendcf: service 'ORG.TENDCF.EXECD' tombstone refused: installer-owned unit (tendcf-install) cannot be removed by cfengine"
reserved_cross_case systemd-absent reserved-systemd-absent.json \
    "tendcf: service 'tendcf-execd.service' tombstone refused: installer-owned unit (tendcf-install) cannot be removed by cfengine"

# Malformed state on a reserved unit fails closed with dedicated refusal.
printf '%s\n' '{"vars":{"tendcf_interlock":{},"tendcf_service":{"org.tendcf.execd":{"state":"bogus"}}}}' > "$work/data/host_specific.json"
out="$work/reserved-malformed-state.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "reserved (malformed state): policy completed" policy_completed "$out"
check "reserved (malformed state): dedicated refusal reported" \
    grep -qF "tendcf: service 'org.tendcf.execd' refused: installer-owned unit (tendcf-install) cannot be managed by cfengine" "$out"
check "reserved (malformed state): nothing rendered and no launchctl/systemctl" no_render_start "$out"

# Bare `tendcf-execd` (present & absent) and companion `tendcf-execd.timer` (present) reserved checks (Opus H1 / Adv B1).
for spec in \
    "systemd-nosuffix-present:tendcf-execd:present:tendcf: service 'tendcf-execd' refused: installer-owned unit (tendcf-install) cannot be actuated by cfengine" \
    "systemd-nosuffix-absent:tendcf-execd:absent:tendcf: service 'tendcf-execd' tombstone refused: installer-owned unit (tendcf-install) cannot be removed by cfengine" \
    "systemd-timer-present:tendcf-execd.timer:present:tendcf: service 'tendcf-execd.timer' refused: installer-owned unit (tendcf-install) cannot be actuated by cfengine"; do
    cname="${spec%%:*}"; rest="${spec#*:}"
    cid="${rest%%:*}"; rest="${rest#*:}"
    cstate="${rest%%:*}"; expected="${rest#*:}"
    python3 - "$work/data/host_specific.json" "$cid" "$cstate" <<'PYEOF'
import json, pathlib, sys
out_path, cid, state = sys.argv[1], sys.argv[2], sys.argv[3]
if state == "present":
    entry = {
        "bundle": "demo",
        "command": ["/usr/bin/sleep", "3600"],
        "run_as": "nobody",
        "state": "present",
        "unit": {"systemd": {"enabled": True, "restart": "on-failure", "wanted_by": "multi-user.target"}},
        "working_dir": "/",
    }
else:
    entry = {"state": "absent"}
doc = {"vars": {"tendcf_interlock": {}, "tendcf_service": {cid: entry}}}
pathlib.Path(out_path).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    out="$work/reserved-$cname.out"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "reserved ($cname): policy completed" policy_completed "$out"
    check "reserved ($cname): no CMDB cross-check refusal" no_crosscheck "$out"
    check "reserved ($cname): dedicated refusal reported" grep -qF "$expected" "$out"
    check "reserved ($cname): no generic flavour/host/bad-id refusal" \
        bash -c "! grep -Eq \"refused: (unit flavour|launchd domain|missing or invalid|system-domain|user-domain|/etc/systemd/system)|is not a valid|tombstone not actuated\" '$out'"
    check "reserved ($cname): nothing rendered and no launchctl/systemctl" no_render_start "$out"
done

# Dry-run (-n) reserved-unit check (Opus L3): dedicated refusal previewed, zero mutations.
for dry_spec in \
    "launchd:reserved-launchd-present.json:tendcf: service 'org.tendcf.execd' refused: installer-owned unit (tendcf-install) cannot be actuated by cfengine" \
    "systemd:reserved-systemd-present.json:tendcf: service 'tendcf-execd.service' refused: installer-owned unit (tendcf-install) cannot be actuated by cfengine"; do
    dname="${dry_spec%%:*}"; rest="${dry_spec#*:}"
    dfx="${rest%%:*}"; dexpected="${rest#*:}"
    cp "$repo/tests/policy/fixtures/$dfx" "$work/data/host_specific.json"
    out="$work/reserved-dry-$dname.out"
    "$cf_agent" -n -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "reserved dry-run ($dname): dedicated refusal reported" grep -qF "$dexpected" "$out"
    check "reserved dry-run ($dname): nothing rendered and no launchctl/systemctl" no_render_start "$out"
done

# Path-traversal / bad systemd service IDs refused fail-closed without echoing raw untrusted ID (Opus M1 / Neon #1 / Adv B2).
for bad_spec in \
    "dot-slash-present:./tendcf-execd.service:present" \
    "dot-slash-absent:./tendcf-execd.service:absent" \
    "parent-trav-present:../system/tendcf-execd.service:present" \
    "parent-trav-absent:../system/tendcf-execd.service:absent" \
    "dropin-present:tendcf-execd.service.d/override.conf:present" \
    "space-present:foo bar.service:present"; do
    bname="${bad_spec%%:*}"; rest="${bad_spec#*:}"
    bid="${rest%%:*}"; bstate="${rest#*:}"
    python3 - "$work/data/host_specific.json" "$bid" "$bstate" <<'PYEOF'
import json, pathlib, sys
out_path, bid, state = sys.argv[1], sys.argv[2], sys.argv[3]
if state == "present":
    entry = {
        "bundle": "demo",
        "command": ["/usr/bin/sleep", "3600"],
        "run_as": "nobody",
        "state": "present",
        "unit": {"systemd": {"enabled": True, "restart": "on-failure", "wanted_by": "multi-user.target"}},
        "working_dir": "/",
    }
else:
    entry = {"state": "absent"}
doc = {"vars": {"tendcf_interlock": {}, "tendcf_service": {bid: entry}}}
pathlib.Path(out_path).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    out="$work/bad-systemd-id-$bname.out"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "bad systemd id ($bname): policy completed" policy_completed "$out"
    check "bad systemd id ($bname): no CMDB cross-check refusal" no_crosscheck "$out"
    if [ "$bstate" = present ]; then
        check "bad systemd id ($bname): dedicated systemd bad-id refusal reported" \
            grep -qF "tendcf: systemd service refused: id is not a valid systemd service unit name" "$out"
        check "bad systemd id ($bname): no generic flavour refusal" \
            bash -c "! grep -q 'refused: unit flavour' '$out'"
    else
        check "bad systemd id ($bname): tombstone bad-id refusal reported" \
            grep -Eq "tendcf: (launchd|systemd) tombstone refused: id is not a valid " "$out"
    fi
    check "bad systemd id ($bname): raw untrusted id not echoed in reports" \
        python3 - "$out" "$bid" <<'PYEOF'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
bad_id = sys.argv[2]
assert not any(bad_id in line for line in lines if line.startswith("R:")), f"raw id leaked in R: line: {lines}"
PYEOF
    check "bad systemd id ($bname): nothing rendered and no launchctl/systemctl" no_render_start "$out"
done

# Positive controls (issue #102 R3 Codex finding): embedded `..` in a single
# filename (`backup..daily.service`) and `.timer` tombstones (`tendcf-test-backup.timer`)
# are schema-valid and must NOT be rejected by the systemd bad-id guards.
printf '%s\n' '{"vars":{"tendcf_interlock":{},"tendcf_service":{"backup..daily.service":{"bundle":"demo","command":["/usr/bin/sleep","3600"],"run_as":"nobody","state":"present","unit":{"systemd":{"enabled":false,"restart":"on-failure","wanted_by":"multi-user.target"}},"working_dir":"/"}}}}' > "$work/data/host_specific.json"
out="$work/pos-systemd-dotdot-present.out"
"$cf_agent" -n -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "systemd id positive (backup..daily.service present, -n): policy completed" \
    grep -q 'Need to repair reports promise: tendcf-test-done: the entry policy evaluated tendcf_interlocks and tendcf_services' "$out"
check "systemd id positive (backup..daily.service present, -n): not rejected as bad systemd id" \
    bash -c "! grep -q 'is not a valid systemd' '$out'"
check "systemd id positive (backup..daily.service present, -n): not rejected as reserved" \
    bash -c "! grep -q 'installer-owned unit' '$out'"

printf '%s\n' '{"vars":{"tendcf_interlock":{},"tendcf_service":{"tendcf-test-backup.timer":{"state":"absent"}}}}' > "$work/data/host_specific.json"
out="$work/pos-systemd-timer-absent.out"
"$cf_agent" -n -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "systemd tombstone positive (tendcf-test-backup.timer absent, -n): policy completed" \
    grep -q 'Need to repair reports promise: tendcf-test-done: the entry policy evaluated tendcf_interlocks and tendcf_services' "$out"
check "systemd tombstone positive (tendcf-test-backup.timer absent, -n): no CMDB cross-check refusal" no_crosscheck "$out"
check "systemd tombstone positive (tendcf-test-backup.timer absent, -n): not rejected as bad id" \
    bash -c "! grep -q 'is not a valid' '$out'"
check "systemd tombstone positive (tendcf-test-backup.timer absent, -n): not rejected as reserved" \
    bash -c "! grep -q 'installer-owned unit' '$out'"
check "systemd tombstone positive (tendcf-test-backup.timer absent, -n): nothing rendered and no launchctl/systemctl" no_render_start "$out"

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
    echo "# 5. host guard: non-Darwin launchd refusal"
    platform_skip "host is Darwin; launchd is native here" \
        "host guard: launchd entries refused on non-Darwin"
fi

echo "# 5m. launchd adapter, per-domain system+user-gui+user-background goldens and lifecycle (C-policy-03/04/05, issues #94/#99/#103)"
plutil_lint() { plutil -lint "$1" >/dev/null; }
golden_sys_dir="$repo/tests/policy/golden/launchd/system"
golden_user_gui_dir="$repo/tests/policy/golden/launchd/user-gui"
golden_user_bg_dir="$repo/tests/policy/golden/launchd/user-background"
for svc in com.tendcf.demo.main com.tendcf.demo.second com.tendcf.canary.main; do
    gplist="$golden_sys_dir/$svc.plist"
    check "launchd golden exists: system/$svc.plist" test -f "$gplist"
    check "launchd golden parses as valid plist (plistlib): system/$svc.plist" \
        python3 - "$gplist" "$svc" <<'PYEOF'
import plistlib, sys
path, svc = sys.argv[1], sys.argv[2]
with open(path, "rb") as f:
    doc = plistlib.load(f)
assert doc["Label"] == svc, f"Label={doc.get('Label')!r}"
assert isinstance(doc["ProgramArguments"], list) and len(doc["ProgramArguments"]) == 2
assert doc["UserName"] == "nobody"
assert "LimitLoadToSessionType" not in doc, f"unexpected LimitLoadToSessionType in system golden: {doc!r}"
assert doc["WorkingDirectory"] == "/"
assert doc["RunAtLoad"] is True
expected_ka = svc in ("com.tendcf.demo.main", "com.tendcf.canary.main")
assert doc["KeepAlive"] is expected_ka, f"KeepAlive={doc.get('KeepAlive')!r}"
PYEOF
    if command -v plutil >/dev/null 2>&1; then
        check "launchd golden passes plutil -lint: system/$svc.plist" \
            plutil_lint "$gplist"
    else
        platform_skip "plutil not available on $(uname)" \
            "launchd golden passes plutil -lint: system/$svc.plist"
    fi
done
for udom_spec in "user-gui:$golden_user_gui_dir:Aqua" "user-background:$golden_user_bg_dir:Background"; do
    udom="${udom_spec%%:*}"; rest="${udom_spec#*:}"
    udir="${rest%%:*}"; usess="${rest#*:}"
    uplist="$udir/com.tendcf.canary.main.plist"
    check "launchd golden exists: $udom/com.tendcf.canary.main.plist" test -f "$uplist"
    check "launchd golden parses as valid plist (plistlib, no UserName, LimitLoadToSessionType=$usess, parity with system): $udom/com.tendcf.canary.main.plist" \
        python3 - "$uplist" "$golden_sys_dir/com.tendcf.canary.main.plist" "$usess" <<'PYEOF'
import plistlib, sys
with open(sys.argv[1], "rb") as f:
    user_doc = plistlib.load(f)
with open(sys.argv[2], "rb") as f:
    sys_doc = plistlib.load(f)
want_sess = sys.argv[3]
assert "UserName" not in user_doc, f"unexpected UserName in user golden: {user_doc!r}"
assert user_doc.get("LimitLoadToSessionType") == want_sess, f"expected LimitLoadToSessionType={want_sess!r}: {user_doc!r}"
assert "UserName" in sys_doc and "LimitLoadToSessionType" not in sys_doc
sys_base = {k: v for k, v in sys_doc.items() if k != "UserName"}
usr_base = {k: v for k, v in user_doc.items() if k != "LimitLoadToSessionType"}
assert usr_base == sys_base, f"mismatch: {usr_base!r} != {sys_base!r}"
PYEOF
    if command -v plutil >/dev/null 2>&1; then
        check "launchd golden passes plutil -lint: $udom/com.tendcf.canary.main.plist" \
            plutil_lint "$uplist"
    else
        platform_skip "plutil not available on $(uname)" \
            "launchd golden passes plutil -lint: $udom/com.tendcf.canary.main.plist"
    fi
done

# Override safety (every platform): a CMDB host_specific.json or def.json
# trying to preset tendcf_services_apply's bundle parameters or service_ids
# through production entry.cf (tendcf_services) must be refused and actuate
# nothing. Uses an existing real directory under $work (not global /tmp) and a
# non-piped Python output check (no exit status through a pipe).
no_actuation_non_crosscheck() {
    python3 - "$1" <<'PYEOF'
import pathlib, re, sys
txt = pathlib.Path(sys.argv[1]).read_text()
assert txt.strip(), "empty cf-agent output"
pat = re.compile(r"Executing|Created file|launchctl|systemctl|tendcf: (service|interlock) '")
for line in txt.splitlines():
    if line.startswith("R: tendcf: CMDB cross-check:"):
        continue
    assert not pat.search(line), f"unexpected actuation line: {line!r}"
PYEOF
}
evil_launchd="$work/evil-launchd"
mkdir -p "$evil_launchd"
python3 - "$evil_launchd" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
evil_dir, out_path = sys.argv[1], sys.argv[2]
doc = {
    "vars": {
        "default:tendcf_services_apply.launchd_domain": "system",
        "default:tendcf_services_apply.launchd_dir": evil_dir,
        "default:tendcf_services_apply.launchctl_bin": "/bin/echo",
        "default:tendcf_services_apply.launchd_owner": "nobody",
        "default:tendcf_services_apply.launchd_group": "nobody",
        "default:tendcf_services_apply.launchd_run_user": "nobody",
        "default:tendcf_services_apply.launchd_uid": "0",
        "default:tendcf_services_apply.service_ids": ["com.tendcf.demo.main"],
        "tendcf_interlock": {
            "demo-check": {
                "blocks": "enclosing-bundle",
                "bundle": "demo",
                "defines_class": "demo_ok",
                "pre_action": {"command": ["/usr/bin/true"], "expect_exit": 0, "timeout_seconds": 5},
                "report": True,
                "state": "present",
            }
        },
        "tendcf_service": {
            "com.tendcf.demo.main": {
                "bundle": "demo",
                "command": ["/bin/sleep", "1"],
                "run_as": "nobody",
                "state": "present",
                "unit": {"launchd": {"domain": "system", "keep_alive": True, "run_at_load": True}},
                "working_dir": "/",
            }
        },
    }
}
pathlib.Path(out_path).write_text(json.dumps(doc))
PYEOF
# Control: with no tendcf policy, the loader really installs default:tendcf_services_apply.launchd_dir.
printf 'bundle agent main\n{\n}\n' > "$work/inputs/empty-launchd-ctrl.cf"
"$cf_promises" --show-vars -f "$work/inputs/empty-launchd-ctrl.cf" >"$work/launchd-override-vars.out" 2>&1 || true
check "launchd override preset (control): loader installs default:tendcf_services_apply.launchd_dir" \
    python3 - "$work/launchd-override-vars.out" "$evil_launchd" <<'PYEOF'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
assert any("default:tendcf_services_apply.launchd_dir" in l and sys.argv[2] in l for l in lines)
PYEOF
out="$work/launchd-override-preset.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "launchd override preset: policy completed" policy_completed "$out"
check "launchd override preset: refusal reported" refusal_reported "$out"
check "launchd override preset: foreign variable reported" foreign_var_reported "$out"
check "launchd override preset: refusal reported once" refusal_once "$out"
check "launchd override preset: nothing actuated" no_actuation_non_crosscheck "$out"
check "launchd override preset: no plist written to preset dir" \
    bash -c "[ -z \"\$(ls -A '$evil_launchd')\" ]"

# def.json override preset targeting default:tendcf_services_apply.*
cp "$repo/tests/policy/fixtures/launchd-present.json" "$work/data/host_specific.json"
python3 - "$evil_launchd" "$work/inputs/def.json" <<'PYEOF'
import json, pathlib, sys
doc = {
    "vars": {
        "default:tendcf_services_apply.launchd_dir": sys.argv[1],
        "default:tendcf_services_apply.launchctl_bin": "/bin/echo",
    }
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc))
PYEOF
out="$work/launchd-def-override.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
rm -f "$work/inputs/def.json"
check "launchd def.json override preset: policy completed" policy_completed "$out"
check "launchd def.json override preset: refusal reported" refusal_reported "$out"
check "launchd def.json override preset: foreign variable reported" foreign_var_reported "$out"
check "launchd def.json override preset: nothing actuated" no_actuation_non_crosscheck "$out"
check "launchd def.json override preset: no plist written to preset dir" \
    bash -c "[ -z \"\$(ls -A '$evil_launchd')\" ]"

if [ "$(uname)" = Darwin ]; then
    launchd_daemons="$work/launchd-daemons"
    launchd_agents="$work/launchd-agents"
    launchctl_state="$work/launchd-loaded"
    launchctl_log="$work/launchctl.log"
    launchctl_mode="$work/launchctl.mode"
    launchctl_stub="$work/launchctl-stub"
    mkdir -p "$launchd_daemons" "$launchd_agents" "$launchctl_state"
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    {
        printf '#!/usr/bin/env bash\nset -euo pipefail\n'
        printf 'log=%q\nstate=%q\ndaemons=%q\nagents=%q\nmode_file=%q\n' \
            "$launchctl_log" "$launchctl_state" "$launchd_daemons" "$launchd_agents" "$launchctl_mode"
        cat <<'STUBEOF'
if [ $# -gt 0 ]; then
    printf '%s' "$1" >> "$log"
    for arg in "${@:2}"; do
        printf '\t%s' "$arg" >> "$log"
    done
    printf '\n' >> "$log"
fi
mode="normal"
if [ -f "$mode_file" ]; then
    mode="$(cat "$mode_file")"
fi
sub="${1:-}"
case "$sub" in
    print)
        target="${2:-}"
        case "$target" in
            system/*)
                label="${target#system/}"
                st="$state/$label"
                if [ "$mode" = "fail-print" ]; then exit 5; fi
                if [ "$mode" = "print-unloaded-3" ]; then exit 3; fi
                if [ -f "$st" ]; then exit 0; else exit 113; fi
                ;;
            gui/[1-9]*/*)
                rest="${target#gui/}"
                uid="${rest%%/*}"
                label="${rest#*/}"
                [[ "$uid" =~ ^[1-9][0-9]*$ ]] || exit 64
                if [ "$mode" = "headless-no-gui" ]; then exit 125; fi
                if [ "$mode" = "fail-print" ] || [ "$mode" = "fail-gui-print" ]; then exit 5; fi
                if [ "$mode" = "print-unloaded-3" ]; then exit 3; fi
                st="$state/gui.$label"
                if [ -f "$st" ]; then exit 0; else exit 113; fi
                ;;
            user/[1-9]*/*)
                rest="${target#user/}"
                uid="${rest%%/*}"
                label="${rest#*/}"
                [[ "$uid" =~ ^[1-9][0-9]*$ ]] || exit 64
                if [ "$mode" = "fail-print" ] || [ "$mode" = "fail-user-print" ]; then exit 5; fi
                if [ "$mode" = "print-unloaded-3" ]; then exit 3; fi
                st="$state/user.$label"
                if [ -f "$st" ]; then exit 0; else exit 113; fi
                ;;
            gui/[1-9]*)
                uid="${target#gui/}"
                [[ "$uid" =~ ^[1-9][0-9]*$ ]] || exit 64
                if [ "$mode" = "headless-no-gui" ]; then exit 125; fi
                if [ "$mode" = "fail-gui-domain" ]; then exit 5; fi
                exit 0
                ;;
            user/[1-9]*)
                uid="${target#user/}"
                [[ "$uid" =~ ^[1-9][0-9]*$ ]] || exit 64
                if [ "$mode" = "user-domain-absent" ]; then exit 112; fi
                if [ "$mode" = "fail-user-domain" ]; then exit 5; fi
                exit 0
                ;;
            *) exit 64 ;;
        esac
        ;;
    bootstrap)
        dom="${2:-}"
        plist="${3:-}"
        [ -f "$plist" ] || exit 2
        if [ "$mode" = "fail-bootstrap" ]; then exit 5; fi
        label="$(basename "$plist" .plist)"
        case "$dom" in
            system)
                : > "$state/$label"
                ;;
            gui/[1-9]*)
                uid="${dom#gui/}"
                [[ "$uid" =~ ^[1-9][0-9]*$ ]] || exit 64
                if [ "$mode" = "headless-no-gui" ]; then exit 125; fi
                if grep -q "<string>Background</string>" "$plist"; then exit 134; fi
                : > "$state/gui.$label"
                ;;
            user/[1-9]*)
                uid="${dom#user/}"
                [[ "$uid" =~ ^[1-9][0-9]*$ ]] || exit 64
                if ! grep -q "<string>Background</string>" "$plist"; then exit 5; fi
                : > "$state/user.$label"
                ;;
            *) exit 64 ;;
        esac
        exit 0
        ;;
    bootout)
        target="${2:-}"
        case "$target" in
            system/*)
                label="${target#system/}"
                st="$state/$label"
                had="$state/$label.had_plist"
                pfile="$daemons/$label.plist"
                if [ "$mode" = "fail-bootout" ]; then exit 5; fi
                ;;
            gui/[1-9]*/*)
                rest="${target#gui/}"
                uid="${rest%%/*}"
                label="${rest#*/}"
                [[ "$uid" =~ ^[1-9][0-9]*$ ]] || exit 64
                if [ "$mode" = "headless-no-gui" ]; then exit 125; fi
                if [ "$mode" = "fail-bootout" ] || [ "$mode" = "fail-gui-bootout" ] || [ "$mode" = "fail-peer-bootout" ]; then exit 5; fi
                st="$state/gui.$label"
                had="$state/gui.$label.had_plist"
                pfile="$agents/$label.plist"
                ;;
            user/[1-9]*/*)
                rest="${target#user/}"
                uid="${rest%%/*}"
                label="${rest#*/}"
                [[ "$uid" =~ ^[1-9][0-9]*$ ]] || exit 64
                if [ "$mode" = "fail-bootout" ] || [ "$mode" = "fail-user-bootout" ] || [ "$mode" = "fail-peer-bootout" ]; then exit 5; fi
                st="$state/user.$label"
                had="$state/user.$label.had_plist"
                pfile="$agents/$label.plist"
                ;;
            *) exit 64 ;;
        esac
        if [ -f "$pfile" ]; then
            : > "$had"
        fi
        rm -f "$st"
        exit 0
        ;;
    *)
        exit 64
        ;;
esac
STUBEOF
    } > "$launchctl_stub"
    chmod 700 "$launchctl_stub"

    test_user="$(id -un)"
    test_group="$(id -gn)"
    test_uid="$(id -u)"
    test_gid="$(id -g)"
    cat > "$work/inputs/launchd-harness.cf" <<EOF
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf", "$repo/tests/policy/fixtures/test-done.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_launchd_harness", "tendcf_test_done" };
}
bundle agent tendcf_launchd_harness
{
  methods:
      "run"
        usebundle => tendcf_services_apply("system", "$launchd_daemons", "$launchctl_stub", "$test_user", "$test_group", "$test_user", "0");
}
EOF
    cat > "$work/inputs/launchd-user-harness.cf" <<EOF
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf", "$repo/tests/policy/fixtures/test-done.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_launchd_user_harness", "tendcf_test_done" };
}
bundle agent tendcf_launchd_user_harness
{
  methods:
      "run"
        usebundle => tendcf_services_apply("user", "$launchd_agents", "$launchctl_stub", "$test_user", "$test_gid", "$test_user", "$test_uid");
}
EOF
    cat > "$work/inputs/launchd-sim-harness.cf" <<EOF
body common control
{
      inputs => { "$repo/tests/policy/sim-loader.cf", "$repo/policy/tendcf_services.cf", "$repo/tests/policy/fixtures/test-done.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_launchd_harness", "tendcf_test_done" };
}
bundle agent tendcf_launchd_harness
{
  methods:
      "run"
        usebundle => tendcf_services_apply("system", "$launchd_daemons", "$launchctl_stub", "$test_user", "$test_group", "$test_user", "0");
}
EOF

    launchd_run() {  # launchd_run FIXTURE OUT [MODE]
        local fx="$1" outf="$2" mode="${3:-normal}"
        : > "$launchctl_log"
        printf '%s\n' "$mode" > "$launchctl_mode"
        cp "$repo/tests/policy/fixtures/$fx" "$work/data/host_specific.json"
        "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$outf" 2>&1 || true
    }
    launchd_run_dry() {  # launchd_run_dry FIXTURE OUT [MODE]
        local fx="$1" outf="$2" mode="${3:-normal}"
        : > "$launchctl_log"
        printf '%s\n' "$mode" > "$launchctl_mode"
        cp "$repo/tests/policy/fixtures/$fx" "$work/data/host_specific.json"
        "$cf_agent" -n -K -I -f "$work/inputs/launchd-harness.cf" >"$outf" 2>&1 || true
    }
    launchd_run_dry_file() {  # launchd_run_dry_file ABS-FIXTURE-PATH OUT [MODE]
        local fx="$1" outf="$2" mode="${3:-normal}"
        : > "$launchctl_log"
        printf '%s\n' "$mode" > "$launchctl_mode"
        cp "$fx" "$work/data/host_specific.json"
        "$cf_agent" -n -K -I -f "$work/inputs/launchd-harness.cf" >"$outf" 2>&1 || true
    }
    dry_policy_completed() {
        # Under `cf-agent -n`, `reports:` emits `warning: Need to repair reports promise: ...`
        # instead of `R: ...`.
        grep -q 'Need to repair reports promise: tendcf-test-done: the entry policy evaluated tendcf_interlocks and tendcf_services' "$1"
    }
    no_failed_reports() {
        # Matches both normal (`R: tendcf: service ... failed:`) and dry-run
        # (`warning: Need to repair reports promise: tendcf: service ... failed:`) forms.
        ! grep -q 'tendcf: service .* failed:' "$1"
    }
    # No-interlock copy of launchd-present.json for `-n` dry-run checks: under `-n`,
    # `tendcf_interlocks` intentionally does NOT execute pre_action commands (they
    # could mutate the host), which blocks interlock-gated bundles before reaching
    # launchd files:/commands:. Generating a no-interlock fixture exercises the
    # launchd files: and commands: dry-run preview paths directly.
    launchd_present_no_interlock="$work/launchd-present-no-interlock.json"
    python3 - "$repo/tests/policy/fixtures/launchd-present.json" "$launchd_present_no_interlock" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["vars"]["tendcf_interlock"] = {}
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc))
PYEOF
    no_cf_edit_files() {
        [ -z "$(find "$launchd_daemons" -name '*.cf-*-edit')" ]
    }
    launchd_log_count() {  # launchd_log_count EXACT-LINE EXPECTED-COUNT
        local c
        c="$(grep -cxF "$1" "$launchctl_log" || true)"
        [ "$c" = "$2" ]
    }

    # 5m.0 Direct tendcf_services_apply fails closed under tendcf_cmdb_refused.
    : > "$launchctl_log"
    cp "$repo/tests/policy/fixtures/launchd-present.json" "$work/data/host_specific.json"
    "$cf_agent" -K -I --no-host-specific-data -D sim_service -f "$work/inputs/launchd-sim-harness.cf" >"$work/launchd-sim-refused.out" 2>&1 || true
    check "launchd direct apply under CMDB refusal: reported" refusal_reported "$work/launchd-sim-refused.out"
    check "launchd direct apply under CMDB refusal: no plist rendered" test ! -e "$launchd_daemons/com.tendcf.demo.main.plist"
    check "launchd direct apply under CMDB refusal: zero launchctl calls" test ! -s "$launchctl_log"

    # 5m.15a-interlock Dry-run (-n) with interlock-gated fixture: pre_action does not run, bundle safely refused, zero failed reports, zero mutations.
    launchd_run_dry launchd-present.json "$work/launchd-dry-interlock.out"
    check "launchd dry-run (interlock-gated): policy completed" dry_policy_completed "$work/launchd-dry-interlock.out"
    check "launchd dry-run (interlock-gated): pre_action previewed without running" \
        grep -q "Would execute script '/usr/bin/true'" "$work/launchd-dry-interlock.out"
    check "launchd dry-run (interlock-gated): bundle safely refused" \
        grep -q "interlock 'demo-check' not satisfied, bundle 'demo' refused" "$work/launchd-dry-interlock.out"
    check "launchd dry-run (interlock-gated): zero failed report lines" no_failed_reports "$work/launchd-dry-interlock.out"
    check "launchd dry-run (interlock-gated): no plist created on disk" test ! -e "$launchd_daemons/com.tendcf.demo.main.plist"
    check "launchd dry-run (interlock-gated): zero launchctl calls" test ! -s "$launchctl_log"

    # 5m.15a Dry-run (-n) on missing plists (no-interlock fixture): zero failed reports, zero files written, zero launchctl write calls, bootstrap previewed.
    launchd_run_dry_file "$launchd_present_no_interlock" "$work/launchd-dry-missing.out"
    check "launchd dry-run (missing): policy completed" dry_policy_completed "$work/launchd-dry-missing.out"
    check "launchd dry-run (missing): zero failed report lines" no_failed_reports "$work/launchd-dry-missing.out"
    check "launchd dry-run (missing): no plist created on disk" \
        test ! -e "$launchd_daemons/com.tendcf.demo.main.plist"
    check "launchd dry-run (missing): zero launchctl write calls" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"
    check "launchd dry-run (missing): bootstrap previewed via Would execute" \
        grep -q "Would execute script .*bootstrap system .*com.tendcf.demo.main.plist" "$work/launchd-dry-missing.out"
    check "launchd dry-run (missing): no bootout previewed for unloaded service" \
        bash -c "! grep -q 'Would execute script .*bootout' '$work/launchd-dry-missing.out'"

    # 5m.14 Render/write failure (read-only daemons dir, Neon MH2 + Adv #3): plist_failed reported, zero launchctl write calls, zero 0-byte plist left.
    chmod 500 "$launchd_daemons"
    launchd_run launchd-present.json "$work/launchd-plist-fail.out"
    chmod 700 "$launchd_daemons"
    check "launchd plist failure (ro dir): plist_failed reported" \
        grep -q "tendcf: service 'com.tendcf.demo.main' failed: could not render or set permissions on .*com.tendcf.demo.main.plist; launchctl not run" "$work/launchd-plist-fail.out"
    check "launchd plist failure (ro dir): zero launchctl write calls" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"
    check "launchd plist failure (ro dir): no 0-byte plist created" \
        test ! -e "$launchd_daemons/com.tendcf.demo.main.plist"

    # 5m.1 First render (unloaded -> render, perms 0644, no backup, golden match, plutil, bootstrap).
    launchd_run launchd-present.json "$work/launchd-first.out"
    check "launchd first render: policy completed" policy_completed "$work/launchd-first.out"
    for svc in com.tendcf.demo.main com.tendcf.demo.second; do
        p="$launchd_daemons/$svc.plist"
        if [ -n "${TENDCF_DUMP_LAUNCHD_PLISTS_DIR:-}" ] && [ -f "$p" ]; then
            mkdir -p "$TENDCF_DUMP_LAUNCHD_PLISTS_DIR"
            cp "$p" "$TENDCF_DUMP_LAUNCHD_PLISTS_DIR/$svc.plist"
        fi
        check "launchd first render: $svc.plist byte-identical to committed golden" \
            cmp -s "$golden_sys_dir/$svc.plist" "$p"
        check "launchd first render: $svc.plist passes plutil -lint" \
            plutil_lint "$p"
        check "launchd first render: $svc.plist mode is 0644" \
            bash -c "[ \"\$(stat -f '%Lp' '$p')\" = 644 ]"
        check "launchd first render: $svc.plist owner:group is $test_user:$test_group" \
            bash -c "[ \"\$(stat -f '%Su:%Sg' '$p')\" = '$test_user:$test_group' ]"
        check "launchd first render: probed via launchctl print system/$svc" \
            grep -qxF "$(printf 'print\tsystem/%s' "$svc")" "$launchctl_log"
        check "launchd first render: bootstrapped via launchctl bootstrap system $svc.plist" \
            grep -qxF "$(printf 'bootstrap\tsystem\t%s' "$p")" "$launchctl_log"
    done
    check "launchd first render: no bootout call on initial load" \
        bash -c "! grep -q '^bootout' '$launchctl_log'"
    check "launchd first render: no .cf-*-edit backup/temp left" no_cf_edit_files

    # 5m.1b Canary system render (issue #99 L6): deploy/darwin/canary/host_specific.json renders byte-identical to system golden.
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    cp "$repo/deploy/darwin/canary/host_specific.json" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-canary-sys.out" 2>&1 || true
    canary_sys_p="$launchd_daemons/com.tendcf.canary.main.plist"
    check "launchd canary system render: policy completed" policy_completed "$work/launchd-canary-sys.out"
    check "launchd canary system render: byte-identical to committed system golden" \
        cmp -s "$golden_sys_dir/com.tendcf.canary.main.plist" "$canary_sys_p"
    check "launchd canary system render: passes plutil -lint" plutil_lint "$canary_sys_p"
    check "launchd canary system render: mode is 0644" \
        bash -c "[ \"\$(stat -f '%Lp' '$canary_sys_p')\" = 644 ]"
    check "launchd canary system render: bootstrapped via launchctl bootstrap system" \
        grep -qxF "$(printf 'bootstrap\tsystem\t%s' "$canary_sys_p")" "$launchctl_log"
    check "launchd canary system render: no .cf-*-edit backup/temp left" no_cf_edit_files

    # 5m.2 Unchanged re-run (loaded, unchanged -> hash unchanged, zero launchctl write calls).
    hash_main_1="$(shasum -a 256 "$launchd_daemons/com.tendcf.demo.main.plist" | awk '{print $1}')"
    hash_second_1="$(shasum -a 256 "$launchd_daemons/com.tendcf.demo.second.plist" | awk '{print $1}')"
    launchd_run launchd-present.json "$work/launchd-unchanged.out"
    hash_main_2="$(shasum -a 256 "$launchd_daemons/com.tendcf.demo.main.plist" | awk '{print $1}')"
    hash_second_2="$(shasum -a 256 "$launchd_daemons/com.tendcf.demo.second.plist" | awk '{print $1}')"
    check "launchd unchanged re-run: main plist hash unchanged" test "$hash_main_1" = "$hash_main_2"
    check "launchd unchanged re-run: second plist hash unchanged" test "$hash_second_1" = "$hash_second_2"
    check "launchd unchanged re-run: print probe ran for main" \
        grep -qxF "$(printf 'print\tsystem/com.tendcf.demo.main')" "$launchctl_log"
    check "launchd unchanged re-run: zero launchctl write calls (no bootstrap or bootout)" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"
    check "launchd unchanged re-run: no .cf-*-edit backup/temp left" no_cf_edit_files

    # 5m.15b Dry-run (-n) on converged loaded plists (no-interlock fixture): zero failed lines, zero Would execute, zero write calls.
    launchd_run_dry_file "$launchd_present_no_interlock" "$work/launchd-dry-converged.out"
    check "launchd dry-run (converged): policy completed" dry_policy_completed "$work/launchd-dry-converged.out"
    check "launchd dry-run (converged): zero failed report lines" no_failed_reports "$work/launchd-dry-converged.out"
    check "launchd dry-run (converged): zero Would execute previews" \
        bash -c "! grep -q 'Would execute script .*launchctl' '$work/launchd-dry-converged.out'"
    check "launchd dry-run (converged): zero launchctl write calls" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"

    # 5m.15c Dry-run (-n) on drifted loaded plist (no-interlock fixture): zero failed lines, plist stays drifted, zero write calls, bootout+bootstrap previewed for drifted service only.
    python3 - "$launchd_daemons/com.tendcf.demo.main.plist" <<'PYEOF'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
txt = p.read_text()
assert "<string>1</string>" in txt
p.write_text(txt.replace("<string>1</string>", "<string>99</string>", 1))
PYEOF
    launchd_run_dry_file "$launchd_present_no_interlock" "$work/launchd-dry-drift.out"
    check "launchd dry-run (drifted): policy completed" dry_policy_completed "$work/launchd-dry-drift.out"
    check "launchd dry-run (drifted): zero failed report lines" no_failed_reports "$work/launchd-dry-drift.out"
    check "launchd dry-run (drifted): drifted plist untouched on disk" \
        grep -q '<string>99</string>' "$launchd_daemons/com.tendcf.demo.main.plist"
    check "launchd dry-run (drifted): zero launchctl write calls" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"
    check "launchd dry-run (drifted): bootout previewed via Would execute" \
        grep -q "Would execute script .*bootout system/com.tendcf.demo.main" "$work/launchd-dry-drift.out"
    check "launchd dry-run (drifted): bootstrap previewed via Would execute" \
        grep -q "Would execute script .*bootstrap system .*com.tendcf.demo.main.plist" "$work/launchd-dry-drift.out"
    check "launchd dry-run (drifted): untouched sibling second not previewed" \
        bash -c "! grep -q 'Would execute script .*com\.tendcf\.demo\.second' '$work/launchd-dry-drift.out'"

    # 5m.3 One-key drift on main only -> main repaired to golden, no backup, bootout before bootstrap; second untouched.
    launchd_run launchd-present.json "$work/launchd-drift.out"
    check "launchd one-key drift: main repaired byte-identical to golden" \
        cmp -s "$golden_sys_dir/com.tendcf.demo.main.plist" "$launchd_daemons/com.tendcf.demo.main.plist"
    check "launchd one-key drift: no .cf-*-edit backup/temp left" no_cf_edit_files
    check "launchd one-key drift: main bootout ran strictly before bootstrap" \
        python3 - "$launchctl_log" "$launchd_daemons/com.tendcf.demo.main.plist" <<'PYEOF'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
bo = "bootout\tsystem/com.tendcf.demo.main"
bs = f"bootstrap\tsystem\t{sys.argv[2]}"
assert lines.count(bo) == 1, f"bootout count != 1: {lines}"
assert lines.count(bs) == 1, f"bootstrap count != 1: {lines}"
assert lines.index(bo) < lines.index(bs), f"bootout not before bootstrap: {lines}"
PYEOF
    check "launchd one-key drift: untouched sibling second got no bootout or bootstrap" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]].*com\.tendcf\.demo\.second' '$launchctl_log'"

    # 5m.4 Perms drift (0600 -> repaired to 0644, reloaded, no backup).
    chmod 0600 "$launchd_daemons/com.tendcf.demo.main.plist"
    launchd_run launchd-present.json "$work/launchd-perms.out"
    check "launchd perms drift: mode repaired to 0644" \
        bash -c "[ \"\$(stat -f '%Lp' '$launchd_daemons/com.tendcf.demo.main.plist')\" = 644 ]"
    check "launchd perms drift: bootout + bootstrap ran for main" \
        python3 - "$launchctl_log" "$launchd_daemons/com.tendcf.demo.main.plist" <<'PYEOF'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
bo = "bootout\tsystem/com.tendcf.demo.main"
bs = f"bootstrap\tsystem\t{sys.argv[2]}"
assert bo in lines and bs in lines and lines.index(bo) < lines.index(bs), lines
PYEOF
    check "launchd perms drift: no .cf-*-edit backup/temp left" no_cf_edit_files

    # 5m.5 Failed bootout on drift -> fail-closed (no bootstrap, failure reported), persists reload_pending (M1).
    python3 - "$launchd_daemons/com.tendcf.demo.main.plist" <<'PYEOF'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace("<string>1</string>", "<string>77</string>", 1))
PYEOF
    launchd_run launchd-present.json "$work/launchd-fail-bootout.out" fail-bootout
    check "launchd failed bootout: failure reported" \
        grep -q "tendcf: service 'com.tendcf.demo.main' failed: launchctl bootout system/com.tendcf.demo.main exited non-zero; bootstrap not run" "$work/launchd-fail-bootout.out"
    check "launchd failed bootout: bootout attempted once" \
        launchd_log_count "$(printf 'bootout\tsystem/com.tendcf.demo.main')" 1
    check "launchd failed bootout: bootstrap NOT run" \
        bash -c "! grep -q '^bootstrap' '$launchctl_log'"

    # 5m.5b Recovery on next run (Opus M1): plist on disk is now unchanged, yet persisted reload_pending triggers bootout+bootstrap.
    launchd_run launchd-present.json "$work/launchd-reload-recover.out"
    check "launchd reload recovery (M1): bootout then bootstrap ran despite unchanged plist" \
        python3 - "$launchctl_log" "$launchd_daemons/com.tendcf.demo.main.plist" <<'PYEOF'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
bo = "bootout\tsystem/com.tendcf.demo.main"
bs = f"bootstrap\tsystem\t{sys.argv[2]}"
assert lines.count(bo) == 1, f"expected 1 bootout: {lines}"
assert lines.count(bs) == 1, f"expected 1 bootstrap: {lines}"
assert lines.index(bo) < lines.index(bs), f"bootout not before bootstrap: {lines}"
PYEOF
    check "launchd reload recovery (M1): sibling second got no bootout or bootstrap" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]].*com\.tendcf\.demo\.second' '$launchctl_log'"

    # 5m.5c Run after recovery: cancel_repaired cleared reload_pending -> zero launchctl write calls.
    launchd_run launchd-present.json "$work/launchd-reload-settled.out"
    check "launchd post-recovery re-run (M1): zero launchctl write calls" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"

    # 5m.6 Failed bootstrap when unloaded -> failure reported (only attempted once).
    rm -f "$launchctl_state/com.tendcf.demo.main"
    launchd_run launchd-present.json "$work/launchd-fail-bootstrap.out" fail-bootstrap
    check "launchd failed bootstrap: failure reported" \
        grep -q "tendcf: service 'com.tendcf.demo.main' failed: launchctl bootstrap system .*com.tendcf.demo.main.plist exited non-zero" "$work/launchd-fail-bootstrap.out"
    check "launchd failed bootstrap: bootstrap attempted once" \
        launchd_log_count "$(printf 'bootstrap\tsystem\t%s' "$launchd_daemons/com.tendcf.demo.main.plist")" 1
    : > "$launchctl_state/com.tendcf.demo.main"

    # 5m.15d Dry-run (-n) on loaded tombstone: read-only print runs, bootout previewed, plist preserved, zero failed lines.
    launchd_run_dry launchd-absent.json "$work/launchd-dry-tomb.out"
    check "launchd dry-run (tombstone): zero failed report lines" \
        bash -c "! grep -q 'tendcf: service .* failed:' '$work/launchd-dry-tomb.out'"
    check "launchd dry-run (tombstone): plist left on disk" \
        test -f "$launchd_daemons/com.tendcf.demo.main.plist"
    check "launchd dry-run (tombstone): zero bootout executed" \
        bash -c "! grep -q '^bootout' '$launchctl_log'"
    check "launchd dry-run (tombstone): bootout previewed via Would execute" \
        grep -q "Would execute script .*bootout system/com.tendcf.demo.main" "$work/launchd-dry-tomb.out"

    # 5m.7a Tombstone when print probe returns unexpected error (exit 5, Adversary #2) -> fail-closed, plist preserved.
    launchd_run launchd-absent.json "$work/launchd-tomb-probe-fail.out" fail-print
    check "launchd tombstone failed print probe: failure reported" \
        grep -q "tendcf: service 'com.tendcf.demo.main' tombstone failed: launchctl print system/com.tendcf.demo.main exited with unexpected error; plist left in place" "$work/launchd-tomb-probe-fail.out"
    check "launchd tombstone failed print probe: zero bootout calls" \
        bash -c "! grep -q '^bootout' '$launchctl_log'"
    check "launchd tombstone failed print probe: plist left in place" \
        test -f "$launchd_daemons/com.tendcf.demo.main.plist"

    # 5m.7b Tombstone when bootout fails -> plist preserved on disk (fail-closed), failure reported.
    launchd_run launchd-absent.json "$work/launchd-tomb-fail.out" fail-bootout
    check "launchd tombstone failed bootout: failure reported" \
        grep -q "tendcf: service 'com.tendcf.demo.main' tombstone failed: launchctl bootout system/com.tendcf.demo.main exited non-zero; plist left in place" "$work/launchd-tomb-fail.out"
    check "launchd tombstone failed bootout: plist left in place" \
        test -f "$launchd_daemons/com.tendcf.demo.main.plist"

    # 5m.8 Tombstone when loaded -> bootout runs strictly BEFORE delete, then plist removed; sibling untouched.
    rm -f "$launchctl_state/com.tendcf.demo.main.had_plist"
    launchd_run launchd-absent.json "$work/launchd-tomb.out"
    check "launchd tombstone: bootout ran for main" \
        grep -qxF "$(printf 'bootout\tsystem/com.tendcf.demo.main')" "$launchctl_log"
    check "launchd tombstone: plist still existed when bootout ran (bootout before delete)" \
        test -f "$launchctl_state/com.tendcf.demo.main.had_plist"
    check "launchd tombstone: plist removed after bootout" \
        test ! -e "$launchd_daemons/com.tendcf.demo.main.plist"
    check "launchd tombstone: sibling second.plist left in place" \
        test -f "$launchd_daemons/com.tendcf.demo.second.plist"

    # 5m.9 Second tombstone run (plist already absent) -> zero launchctl calls (not even print).
    launchd_run launchd-absent.json "$work/launchd-tomb2.out"
    check "launchd second tombstone run: zero launchctl calls" test ! -s "$launchctl_log"

    # 5m.10a Tombstone on unloaded regular plist (exit 113) -> deleted without calling bootout.
    cp "$golden_sys_dir/com.tendcf.demo.main.plist" "$launchd_daemons/com.tendcf.demo.main.plist"
    rm -f "$launchctl_state/com.tendcf.demo.main"
    launchd_run launchd-absent.json "$work/launchd-tomb-unloaded.out"
    check "launchd unloaded tombstone (113): no bootout call" \
        bash -c "! grep -q '^bootout' '$launchctl_log'"
    check "launchd unloaded tombstone (113): stale regular plist deleted" \
        test ! -e "$launchd_daemons/com.tendcf.demo.main.plist"

    # 5m.10b Tombstone on unloaded regular plist (exit 3 ESRCH) -> deleted without calling bootout.
    cp "$golden_sys_dir/com.tendcf.demo.main.plist" "$launchd_daemons/com.tendcf.demo.main.plist"
    launchd_run launchd-absent.json "$work/launchd-tomb-unloaded3.out" print-unloaded-3
    check "launchd unloaded tombstone (3 ESRCH): no bootout call" \
        bash -c "! grep -q '^bootout' '$launchctl_log'"
    check "launchd unloaded tombstone (3 ESRCH): stale regular plist deleted" \
        test ! -e "$launchd_daemons/com.tendcf.demo.main.plist"

    # 5m.11 Tombstone gate (C-policy-04): symlink, dangling link, directory refused with zero launchctl calls.
    sym_target="$work/launchd-symlink-target.plist"
    printf 'sentinel\n' > "$sym_target"
    ln -s "$sym_target" "$launchd_daemons/com.tendcf.demo.symlink.plist"
    ln -s /nonexistent/tendcf-launchd "$launchd_daemons/com.tendcf.demo.dangling.plist"
    mkdir -p "$launchd_daemons/com.tendcf.demo.dir.plist"
    launchd_run launchd-absent-links.json "$work/launchd-tomb-links.out"
    for kind in symlink dangling dir; do
        check "launchd tombstone non-regular ($kind): refused and reported" \
            grep -q "tendcf: service 'com.tendcf.demo.$kind' tombstone not actuated: .*com.tendcf.demo.$kind.plist is not a regular file" "$work/launchd-tomb-links.out"
    done
    check "launchd tombstone non-regular: zero launchctl calls (not even print)" \
        test ! -s "$launchctl_log"
    check "launchd tombstone non-regular: symlink preserved" \
        bash -c "[ \"\$(readlink '$launchd_daemons/com.tendcf.demo.symlink.plist')\" = '$sym_target' ]"
    check "launchd tombstone non-regular: symlink target untouched" \
        grep -qxF "sentinel" "$sym_target"
    check "launchd tombstone non-regular: dangling link preserved" \
        bash -c "[ \"\$(readlink '$launchd_daemons/com.tendcf.demo.dangling.plist')\" = /nonexistent/tendcf-launchd ]"
    check "launchd tombstone non-regular: directory preserved" \
        test -d "$launchd_daemons/com.tendcf.demo.dir.plist"

    # 5m.12 Present service targeting non-regular paths (symlink, dangling symlink, directory) -> refused, untouched, zero launchctl calls.
    present_target="$work/launchd-present-sym-target.plist"
    printf 'untouched\n' > "$present_target"
    ln -s "$present_target" "$launchd_daemons/com.tendcf.demo.present-sym.plist"
    ln -s /nonexistent/tendcf-present "$launchd_daemons/com.tendcf.demo.present-dangling.plist"
    mkdir -p "$launchd_daemons/com.tendcf.demo.present-dir.plist"
    cat > "$work/data/host_specific.json" <<'EOF'
{"vars":{"tendcf_interlock":{"demo-check":{"blocks":"enclosing-bundle","bundle":"demo","defines_class":"demo_ok","pre_action":{"command":["/usr/bin/true"],"expect_exit":0,"timeout_seconds":5},"report":true,"state":"present"}},"tendcf_service":{"com.tendcf.demo.present-sym":{"bundle":"demo","command":["/bin/sleep","1"],"run_as":"nobody","state":"present","unit":{"launchd":{"domain":"system","keep_alive":true,"run_at_load":true}},"working_dir":"/"},"com.tendcf.demo.present-dangling":{"bundle":"demo","command":["/bin/sleep","1"],"run_as":"nobody","state":"present","unit":{"launchd":{"domain":"system","keep_alive":true,"run_at_load":true}},"working_dir":"/"},"com.tendcf.demo.present-dir":{"bundle":"demo","command":["/bin/sleep","1"],"run_as":"nobody","state":"present","unit":{"launchd":{"domain":"system","keep_alive":true,"run_at_load":true}},"working_dir":"/"}}}}
EOF
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-present-sym.out" 2>&1 || true
    for kind in present-sym present-dangling present-dir; do
        check "launchd present non-regular ($kind): refused and reported" \
            grep -q "tendcf: service 'com.tendcf.demo.$kind' refused: .*com.tendcf.demo.$kind.plist is not a regular file" "$work/launchd-present-sym.out"
    done
    check "launchd present non-regular: symlink target untouched" \
        grep -qxF "untouched" "$present_target"
    check "launchd present non-regular: dangling link preserved" \
        bash -c "[ \"\$(readlink '$launchd_daemons/com.tendcf.demo.present-dangling.plist')\" = /nonexistent/tendcf-present ]"
    check "launchd present non-regular: directory preserved" \
        test -d "$launchd_daemons/com.tendcf.demo.present-dir.plist"
    check "launchd present non-regular: zero launchctl calls" \
        test ! -s "$launchctl_log"
    rm -rf "$launchd_daemons/com.tendcf.demo.present-sym.plist" \
           "$launchd_daemons/com.tendcf.demo.present-dangling.plist" \
           "$launchd_daemons/com.tendcf.demo.present-dir.plist"

    # 5m.13 Invalid service ids (traversal, spaces, quotes, leading dot/dash, 129-char) refused; 128-char accepted.
    id_128="com.tendcf.$(printf 'a%.0s' $(seq 1 117))"
    id_129="com.tendcf.$(printf 'b%.0s' $(seq 1 118))"
    python3 - "$work/data/host_specific.json" "$id_128" "$id_129" <<'PYEOF'
import json, pathlib, sys
out_path, id128, id129 = sys.argv[1], sys.argv[2], sys.argv[3]
assert len(id128) == 128 and len(id129) == 129
svc_body = {
    "bundle": "demo",
    "command": ["/bin/sleep", "1"],
    "run_as": "nobody",
    "state": "present",
    "unit": {"launchd": {"domain": "system", "keep_alive": True, "run_at_load": True}},
    "working_dir": "/",
}
doc = {
    "vars": {
        "tendcf_interlock": {
            "demo-check": {
                "blocks": "enclosing-bundle",
                "bundle": "demo",
                "defines_class": "demo_ok",
                "pre_action": {"command": ["/usr/bin/true"], "expect_exit": 0, "timeout_seconds": 5},
                "report": True,
                "state": "present",
            }
        },
        "tendcf_service": {
            "../escaped": svc_body,
            "../escaped-tomb": {"state": "absent"},
            "bad space": svc_body,
            'bad"quote': svc_body,
            ".leading-dot": svc_body,
            "-leading-dash": svc_body,
            id129: svc_body,
            id128: svc_body,
        },
    }
}
pathlib.Path(out_path).write_text(json.dumps(doc))
PYEOF
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    printf 'keep\n' > "$work/escaped-tomb.plist"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-bad-id.out" 2>&1 || true
    check "launchd invalid present ids: refused and reported" \
        grep -q "tendcf: launchd service refused: id is not a valid launchd label" "$work/launchd-bad-id.out"
    check "launchd invalid tombstone id: refused and reported" \
        grep -q "tendcf: launchd tombstone refused: id is not a valid launchd label" "$work/launchd-bad-id.out"
    check "launchd invalid id: no file created outside launchd_dir" \
        test ! -e "$work/escaped.plist"
    check "launchd invalid id: file outside launchd_dir not deleted" \
        test -f "$work/escaped-tomb.plist"
    for bad in "bad space" 'bad"quote' ".leading-dot" "-leading-dash" "$id_129"; do
        check "launchd invalid id ($bad): no plist created" test ! -e "$launchd_daemons/$bad.plist"
    done
    check "launchd 128-char valid id: plist rendered and passes plutil -lint" \
        plutil_lint "$launchd_daemons/$id_128.plist"
    check "launchd 128-char valid id: bootstrapped" \
        grep -qxF "$(printf 'bootstrap\tsystem\t%s' "$launchd_daemons/$id_128.plist")" "$launchctl_log"
    check "launchd invalid ids: only 128-char valid id reached launchctl" \
        python3 - "$launchctl_log" "$id_128" <<'PYEOF'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
assert lines and all(sys.argv[2] in l for l in lines), lines
PYEOF
    rm -f "$launchd_daemons/$id_128.plist" "$launchctl_state/$id_128"

    # 5m.16a Service-id canonify() collision (H1 / Adversary #1): two schema-valid colliding ids
    # (present regular plist + absent symlink) -> all actuation refused, zero bootouts, zero deletions, symlink preserved.
    cp "$golden_sys_dir/com.tendcf.demo.main.plist" "$launchd_daemons/com.tendcf.demo.main.plist"
    : > "$launchctl_state/com.tendcf.demo.main"
    col_sym_target="$work/launchd-col-sym-target.plist"
    printf 'keep-symlink\n' > "$col_sym_target"
    ln -s "$col_sym_target" "$launchd_daemons/com.tendcf.demo-main.plist"
    cat > "$work/data/host_specific.json" <<'EOF'
{"vars":{"tendcf_interlock":{"demo-check":{"blocks":"enclosing-bundle","bundle":"demo","defines_class":"demo_ok","pre_action":{"command":["/usr/bin/true"],"expect_exit":0,"timeout_seconds":5},"report":true,"state":"present"}},"tendcf_service":{"com.tendcf.demo.main":{"bundle":"demo","command":["/bin/sleep","1"],"run_as":"nobody","state":"present","unit":{"launchd":{"domain":"system","keep_alive":true,"run_at_load":true}},"working_dir":"/"},"com.tendcf.demo-main":{"state":"absent"}}}}
EOF
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-col-canon.out" 2>&1 || true
    check "launchd canonify collision (schema-valid): refusal reported" \
        grep -q "tendcf: service actuation refused: two or more service ids collide under canonify()" "$work/launchd-col-canon.out"
    check "launchd canonify collision (schema-valid): zero launchctl calls" \
        test ! -s "$launchctl_log"
    check "launchd canonify collision (schema-valid): present plist preserved" \
        test -f "$launchd_daemons/com.tendcf.demo.main.plist"
    check "launchd canonify collision (schema-valid): colliding symlink preserved" \
        bash -c "[ \"\$(readlink '$launchd_daemons/com.tendcf.demo-main.plist')\" = '$col_sym_target' ]"
    rm -f "$launchd_daemons/com.tendcf.demo-main.plist"

    # 5m.16b Valid ID paired with colliding invalid ID (space) -> refused, zero actuation.
    cat > "$work/data/host_specific.json" <<'EOF'
{"vars":{"tendcf_interlock":{"demo-check":{"blocks":"enclosing-bundle","bundle":"demo","defines_class":"demo_ok","pre_action":{"command":["/usr/bin/true"],"expect_exit":0,"timeout_seconds":5},"report":true,"state":"present"}},"tendcf_service":{"com.tendcf.demo.main":{"bundle":"demo","command":["/bin/sleep","1"],"run_as":"nobody","state":"present","unit":{"launchd":{"domain":"system","keep_alive":true,"run_at_load":true}},"working_dir":"/"},"com.tendcf.demo main":{"bundle":"demo","command":["/bin/sleep","1"],"run_as":"nobody","state":"present","unit":{"launchd":{"domain":"system","keep_alive":true,"run_at_load":true}},"working_dir":"/"}}}}
EOF
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-col-invalid.out" 2>&1 || true
    check "launchd canonify collision (valid+invalid): refusal reported" \
        grep -q "tendcf: service actuation refused: two or more service ids collide under canonify()" "$work/launchd-col-invalid.out"
    check "launchd canonify collision (valid+invalid): zero launchctl calls" \
        test ! -s "$launchctl_log"
    check "launchd canonify collision (valid+invalid): invalid plist not created" \
        test ! -e "$launchd_daemons/com.tendcf.demo main.plist"

    # 5m.16c Case-colliding IDs on darwin APFS -> refused, zero actuation.
    cat > "$work/data/host_specific.json" <<'EOF'
{"vars":{"tendcf_interlock":{"demo-check":{"blocks":"enclosing-bundle","bundle":"demo","defines_class":"demo_ok","pre_action":{"command":["/usr/bin/true"],"expect_exit":0,"timeout_seconds":5},"report":true,"state":"present"}},"tendcf_service":{"com.tendcf.Demo.main":{"bundle":"demo","command":["/bin/sleep","1"],"run_as":"nobody","state":"present","unit":{"launchd":{"domain":"system","keep_alive":true,"run_at_load":true}},"working_dir":"/"},"com.tendcf.demo.main":{"state":"absent"}}}}
EOF
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-col-case.out" 2>&1 || true
    check "launchd APFS case collision: refusal reported" \
        grep -q "tendcf: service actuation refused: two or more service ids collide case-insensitively on darwin (APFS)" "$work/launchd-col-case.out"
    check "launchd APFS case collision: zero launchctl calls" \
        test ! -s "$launchctl_log"
    check "launchd APFS case collision: existing plist preserved" \
        test -f "$launchd_daemons/com.tendcf.demo.main.plist"

    # 5m.16d Single-tombstone APFS case mismatch: file com.tendcf.Demo.case.plist on disk, tombstone com.tendcf.demo.case.
    cp "$golden_sys_dir/com.tendcf.demo.main.plist" "$launchd_daemons/com.tendcf.Demo.case.plist"
    cat > "$work/data/host_specific.json" <<'EOF'
{"vars":{"tendcf_interlock":{"demo-check":{"blocks":"enclosing-bundle","bundle":"demo","defines_class":"demo_ok","pre_action":{"command":["/usr/bin/true"],"expect_exit":0,"timeout_seconds":5},"report":true,"state":"present"}},"tendcf_service":{"com.tendcf.demo.case":{"state":"absent"}}}}
EOF
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-case-tomb.out" 2>&1 || true
    check "launchd single-tombstone case mismatch: zero launchctl calls" test ! -s "$launchctl_log"
    check "launchd single-tombstone case mismatch: differently-cased plist preserved" \
        test -f "$launchd_daemons/com.tendcf.Demo.case.plist"
    if [ -f "$launchd_daemons/com.tendcf.demo.case.plist" ]; then
        check "launchd single-tombstone case mismatch (case-insensitive FS): mismatch reported" \
            grep -q "tendcf: service 'com.tendcf.demo.case' tombstone not actuated: no exact-case entry 'com.tendcf.demo.case.plist'" "$work/launchd-case-tomb.out"
    fi
    rm -f "$launchd_daemons/com.tendcf.Demo.case.plist"

    # 5m.17 XML-escaping & shell-metacharacter inertness round-trip
    # (<, >, &, ", ', ;, |, &&, backticks, redirection) through
    # launchd.plist.mustache + plutil -lint + plistlib.load (issue #54).
    meta_sentinel="$work/launchd-meta-should-not-exist"
    rm -f "$meta_sentinel"
    python3 - "$work/data/host_specific.json" "$meta_sentinel" <<'PYEOF'
import json, pathlib, sys
out_path, sentinel = sys.argv[1], sys.argv[2]
doc = {
    "vars": {
        "tendcf_interlock": {
            "demo-check": {
                "blocks": "enclosing-bundle",
                "bundle": "demo",
                "defines_class": "demo_ok",
                "pre_action": {"command": ["/usr/bin/true"], "expect_exit": 0, "timeout_seconds": 5},
                "report": True,
                "state": "present",
            }
        },
        "tendcf_service": {
            "com.tendcf.demo.xml": {
                "bundle": "demo",
                "command": [
                    "/bin/echo",
                    "a&b",
                    "<tag>",
                    '"quoted"',
                    "'single'",
                    ";",
                    "|",
                    "&&",
                    f"`touch {sentinel}`",
                    f">{sentinel}",
                    "</dev/null",
                ],
                "run_as": "nobody",
                "state": "present",
                "unit": {"launchd": {"domain": "system", "keep_alive": False, "run_at_load": True}},
                "working_dir": '/tmp/dir&<"x">;a|b&&`c`',
            }
        },
    }
}
pathlib.Path(out_path).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-xml.out" 2>&1 || true
    xml_plist="$launchd_daemons/com.tendcf.demo.xml.plist"
    check "launchd XML escaping & metacharacter inertness: rendered plist passes plutil -lint" plutil_lint "$xml_plist"
    check "launchd XML escaping & metacharacter inertness: plistlib decodes exact characters" \
        python3 - "$xml_plist" "$meta_sentinel" <<'PYEOF'
import plistlib, sys
sentinel = sys.argv[2]
with open(sys.argv[1], "rb") as f:
    doc = plistlib.load(f)
assert doc["Label"] == "com.tendcf.demo.xml"
assert doc["ProgramArguments"] == [
    "/bin/echo",
    "a&b",
    "<tag>",
    '"quoted"',
    "'single'",
    ";",
    "|",
    "&&",
    f"`touch {sentinel}`",
    f">{sentinel}",
    "</dev/null",
], doc["ProgramArguments"]
assert doc["WorkingDirectory"] == '/tmp/dir&<"x">;a|b&&`c`', doc["WorkingDirectory"]
PYEOF
    check "launchd metacharacter inertness: no shell command executed during render" \
        test ! -e "$meta_sentinel"
    rm -f "$xml_plist" "$launchctl_state/com.tendcf.demo.xml"

    # 5m.18 Tombstone on darwin.!tendcf_launchd_host (symlinked launchd_dir, Neon L6) -> refused and reported, zero launchctl calls.
    bad_dir_link="$work/launchd-dir-symlink"
    ln -s "$launchd_daemons" "$bad_dir_link"
    cat > "$work/inputs/launchd-badhost.cf" <<EOF
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf", "$repo/tests/policy/fixtures/test-done.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_launchd_badhost", "tendcf_test_done" };
}
bundle agent tendcf_launchd_badhost
{
  methods:
      "run"
        usebundle => tendcf_services_apply("system", "$bad_dir_link", "$launchctl_stub", "$test_user", "$test_group", "$test_user", "0");
}
EOF
    : > "$launchctl_log"
    cp "$repo/tests/policy/fixtures/launchd-absent.json" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-badhost.cf" >"$work/launchd-tomb-badhost.out" 2>&1 || true
    check "launchd tombstone on !tendcf_launchd_host: refused and reported" \
        grep -q "tendcf: service 'com.tendcf.demo.main' tombstone not actuated: launchd domain/identity invalid, .* is not a real directory, or .* is not executable" "$work/launchd-tomb-badhost.out"
    check "launchd tombstone on !tendcf_launchd_host: zero launchctl calls" test ! -s "$launchctl_log"
    check "launchd tombstone on !tendcf_launchd_host: plist untouched" \
        test -f "$launchd_daemons/com.tendcf.demo.main.plist"

    # 5m.19 User-domain LaunchAgent lifecycle (user-gui + user-background), Q1 skips,
    # headless deferral, peer anti-dual-load sweeps, and dual-domain tombstones (issues #94, #103).
    user_gui_canary_fx="$work/host_specific-user-gui-canary.json"
    user_bg_canary_fx="$work/host_specific-user-bg-canary.json"
    python3 - "$repo/deploy/darwin/canary/host_specific-user-gui.json" "$user_gui_canary_fx" "$test_user" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["vars"]["tendcf_service"]["com.tendcf.canary.main"]["run_as"] = sys.argv[3]
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    python3 - "$repo/deploy/darwin/canary/host_specific-user-background.json" "$user_bg_canary_fx" "$test_user" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["vars"]["tendcf_service"]["com.tendcf.canary.main"]["run_as"] = sys.argv[3]
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF

    # 5m.19a First render in user-gui domain -> byte-identical to user-gui golden (LimitLoadToSessionType=Aqua, no UserName), gui/<uid> bootstrap.
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    cp "$user_gui_canary_fx" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-first.out" 2>&1 || true
    user_plist="$launchd_agents/com.tendcf.canary.main.plist"
    check "launchd user-gui render: policy completed" policy_completed "$work/launchd-user-first.out"
    check "launchd user-gui render: byte-identical to committed user-gui golden (Aqua, no UserName)" \
        cmp -s "$golden_user_gui_dir/com.tendcf.canary.main.plist" "$user_plist"
    check "launchd user-gui render: passes plutil -lint" plutil_lint "$user_plist"
    check "launchd user-gui render: mode is 0644" \
        bash -c "[ \"\$(stat -f '%Lp' '$user_plist')\" = 644 ]"
    check "launchd user-gui render: owner is $test_user" \
        bash -c "[ \"\$(stat -f '%Su' '$user_plist')\" = '$test_user' ]"
    check "launchd user-gui render: domain-level probes ran once each" \
        bash -c "grep -cxF \"\$(printf 'print\tgui/%s' '$test_uid')\" '$launchctl_log' | grep -qx 1 && grep -cxF \"\$(printf 'print\tuser/%s' '$test_uid')\" '$launchctl_log' | grep -qx 1"
    check "launchd user-gui render: probed via launchctl print gui/$test_uid/com.tendcf.canary.main" \
        grep -qxF "$(printf 'print\tgui/%s/com.tendcf.canary.main' "$test_uid")" "$launchctl_log"
    check "launchd user-gui render: bootstrapped via launchctl bootstrap gui/$test_uid" \
        grep -qxF "$(printf 'bootstrap\tgui/%s\t%s' "$test_uid" "$user_plist")" "$launchctl_log"
    check "launchd user-gui render: no .cf-*-edit backup/temp left" \
        bash -c "[ -z \"\$(find '$launchd_agents' -name '*.cf-*-edit')\" ]"

    # 5m.19b User-gui unchanged re-run -> zero bootstrap/bootout calls.
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-unchanged.out" 2>&1 || true
    check "launchd user-gui unchanged re-run: zero launchctl write calls" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"

    # 5m.19c User-domain tombstone teardown (single-domain + dual-loaded + fail-closed legs).
    : > "$launchctl_log"
    cp "$repo/deploy/darwin/canary/host_specific-absent.json" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-tomb.out" 2>&1 || true
    check "launchd user tombstone: bootout ran on gui/$test_uid" \
        grep -qxF "$(printf 'bootout\tgui/%s/com.tendcf.canary.main' "$test_uid")" "$launchctl_log"
    check "launchd user tombstone: user plist removed" test ! -e "$user_plist"
    check "launchd user tombstone: system canary plist untouched" test -f "$canary_sys_p"

    # Second user tombstone run (plist already gone) -> zero launchctl calls (not even domain probes).
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-tomb2.out" 2>&1 || true
    check "launchd user second tombstone run: zero launchctl calls" test ! -s "$launchctl_log"

    # Dual-loaded tombstone (loaded in BOTH gui/<uid> and user/<uid>): BOTH booted out before delete; failure in either keeps plist.
    cp "$golden_user_gui_dir/com.tendcf.canary.main.plist" "$user_plist"
    : > "$launchctl_state/gui.com.tendcf.canary.main"
    : > "$launchctl_state/user.com.tendcf.canary.main"
    rm -f "$launchctl_state/gui.com.tendcf.canary.main.had_plist" "$launchctl_state/user.com.tendcf.canary.main.had_plist"
    for leg_mode in fail-gui-bootout fail-user-bootout fail-gui-print fail-user-print; do
        : > "$launchctl_log"
        printf '%s\n' "$leg_mode" > "$launchctl_mode"
        cp "$repo/deploy/darwin/canary/host_specific-absent.json" "$work/data/host_specific.json"
        "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-tomb-$leg_mode.out" 2>&1 || true
        check "launchd dual tombstone ($leg_mode): plist preserved fail-closed" test -f "$user_plist"
        check "launchd dual tombstone ($leg_mode): tombstone failed reported" \
            grep -q "tendcf: service 'com.tendcf.canary.main' tombstone failed:" "$work/launchd-user-tomb-$leg_mode.out"
        : > "$launchctl_state/gui.com.tendcf.canary.main"
        : > "$launchctl_state/user.com.tendcf.canary.main"
    done
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-tomb-dual.out" 2>&1 || true
    check "launchd dual tombstone: bootout ran on BOTH gui/$test_uid and user/$test_uid" \
        bash -c "grep -qxF \"\$(printf 'bootout\tgui/%s/com.tendcf.canary.main' '$test_uid')\" '$launchctl_log' && grep -qxF \"\$(printf 'bootout\tuser/%s/com.tendcf.canary.main' '$test_uid')\" '$launchctl_log'"
    check "launchd dual tombstone: plist still existed when both bootouts ran" \
        bash -c "[ -f '$launchctl_state/gui.com.tendcf.canary.main.had_plist' ] && [ -f '$launchctl_state/user.com.tendcf.canary.main.had_plist' ]"
    check "launchd dual tombstone: plist deleted after both bootouts" test ! -e "$user_plist"

    # 5m.19d Q1 cross-domain informational skips + fail-closed invalid/stale-v8 domain & run_as refusals.
    # (1a) domain: "user-gui" skipped informationally (NOT refused) in system mode.
    : > "$launchctl_log"
    cp "$user_gui_canary_fx" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-skip-user-gui-in-sys.out" 2>&1 || true
    check "launchd Q1 skip (user-gui in system mode): informational skipped reported" \
        grep -qF "tendcf: service 'com.tendcf.canary.main' skipped: belongs to launchd 'user-gui' domain (this agent runs 'system')" "$work/launchd-skip-user-gui-in-sys.out"
    check "launchd Q1 skip (user-gui in system mode): NOT reported as refused" \
        bash -c "! grep -q 'refused:' '$work/launchd-skip-user-gui-in-sys.out'"
    check "launchd Q1 skip (user-gui in system mode): zero launchctl calls" test ! -s "$launchctl_log"

    # (1b) domain: "user-background" skipped informationally (NOT refused) in system mode.
    : > "$launchctl_log"
    cp "$user_bg_canary_fx" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-skip-user-bg-in-sys.out" 2>&1 || true
    check "launchd Q1 skip (user-background in system mode): informational skipped reported" \
        grep -qF "tendcf: service 'com.tendcf.canary.main' skipped: belongs to launchd 'user-background' domain (this agent runs 'system')" "$work/launchd-skip-user-bg-in-sys.out"
    check "launchd Q1 skip (user-background in system mode): NOT reported as refused" \
        bash -c "! grep -q 'refused:' '$work/launchd-skip-user-bg-in-sys.out'"
    check "launchd Q1 skip (user-background in system mode): zero launchctl calls" test ! -s "$launchctl_log"

    # (2) domain: "system" skipped informationally (NOT refused) in user mode, even with run_as=nobody.
    : > "$launchctl_log"
    cp "$repo/deploy/darwin/canary/host_specific.json" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-skip-sys-in-user.out" 2>&1 || true
    check "launchd Q1 skip (system in user mode): informational skipped reported" \
        grep -qF "tendcf: service 'com.tendcf.canary.main' skipped: belongs to launchd 'system' domain (this agent runs 'user-gui' and 'user-background')" "$work/launchd-skip-sys-in-user.out"
    check "launchd Q1 skip (system in user mode): NOT reported as refused" \
        bash -c "! grep -q 'refused:' '$work/launchd-skip-sys-in-user.out'"
    check "launchd Q1 skip (system in user mode): no plist written in agents dir" test ! -e "$user_plist"
    check "launchd Q1 skip (system in user mode): zero launchctl calls" test ! -s "$launchctl_log"

    # (3) domain: "user-gui" with mismatched run_as stays refused in user mode.
    python3 - "$repo/deploy/darwin/canary/host_specific-user-gui.json" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["vars"]["tendcf_service"]["com.tendcf.canary.main"]["run_as"] = "otheruser"
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-mismatch-runas.out" 2>&1 || true
    check "launchd privilege split (mismatched run_as in user mode): refused and reported" \
        grep -q "tendcf: service 'com.tendcf.canary.main' refused: user-domain service run_as 'otheruser' does not match running user '$test_user'" "$work/launchd-mismatch-runas.out"
    check "launchd privilege split (mismatched run_as in user mode): no plist written" test ! -e "$user_plist"
    check "launchd privilege split (mismatched run_as in user mode): zero launchctl calls" test ! -s "$launchctl_log"

    # (4a) missing unit.launchd.domain refused fail-closed.
    python3 - "$repo/deploy/darwin/canary/host_specific.json" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
del doc["vars"]["tendcf_service"]["com.tendcf.canary.main"]["unit"]["launchd"]["domain"]
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-missing-domain.out" 2>&1 || true
    check "launchd missing unit.launchd.domain: refused and reported" \
        grep -qF "tendcf: service 'com.tendcf.canary.main' refused: missing or invalid unit.launchd.domain (expected 'system', 'user-gui', or 'user-background')" "$work/launchd-missing-domain.out"
    check "launchd missing unit.launchd.domain: zero launchctl calls" test ! -s "$launchctl_log"

    # (4b) stale v8 domain: "user" refused fail-closed in BOTH system and user modes (NOT skipped!).
    python3 - "$user_gui_canary_fx" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["vars"]["tendcf_service"]["com.tendcf.canary.main"]["unit"]["launchd"]["domain"] = "user"
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-stale-v8-sys.out" 2>&1 || true
    check "launchd stale v8 domain='user' (system mode): refused and reported" \
        grep -qF "tendcf: service 'com.tendcf.canary.main' refused: missing or invalid unit.launchd.domain (expected 'system', 'user-gui', or 'user-background')" "$work/launchd-stale-v8-sys.out"
    check "launchd stale v8 domain='user' (system mode): zero launchctl calls" test ! -s "$launchctl_log"
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-stale-v8-user.out" 2>&1 || true
    check "launchd stale v8 domain='user' (user mode): refused and reported" \
        grep -qF "tendcf: service 'com.tendcf.canary.main' refused: missing or invalid unit.launchd.domain (expected 'system', 'user-gui', or 'user-background')" "$work/launchd-stale-v8-user.out"
    check "launchd stale v8 domain='user' (user mode): no plist written" test ! -e "$user_plist"
    check "launchd stale v8 domain='user' (user mode): zero launchctl calls" test ! -s "$launchctl_log"

    # (5) user mode with uid 0 fails closed (!tendcf_launchd_host).
    cat > "$work/inputs/launchd-user-uid0.cf" <<EOF
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf", "$repo/tests/policy/fixtures/test-done.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_launchd_user_uid0", "tendcf_test_done" };
}
bundle agent tendcf_launchd_user_uid0
{
  methods:
      "run"
        usebundle => tendcf_services_apply("user", "$launchd_agents", "$launchctl_stub", "$test_user", "$test_gid", "$test_user", "0");
}
EOF
    : > "$launchctl_log"
    cp "$user_gui_canary_fx" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-uid0.cf" >"$work/launchd-user-uid0.out" 2>&1 || true
    check "launchd user mode with uid 0: refused fail-closed" \
        grep -q "tendcf: service 'com.tendcf.canary.main' refused: launchd domain/identity invalid" "$work/launchd-user-uid0.out"
    check "launchd user mode with uid 0: no plist written" test ! -e "$user_plist"
    check "launchd user mode with uid 0: zero launchctl calls" test ! -s "$launchctl_log"

    # (6)-(7) user mode must reject system-wide /Library/LaunchAgents variants
    # including APFS firmlink aliases under /System/Volumes/Data/Library/... (Neon HIGH #1, Adversary Note B, Opus R2 N3).
    for sys_agents_case in \
        "single:/Library/LaunchAgents" \
        "double://Library/LaunchAgents" \
        "case:/library/launchagents" \
        "dotslash:/./Library/LaunchAgents" \
        "syslib:/System/Library/LaunchAgents" \
        "trailing:/Library/LaunchAgents/." \
        "firmlink-agents:/System/Volumes/Data/Library/LaunchAgents" \
        "firmlink-daemons:/System/Volumes/Data/Library/LaunchDaemons" \
        "firmlink-case:/system/volumes/data/library/launchagents/." \
        "dotdot-sys:/System/../Library/LaunchAgents" \
        "dotdot-parent:$launchd_agents/.."; do
        cname="${sys_agents_case%%:*}"
        cdir="${sys_agents_case#*:}"
        cat > "$work/inputs/launchd-user-sysdir-$cname.cf" <<EOF
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf", "$repo/tests/policy/fixtures/test-done.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_launchd_user_sysdir", "tendcf_test_done" };
}
bundle agent tendcf_launchd_user_sysdir
{
  methods:
      "run"
        usebundle => tendcf_services_apply("user", "$cdir", "$launchctl_stub", "$test_user", "$test_gid", "$test_user", "$test_uid");
}
EOF
        : > "$launchctl_log"
        cp "$user_gui_canary_fx" "$work/data/host_specific.json"
        "$cf_agent" -K -I -f "$work/inputs/launchd-user-sysdir-$cname.cf" >"$work/launchd-user-sysdir-$cname.out" 2>&1 || true
        check "launchd user mode rejecting $cdir: refused fail-closed" \
            grep -q "tendcf: service 'com.tendcf.canary.main' refused: launchd domain/identity invalid" "$work/launchd-user-sysdir-$cname.out"
        check "launchd user mode rejecting $cdir: zero launchctl calls" test ! -s "$launchctl_log"
    done

    # (8)-(10) missing/invalid run_as refused cleanly in both system and user modes (Adversary L2, Neon M3).
    rm -f "$canary_sys_p" "$launchctl_state/com.tendcf.canary.main" "$user_plist" "$launchctl_state/gui.com.tendcf.canary.main" "$launchctl_state/user.com.tendcf.canary.main"
    python3 - "$repo/deploy/darwin/canary/host_specific.json" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
del doc["vars"]["tendcf_service"]["com.tendcf.canary.main"]["run_as"]
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-sys-missing-runas.out" 2>&1 || true
    check "launchd system mode missing run_as: refused with <missing>" \
        grep -q "tendcf: service 'com.tendcf.canary.main' refused: system-domain service run_as '<missing>' is missing or invalid" "$work/launchd-sys-missing-runas.out"
    check "launchd system mode missing run_as: no plist written" test ! -e "$canary_sys_p"
    check "launchd system mode missing run_as: zero launchctl calls" test ! -s "$launchctl_log"

    python3 - "$repo/deploy/darwin/canary/host_specific.json" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["vars"]["tendcf_service"]["com.tendcf.canary.main"]["run_as"] = "Bad User!"
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-sys-bad-runas.out" 2>&1 || true
    check "launchd system mode invalid run_as: refused and reported (sanitized)" \
        grep -q "tendcf: service 'com.tendcf.canary.main' refused: system-domain service run_as 'Bad?User?' is missing or invalid" "$work/launchd-sys-bad-runas.out"
    check "launchd system mode invalid run_as: no plist written" test ! -e "$canary_sys_p"
    check "launchd system mode invalid run_as: zero launchctl calls" test ! -s "$launchctl_log"

    python3 - "$user_gui_canary_fx" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
del doc["vars"]["tendcf_service"]["com.tendcf.canary.main"]["run_as"]
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-missing-runas.out" 2>&1 || true
    check "launchd user mode missing run_as: refused with <missing>" \
        grep -q "tendcf: service 'com.tendcf.canary.main' refused: user-domain service run_as '<missing>' does not match running user '$test_user'" "$work/launchd-user-missing-runas.out"
    check "launchd user mode missing run_as: no plist written" test ! -e "$user_plist"
    check "launchd user mode missing run_as: zero launchctl calls" test ! -s "$launchctl_log"

    # 5m.19e Adversary M1 regression: class-suffix aliasing (`com.tendcf.canary.main`
    # vs `com.tendcf.canary.main.launchd`) must NEVER bypass domain skip/refusal.
    alias_sys_p="$launchd_daemons/com.tendcf.canary.main.launchd.plist"
    alias_usr_p="$launchd_agents/com.tendcf.canary.main.launchd.plist"
    rm -f "$canary_sys_p" "$alias_sys_p" "$user_plist" "$alias_usr_p" \
        "$launchctl_state/com.tendcf.canary.main" "$launchctl_state/com.tendcf.canary.main.launchd" \
        "$launchctl_state/gui.com.tendcf.canary.main" "$launchctl_state/gui.com.tendcf.canary.main.launchd" \
        "$launchctl_state/user.com.tendcf.canary.main" "$launchctl_state/user.com.tendcf.canary.main.launchd"

    python3 - "$repo/deploy/darwin/canary/host_specific.json" "$user_gui_canary_fx" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
sys_doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
usr_doc = json.loads(pathlib.Path(sys.argv[2]).read_text())
doc = {
    "vars": {
        "tendcf_interlock": sys_doc["vars"]["tendcf_interlock"],
        "tendcf_service": {
            "com.tendcf.canary.main": usr_doc["vars"]["tendcf_service"]["com.tendcf.canary.main"],
            "com.tendcf.canary.main.launchd": sys_doc["vars"]["tendcf_service"]["com.tendcf.canary.main"],
        },
    }
}
pathlib.Path(sys.argv[3]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-alias-sys.out" 2>&1 || true
    check "launchd class-alias regression (system): user-gui entry skipped and reported" \
        grep -qF "tendcf: service 'com.tendcf.canary.main' skipped: belongs to launchd 'user-gui' domain (this agent runs 'system')" "$work/launchd-alias-sys.out"
    check "launchd class-alias regression (system): skipped entry wrote no plist" test ! -e "$canary_sys_p"
    check "launchd class-alias regression (system): zero launchctl calls for skipped entry" \
        bash -c "! grep -Eq '(system/com\\.tendcf\\.canary\\.main$|com\\.tendcf\\.canary\\.main\\.plist$)' '$launchctl_log'"
    check "launchd class-alias regression (system): valid .launchd sibling rendered" test -f "$alias_sys_p"
    check "launchd class-alias regression (system): valid .launchd sibling bootstrapped" \
        grep -qxF "$(printf 'bootstrap\tsystem\t%s' "$alias_sys_p")" "$launchctl_log"

    python3 - "$repo/deploy/darwin/canary/host_specific.json" "$user_gui_canary_fx" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
sys_doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
usr_doc = json.loads(pathlib.Path(sys.argv[2]).read_text())
doc = {
    "vars": {
        "tendcf_interlock": usr_doc["vars"]["tendcf_interlock"],
        "tendcf_service": {
            "com.tendcf.canary.main": sys_doc["vars"]["tendcf_service"]["com.tendcf.canary.main"],
            "com.tendcf.canary.main.launchd": usr_doc["vars"]["tendcf_service"]["com.tendcf.canary.main"],
        },
    }
}
pathlib.Path(sys.argv[3]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-alias-user.out" 2>&1 || true
    check "launchd class-alias regression (user): system entry skipped and reported" \
        grep -qF "tendcf: service 'com.tendcf.canary.main' skipped: belongs to launchd 'system' domain (this agent runs 'user-gui' and 'user-background')" "$work/launchd-alias-user.out"
    check "launchd class-alias regression (user): skipped entry wrote no plist" test ! -e "$user_plist"
    check "launchd class-alias regression (user): zero launchctl calls for skipped entry" \
        bash -c "! grep -Eq '((gui|user)/[0-9]+/com\\.tendcf\\.canary\\.main$|com\\.tendcf\\.canary\\.main\\.plist$)' '$launchctl_log'"
    check "launchd class-alias regression (user): valid .launchd sibling rendered" test -f "$alias_usr_p"
    check "launchd class-alias regression (user): valid .launchd sibling bootstrapped" \
        grep -qxF "$(printf 'bootstrap\tgui/%s\t%s' "$test_uid" "$alias_usr_p")" "$launchctl_log"
    rm -f "$alias_sys_p" "$alias_usr_p" \
        "$launchctl_state/com.tendcf.canary.main.launchd" "$launchctl_state/gui.com.tendcf.canary.main.launchd"

    # 5m.19f mergedata() precedence regression (Opus M2, Adversary L3.1, issue #103):
    # injected `launchd_include_username`, `launchd_session_type`, or `id` inside a
    # service entry must NEVER override the trailing literal object in mergedata().
    python3 - "$repo/deploy/darwin/canary/host_specific.json" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
svc = doc["vars"]["tendcf_service"]["com.tendcf.canary.main"]
svc["launchd_include_username"] = False
svc["launchd_include_session_type"] = True
svc["launchd_session_type"] = "Aqua"
svc["id"] = "evil"
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-mergedata-sys.out" 2>&1 || true
    check "launchd mergedata precedence (system): overrides injected id, launchd_include_username, launchd_session_type" \
        python3 - "$canary_sys_p" <<'PYEOF'
import plistlib, sys
with open(sys.argv[1], "rb") as f:
    doc = plistlib.load(f)
assert doc["Label"] == "com.tendcf.canary.main", doc
assert doc.get("UserName") == "nobody", doc
assert "LimitLoadToSessionType" not in doc, doc
PYEOF
    rm -f "$canary_sys_p" "$launchctl_state/com.tendcf.canary.main"

    for mspec in "gui:$user_gui_canary_fx:Aqua:Background" "bg:$user_bg_canary_fx:Background:Aqua"; do
        mname="${mspec%%:*}"; rest="${mspec#*:}"
        mfx="${rest%%:*}"; rest="${rest#*:}"
        mwant="${rest%%:*}"; mspoof="${rest#*:}"
        python3 - "$mfx" "$work/data/host_specific.json" "$mspoof" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
svc = doc["vars"]["tendcf_service"]["com.tendcf.canary.main"]
svc["launchd_include_username"] = True
svc["launchd_include_session_type"] = False
svc["launchd_session_type"] = sys.argv[3]
svc["id"] = "evil"
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
        : > "$launchctl_log"
        "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-mergedata-user-$mname.out" 2>&1 || true
        check "launchd mergedata precedence (user-$mname): overrides injected id, UserName, and LimitLoadToSessionType" \
            python3 - "$user_plist" "$mwant" <<'PYEOF'
import plistlib, sys
with open(sys.argv[1], "rb") as f:
    doc = plistlib.load(f)
assert doc["Label"] == "com.tendcf.canary.main", doc
assert "UserName" not in doc, doc
assert doc.get("LimitLoadToSessionType") == sys.argv[2], doc
PYEOF
        rm -f "$user_plist" "$launchctl_state/gui.com.tendcf.canary.main" "$launchctl_state/user.com.tendcf.canary.main"
    done

    # 5m.19g Safe ~/Library/LaunchAgents creation guard (Codex Bot P2 + Opus L8)
    # and Darwin unprivileged entry.cf safety checks (Opus L5, Adversary L3.3).
    fake_home_ok="$work/fake-home-ok"
    mkdir -p "$fake_home_ok/Library"
    cat > "$work/inputs/launchd-ensure-ok.cf" <<EOF
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf", "$repo/tests/policy/fixtures/test-done.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_test_ensure_ok", "tendcf_test_done" };
}
bundle agent tendcf_test_ensure_ok
{
  methods:
      "ensure"
        usebundle => tendcf_ensure_user_launchagents("$fake_home_ok", "$test_user");
      "apply"
        usebundle => tendcf_services_apply("user", "$fake_home_ok/Library/LaunchAgents", "$launchctl_stub", "$test_user", "$test_gid", "$test_user", "$test_uid");
}
EOF
    : > "$launchctl_log"
    cp "$user_gui_canary_fx" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-ensure-ok.cf" >"$work/launchd-ensure-ok.out" 2>&1 || true
    ensure_ok_plist="$fake_home_ok/Library/LaunchAgents/com.tendcf.canary.main.plist"
    check "launchd user LaunchAgents creation: created real directory" \
        bash -c "[ -d '$fake_home_ok/Library/LaunchAgents' ] && [ ! -L '$fake_home_ok/Library/LaunchAgents' ]"
    check "launchd user LaunchAgents creation: directory mode is 0755" \
        bash -c "[ \"\$(stat -f '%Lp' '$fake_home_ok/Library/LaunchAgents')\" = 755 ]"
    check "launchd user LaunchAgents creation: plist rendered in same run" \
        cmp -s "$golden_user_gui_dir/com.tendcf.canary.main.plist" "$ensure_ok_plist"
    check "launchd user LaunchAgents creation: bootstrap ran" \
        grep -qxF "$(printf 'bootstrap\tgui/%s\t%s' "$test_uid" "$ensure_ok_plist")" "$launchctl_log"
    rm -f "$launchctl_state/gui.com.tendcf.canary.main"

    fake_home_sym="$work/fake-home-sym"
    sym_agents_target="$work/sym-agents-target"
    mkdir -p "$fake_home_sym/Library" "$sym_agents_target"
    ln -s "$sym_agents_target" "$fake_home_sym/Library/LaunchAgents"
    cat > "$work/inputs/launchd-ensure-sym.cf" <<EOF
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf", "$repo/tests/policy/fixtures/test-done.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_test_ensure_sym", "tendcf_test_done" };
}
bundle agent tendcf_test_ensure_sym
{
  methods:
      "ensure"
        usebundle => tendcf_ensure_user_launchagents("$fake_home_sym", "$test_user");
      "apply"
        usebundle => tendcf_services_apply("user", "$fake_home_sym/Library/LaunchAgents", "$launchctl_stub", "$test_user", "$test_gid", "$test_user", "$test_uid");
}
EOF
    : > "$launchctl_log"
    cp "$user_gui_canary_fx" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-ensure-sym.cf" >"$work/launchd-ensure-sym.out" 2>&1 || true
    check "launchd user LaunchAgents symlink negative: symlink left intact" \
        test -L "$fake_home_sym/Library/LaunchAgents"
    check "launchd user LaunchAgents symlink negative: target dir untouched" \
        bash -c "[ -z \"\$(ls -A '$sym_agents_target')\" ]"
    check "launchd user LaunchAgents symlink negative: refused fail-closed" \
        grep -q "tendcf: service 'com.tendcf.canary.main' refused: launchd domain/identity invalid" "$work/launchd-ensure-sym.out"
    check "launchd user LaunchAgents symlink negative: zero launchctl calls" test ! -s "$launchctl_log"

    # Adversary Note B: home_dir = "/." must be rejected by tendcf_user_home_ok.
    cat > "$work/inputs/launchd-ensure-dot.cf" <<EOF
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf", "$repo/tests/policy/fixtures/test-done.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_test_ensure_dot", "tendcf_test_done" };
}
bundle agent tendcf_test_ensure_dot
{
  methods:
      "ensure"
        usebundle => tendcf_ensure_user_launchagents("/.", "$test_user");
}
EOF
    printf '%s\n' '{"vars":{}}' > "$work/data/host_specific.json"
    "$cf_agent" -K -v -n -f "$work/inputs/launchd-ensure-dot.cf" >"$work/launchd-ensure-dot.out" 2>&1 || true
    check "launchd user LaunchAgents '/.' home_dir negative: tendcf_user_home_ok NOT defined" \
        bash -c "! grep -q 'Private class: tendcf_user_home_ok' '$work/launchd-ensure-dot.out'"

    # 5m.19h Mixed goal file in non-root user mode: converges BOTH user-gui AND user-background
    # while informationally skipping a system entry, all in ONE cf-agent invocation!
    mixed_gui_p="$launchd_agents/com.tendcf.mixed.gui.plist"
    mixed_bg_p="$launchd_agents/com.tendcf.mixed.bg.plist"
    mixed_sys_p="$launchd_agents/com.tendcf.mixed.sys.plist"
    rm -f "$mixed_gui_p" "$mixed_bg_p" "$mixed_sys_p" \
        "$launchctl_state/gui.com.tendcf.mixed.gui" "$launchctl_state/user.com.tendcf.mixed.gui" \
        "$launchctl_state/gui.com.tendcf.mixed.bg" "$launchctl_state/user.com.tendcf.mixed.bg"
    python3 - "$work/data/host_specific.json" "$test_user" <<'PYEOF'
import json, pathlib, sys
user = sys.argv[2]
doc = {
    "vars": {
        "tendcf_interlock": {},
        "tendcf_service": {
            "com.tendcf.mixed.gui": {
                "bundle": "mixed",
                "command": ["/bin/sleep", "86400"],
                "run_as": user,
                "state": "present",
                "unit": {"launchd": {"domain": "user-gui", "keep_alive": True, "run_at_load": True}},
                "working_dir": "/",
            },
            "com.tendcf.mixed.bg": {
                "bundle": "mixed",
                "command": ["/bin/sleep", "86400"],
                "run_as": user,
                "state": "present",
                "unit": {"launchd": {"domain": "user-background", "keep_alive": True, "run_at_load": True}},
                "working_dir": "/",
            },
            "com.tendcf.mixed.sys": {
                "bundle": "mixed",
                "command": ["/bin/sleep", "86400"],
                "run_as": "nobody",
                "state": "present",
                "unit": {"launchd": {"domain": "system", "keep_alive": True, "run_at_load": True}},
                "working_dir": "/",
            },
        },
    }
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-mixed.out" 2>&1 || true
    check "launchd mixed user mode: user-gui plist rendered with LimitLoadToSessionType=Aqua" \
        python3 - "$mixed_gui_p" <<'PYEOF'
import plistlib, sys
with open(sys.argv[1], "rb") as f:
    doc = plistlib.load(f)
assert doc["Label"] == "com.tendcf.mixed.gui"
assert doc["LimitLoadToSessionType"] == "Aqua"
assert "UserName" not in doc
PYEOF
    check "launchd mixed user mode: user-background plist rendered with LimitLoadToSessionType=Background" \
        python3 - "$mixed_bg_p" <<'PYEOF'
import plistlib, sys
with open(sys.argv[1], "rb") as f:
    doc = plistlib.load(f)
assert doc["Label"] == "com.tendcf.mixed.bg"
assert doc["LimitLoadToSessionType"] == "Background"
assert "UserName" not in doc
PYEOF
    check "launchd mixed user mode: user-gui bootstrapped into gui/$test_uid" \
        grep -qxF "$(printf 'bootstrap\tgui/%s\t%s' "$test_uid" "$mixed_gui_p")" "$launchctl_log"
    check "launchd mixed user mode: user-background bootstrapped into user/$test_uid" \
        grep -qxF "$(printf 'bootstrap\tuser/%s\t%s' "$test_uid" "$mixed_bg_p")" "$launchctl_log"
    check "launchd mixed user mode: system entry skipped informationally, no plist written" \
        bash -c "grep -qF \"tendcf: service 'com.tendcf.mixed.sys' skipped: belongs to launchd 'system' domain (this agent runs 'user-gui' and 'user-background')\" '$work/launchd-user-mixed.out' && [ ! -e '$mixed_sys_p' ]"
    check "launchd mixed user mode: domain probes ran at most once each" \
        bash -c "grep -cxF \"\$(printf 'print\tgui/%s' '$test_uid')\" '$launchctl_log' | grep -qx 1 && grep -cxF \"\$(printf 'print\tuser/%s' '$test_uid')\" '$launchctl_log' | grep -qx 1"

    # Unchanged mixed re-run -> zero write calls.
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-mixed-noop.out" 2>&1 || true
    check "launchd mixed user mode unchanged re-run: zero launchctl write calls" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"
    rm -f "$mixed_gui_p" "$mixed_bg_p" \
        "$launchctl_state/gui.com.tendcf.mixed.gui" "$launchctl_state/user.com.tendcf.mixed.bg"

    # 5m.19i Headless mode (`headless-no-gui`: print gui/<uid> returns 125):
    # - user-background converges cleanly in user/<uid> (byte-identical to user-background golden)
    # - user-gui emits exact `deferred:` notice, writes NO plist, calls NO bootstrap gui/<uid>
    # - tombstone sweeps user/<uid> and deletes plist cleanly without touching gui/<uid>
    headless_gui_p="$launchd_agents/com.tendcf.headless.gui.plist"
    headless_bg_p="$launchd_agents/com.tendcf.canary.main.plist"
    headless_tomb_p="$launchd_agents/com.tendcf.headless.tomb.plist"
    cp "$golden_user_bg_dir/com.tendcf.canary.main.plist" "$headless_tomb_p"
    : > "$launchctl_state/user.com.tendcf.headless.tomb"
    rm -f "$headless_gui_p" "$headless_bg_p" "$launchctl_state/user.com.tendcf.canary.main" "$launchctl_state/gui.com.tendcf.canary.main"
    python3 - "$work/data/host_specific.json" "$test_user" <<'PYEOF'
import json, pathlib, sys
user = sys.argv[2]
doc = {
    "vars": {
        "tendcf_interlock": {},
        "tendcf_service": {
            "com.tendcf.canary.main": {
                "bundle": "canary",
                "command": ["/bin/sleep", "86400"],
                "run_as": user,
                "state": "present",
                "unit": {"launchd": {"domain": "user-background", "keep_alive": True, "run_at_load": True}},
                "working_dir": "/",
            },
            "com.tendcf.headless.gui": {
                "bundle": "canary",
                "command": ["/bin/sleep", "86400"],
                "run_as": user,
                "state": "present",
                "unit": {"launchd": {"domain": "user-gui", "keep_alive": True, "run_at_load": True}},
                "working_dir": "/",
            },
            "com.tendcf.headless.tomb": {"state": "absent"},
        },
    }
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    printf 'headless-no-gui\n' > "$launchctl_mode"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-headless.out" 2>&1 || true
    check "launchd headless: user-background rendered byte-identical to user-background golden" \
        cmp -s "$golden_user_bg_dir/com.tendcf.canary.main.plist" "$headless_bg_p"
    check "launchd headless: user-background bootstrapped into user/$test_uid" \
        grep -qxF "$(printf 'bootstrap\tuser/%s\t%s' "$test_uid" "$headless_bg_p")" "$launchctl_log"
    check "launchd headless: user-gui emitted exact deferred notice" \
        grep -qF "tendcf: service 'com.tendcf.headless.gui' deferred: launchd 'gui/$test_uid' domain is unavailable (no active Aqua GUI login session); user-gui convergence skipped" "$work/launchd-headless.out"
    check "launchd headless: user-gui NOT reported as refused or failed" \
        bash -c "! grep -Eq \"'com\\.tendcf\\.headless\\.gui' (refused|failed):\" '$work/launchd-headless.out'"
    check "launchd headless: user-gui wrote no plist" test ! -e "$headless_gui_p"
    check "launchd headless: zero bootstrap/bootout calls on gui/$test_uid" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]+gui/' '$launchctl_log'"
    check "launchd headless: tombstone booted out user/$test_uid and deleted plist" \
        bash -c "grep -qxF \"\$(printf 'bootout\tuser/%s/com.tendcf.headless.tomb' '$test_uid')\" '$launchctl_log' && [ ! -e '$headless_tomb_p' ]"
    rm -f "$headless_bg_p" "$launchctl_state/user.com.tendcf.canary.main"

    # 5m.19j Domain-probe IPC failure (`fail-gui-domain` and `fail-user-domain` -> exit 5):
    # fail-closed on user-gui, user-background, AND tombstones (plist preserved, zero bootstraps/bootouts).
    for dmode in fail-gui-domain fail-user-domain; do
        cp "$golden_user_bg_dir/com.tendcf.canary.main.plist" "$headless_tomb_p"
        : > "$launchctl_state/user.com.tendcf.headless.tomb"
        rm -f "$headless_gui_p" "$headless_bg_p" "$launchctl_state/user.com.tendcf.canary.main"
        : > "$launchctl_log"
        printf '%s\n' "$dmode" > "$launchctl_mode"
        "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-$dmode.out" 2>&1 || true
        check "launchd $dmode: user-background fail-closed (no plist, failure reported)" \
            bash -c "[ ! -e '$headless_bg_p' ] && grep -q \"tendcf: service 'com.tendcf.canary.main' failed:\" '$work/launchd-$dmode.out'"
        check "launchd $dmode: user-gui fail-closed (no plist, failure reported)" \
            bash -c "[ ! -e '$headless_gui_p' ] && grep -q \"tendcf: service 'com.tendcf.headless.gui' failed:\" '$work/launchd-$dmode.out'"
        check "launchd $dmode: tombstone fail-closed (plist preserved, failure reported)" \
            bash -c "[ -f '$headless_tomb_p' ] && grep -q \"tendcf: service 'com.tendcf.headless.tomb' tombstone failed:\" '$work/launchd-$dmode.out'"
        check "launchd $dmode: zero bootstrap or bootout calls" \
            bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"
        rm -f "$headless_tomb_p" "$launchctl_state/user.com.tendcf.headless.tomb"
    done

    # 5m.19k `user-domain-absent` (print user/<uid> returns 112; Opus R2 L1):
    # - user-background writes NO plist, makes ZERO `bootstrap user/<uid>` calls, emits the
    #   `deferred: launchd domain 'user/<uid>' unavailable (no user domain)` notice, and STILL
    #   boots out any stale `gui/<uid>` peer job while `gui/<uid>` is available;
    # - user-gui sees peer absent -> converges cleanly in `gui/<uid>`;
    # - tombstone boots out `gui/<uid>` and deletes its plist cleanly.
    cp "$golden_user_gui_dir/com.tendcf.canary.main.plist" "$headless_tomb_p"
    : > "$launchctl_state/gui.com.tendcf.headless.tomb"
    : > "$launchctl_state/gui.com.tendcf.canary.main"
    rm -f "$headless_gui_p" "$headless_bg_p" "$launchctl_state/user.com.tendcf.canary.main" "$launchctl_state/gui.com.tendcf.headless.gui"
    : > "$launchctl_log"
    printf 'user-domain-absent\n' > "$launchctl_mode"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-absent.out" 2>&1 || true
    check "launchd user-domain-absent: user-background wrote no plist" \
        test ! -e "$headless_bg_p"
    check "launchd user-domain-absent: zero bootstrap user/$test_uid calls" \
        bash -c "! grep -Eq '^bootstrap[[:space:]]+user/' '$launchctl_log'"
    check "launchd user-domain-absent: user-background emitted exact deferred notice" \
        grep -qF "tendcf: service 'com.tendcf.canary.main' deferred: launchd domain 'user/$test_uid' unavailable (no user domain)" "$work/launchd-user-absent.out"
    check "launchd user-domain-absent: user-background NOT reported as refused or failed" \
        bash -c "! grep -Eq \"'com\\.tendcf\\.canary\\.main' (refused|failed):\" '$work/launchd-user-absent.out'"
    check "launchd user-domain-absent: stale gui/$test_uid peer for user-background still booted out" \
        bash -c "grep -qxF \"\$(printf 'bootout\tgui/%s/com.tendcf.canary.main' '$test_uid')\" '$launchctl_log' && [ ! -e '$launchctl_state/gui.com.tendcf.canary.main' ]"
    check "launchd user-domain-absent: user-gui bootstrapped into gui/$test_uid with zero peer user/<uid>/<id> probe" \
        bash -c "grep -qxF \"\$(printf 'bootstrap\tgui/%s\t%s' '$test_uid' '$headless_gui_p')\" '$launchctl_log' && ! grep -q \"print\tuser/$test_uid/com.tendcf.headless.gui\" '$launchctl_log'"
    check "launchd user-domain-absent: tombstone booted out gui/$test_uid and deleted plist" \
        bash -c "grep -qxF \"\$(printf 'bootout\tgui/%s/com.tendcf.headless.tomb' '$test_uid')\" '$launchctl_log' && [ ! -e '$headless_tomb_p' ]"
    rm -f "$headless_bg_p" "$headless_gui_p" "$launchctl_state/user.com.tendcf.canary.main" "$launchctl_state/gui.com.tendcf.canary.main" "$launchctl_state/gui.com.tendcf.headless.gui"

    # 5m.19l Domain switches (`user-gui` <-> `user-background`) & peer bootout fail-closed & headless bg->gui cleanup.
    # Start loaded in user-gui:
    cp "$golden_user_gui_dir/com.tendcf.canary.main.plist" "$user_plist"
    : > "$launchctl_state/gui.com.tendcf.canary.main"
    rm -f "$launchctl_state/user.com.tendcf.canary.main"
    # (1) fail-peer-bootout while switching user-gui -> user-background -> blocks bootstrap user/<uid> (zero dual-load!).
    : > "$launchctl_log"
    printf 'fail-peer-bootout\n' > "$launchctl_mode"
    cp "$user_bg_canary_fx" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-switch-peer-fail.out" 2>&1 || true
    check "launchd domain switch (fail-peer-bootout): peer bootout failed reported" \
        grep -qF "tendcf: service 'com.tendcf.canary.main' failed: launchctl bootout gui/$test_uid/com.tendcf.canary.main exited non-zero; bootstrap not run" "$work/launchd-switch-peer-fail.out"
    check "launchd domain switch (fail-peer-bootout): target bootstrap NOT run (zero dual-load)" \
        bash -c "! grep -q '^bootstrap' '$launchctl_log'"
    check "launchd domain switch (fail-peer-bootout): old Aqua plist preserved" \
        cmp -s "$golden_user_gui_dir/com.tendcf.canary.main.plist" "$user_plist"

    # (2) Active GUI: user-gui -> user-background succeeds in ONE run, peer bootout strictly before target bootstrap.
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-switch-gui-to-bg.out" 2>&1 || true
    check "launchd switch user-gui -> user-background: plist rewritten byte-identical to user-background golden" \
        cmp -s "$golden_user_bg_dir/com.tendcf.canary.main.plist" "$user_plist"
    check "launchd switch user-gui -> user-background: bootout gui/<uid>/<id> ran strictly before bootstrap user/<uid>" \
        python3 - "$launchctl_log" "$test_uid" "$user_plist" <<'PYEOF'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
uid, plist = sys.argv[2], sys.argv[3]
bo = f"bootout\tgui/{uid}/com.tendcf.canary.main"
bs = f"bootstrap\tuser/{uid}\t{plist}"
assert lines.count(bo) == 1, f"expected 1 peer bootout: {lines}"
assert lines.count(bs) == 1, f"expected 1 target bootstrap: {lines}"
assert lines.index(bo) < lines.index(bs), f"peer bootout not before target bootstrap: {lines}"
PYEOF
    check "launchd switch user-gui -> user-background: loaded in user/<uid> only (not gui/<uid>)" \
        bash -c "[ -f '$launchctl_state/user.com.tendcf.canary.main' ] && [ ! -e '$launchctl_state/gui.com.tendcf.canary.main' ]"

    # (3) Active GUI: user-background -> user-gui succeeds in ONE run, peer bootout strictly before target bootstrap.
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    cp "$user_gui_canary_fx" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-switch-bg-to-gui.out" 2>&1 || true
    check "launchd switch user-background -> user-gui: plist rewritten byte-identical to user-gui golden" \
        cmp -s "$golden_user_gui_dir/com.tendcf.canary.main.plist" "$user_plist"
    check "launchd switch user-background -> user-gui: bootout user/<uid>/<id> ran strictly before bootstrap gui/<uid>" \
        python3 - "$launchctl_log" "$test_uid" "$user_plist" <<'PYEOF'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
uid, plist = sys.argv[2], sys.argv[3]
bo = f"bootout\tuser/{uid}/com.tendcf.canary.main"
bs = f"bootstrap\tgui/{uid}\t{plist}"
assert lines.count(bo) == 1, f"expected 1 peer bootout: {lines}"
assert lines.count(bs) == 1, f"expected 1 target bootstrap: {lines}"
assert lines.index(bo) < lines.index(bs), f"peer bootout not before target bootstrap: {lines}"
PYEOF
    check "launchd switch user-background -> user-gui: loaded in gui/<uid> only (not user/<uid>)" \
        bash -c "[ -f '$launchctl_state/gui.com.tendcf.canary.main' ] && [ ! -e '$launchctl_state/user.com.tendcf.canary.main' ]"

    # (4) Headless switch user-background -> user-gui: STILL boots out stale user/<uid>/<id> immediately, defers gui/<uid>!
    cp "$golden_user_bg_dir/com.tendcf.canary.main.plist" "$user_plist"
    rm -f "$launchctl_state/gui.com.tendcf.canary.main"
    : > "$launchctl_state/user.com.tendcf.canary.main"
    : > "$launchctl_log"
    printf 'headless-no-gui\n' > "$launchctl_mode"
    cp "$user_gui_canary_fx" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-switch-bg-to-gui-headless.out" 2>&1 || true
    check "launchd headless switch bg->gui: stale user/<uid>/<id> booted out immediately" \
        bash -c "grep -qxF \"\$(printf 'bootout\tuser/%s/com.tendcf.canary.main' '$test_uid')\" '$launchctl_log' && [ ! -e '$launchctl_state/user.com.tendcf.canary.main' ]"
    check "launchd headless switch bg->gui: deferred notice emitted and zero bootstrap gui/<uid>" \
        bash -c "grep -qF \"tendcf: service 'com.tendcf.canary.main' deferred: launchd 'gui/$test_uid' domain is unavailable\" '$work/launchd-switch-bg-to-gui-headless.out' && ! grep -q '^bootstrap' '$launchctl_log'"
    rm -f "$user_plist" "$launchctl_state/gui.com.tendcf.canary.main" "$launchctl_state/user.com.tendcf.canary.main"

    # 5m.19m User-mode reload failure + M1 persistent reload-pending recovery (3-pass persistence check).
    cp "$golden_user_bg_dir/com.tendcf.canary.main.plist" "$user_plist"
    : > "$launchctl_state/user.com.tendcf.canary.main"
    python3 - "$user_plist" <<'PYEOF'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace("<string>86400</string>", "<string>12345</string>", 1))
PYEOF
    : > "$launchctl_log"
    printf 'fail-user-bootout\n' > "$launchctl_mode"
    cp "$user_bg_canary_fx" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-reload-fail.out" 2>&1 || true
    check "launchd user-background failed reload bootout: failure reported and bootstrap skipped" \
        bash -c "grep -qF \"tendcf: service 'com.tendcf.canary.main' failed: launchctl bootout user/$test_uid/com.tendcf.canary.main exited non-zero; bootstrap not run\" '$work/launchd-user-reload-fail.out' && ! grep -q '^bootstrap' '$launchctl_log'"
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-reload-recover.out" 2>&1 || true
    check "launchd user-background M1 reload recovery: bootout+bootstrap ran despite unchanged plist" \
        python3 - "$launchctl_log" "$test_uid" "$user_plist" <<'PYEOF'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
uid, plist = sys.argv[2], sys.argv[3]
bo = f"bootout\tuser/{uid}/com.tendcf.canary.main"
bs = f"bootstrap\tuser/{uid}\t{plist}"
assert lines.count(bo) == 1 and lines.count(bs) == 1 and lines.index(bo) < lines.index(bs), lines
PYEOF
    : > "$launchctl_log"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-reload-settled.out" 2>&1 || true
    check "launchd user-background post-recovery: reload_pending cleared (zero write calls)" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"
    rm -f "$user_plist" "$launchctl_state/user.com.tendcf.canary.main"

    # 5m.19m2 Peer bootout (`0d`) must NOT clear target's persisted reload_pending (Neon M2 / Macroscope 4683466167):
    # persist user_background reload_pending via drifted plist + fail-user-bootout, then plant a stale
    # gui/<uid> peer and run normal -> peer bootout runs AND target reload (bootout + bootstrap user/<uid>) still runs!
    cp "$golden_user_bg_dir/com.tendcf.canary.main.plist" "$user_plist"
    : > "$launchctl_state/user.com.tendcf.canary.main"
    rm -f "$launchctl_state/gui.com.tendcf.canary.main"
    python3 - "$user_plist" <<'PYEOF'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
p.write_text(p.read_text().replace("<string>86400</string>", "<string>54321</string>", 1))
PYEOF
    : > "$launchctl_log"
    printf 'fail-user-bootout\n' > "$launchctl_mode"
    cp "$user_bg_canary_fx" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-r1-peer-preserves-reload-fail.out" 2>&1 || true
    check "launchd peer-preserves-reload (step 1 fail-user-bootout): plist repaired and target bootout failed" \
        bash -c "cmp -s '$golden_user_bg_dir/com.tendcf.canary.main.plist' '$user_plist' && grep -qF \"tendcf: service 'com.tendcf.canary.main' failed: launchctl bootout user/$test_uid/com.tendcf.canary.main exited non-zero; bootstrap not run\" '$work/launchd-r1-peer-preserves-reload-fail.out'"
    : > "$launchctl_state/gui.com.tendcf.canary.main"
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-r1-peer-preserves-reload-recover.out" 2>&1 || true
    check "launchd peer-preserves-reload (step 2 normal): peer bootout did not wipe target reload_pending (peer bootout < target bootout < target bootstrap)" \
        python3 - "$launchctl_log" "$test_uid" "$user_plist" <<'PYEOF'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
uid, plist = sys.argv[2], sys.argv[3]
pbo = f"bootout\tgui/{uid}/com.tendcf.canary.main"
tbo = f"bootout\tuser/{uid}/com.tendcf.canary.main"
tbs = f"bootstrap\tuser/{uid}\t{plist}"
assert lines.count(pbo) == 1, f"expected 1 peer bootout: {lines}"
assert lines.count(tbo) == 1, f"expected 1 target bootout: {lines}"
assert lines.count(tbs) == 1, f"expected 1 target bootstrap: {lines}"
assert lines.index(pbo) < lines.index(tbo) < lines.index(tbs), f"wrong order: {lines}"
PYEOF
    check "launchd peer-preserves-reload (step 2 normal): gui peer unloaded and user target loaded" \
        bash -c "[ ! -e '$launchctl_state/gui.com.tendcf.canary.main' ] && [ -f '$launchctl_state/user.com.tendcf.canary.main' ]"
    rm -f "$user_plist" "$launchctl_state/user.com.tendcf.canary.main" "$launchctl_state/gui.com.tendcf.canary.main"

    # 5m.19n Dry-run (`-n`) in user mode across user-gui, user-background, headless, dual-loaded tombstone,
    # domain-switch preview (Neon H1), and real probe error reporting under -n (Neon M3).
    cp "$golden_user_gui_dir/com.tendcf.canary.main.plist" "$headless_tomb_p"
    : > "$launchctl_state/gui.com.tendcf.headless.tomb"
    : > "$launchctl_state/user.com.tendcf.headless.tomb"
    python3 - "$work/data/host_specific.json" "$test_user" <<'PYEOF'
import json, pathlib, sys
user = sys.argv[2]
doc = {
    "vars": {
        "tendcf_interlock": {},
        "tendcf_service": {
            "com.tendcf.dry.gui": {
                "bundle": "dry",
                "command": ["/bin/sleep", "86400"],
                "run_as": user,
                "state": "present",
                "unit": {"launchd": {"domain": "user-gui", "keep_alive": True, "run_at_load": True}},
                "working_dir": "/",
            },
            "com.tendcf.dry.bg": {
                "bundle": "dry",
                "command": ["/bin/sleep", "86400"],
                "run_as": user,
                "state": "present",
                "unit": {"launchd": {"domain": "user-background", "keep_alive": True, "run_at_load": True}},
                "working_dir": "/",
            },
            "com.tendcf.headless.tomb": {"state": "absent"},
        },
    }
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    for dry_mode in normal headless-no-gui; do
        : > "$launchctl_log"
        printf '%s\n' "$dry_mode" > "$launchctl_mode"
        "$cf_agent" -n -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-dry-$dry_mode.out" 2>&1 || true
        check "launchd user dry-run ($dry_mode): policy completed" dry_policy_completed "$work/launchd-user-dry-$dry_mode.out"
        check "launchd user dry-run ($dry_mode): zero failed report lines" no_failed_reports "$work/launchd-user-dry-$dry_mode.out"
        check "launchd user dry-run ($dry_mode): zero launchctl write calls" \
            bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"
        check "launchd user dry-run ($dry_mode): no new plists created and tombstone plist preserved" \
            bash -c "[ ! -e '$launchd_agents/com.tendcf.dry.gui.plist' ] && [ ! -e '$launchd_agents/com.tendcf.dry.bg.plist' ] && [ -f '$headless_tomb_p' ]"
    done

    # Neon M3: real preview=>"true" domain probe failure IS reported under -n (never suppressed).
    : > "$launchctl_log"
    printf 'fail-gui-domain\n' > "$launchctl_mode"
    "$cf_agent" -n -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-dry-fail-gui-domain.out" 2>&1 || true
    check "launchd user dry-run (fail-gui-domain): real probe error reported under -n" \
        grep -qF "tendcf: service 'com.tendcf.dry.bg' failed: launchctl print gui/$test_uid exited with unexpected error; user-domain convergence skipped" "$work/launchd-user-dry-fail-gui-domain.out"
    check "launchd user dry-run (fail-gui-domain): tombstone probe error reported under -n" \
        grep -qF "tendcf: service 'com.tendcf.headless.tomb' tombstone failed: launchctl print gui/$test_uid exited with unexpected error; plist left in place" "$work/launchd-user-dry-fail-gui-domain.out"
    rm -f "$headless_tomb_p" "$launchctl_state/gui.com.tendcf.headless.tomb" "$launchctl_state/user.com.tendcf.headless.tomb"

    # Neon H1: dry-run (-n) domain-switch preview (loaded in gui/<uid>, switching to user-background)
    # must preview BOTH peer bootout AND target bootstrap while leaving disk and loaded state untouched.
    # Strip interlock so `-n` reaches launchd files:/commands: preview paths directly.
    cp "$golden_user_gui_dir/com.tendcf.canary.main.plist" "$user_plist"
    : > "$launchctl_state/gui.com.tendcf.canary.main"
    rm -f "$launchctl_state/user.com.tendcf.canary.main"
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    python3 - "$user_bg_canary_fx" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["vars"]["tendcf_interlock"] = {}
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    "$cf_agent" -n -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-dry-switch.out" 2>&1 || true
    check "launchd user dry-run domain switch: policy completed" dry_policy_completed "$work/launchd-user-dry-switch.out"
    check "launchd user dry-run domain switch: zero failed reports" no_failed_reports "$work/launchd-user-dry-switch.out"
    check "launchd user dry-run domain switch: previews peer bootout gui/<uid>/<id>" \
        grep -Eq "Would execute script .*bootout gui/$test_uid/com\\.tendcf\\.canary\\.main" "$work/launchd-user-dry-switch.out"
    check "launchd user dry-run domain switch: previews target bootstrap user/<uid> <plist>" \
        grep -Eq "Would execute script .*bootstrap user/$test_uid $user_plist" "$work/launchd-user-dry-switch.out"
    check "launchd user dry-run domain switch: zero launchctl write calls" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"
    check "launchd user dry-run domain switch: plist and loaded state untouched" \
        bash -c "cmp -s '$golden_user_gui_dir/com.tendcf.canary.main.plist' '$user_plist' && [ -f '$launchctl_state/gui.com.tendcf.canary.main' ] && [ ! -e '$launchctl_state/user.com.tendcf.canary.main' ]"
    rm -f "$user_plist" "$launchctl_state/gui.com.tendcf.canary.main" "$launchctl_state/user.com.tendcf.canary.main"

    # Opus R2 N1: dry-run (-n) headless domain-switch (loaded in user/<uid>, switching to user-gui
    # while gui/<uid> is absent) must preserve BOTH the peer bootout preview AND the `deferred:`
    # report line without mutating disk or loaded state.
    cp "$golden_user_bg_dir/com.tendcf.canary.main.plist" "$user_plist"
    rm -f "$launchctl_state/gui.com.tendcf.canary.main"
    : > "$launchctl_state/user.com.tendcf.canary.main"
    : > "$launchctl_log"
    printf 'headless-no-gui\n' > "$launchctl_mode"
    python3 - "$user_gui_canary_fx" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["vars"]["tendcf_interlock"] = {}
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    "$cf_agent" -n -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-dry-switch-headless.out" 2>&1 || true
    check "launchd user dry-run headless switch bg->gui: policy completed" dry_policy_completed "$work/launchd-user-dry-switch-headless.out"
    check "launchd user dry-run headless switch bg->gui: zero failed reports" no_failed_reports "$work/launchd-user-dry-switch-headless.out"
    check "launchd user dry-run headless switch bg->gui: previews peer bootout user/<uid>/<id>" \
        grep -Eq "Would execute script .*bootout user/$test_uid/com\\.tendcf\\.canary\\.main" "$work/launchd-user-dry-switch-headless.out"
    check "launchd user dry-run headless switch bg->gui: preserves deferred notice under -n" \
        grep -qF "tendcf: service 'com.tendcf.canary.main' deferred: launchd 'gui/$test_uid' domain is unavailable" "$work/launchd-user-dry-switch-headless.out"
    check "launchd user dry-run headless switch bg->gui: zero launchctl write calls" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"
    check "launchd user dry-run headless switch bg->gui: plist and loaded state untouched" \
        bash -c "cmp -s '$golden_user_bg_dir/com.tendcf.canary.main.plist' '$user_plist' && [ -f '$launchctl_state/user.com.tendcf.canary.main' ] && [ ! -e '$launchctl_state/gui.com.tendcf.canary.main' ]"
    rm -f "$user_plist" "$launchctl_state/gui.com.tendcf.canary.main" "$launchctl_state/user.com.tendcf.canary.main"

    # PR #108 Opus R1 Nit-2: symmetric dry-run (-n) user-domain-absent (112) domain switch
    # (loaded in gui/<uid>, switching to user-background while user/<uid> is absent) must preserve
    # BOTH the peer bootout preview AND the user/<uid> `deferred:` notice without mutating state.
    cp "$golden_user_gui_dir/com.tendcf.canary.main.plist" "$user_plist"
    : > "$launchctl_state/gui.com.tendcf.canary.main"
    rm -f "$launchctl_state/user.com.tendcf.canary.main"
    : > "$launchctl_log"
    printf 'user-domain-absent\n' > "$launchctl_mode"
    python3 - "$user_bg_canary_fx" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["vars"]["tendcf_interlock"] = {}
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    "$cf_agent" -n -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-user-dry-switch-user-absent.out" 2>&1 || true
    check "launchd user dry-run user-domain-absent switch gui->bg: policy completed" dry_policy_completed "$work/launchd-user-dry-switch-user-absent.out"
    check "launchd user dry-run user-domain-absent switch gui->bg: zero failed reports" no_failed_reports "$work/launchd-user-dry-switch-user-absent.out"
    check "launchd user dry-run user-domain-absent switch gui->bg: previews peer bootout gui/<uid>/<id>" \
        grep -Eq "Would execute script .*bootout gui/$test_uid/com\\.tendcf\\.canary\\.main" "$work/launchd-user-dry-switch-user-absent.out"
    check "launchd user dry-run user-domain-absent switch gui->bg: preserves user/<uid> deferred notice under -n" \
        grep -qF "tendcf: service 'com.tendcf.canary.main' deferred: launchd domain 'user/$test_uid' unavailable (no user domain)" "$work/launchd-user-dry-switch-user-absent.out"
    check "launchd user dry-run user-domain-absent switch gui->bg: zero launchctl write calls" \
        bash -c "! grep -Eq '^(bootstrap|bootout)[[:space:]]' '$launchctl_log'"
    check "launchd user dry-run user-domain-absent switch gui->bg: plist and loaded state untouched" \
        bash -c "cmp -s '$golden_user_gui_dir/com.tendcf.canary.main.plist' '$user_plist' && [ -f '$launchctl_state/gui.com.tendcf.canary.main' ] && [ ! -e '$launchctl_state/user.com.tendcf.canary.main' ]"
    rm -f "$user_plist" "$launchctl_state/gui.com.tendcf.canary.main" "$launchctl_state/user.com.tendcf.canary.main"

    # 5m.19o Adversary Blocker #1: forged class `tendcf_launchd_user_needs_domain_probes`
    # via CMDB `"classes"` (`"any::"`) AND via `def.json` (`["any"]`) must NEVER trigger
    # non-iterating domain probes 0a/0b in either user or system harness.
    printf '%s\n' '{"vars":{"tendcf_interlock":{},"tendcf_service":{}},"classes":{"tendcf_launchd_user_needs_domain_probes":"any::"}}' > "$work/data/host_specific.json"
    printf 'normal\n' > "$launchctl_mode"
    for hspec in "user:launchd-user-harness.cf" "sys:launchd-harness.cf"; do
        hname="${hspec%%:*}"
        hcf="${hspec#*:}"
        : > "$launchctl_log"
        "$cf_agent" -K -I -f "$work/inputs/$hcf" >"$work/launchd-r1-probe-class-$hname.out" 2>&1 || true
        check "launchd forged needs_domain_probes CMDB class ($hname): CMDB refusal reported" \
            refusal_reported "$work/launchd-r1-probe-class-$hname.out"
        check "launchd forged needs_domain_probes CMDB class ($hname): foreign class reported" \
            foreign_class_reported "$work/launchd-r1-probe-class-$hname.out"
        check "launchd forged needs_domain_probes CMDB class ($hname): zero launchctl calls" \
            test ! -s "$launchctl_log"
    done
    printf '%s\n' '{"vars":{"tendcf_interlock":{},"tendcf_service":{}}}' > "$work/data/host_specific.json"
    printf '%s\n' '{"classes":{"tendcf_launchd_user_needs_domain_probes":["any"]}}' > "$work/inputs/def.json"
    for hspec in "user:launchd-user-harness.cf" "sys:launchd-harness.cf"; do
        hname="${hspec%%:*}"
        hcf="${hspec#*:}"
        : > "$launchctl_log"
        "$cf_agent" -K -I -f "$work/inputs/$hcf" >"$work/launchd-r1-probe-def-$hname.out" 2>&1 || true
        check "launchd forged needs_domain_probes def.json class ($hname): CMDB refusal reported" \
            refusal_reported "$work/launchd-r1-probe-def-$hname.out"
        check "launchd forged needs_domain_probes def.json class ($hname): foreign class reported" \
            foreign_class_reported "$work/launchd-r1-probe-def-$hname.out"
        check "launchd forged needs_domain_probes def.json class ($hname): zero launchctl calls" \
            test ! -s "$launchctl_log"
    done
    rm -f "$work/inputs/def.json"

    # 5m.19p Adversary Blocker #2: present render must refuse case-mismatched regular plist on APFS.
    case_upper_p="$launchd_agents/COM.TENDCF.CASE.TEST.plist"
    case_lower_p="$launchd_agents/com.tendcf.case.test.plist"
    rm -f "$case_upper_p" "$case_lower_p" "$launchctl_state/user.com.tendcf.case.test" "$launchctl_state/gui.com.tendcf.case.test"
    printf 'sentinel-case-mismatch-plist\n' > "$case_upper_p"
    case_upper_hash="$(shasum -a 256 "$case_upper_p" | awk '{print $1}')"
    python3 - "$work/data/host_specific.json" "$test_user" <<'PYEOF'
import json, pathlib, sys
doc = {
    "vars": {
        "tendcf_interlock": {},
        "tendcf_service": {
            "com.tendcf.case.test": {
                "bundle": "case",
                "command": ["/bin/sleep", "86400"],
                "run_as": sys.argv[2],
                "state": "present",
                "unit": {"launchd": {"domain": "user-background", "keep_alive": True, "run_at_load": True}},
                "working_dir": "/",
            }
        },
    }
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-r1-present-case-mismatch.out" 2>&1 || true
    if [ -f "$case_lower_p" ]; then
        check "launchd present case mismatch (case-insensitive FS): refusal reported" \
            grep -qF "tendcf: service 'com.tendcf.case.test' refused: no exact-case entry 'com.tendcf.case.test.plist' in $launchd_agents (case-insensitive filesystem mismatch)" "$work/launchd-r1-present-case-mismatch.out"
        check "launchd present case mismatch (case-insensitive FS): zero launchctl calls" \
            test ! -s "$launchctl_log"
        check "launchd present case mismatch (case-insensitive FS): existing file untouched" \
            bash -c "[ \"\$(shasum -a 256 '$case_upper_p' | awk '{print \$1}')\" = '$case_upper_hash' ]"
    fi
    rm -f "$case_upper_p" "$case_lower_p" "$launchctl_state/user.com.tendcf.case.test" "$launchctl_state/gui.com.tendcf.case.test"

    # 5m.19q Neon M1: consecutive user-mode runs WITHOUT `-K` (production cf-execd omits -K)
    # must NOT lock-skip read-only domain probes 0a/0b (`ifelapsed => "0"`).
    cat > "$work/inputs/launchd-user-nok-harness.cf" <<EOF
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf", "$repo/tests/policy/fixtures/test-done.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_launchd_user_nok_harness", "tendcf_test_done" };
}
bundle agent tendcf_launchd_user_nok_harness
{
  methods:
      "run"
        usebundle => tendcf_services_apply("user", "$launchd_agents", "$launchctl_stub", "$test_user", "$test_gid", "$test_user", "$test_uid"),
        action => tendcf_probe_always;
}
EOF
    rm -f "$user_plist" "$launchctl_state/user.com.tendcf.canary.main" "$launchctl_state/gui.com.tendcf.canary.main"
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    python3 - "$user_bg_canary_fx" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["vars"]["tendcf_interlock"] = {}
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    "$cf_agent" -I -f "$work/inputs/launchd-user-nok-harness.cf" >"$work/launchd-r1-nok-run1.out" 2>&1 || true
    check "launchd no -K run 1: domain probes 0a/0b ran and service bootstrapped" \
        bash -c "grep -qxF \"\$(printf 'print\tgui/%s' '$test_uid')\" '$launchctl_log' && grep -qxF \"\$(printf 'print\tuser/%s' '$test_uid')\" '$launchctl_log' && grep -qxF \"\$(printf 'bootstrap\tuser/%s\t%s' '$test_uid' '$user_plist')\" '$launchctl_log'"
    # Immediately run a 2nd invocation within 1s without -K adding a second user-background service:
    nok2_p="$launchd_agents/com.tendcf.nok.second.plist"
    rm -f "$nok2_p" "$launchctl_state/user.com.tendcf.nok.second" "$launchctl_state/gui.com.tendcf.nok.second"
    python3 - "$user_bg_canary_fx" "$work/data/host_specific.json" "$test_user" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["vars"]["tendcf_interlock"] = {}
doc["vars"]["tendcf_service"]["com.tendcf.nok.second"] = {
    "bundle": "canary",
    "command": ["/bin/sleep", "86400"],
    "run_as": sys.argv[3],
    "state": "present",
    "unit": {"launchd": {"domain": "user-background", "keep_alive": True, "run_at_load": True}},
    "working_dir": "/",
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    "$cf_agent" -I -f "$work/inputs/launchd-user-nok-harness.cf" >"$work/launchd-r1-nok-run2.out" 2>&1 || true
    check "launchd no -K run 2 (within 60s): domain probes 0a/0b re-ran (not lock-skipped)" \
        bash -c "grep -qxF \"\$(printf 'print\tgui/%s' '$test_uid')\" '$launchctl_log' && grep -qxF \"\$(printf 'print\tuser/%s' '$test_uid')\" '$launchctl_log'"
    check "launchd no -K run 2 (within 60s): second service rendered and bootstrapped cleanly" \
        bash -c "[ -f '$nok2_p' ] && grep -qxF \"\$(printf 'bootstrap\tuser/%s\t%s' '$test_uid' '$nok2_p')\" '$launchctl_log'"

    # Opus R2 L4: consecutive non-`-K` runs within 1s must NOT lock-skip one-shot
    # `bootout` actuation commands (`0d` peer, `3d`/`3f` user tombstones, `3b` system tombstone).
    # Run 3 (no -K): switch canary.main user-background -> user-gui (0d peer bootout) and
    # tombstone nok.second loaded in both gui & user (3d/3f tombstone bootouts + plist delete).
    : > "$launchctl_state/gui.com.tendcf.nok.second"
    python3 - "$user_gui_canary_fx" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["vars"]["tendcf_interlock"] = {}
doc["vars"]["tendcf_service"]["com.tendcf.nok.second"] = {"state": "absent"}
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    "$cf_agent" -I -f "$work/inputs/launchd-user-nok-harness.cf" >"$work/launchd-r1-nok-run3.out" 2>&1 || true
    check "launchd no -K run 3: peer 0d bootout + user-gui bootstrap ran" \
        bash -c "grep -qxF \"\$(printf 'bootout\tuser/%s/com.tendcf.canary.main' '$test_uid')\" '$launchctl_log' && grep -qxF \"\$(printf 'bootstrap\tgui/%s\t%s' '$test_uid' '$user_plist')\" '$launchctl_log'"
    check "launchd no -K run 3: dual-leg tombstone 3d/3f bootouts ran and deleted plist" \
        bash -c "grep -qxF \"\$(printf 'bootout\tgui/%s/com.tendcf.nok.second' '$test_uid')\" '$launchctl_log' && grep -qxF \"\$(printf 'bootout\tuser/%s/com.tendcf.nok.second' '$test_uid')\" '$launchctl_log' && [ ! -e '$nok2_p' ]"

    # Run 4 (within 1s, no -K): re-plant the exact same peer & tombstone targets so identical
    # bootout command locks would fire without `action => tendcf_probe_always`.
    : > "$launchctl_state/user.com.tendcf.canary.main"
    cp "$golden_user_bg_dir/com.tendcf.canary.main.plist" "$nok2_p"
    : > "$launchctl_state/gui.com.tendcf.nok.second"
    : > "$launchctl_state/user.com.tendcf.nok.second"
    : > "$launchctl_log"
    "$cf_agent" -I -f "$work/inputs/launchd-user-nok-harness.cf" >"$work/launchd-r1-nok-run4.out" 2>&1 || true
    check "launchd no -K run 4 (within 1s): peer 0d bootout re-ran (not lock-skipped)" \
        bash -c "grep -qxF \"\$(printf 'bootout\tuser/%s/com.tendcf.canary.main' '$test_uid')\" '$launchctl_log' && [ ! -e '$launchctl_state/user.com.tendcf.canary.main' ]"
    check "launchd no -K run 4 (within 1s): tombstone 3d/3f bootouts re-ran (not lock-skipped)" \
        bash -c "grep -qxF \"\$(printf 'bootout\tgui/%s/com.tendcf.nok.second' '$test_uid')\" '$launchctl_log' && grep -qxF \"\$(printf 'bootout\tuser/%s/com.tendcf.nok.second' '$test_uid')\" '$launchctl_log' && [ ! -e '$launchctl_state/gui.com.tendcf.nok.second' ] && [ ! -e '$launchctl_state/user.com.tendcf.nok.second' ]"
    rm -f "$user_plist" "$nok2_p" "$launchctl_state/user.com.tendcf.canary.main" "$launchctl_state/gui.com.tendcf.canary.main" "$launchctl_state/user.com.tendcf.nok.second" "$launchctl_state/gui.com.tendcf.nok.second"

    # System-mode tombstone 3b across two consecutive non-`-K` runs within 1s:
    cat > "$work/inputs/launchd-sys-nok-harness.cf" <<EOF
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf", "$repo/tests/policy/fixtures/test-done.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_launchd_sys_nok_harness", "tendcf_test_done" };
}
bundle agent tendcf_launchd_sys_nok_harness
{
  methods:
      "run"
        usebundle => tendcf_services_apply("system", "$launchd_daemons", "$launchctl_stub", "$test_user", "$test_group", "$test_user", "0"),
        action => tendcf_probe_always;
}
EOF
    nok_sys_p="$launchd_daemons/com.tendcf.nok.sys.plist"
    printf '%s\n' '{"vars":{"tendcf_interlock":{},"tendcf_service":{"com.tendcf.nok.sys":{"state":"absent"}}}}' > "$work/data/host_specific.json"
    cp "$golden_sys_dir/com.tendcf.demo.main.plist" "$nok_sys_p"
    : > "$launchctl_state/com.tendcf.nok.sys"
    : > "$launchctl_log"
    "$cf_agent" -I -f "$work/inputs/launchd-sys-nok-harness.cf" >"$work/launchd-r1-sys-nok-run1.out" 2>&1 || true
    check "launchd system tombstone no -K run 1: 3b bootout ran and deleted plist" \
        bash -c "grep -qxF \"\$(printf 'bootout\tsystem/com.tendcf.nok.sys')\" '$launchctl_log' && [ ! -e '$nok_sys_p' ]"
    cp "$golden_sys_dir/com.tendcf.demo.main.plist" "$nok_sys_p"
    : > "$launchctl_state/com.tendcf.nok.sys"
    : > "$launchctl_log"
    "$cf_agent" -I -f "$work/inputs/launchd-sys-nok-harness.cf" >"$work/launchd-r1-sys-nok-run2.out" 2>&1 || true
    check "launchd system tombstone no -K run 2 (within 1s): 3b bootout re-ran (not lock-skipped)" \
        bash -c "grep -qxF \"\$(printf 'bootout\tsystem/com.tendcf.nok.sys')\" '$launchctl_log' && [ ! -e '$launchctl_state/com.tendcf.nok.sys' ]"
    rm -f "$nok_sys_p" "$launchctl_state/com.tendcf.nok.sys"

    # Darwin entry.cf safety guard: no repo fixture fed to entry.cf may match
    # unprivileged user-domain actuation (domain in user/user-gui/user-background && run_as==$test_user),
    # and unprivileged tendcf_services must select tendcf_running_as_nonroot only.
    check "darwin entry.cf safety: no tests/policy/fixtures/*.json actuates user domain for $test_user" \
        python3 - "$repo/tests/policy/fixtures" "$test_user" <<'PYEOF'
import json, pathlib, sys
fdir, user = pathlib.Path(sys.argv[1]), sys.argv[2]
for p in sorted(fdir.glob("*.json")):
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        continue
    svcs = (doc.get("vars") or {}).get("tendcf_service") or {}
    if not isinstance(svcs, dict):
        continue
    for sid, svc in svcs.items():
        if not isinstance(svc, dict):
            continue
        dom = ((svc.get("unit") or {}).get("launchd") or {}).get("domain")
        if dom in ("user", "user-gui", "user-background") and svc.get("run_as") == user:
            raise SystemExit(f"{p.name}: service {sid!r} has domain={dom!r} and run_as={user!r}")
PYEOF
    if [ "$test_uid" != 0 ]; then
        printf '%s\n' '{"vars":{}}' > "$work/data/host_specific.json"
        "$cf_agent" -K -v -n -f "$work/inputs/entry.cf" >"$work/launchd-entry-nonroot.out" 2>&1 || true
        check "darwin entry.cf safety: unprivileged tendcf_services defines tendcf_running_as_nonroot" \
            grep -q "Private class: tendcf_running_as_nonroot" "$work/launchd-entry-nonroot.out"
        check "darwin entry.cf safety: unprivileged tendcf_services does NOT define tendcf_running_as_root" \
            bash -c "! grep -q 'Private class: tendcf_running_as_root' '$work/launchd-entry-nonroot.out'"
    fi

    # 5m.20 Installer-owned unit defence-in-depth on Darwin launchd harness (issue #102):
    # system & user modes, exact & case-variant present/tombstone, plus sibling convergence.
    execd_sys_plist="$launchd_daemons/org.tendcf.execd.plist"
    execd_usr_plist="$launchd_agents/org.tendcf.execd.plist"
    printf 'sentinel-execd-system-plist\n' > "$execd_sys_plist"
    : > "$launchctl_state/org.tendcf.execd"
    execd_sys_hash="$(shasum -a 256 "$execd_sys_plist" | awk '{print $1}')"

    # (a) Present org.tendcf.execd (system mode)
    launchd_run reserved-launchd-present.json "$work/launchd-reserved-sys-present.out"
    check "launchd reserved (system present org.tendcf.execd): refused and reported" \
        grep -qF "tendcf: service 'org.tendcf.execd' refused: installer-owned unit (tendcf-install) cannot be actuated by cfengine" "$work/launchd-reserved-sys-present.out"
    check "launchd reserved (system present org.tendcf.execd): zero launchctl calls (not even print)" test ! -s "$launchctl_log"
    check "launchd reserved (system present org.tendcf.execd): existing plist hash unchanged" \
        bash -c "[ \"\$(shasum -a 256 '$execd_sys_plist' | awk '{print \$1}')\" = '$execd_sys_hash' ]"

    # (b) Present ORG.TENDCF.EXECD (system mode, APFS case-insensitive)
    launchd_run reserved-launchd-case-present.json "$work/launchd-reserved-sys-case-present.out"
    check "launchd reserved (system present ORG.TENDCF.EXECD): refused and reported" \
        grep -qF "tendcf: service 'ORG.TENDCF.EXECD' refused: installer-owned unit (tendcf-install) cannot be actuated by cfengine" "$work/launchd-reserved-sys-case-present.out"
    check "launchd reserved (system present ORG.TENDCF.EXECD): zero launchctl calls" test ! -s "$launchctl_log"
    check "launchd reserved (system present ORG.TENDCF.EXECD): existing plist hash unchanged" \
        bash -c "[ \"\$(shasum -a 256 '$execd_sys_plist' | awk '{print \$1}')\" = '$execd_sys_hash' ]"

    # (c) Present org.tendcf.execd & ORG.TENDCF.EXECD (user mode)
    for case_spec in "exact:org.tendcf.execd" "case:ORG.TENDCF.EXECD"; do
        cname="${case_spec%%:*}"
        clabel="${case_spec#*:}"
        python3 - "$work/data/host_specific.json" "$clabel" "$test_user" <<'PYEOF'
import json, pathlib, sys
doc = {
    "vars": {
        "tendcf_interlock": {},
        "tendcf_service": {
            sys.argv[2]: {
                "bundle": "demo",
                "command": ["/bin/sleep", "1"],
                "run_as": sys.argv[3],
                "state": "present",
                "unit": {"launchd": {"domain": "user-gui", "keep_alive": True, "run_at_load": True}},
                "working_dir": "/",
            }
        },
    }
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
        : > "$launchctl_log"
        printf 'normal\n' > "$launchctl_mode"
        "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-reserved-user-$cname-present.out" 2>&1 || true
        check "launchd reserved (user present $clabel): refused and reported" \
            grep -qF "tendcf: service '$clabel' refused: installer-owned unit (tendcf-install) cannot be actuated by cfengine" "$work/launchd-reserved-user-$cname-present.out"
        check "launchd reserved (user present $clabel): zero launchctl calls" test ! -s "$launchctl_log"
        check "launchd reserved (user present $clabel): no plist created in agents dir" test ! -e "$execd_usr_plist"
    done

    # (d) Tombstone org.tendcf.execd (system mode, loaded regular plist on disk)
    launchd_run reserved-launchd-absent.json "$work/launchd-reserved-sys-absent.out"
    check "launchd reserved (system tombstone org.tendcf.execd): refused and reported" \
        grep -qF "tendcf: service 'org.tendcf.execd' tombstone refused: installer-owned unit (tendcf-install) cannot be removed by cfengine" "$work/launchd-reserved-sys-absent.out"
    check "launchd reserved (system tombstone org.tendcf.execd): zero launchctl calls" test ! -s "$launchctl_log"
    check "launchd reserved (system tombstone org.tendcf.execd): regular plist preserved intact" \
        bash -c "[ -f '$execd_sys_plist' ] && [ \"\$(shasum -a 256 '$execd_sys_plist' | awk '{print \$1}')\" = '$execd_sys_hash' ]"

    # (e) Tombstone ORG.TENDCF.EXECD (system mode, loaded regular plist on disk)
    launchd_run reserved-launchd-case-absent.json "$work/launchd-reserved-sys-case-absent.out"
    check "launchd reserved (system tombstone ORG.TENDCF.EXECD): refused and reported" \
        grep -qF "tendcf: service 'ORG.TENDCF.EXECD' tombstone refused: installer-owned unit (tendcf-install) cannot be removed by cfengine" "$work/launchd-reserved-sys-case-absent.out"
    check "launchd reserved (system tombstone ORG.TENDCF.EXECD): zero launchctl calls" test ! -s "$launchctl_log"
    check "launchd reserved (system tombstone ORG.TENDCF.EXECD): regular plist preserved intact" \
        bash -c "[ -f '$execd_sys_plist' ] && [ \"\$(shasum -a 256 '$execd_sys_plist' | awk '{print \$1}')\" = '$execd_sys_hash' ]"

    # (f) Tombstone org.tendcf.execd (user mode, loaded regular plist in agents dir)
    printf 'sentinel-execd-user-plist\n' > "$execd_usr_plist"
    : > "$launchctl_state/gui.org.tendcf.execd"
    execd_usr_hash="$(shasum -a 256 "$execd_usr_plist" | awk '{print $1}')"
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    cp "$repo/tests/policy/fixtures/reserved-launchd-absent.json" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$work/launchd-reserved-user-absent.out" 2>&1 || true
    check "launchd reserved (user tombstone org.tendcf.execd): refused and reported" \
        grep -qF "tendcf: service 'org.tendcf.execd' tombstone refused: installer-owned unit (tendcf-install) cannot be removed by cfengine" "$work/launchd-reserved-user-absent.out"
    check "launchd reserved (user tombstone org.tendcf.execd): zero launchctl calls" test ! -s "$launchctl_log"
    check "launchd reserved (user tombstone org.tendcf.execd): user plist preserved intact" \
        bash -c "[ -f '$execd_usr_plist' ] && [ \"\$(shasum -a 256 '$execd_usr_plist' | awk '{print \$1}')\" = '$execd_usr_hash' ]"
    rm -f "$execd_usr_plist" "$launchctl_state/gui.org.tendcf.execd"

    # (g) Valid sibling alongside reserved org.tendcf.execd: sibling converges while reserved unit is refused and untouched.
    rm -f "$canary_sys_p" "$launchctl_state/com.tendcf.canary.main"
    python3 - "$repo/deploy/darwin/canary/host_specific.json" "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
doc["vars"]["tendcf_service"]["org.tendcf.execd"] = {
    "bundle": "canary",
    "command": ["/bin/sleep", "1"],
    "run_as": "nobody",
    "state": "present",
    "unit": {"launchd": {"domain": "system", "keep_alive": True, "run_at_load": True}},
    "working_dir": "/",
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    : > "$launchctl_log"
    printf 'normal\n' > "$launchctl_mode"
    "$cf_agent" -K -I -f "$work/inputs/launchd-harness.cf" >"$work/launchd-reserved-sibling.out" 2>&1 || true
    check "launchd reserved + sibling: reserved org.tendcf.execd refused" \
        grep -qF "tendcf: service 'org.tendcf.execd' refused: installer-owned unit (tendcf-install) cannot be actuated by cfengine" "$work/launchd-reserved-sibling.out"
    check "launchd reserved + sibling: org.tendcf.execd plist hash unchanged" \
        bash -c "[ \"\$(shasum -a 256 '$execd_sys_plist' | awk '{print \$1}')\" = '$execd_sys_hash' ]"
    check "launchd reserved + sibling: zero launchctl calls naming org.tendcf.execd" \
        bash -c "! grep -q 'org\\.tendcf\\.execd' '$launchctl_log'"
    check "launchd reserved + sibling: valid sibling canary rendered byte-identical to golden" \
        cmp -s "$golden_sys_dir/com.tendcf.canary.main.plist" "$canary_sys_p"
    check "launchd reserved + sibling: valid sibling canary bootstrapped" \
        grep -qxF "$(printf 'bootstrap\tsystem\t%s' "$canary_sys_p")" "$launchctl_log"
    rm -f "$execd_sys_plist" "$launchctl_state/org.tendcf.execd" "$canary_sys_p" "$launchctl_state/com.tendcf.canary.main"
else
    for name in \
        "launchd first render: byte-identical to committed golden, perms 0644, no backup, bootstrap" \
        "launchd canary system render: byte-identical to committed system golden" \
        "launchd unchanged re-run: plist hash unchanged, zero launchctl write calls" \
        "launchd one-key drift: repaired to golden, bootout before bootstrap, sibling untouched" \
        "launchd perms drift: mode repaired to 0644, reloaded" \
        "launchd failed bootout/bootstrap and M1 reload recovery: fail-closed, persisted recovery, reported" \
        "launchd tombstone: bootout before delete, print-error fail-closed, second run no-op, C-policy-04 non-regular refusal" \
        "launchd dry-run (-n), plist_failed, canonify/APFS collisions, XML escaping, invalid ids, and non-regular present refusals" \
        "launchd user-domain LaunchAgent render/tombstone (gui/<uid>) and fail-closed domain/run_as privilege separation" \
        "launchd installer-owned org.tendcf.execd defence-in-depth (system/user, exact/case-variant, present/tombstone, sibling)"; do
        platform_skip "not Darwin ($(uname)); launchd adapter requires darwin class" "$name"
    done
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
        execd_sentinel_path=/etc/systemd/system/tendcf-execd.service
        execd_sentinel_created=0
        execd_timer_path=/etc/systemd/system/tendcf-execd.timer
        execd_timer_created=0
        dotdot_unit="tendcf-test-backup..daily-$$.service"
        dotdot_unit_path="/etc/systemd/system/$dotdot_unit"
        dotdot_unit_acquired=0
        timer_unit="tendcf-test-backup-$$.timer"
        timer_unit_path="/etc/systemd/system/$timer_unit"
        timer_unit_acquired=0
        cleanup_unit() {
            as_root systemctl disable --now "$unit" >/dev/null 2>&1 || true
            as_root rm -f "$unit_path" "$alias_path" "$mask_path" "$dangling_path"
            if [ "${dotdot_unit_acquired:-0}" = 1 ]; then
                as_root systemctl disable --now "$dotdot_unit" >/dev/null 2>&1 || true
                as_root rm -f "$dotdot_unit_path"
            fi
            if [ "${timer_unit_acquired:-0}" = 1 ]; then
                as_root systemctl disable --now "$timer_unit" >/dev/null 2>&1 || true
                as_root rm -f "$timer_unit_path"
            fi
            if [ "${execd_sentinel_created:-0}" = 1 ]; then
                as_root rm -f "$execd_sentinel_path"
            fi
            if [ "${execd_timer_created:-0}" = 1 ]; then
                as_root rm -f "$execd_timer_path"
            fi
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

        # 6c. Installer-owned unit defence-in-depth on a real systemd host (issue #102):
        # plant a regular sentinel at /etc/systemd/system/tendcf-execd.service (only if
        # absent beforehand; removed in cleanup_unit and after 6c) and prove present &
        # tombstone for tendcf-execd.service, bare tendcf-execd, and ./tendcf-execd.service
        # leave it byte-identical with zero systemctl calls and zero file edits (Opus L1 / Neon Note 3).
        if [ ! -e "$execd_sentinel_path" ] && [ ! -L "$execd_sentinel_path" ]; then
            printf '[Unit]\nDescription=tendcf-execd sentinel for policy test 6c\n' \
                | as_root tee "$execd_sentinel_path" >/dev/null
            as_root chmod 0644 "$execd_sentinel_path"
            execd_sentinel_created=1
        fi
        execd_sentinel_hash="$(as_root sha256sum "$execd_sentinel_path" | awk '{print $1}')"
        sysd_no_edit() { ! grep -Eq 'Created file|Updated rendering|Edited file' "$1"; }
        execd_sentinel_unchanged() {
            local cur_hash
            [ -f "$execd_sentinel_path" ] || return 1
            cur_hash="$(as_root sha256sum "$execd_sentinel_path" | awk '{print $1}')"
            [ "$cur_hash" = "$execd_sentinel_hash" ]
        }

        sysd_run_verbose reserved-systemd-present.json "$work/sysd-reserved-present.out"
        check "systemd reserved present tendcf-execd.service: refused and reported" \
            grep -qF "tendcf: service 'tendcf-execd.service' refused: installer-owned unit (tendcf-install) cannot be actuated by cfengine" "$work/sysd-reserved-present.out"
        check "systemd reserved present tendcf-execd.service: zero systemctl commands or probes" \
            no_systemctl "$work/sysd-reserved-present.out"
        check "systemd reserved present tendcf-execd.service: nothing created or edited" \
            sysd_no_edit "$work/sysd-reserved-present.out"
        check "systemd reserved present tendcf-execd.service: sentinel hash unchanged" \
            execd_sentinel_unchanged

        sysd_run_verbose reserved-systemd-absent.json "$work/sysd-reserved-absent.out"
        check "systemd reserved tombstone tendcf-execd.service: refused and reported" \
            grep -qF "tendcf: service 'tendcf-execd.service' tombstone refused: installer-owned unit (tendcf-install) cannot be removed by cfengine" "$work/sysd-reserved-absent.out"
        check "systemd reserved tombstone tendcf-execd.service: zero systemctl commands or probes" \
            no_systemctl "$work/sysd-reserved-absent.out"
        check "systemd reserved tombstone tendcf-execd.service: nothing deleted" \
            bash -c "! grep -q 'Deleted file' '$work/sysd-reserved-absent.out'"
        check "systemd reserved tombstone tendcf-execd.service: sentinel hash unchanged" \
            execd_sentinel_unchanged

        for vm_spec in \
            "nosuffix-present:tendcf-execd:present:tendcf: service 'tendcf-execd' refused: installer-owned unit (tendcf-install) cannot be actuated by cfengine" \
            "nosuffix-absent:tendcf-execd:absent:tendcf: service 'tendcf-execd' tombstone refused: installer-owned unit (tendcf-install) cannot be removed by cfengine" \
            "dotslash-present:./tendcf-execd.service:present:tendcf: systemd service refused: id is not a valid systemd service unit name" \
            "dotslash-absent:./tendcf-execd.service:absent:tendcf: systemd tombstone refused: id is not a valid systemd unit name"; do
            vname="${vm_spec%%:*}"; rest="${vm_spec#*:}"
            vid="${rest%%:*}"; rest="${rest#*:}"
            vstate="${rest%%:*}"; vexpected="${rest#*:}"
            python3 - "$work/data/host_specific.json" "$vid" "$vstate" <<'PYEOF'
import json, pathlib, sys
out_path, vid, state = sys.argv[1], sys.argv[2], sys.argv[3]
if state == "present":
    entry = {
        "bundle": "demo",
        "command": ["/usr/bin/sleep", "3600"],
        "run_as": "nobody",
        "state": "present",
        "unit": {"systemd": {"enabled": True, "restart": "on-failure", "wanted_by": "multi-user.target"}},
        "working_dir": "/",
    }
else:
    entry = {"state": "absent"}
doc = {"vars": {"tendcf_interlock": {}, "tendcf_service": {vid: entry}}}
pathlib.Path(out_path).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
            vout="$work/sysd-reserved-$vname.out"
            as_root env CFENGINE_TEST_OVERRIDE_WORKDIR="$work" \
                "$cf_agent" -K -v -f "$work/inputs/entry.cf" >"$vout" 2>&1 || true
            as_root chown -R "$(id -u):$(id -g)" "$work"
            check "systemd reserved ($vname): expected refusal reported" grep -qF "$vexpected" "$vout"
            check "systemd reserved ($vname): zero systemctl commands or probes" no_systemctl "$vout"
            check "systemd reserved ($vname): nothing created, edited, or deleted" \
                bash -c "! grep -Eq 'Created file|Updated rendering|Edited file|Deleted file' '$vout'"
            check "systemd reserved ($vname): sentinel hash unchanged" \
                execd_sentinel_unchanged
        done

        if [ "$execd_sentinel_created" = 1 ]; then
            as_root rm -f "$execd_sentinel_path"
            execd_sentinel_created=0
        fi

        # 6c positive controls (issue #102 R3/R4 Codex findings):
        # (1) Per-run embedded-`..` service (`$dotdot_unit`) renders, activates, and tears down cleanly.
        if [ ! -e "$dotdot_unit_path" ] && [ ! -L "$dotdot_unit_path" ]; then
            dotdot_unit_acquired=1
            printf '{"vars":{"tendcf_interlock":{},"tendcf_service":{"%s":{"bundle":"demo","command":["/usr/bin/sleep","3600"],"run_as":"nobody","state":"present","unit":{"systemd":{"enabled":false,"restart":"on-failure","wanted_by":"multi-user.target"}},"working_dir":"/"}}}}\n' "$dotdot_unit" > "$work/data/host_specific.json"
            as_root env CFENGINE_TEST_OVERRIDE_WORKDIR="$work" \
                "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$work/sysd-pos-dotdot-present.out" 2>&1 || true
            as_root chown -R "$(id -u):$(id -g)" "$work"
            check "systemd positive ($dotdot_unit present): not refused as bad id" \
                bash -c "! grep -q 'is not a valid systemd' '$work/sysd-pos-dotdot-present.out'"
            check "systemd positive ($dotdot_unit present): unit rendered" \
                test -f "$dotdot_unit_path"
            check "systemd positive ($dotdot_unit present): unit active" \
                as_root systemctl is-active --quiet "$dotdot_unit"

            printf '{"vars":{"tendcf_interlock":{},"tendcf_service":{"%s":{"state":"absent"}}}}\n' "$dotdot_unit" > "$work/data/host_specific.json"
            as_root env CFENGINE_TEST_OVERRIDE_WORKDIR="$work" \
                "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$work/sysd-pos-dotdot-absent.out" 2>&1 || true
            as_root chown -R "$(id -u):$(id -g)" "$work"
            check "systemd positive ($dotdot_unit tombstone): not refused as bad id" \
                bash -c "! grep -q 'is not a valid systemd' '$work/sysd-pos-dotdot-absent.out'"
            check "systemd positive ($dotdot_unit tombstone): unit file removed" \
                test ! -e "$dotdot_unit_path"
            check "systemd positive ($dotdot_unit tombstone): unit stopped" \
                bash -c "! systemctl is-active --quiet '$dotdot_unit'"
            if [ ! -e "$dotdot_unit_path" ] && [ ! -L "$dotdot_unit_path" ] && ! as_root systemctl is-active --quiet "$dotdot_unit"; then
                dotdot_unit_acquired=0
            fi
        else
            check "systemd positive ($dotdot_unit): unit path unused before test" false
        fi

        # (2) Per-run regular `.timer` tombstone (`$timer_unit`) tears down cleanly while `tendcf-execd.timer` stays refused.
        if [ ! -e "$timer_unit_path" ] && [ ! -L "$timer_unit_path" ]; then
            timer_unit_acquired=1
            printf '[Unit]\nDescription=tendcf test backup timer\n[Timer]\nOnCalendar=daily\nUnit=%s\n' "$unit" \
                | as_root tee "$timer_unit_path" >/dev/null
            as_root chmod 0644 "$timer_unit_path"
            printf '{"vars":{"tendcf_interlock":{},"tendcf_service":{"%s":{"state":"absent"}}}}\n' "$timer_unit" > "$work/data/host_specific.json"
            as_root env CFENGINE_TEST_OVERRIDE_WORKDIR="$work" \
                "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$work/sysd-pos-timer-absent.out" 2>&1 || true
            as_root chown -R "$(id -u):$(id -g)" "$work"
            check "systemd positive ($timer_unit tombstone): not refused as bad id" \
                bash -c "! grep -q 'is not a valid systemd' '$work/sysd-pos-timer-absent.out'"
            check "systemd positive ($timer_unit tombstone): regular timer file removed" \
                test ! -e "$timer_unit_path"
            if [ ! -e "$timer_unit_path" ] && [ ! -L "$timer_unit_path" ] && ! as_root systemctl is-active --quiet "$timer_unit"; then
                timer_unit_acquired=0
            fi
        else
            check "systemd positive ($timer_unit): timer path unused before test" false
        fi

        if [ ! -e "$execd_timer_path" ] && [ ! -L "$execd_timer_path" ]; then
            printf '[Unit]\nDescription=tendcf-execd timer sentinel for policy test 6c\n' \
                | as_root tee "$execd_timer_path" >/dev/null
            as_root chmod 0644 "$execd_timer_path"
            execd_timer_created=1
        fi
        execd_timer_hash="$(as_root sha256sum "$execd_timer_path" | awk '{print $1}')"
        execd_timer_unchanged() {
            local cur_hash
            [ -f "$execd_timer_path" ] || return 1
            cur_hash="$(as_root sha256sum "$execd_timer_path" | awk '{print $1}')"
            [ "$cur_hash" = "$execd_timer_hash" ]
        }
        printf '%s\n' '{"vars":{"tendcf_interlock":{},"tendcf_service":{"tendcf-execd.timer":{"state":"absent"}}}}' > "$work/data/host_specific.json"
        as_root env CFENGINE_TEST_OVERRIDE_WORKDIR="$work" \
            "$cf_agent" -K -v -f "$work/inputs/entry.cf" >"$work/sysd-reserved-timer-absent.out" 2>&1 || true
        as_root chown -R "$(id -u):$(id -g)" "$work"
        check "systemd reserved (tendcf-execd.timer tombstone): refused as installer-owned unit" \
            grep -qF "tendcf: service 'tendcf-execd.timer' tombstone refused: installer-owned unit (tendcf-install) cannot be removed by cfengine" "$work/sysd-reserved-timer-absent.out"
        check "systemd reserved (tendcf-execd.timer tombstone): zero systemctl commands or probes" \
            no_systemctl "$work/sysd-reserved-timer-absent.out"
        check "systemd reserved (tendcf-execd.timer tombstone): sentinel hash unchanged" \
            execd_timer_unchanged
        if [ "$execd_timer_created" = 1 ]; then
            as_root rm -f "$execd_timer_path"
            execd_timer_created=0
        fi

        # 6c(3). Issue #54 R1: real systemd-analyze verify on a rendered
        # metacharacter unit (proves systemd parses quoted `;`, `|`, `&&`,
        # backticks, `<`, `>` in command[1:] cleanly when command[0] starts
        # with `/`) and root-level refusal of `+/usr/bin/id` and `|/usr/bin/id`.
        if command -v systemd-analyze >/dev/null 2>&1; then
            meta_verify_unit="$work/tendcf-meta-verify.service"
            true_bin="$(command -v true)"
            python3 - "$work/data/host_specific.json" "$true_bin" <<'PYEOF'
import json, pathlib, sys
out_path, true_bin = sys.argv[1], sys.argv[2]
doc = {
    "vars": {
        "tendcf_service": {
            "tendcf-meta-verify.service": {
                "bundle": "meta",
                "command": [
                    true_bin,
                    ";",
                    "|",
                    "&&",
                    "`echo hi`",
                    ">/dev/null",
                    "</dev/null",
                    "&",
                    "'single'",
                ],
                "run_as": "nobody",
                "state": "present",
                "unit": {
                    "systemd": {
                        "enabled": False,
                        "restart": "on-failure",
                        "wanted_by": "multi-user.target",
                    }
                },
                "working_dir": "/",
            }
        }
    }
}
pathlib.Path(out_path).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
            cat > "$work/inputs/systemd-meta-verify.cf" <<EOF
body common control
{
      bundlesequence => { "tendcf_test_systemd_verify" };
}
bundle agent tendcf_test_systemd_verify
{
  files:
      "$meta_verify_unit"
        create => "true",
        edit_template => "$repo/policy/templates/systemd.service.mustache",
        template_method => "mustache",
        template_data => mergedata("data:variables.tendcf_service[tendcf-meta-verify.service]",
                                    '{"id": "tendcf-meta-verify.service"}');
}
EOF
            "$cf_agent" -K -I -f "$work/inputs/systemd-meta-verify.cf" >"$work/sysd-meta-verify.out" 2>&1 || true
            check "systemd-analyze verify: metacharacter unit rendered" test -f "$meta_verify_unit"
            check "systemd-analyze verify: metacharacter unit passes systemd parser" \
                systemd-analyze verify "$meta_verify_unit"
        fi
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

# 6d. Cross-platform systemd.service.mustache render check (issue #54): proves
#     ExecStart uses unescaped triple-braces `{{{.}}}` inside double quotes so
#     `;`, `|`, `&&`, backticks, `<`, `>` render verbatim (not HTML-escaped),
#     on a single ExecStart= line, without executing a shell during Mustache
#     rendering. Runs on both Darwin and Linux without root.
sysd_meta_unit="$work/systemd-meta.service"
sysd_meta_sentinel="$work/systemd-meta-should-not-exist"
rm -f "$sysd_meta_unit" "$sysd_meta_sentinel"
python3 - "$work/data/host_specific.json" "$sysd_meta_sentinel" <<'PYEOF'
import json, pathlib, sys
out_path, sentinel = sys.argv[1], sys.argv[2]
doc = {
    "vars": {
        "tendcf_service": {
            "tendcf.meta.service": {
                "bundle": "meta",
                "command": [
                    "/usr/bin/echo",
                    ";",
                    "|",
                    "&&",
                    f"`touch {sentinel}`",
                    f">{sentinel}",
                    "</dev/null",
                    "&",
                    "'single'",
                ],
                "run_as": "nobody",
                "state": "present",
                "unit": {
                    "systemd": {
                        "enabled": False,
                        "restart": "on-failure",
                        "wanted_by": "multi-user.target",
                    }
                },
                "working_dir": "/srv",
            }
        }
    }
}
pathlib.Path(out_path).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
cat > "$work/inputs/systemd-mustache-render.cf" <<EOF
body common control
{
      bundlesequence => { "tendcf_test_systemd_render" };
}
bundle agent tendcf_test_systemd_render
{
  files:
      "$sysd_meta_unit"
        create => "true",
        edit_template => "$repo/policy/templates/systemd.service.mustache",
        template_method => "mustache",
        template_data => mergedata("data:variables.tendcf_service[tendcf.meta.service]",
                                    '{"id": "tendcf.meta.service"}');
}
EOF
"$cf_agent" -K -I -f "$work/inputs/systemd-mustache-render.cf" >"$work/sysd-meta-render.out" 2>&1 || true
check "systemd.service.mustache metacharacter render: unit file created" test -f "$sysd_meta_unit"
check "systemd.service.mustache metacharacter render: ExecStart preserves ;, |, &&, backticks, <, > verbatim inside double quotes" \
    python3 - "$sysd_meta_unit" "$sysd_meta_sentinel" <<'PYEOF'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
sentinel = sys.argv[2]
expected_exec = (
    'ExecStart="/usr/bin/echo" ";" "|" "&&" '
    f'"`touch {sentinel}`" ">{sentinel}" "</dev/null" "&" "\'single\'" '
)
lines = text.splitlines()
assert "Type=simple" in lines, lines
assert "User=nobody" in lines, lines
assert "WorkingDirectory=/srv" in lines, lines
assert "Restart=on-failure" in lines, lines
assert "WantedBy=multi-user.target" in lines, lines
exec_lines = [ln for ln in lines if ln.startswith("ExecStart=")]
assert exec_lines == [expected_exec], f"got {exec_lines!r}, want {[expected_exec]!r}"
assert "&amp;" not in text and "&lt;" not in text and "&gt;" not in text, text
PYEOF
check "systemd.service.mustache metacharacter render: no shell command executed during render" \
    test ! -e "$sysd_meta_sentinel"

# 6e. Cross-platform systemd command[0] fail-closed refusal (issue #54 R1):
#     systemd's config_parse_exec() unquotes firstword BEFORE parsing `;` and
#     executable prefixes (`+`/`!`/`|`/`@`/`-`/`:`), so the policy itself must
#     refuse any systemd command[0] that is not a safe absolute non-directory
#     path (even on a projection that skipped schema & projector), rendering
#     nothing and invoking zero systemctl commands.
for bad_cmd0_spec in \
    "plus:+/usr/bin/id" \
    "pipe:|/usr/bin/id" \
    "trailing-slash:/usr/bin/" \
    "relative:sleep"; do
    bname="${bad_cmd0_spec%%:*}"
    bcmd0="${bad_cmd0_spec#*:}"
    python3 - "$work/data/host_specific.json" "$bcmd0" <<'PYEOF'
import json, pathlib, sys
out_path, cmd0 = sys.argv[1], sys.argv[2]
doc = {
    "vars": {
        "tendcf_service": {
            "tendcf.badcmd0.service": {
                "bundle": "demo",
                "command": [cmd0, "arg1"],
                "run_as": "nobody",
                "state": "present",
                "unit": {
                    "systemd": {
                        "enabled": False,
                        "restart": "on-failure",
                        "wanted_by": "multi-user.target",
                    }
                },
                "working_dir": "/",
            }
        }
    }
}
pathlib.Path(out_path).write_text(json.dumps(doc, separators=(",", ":"), sort_keys=True))
PYEOF
    bout="$work/sysd-bad-cmd0-$bname.out"
    "$cf_agent" -K -v -f "$work/inputs/entry.cf" >"$bout" 2>&1 || true
    check "systemd bad command[0] ($bname): refused with dedicated command[0] report" \
        grep -qF "tendcf: service 'tendcf.badcmd0.service' refused: systemd command[0] is missing or not a safe absolute non-directory path" "$bout"
    check "systemd bad command[0] ($bname): not misreported as unsupported flavour" \
        bash -c "! grep -q \"unit flavour 'systemd' is not implemented\" '$bout'"
    check "systemd bad command[0] ($bname): nothing rendered" \
        bash -c "! grep -Eq 'Created file|Updated rendering|Edited file' '$bout'"
    check "systemd bad command[0] ($bname): no systemctl invocation" \
        no_systemctl "$bout"
done

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
        bash -c "! grep -q 'is not a normalized printable-ASCII absolute path' '$out'"
}
argv_case alphabet 'a,b=c:d@e+f' '--k=v,w:/p@h+1._-' '-' 'A0z9' '/x/y'
bt="$(printf '\140')"
argv_case meta ';' '/usr/bin/false' '||' '&&' "a${bt}b" '<' '>' '/dev/null' '&' '*' '~' '#'

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
    grep -q "^R: tendcf: interlock 'demo-check' pre_action command\\[0\\] is not a normalized printable-ASCII absolute path without whitespace, quotes, or backslashes; refused" "$out"
check "relative command[0]: nothing was run" \
    bash -c "[ ! -e '$work/rel/ran' ]"

# 8e. Step 2 arglist via getvalues() (issue #56 item 1):
#     1-element command, spaces/leading-quotes/empty-string/metacharacters/12+
#     elements in arglist without ArgSplitCommand splitting, multi-interlock
#     isolation (distinct arg counts, duplicate commands even without -K,
#     non-zero expect_exit, and one bad interlock leaving other bundles clean).
#     Appends one JSON line per invocation so every test asserts exact call count.
json_recorder="$work/argv-json-recorder"
cat > "$json_recorder" <<'JREC'
#!/usr/bin/env python3
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
with open(out, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(sys.argv[2:]) + "\n")
JREC
chmod 700 "$json_recorder"

zero_recorder="$work/zero-recorder"
zero_count="$work/zero-recorder.count"
cat > "$zero_recorder" <<EOF
#!/usr/bin/env python3
import json, pathlib, sys
with open("$zero_count", "a", encoding="utf-8") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\n")
EOF
chmod 700 "$zero_recorder"

# 8e-1: 1-element command + multi-arg (spaces, leading quotes, backticks,
#       shell metacharacters, empty string, 12+ elements) + non-zero expect_exit
#       + bad-cmd0 sibling in one host_specific.json, run WITHOUT -K to also
#       prove duplicate-command interlocks both run cleanly.
rm -f "$zero_count" "$work/rec-meta.json" "$work/rec-12.json"
python3 - "$work/data/host_specific.json" "$zero_recorder" "$json_recorder" "$work/rec-meta.json" "$work/rec-12.json" <<'PYEOF'
import json, pathlib, sys
out_path, zero_rec, jrec, meta_out, twelve_out = sys.argv[1:6]
doc = {
    "vars": {
        "tendcf_interlock": {
            "zero-one": {
                "blocks": "enclosing-bundle",
                "bundle": "b-zero",
                "defines_class": "zero_one_ok",
                "pre_action": {"command": [zero_rec], "expect_exit": 0, "timeout_seconds": 5},
                "report": True,
                "state": "present",
            },
            "zero-two": {
                "blocks": "enclosing-bundle",
                "bundle": "b-zero-dup",
                "defines_class": "zero_two_ok",
                "pre_action": {"command": [zero_rec], "expect_exit": 0, "timeout_seconds": 5},
                "report": True,
                "state": "present",
            },
            "meta-args": {
                "blocks": "enclosing-bundle",
                "bundle": "b-meta",
                "defines_class": "meta_args_ok",
                "pre_action": {
                    "command": [
                        jrec,
                        meta_out,
                        "a b",
                        "hello   world",
                        "'x'",
                        '"y"',
                        "`bt`",
                        ";|&&",
                        "",
                        "--flag=k v",
                    ],
                    "expect_exit": 0,
                    "timeout_seconds": 5,
                },
                "report": True,
                "state": "present",
            },
            "twelve-args": {
                "blocks": "enclosing-bundle",
                "bundle": "b-twelve",
                "defines_class": "twelve_args_ok",
                "pre_action": {
                    "command": [jrec, twelve_out, "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"],
                    "expect_exit": 0,
                    "timeout_seconds": 5,
                },
                "report": True,
                "state": "present",
            },
            "exit-two": {
                "blocks": "enclosing-bundle",
                "bundle": "b-exit2",
                "defines_class": "exit_two_ok",
                "pre_action": {"command": ["/bin/sh", "-c", "exit 2"], "expect_exit": 2, "timeout_seconds": 5},
                "report": True,
                "state": "present",
            },
            "bad-sibling": {
                "blocks": "enclosing-bundle",
                "bundle": "b-blocked",
                "defines_class": "bad_sib_ok",
                "pre_action": {"command": ["true"], "expect_exit": 0, "timeout_seconds": 5},
                "report": True,
                "state": "present",
            },
        },
        "tendcf_service": {},
    }
}
pathlib.Path(out_path).write_text(json.dumps(doc), encoding="utf-8")
PYEOF
out="$work/arglist-multi.out"
rm -f "$work"/state/cf_lock.*
"$cf_agent" -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "arglist multi-interlock: policy completed" policy_completed "$out"
check "arglist multi-interlock: no CMDB cross-check refusal" no_crosscheck "$out"
check "arglist multi-interlock: both 1-element duplicate commands ran with 0 args (even without -K)" \
    python3 - "$zero_count" <<'PYEOF'
import json, pathlib, sys
lines = [json.loads(l) for l in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()]
assert lines == [[], []], f"expected two 0-arg calls, got {lines!r}"
PYEOF
check "arglist multi-interlock: spaces, quotes, backticks, metachars, and empty string preserved verbatim (1 call)" \
    python3 - "$work/rec-meta.json" <<'PYEOF'
import json, pathlib, sys
lines = [json.loads(l) for l in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()]
want = [["a b", "hello   world", "'x'", '"y"', "`bt`", ";|&&", "", "--flag=k v"]]
assert lines == want, f"got={lines!r} want={want!r}"
PYEOF
check "arglist multi-interlock: 12+ elements preserve exact numeric order (1 call)" \
    python3 - "$work/rec-12.json" <<'PYEOF'
import json, pathlib, sys
lines = [json.loads(l) for l in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()]
want = [[str(i) for i in range(12)]]
assert lines == want, f"got={lines!r} want={want!r}"
PYEOF
for ok_bundle in b-zero b-zero-dup b-meta b-twelve b-exit2; do
    check "arglist multi-interlock: satisfied bundle '$ok_bundle' not refused" \
        bash -c "! grep -q \"bundle '$ok_bundle' refused\" '$out'"
done
check "arglist multi-interlock: bad sibling refused by tendcf_interlock_run" \
    grep -q "^R: tendcf: interlock 'bad-sibling' pre_action command\\[0\\] is not a normalized printable-ASCII absolute path without whitespace, quotes, or backslashes; refused$" "$out"
check "arglist multi-interlock: bad sibling blocked its bundle only" \
    grep -q "tendcf: interlock 'bad-sibling' not satisfied, bundle 'b-blocked' refused" "$out"

# 8f. Bad command[0] (space, quotes, backticks, trailing slash, root, control
#     char, backslash, `.`/`..` segments, non-ASCII) and malformed command
#     shapes (empty list, missing command, scalar string, non-string elements)
#     all fail closed with zero executions, accurate reason, and blocked bundle.
for bad_case in space dquote squote backtick slash root ctrl backslash dotdot dot nonascii int_arg obj_arg empty_list missing_cmd scalar_cmd; do
    rm -f "$zero_count"
    python3 - "$work/data/host_specific.json" "$bad_case" "$zero_recorder" <<'PYEOF'
import json, pathlib, sys
out_path, case, zero_rec = sys.argv[1:4]
cases = {
    "space": ["/usr/bin/true arg"],
    "dquote": ['"/usr/bin/true"'],
    "squote": ["'/usr/bin/true'"],
    "backtick": ["`/usr/bin/true`"],
    "slash": ["/usr/bin/"],
    "root": ["/"],
    "ctrl": ["/usr/bin/tr\nue"],
    "backslash": ["/usr/bin/tr\\\\ue"],
    "dotdot": ["/usr/bin/../bin/true"],
    "dot": ["/usr/bin/./true"],
    "nonascii": ["/usr/bin/\u00a0true"],
    "int_arg": [zero_rec, 42],
    "obj_arg": [zero_rec, {"k": "v"}],
    "empty_list": [],
    "missing_cmd": None,
    "scalar_cmd": "/usr/bin/true",
}
pre = {"expect_exit": 0, "timeout_seconds": 5}
if cases[case] is not None:
    pre["command"] = cases[case]
doc = {
    "vars": {
        "tendcf_interlock": {
            "bad-chk": {
                "blocks": "enclosing-bundle",
                "bundle": "demo",
                "defines_class": "demo_ok",
                "pre_action": pre,
                "report": True,
                "state": "present",
            }
        },
        "tendcf_service": {},
    }
}
pathlib.Path(out_path).write_text(json.dumps(doc), encoding="utf-8")
PYEOF
    out="$work/arglist-bad-$bad_case.out"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "bad pre_action ($bad_case): policy completed" policy_completed "$out"
    check "bad pre_action ($bad_case): bundle refused" \
        grep -q "tendcf: interlock 'bad-chk' not satisfied, bundle 'demo' refused" "$out"
    check "bad pre_action ($bad_case): zero command executions" \
        bash -c "! grep -q 'Executing ' '$out' && [ ! -e '$zero_count' ]"
    case "$bad_case" in
        int_arg|obj_arg|empty_list|missing_cmd|scalar_cmd)
            check "bad pre_action ($bad_case): accurate command-shape refusal line" \
                grep -q "^R: tendcf: interlock 'bad-chk' pre_action command is missing or not a non-empty array of strings; refused$" "$out"
            ;;
        *)
            check "bad pre_action ($bad_case): accurate command[0] refusal line" \
                grep -q "^R: tendcf: interlock 'bad-chk' pre_action command\\[0\\] is not a normalized printable-ASCII absolute path without whitespace, quotes, or backslashes; refused$" "$out"
            ;;
    esac
done

# 8g. Issue #56 item 2 + R1 C2: hostile control characters (\n, \r, \x1b, \t)
#     in bracket-free interlock id are sanitized in BOTH tendcf_interlock_run
#     and tendcf_services_apply R: refusal lines (8g-1); hostile control
#     characters in interlock bundle fail closed across all service actuation
#     with sanitized R: report (8g-2).
python3 - "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = {
    "vars": {
        "tendcf_interlock": {
            "ilk\nR: INJECTED_ILK\r\x1bX\tid": {
                "blocks": "enclosing-bundle",
                "bundle": "demo",
                "defines_class": "ctrl_ok",
                "pre_action": {"command": ["true"], "expect_exit": 0, "timeout_seconds": 5},
                "report": True,
                "state": "present",
            }
        },
        "tendcf_service": {},
    }
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc), encoding="utf-8")
PYEOF
out="$work/interlock-ctrl-id.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "interlock ctrl-char id: policy completed" policy_completed "$out"
check "interlock ctrl-char id: no CMDB cross-check refusal" no_crosscheck "$out"
check "interlock ctrl-char id: sanitized R: lines with no raw ESC/CR/TAB or split lines" \
    python3 - "$out" <<'PYEOF'
import pathlib, re, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
assert b"\x1b" not in raw, f"raw ESC leaked: {raw!r}"
lines = raw.decode("utf-8", errors="replace").splitlines()
assert not any(line.startswith("R: INJECTED_") for line in lines), f"split R: line injected: {lines!r}"
r_lines = [line for line in lines if line.startswith("R:")]
for line in r_lines:
    assert "\r" not in line and "\t" not in line and "\x1b" not in line, f"control char in R: line: {line!r}"
cmd0_re = re.compile(r"^R: tendcf: interlock 'ilk\?R:\?INJECTED_ILK\?\?(?:u001b)?X\?id' pre_action command\[0\] is not a normalized printable-ASCII absolute path without whitespace, quotes, or backslashes; refused$")
blk_re = re.compile(r"^R: tendcf: interlock 'ilk\?R:\?INJECTED_ILK\?\?(?:u001b)?X\?id' not satisfied, bundle 'demo' refused$")
assert any(cmd0_re.match(line) for line in r_lines), f"sanitized command[0] refusal not found in {r_lines!r}"
assert any(blk_re.match(line) for line in r_lines), f"sanitized bundle refusal not found in {r_lines!r}"
PYEOF

# 8h. Issue #56 item 2 + R1 L2 + Codex NB2: bracketed ANSI CSI (\x1b[31m) in
#     interlock id fails closed across ALL services with sanitized R: report,
#     zero bracket errors, and zero LaunchAgents creation (with positive control
#     on Darwin proving the service would otherwise actuate).
python3 - "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = {
    "vars": {
        "tendcf_interlock": {
            "ilk\nR: INJECTED_CSI\r\x1b[31m\tid": {
                "blocks": "enclosing-bundle",
                "bundle": "demo",
                "defines_class": "csi_ok",
                "pre_action": {"command": ["/usr/bin/true"], "expect_exit": 0, "timeout_seconds": 5},
                "report": True,
                "state": "present",
            }
        },
        "tendcf_service": {
            "demo-runit": {
                "bundle": "other",
                "command": ["/bin/sleep", "1"],
                "run_as": "nobody",
                "state": "present",
                "unit": {"runit": {"enabled": True}},
                "working_dir": "/",
            }
        },
    }
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc), encoding="utf-8")
PYEOF
out="$work/interlock-ctrl-csi.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "interlock bracketed CSI id: policy completed" policy_completed "$out"
check "interlock bracketed CSI id: no Broken variable expression error" \
    bash -c "! grep -q 'Broken variable expression' '$out'"
check "interlock bracketed CSI id: nothing actuated and sibling service refused" \
    bash -c "! grep -Eq \"Executing|Created file|launchctl|systemctl|tendcf: service 'demo-runit'\" '$out'"
check "interlock bracketed CSI id: sanitized R: refusal line with no raw ESC or split line" \
    python3 - "$out" <<'PYEOF'
import pathlib, re, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
assert b"\x1b" not in raw, f"raw ESC leaked: {raw!r}"
lines = raw.decode("utf-8", errors="replace").splitlines()
assert not any(line.startswith("R: INJECTED_") for line in lines), f"split R: line injected: {lines!r}"
r_lines = [line for line in lines if line.startswith("R:")]
csi_re = re.compile(r"^R: tendcf: interlock 'ilk\?R:\?INJECTED_CSI\?\?(?:u001b)?\?31m\?id' id is empty, too long \(>128 chars\), or contains bracket characters; refusing all service actuation$")
assert any(csi_re.match(line) for line in r_lines), f"sanitized CSI refusal not found in {r_lines!r}"
PYEOF

# 8i. R1 C1 / Codex #1: colliding interlock IDs under canonify() (`a-b` vs `a.b`,
#     `a-b` vs `a_b`), >128-char interlock id, and empty `""` interlock id all
#     fail closed with zero executions, refusal report, and zero service actuation.
for col_case in col_fail col_invalid id_129 id_empty; do
    rm -f "$zero_count"
    python3 - "$work/data/host_specific.json" "$col_case" "$zero_recorder" <<'PYEOF'
import json, pathlib, sys
out_path, case, zero_rec = sys.argv[1:4]
if case == "col_fail":
    ilks = {
        "a-b": {"blocks": "enclosing-bundle", "bundle": "demo", "defines_class": "ab_ok", "pre_action": {"command": [zero_rec], "expect_exit": 0, "timeout_seconds": 5}, "report": True, "state": "present"},
        "a.b": {"blocks": "enclosing-bundle", "bundle": "demo", "defines_class": "ab2_ok", "pre_action": {"command": ["/usr/bin/false"], "expect_exit": 0, "timeout_seconds": 5}, "report": True, "state": "present"},
    }
elif case == "col_invalid":
    ilks = {
        "a-b": {"blocks": "enclosing-bundle", "bundle": "demo", "defines_class": "ab_ok", "pre_action": {"command": [zero_rec], "expect_exit": 0, "timeout_seconds": 5}, "report": True, "state": "present"},
        "a_b": {"blocks": "enclosing-bundle", "bundle": "demo", "defines_class": "ab2_ok", "pre_action": {"command": ["true"], "expect_exit": 0, "timeout_seconds": 5}, "report": True, "state": "present"},
    }
elif case == "id_129":
    ilks = {
        "i" * 129: {"blocks": "enclosing-bundle", "bundle": "demo", "defines_class": "l_ok", "pre_action": {"command": [zero_rec], "expect_exit": 0, "timeout_seconds": 5}, "report": True, "state": "present"},
    }
else:
    ilks = {
        "": {"blocks": "enclosing-bundle", "bundle": "demo", "defines_class": "e_ok", "pre_action": {"command": [zero_rec], "expect_exit": 0, "timeout_seconds": 5}, "report": True, "state": "present"},
    }
doc = {
    "vars": {
        "tendcf_interlock": ilks,
        "tendcf_service": {
            "demo-runit": {
                "bundle": "demo",
                "command": ["/bin/sleep", "1"],
                "run_as": "nobody",
                "state": "present",
                "unit": {"runit": {"enabled": True}},
                "working_dir": "/",
            }
        },
    }
}
pathlib.Path(out_path).write_text(json.dumps(doc), encoding="utf-8")
PYEOF
    out="$work/ilk-c1-$col_case.out"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "interlock C1 ($col_case): policy completed" policy_completed "$out"
    check "interlock C1 ($col_case): zero command executions and no sibling service processed" \
        bash -c "! grep -Eq \"Executing |tendcf: service 'demo-runit'\" '$out' && [ ! -e '$zero_count' ]"
    case "$col_case" in
        col_*)
            check "interlock C1 ($col_case): collision refusal reported" \
                grep -q "^R: tendcf: interlock actuation refused: two or more interlock ids collide under canonify(); refusing all service actuation until ids are canonically unique$" "$out"
            ;;
        *)
            check "interlock C1 ($col_case): malformed id refusal reported" \
                grep -q "id is empty, too long (>128 chars), or contains bracket characters; refusing all service actuation$" "$out"
            ;;
    esac
done

# 8j. R1 C2 / Codex #1: interlock bundle length (>= 1006 / > 128 chars),
#     missing, empty, array, integer, or control-char bundle fails closed across
#     all service actuation with zero executions and sanitized R: report.
for bcase in len_1010 len_129 missing empty array int ctrl; do
    rm -f "$zero_count"
    python3 - "$work/data/host_specific.json" "$bcase" "$zero_recorder" <<'PYEOF'
import json, pathlib, sys
out_path, case, zero_rec = sys.argv[1:4]
ilk = {
    "blocks": "enclosing-bundle",
    "defines_class": "b_ok",
    "pre_action": {"command": [zero_rec], "expect_exit": 0, "timeout_seconds": 5},
    "report": True,
    "state": "present",
}
if case == "len_1010":
    ilk["bundle"] = "b" * 1010
elif case == "len_129":
    ilk["bundle"] = "b" * 129
elif case == "empty":
    ilk["bundle"] = ""
elif case == "array":
    ilk["bundle"] = ["demo"]
elif case == "int":
    ilk["bundle"] = 42
elif case == "ctrl":
    ilk["bundle"] = "bnd\nR: INJECTED_BND\r\x1bX\tname"
doc = {
    "vars": {
        "tendcf_interlock": {"bad-bundle-ilk": ilk},
        "tendcf_service": {
            "demo-runit": {
                "bundle": "other",
                "command": ["/bin/sleep", "1"],
                "run_as": "nobody",
                "state": "present",
                "unit": {"runit": {"enabled": True}},
                "working_dir": "/",
            }
        },
    }
}
pathlib.Path(out_path).write_text(json.dumps(doc), encoding="utf-8")
PYEOF
    out="$work/ilk-c2-$bcase.out"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "interlock C2 bundle ($bcase): policy completed" policy_completed "$out"
    check "interlock C2 bundle ($bcase): zero executions and no sibling service processed" \
        bash -c "! grep -Eq \"Executing |tendcf: service 'demo-runit'\" '$out' && [ ! -e '$zero_count' ]"
    check "interlock C2 bundle ($bcase): malformed bundle refusal reported cleanly" \
        python3 - "$out" <<'PYEOF'
import pathlib, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
assert b"\x1b" not in raw, f"raw ESC leaked: {raw!r}"
lines = raw.decode("utf-8", errors="replace").splitlines()
assert not any(line.startswith("R: INJECTED_") for line in lines), f"split R: line injected: {lines!r}"
want = "R: tendcf: interlock 'bad-bundle-ilk' bundle is missing, non-string, or invalid ([A-Za-z0-9._:@/-]{1,128}); refusing all service actuation"
assert want in lines, f"expected {want!r} in {[l for l in lines if l.startswith('R:')]!r}"
PYEOF
done

# 8k. R1 H1 / Codex #3: strict JSON integer type and range validation for
#     timeout_seconds (1..3600) and expect_exit (0..255), including upper-bound
#     positive control (3600 / 255), spoofed string/command payloads, containers,
#     floats, 32-bit/64-bit overflows, and >64-bit integers with zero abort.
python3 - "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = {
    "vars": {
        "tendcf_interlock": {
            "meta-max": {
                "blocks": "enclosing-bundle",
                "bundle": "demo",
                "defines_class": "meta_max_ok",
                "pre_action": {"command": ["/bin/sh", "-c", "exit 255"], "expect_exit": 255, "timeout_seconds": 3600},
                "report": True,
                "state": "present",
            }
        },
        "tendcf_service": {},
    }
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc), encoding="utf-8")
PYEOF
out="$work/ilk-meta-bound-ok.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "interlock meta boundary (3600/255): policy completed" policy_completed "$out"
check "interlock meta boundary (3600/255): no CMDB cross-check refusal" no_crosscheck "$out"
check "interlock meta boundary (3600/255): interlock satisfied and bundle not refused" \
    bash -c "! grep -q \"bundle 'demo' refused\" '$out' && ! grep -q 'timeout_seconds (integer 1..3600)' '$out'"

for mcase in to_0 to_3601 to_u32max to_i64max to_huge_str to_arr to_str_spoof to_neg to_float to_missing ex_str_spoof ex_neg ex_256 ex_arr ex_float ex_missing; do
    rm -f "$zero_count"
    python3 - "$work/data/host_specific.json" "$mcase" "$zero_recorder" <<'PYEOF'
import json, pathlib, sys
out_path, case, zero_rec = sys.argv[1:4]
pre = {"command": [zero_rec], "expect_exit": 0, "timeout_seconds": 5}
if case == "to_0":
    pre["timeout_seconds"] = 0
elif case == "to_3601":
    pre["timeout_seconds"] = 3601
elif case == "to_u32max":
    pre["timeout_seconds"] = 4294967295
elif case == "to_i64max":
    pre["timeout_seconds"] = 9223372036854775807
elif case == "to_huge_str":
    pre["timeout_seconds"] = "99999999999999999999"
elif case == "to_arr":
    pre["timeout_seconds"] = [5]
elif case == "to_str_spoof":
    pre["command"] = [zero_rec, '\n  "timeout_seconds": 5,\n']
    pre["timeout_seconds"] = "5"
elif case == "to_neg":
    pre["timeout_seconds"] = -1
elif case == "to_float":
    pre["timeout_seconds"] = 1.5
elif case == "to_missing":
    del pre["timeout_seconds"]
elif case == "ex_str_spoof":
    pre["command"] = [zero_rec, '\n  "expect_exit": 0,\n']
    pre["expect_exit"] = "0"
elif case == "ex_neg":
    pre["expect_exit"] = -1
elif case == "ex_256":
    pre["expect_exit"] = 256
elif case == "ex_arr":
    pre["expect_exit"] = [0]
elif case == "ex_float":
    pre["expect_exit"] = 0.5
elif case == "ex_missing":
    del pre["expect_exit"]
doc = {
    "vars": {
        "tendcf_interlock": {
            "meta-bad": {
                "blocks": "enclosing-bundle",
                "bundle": "demo",
                "defines_class": "meta_bad_ok",
                "pre_action": pre,
                "report": True,
                "state": "present",
            }
        },
        "tendcf_service": {},
    }
}
pathlib.Path(out_path).write_text(json.dumps(doc), encoding="utf-8")
PYEOF
    out="$work/ilk-meta-$mcase.out"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "interlock meta ($mcase): policy completed (zero abort)" policy_completed "$out"
    check "interlock meta ($mcase): metadata refusal reported" \
        grep -q "^R: tendcf: interlock 'meta-bad' pre_action timeout_seconds (integer 1\\.\\.3600) or expect_exit (integer 0\\.\\.255) is missing or invalid; refused$" "$out"
    check "interlock meta ($mcase): bundle refused" \
        grep -q "tendcf: interlock 'meta-bad' not satisfied, bundle 'demo' refused" "$out"
    check "interlock meta ($mcase): zero command executions" \
        bash -c "! grep -q 'Executing ' '$out' && [ ! -e '$zero_count' ]"
done

# Bare JSON integer 99999999999999999999 (>UINT64_MAX): on the pinned fork it
# loads cleanly and policy refuses it cleanly; on unpatched builds without
# libntech B-4/B-10 JsonParseFile exits fail-closed before policy runs. Either
# way, ZERO command execution is permitted.
rm -f "$zero_count"
printf '{"vars":{"tendcf_interlock":{"meta-huge":{"blocks":"enclosing-bundle","bundle":"demo","defines_class":"huge_ok","pre_action":{"command":["%s"],"expect_exit":0,"timeout_seconds":99999999999999999999},"report":true,"state":"present"}},"tendcf_service":{}}}\n' \
    "$zero_recorder" > "$work/data/host_specific.json"
out="$work/ilk-meta-to_huge_int.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "interlock meta (to_huge_int): zero command executions (fail-closed)" \
    bash -c "! grep -q 'Executing ' '$out' && [ ! -e '$zero_count' ]"

# 8l. R1 M1: sanitize all file-derived fields in tendcf_services_apply R:
#     reports (service_ids, unit_flavour, run_as) and fail closed on empty or
#     bracketed service_ids with zero `Broken variable expression` flood.
python3 - "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = {
    "vars": {
        "tendcf_interlock": {},
        "tendcf_service": {
            "svc\nR: INJECTED_SVC\r\x1bX\tid": {
                "bundle": "demo",
                "command": ["/bin/sleep", "1"],
                "run_as": "u\nR: INJECTED_RUNAS\r\x1bX\tx",
                "state": "present",
                "unit": {"fl\nR: INJECTED_FLV\r\x1bX\tname": {"enabled": True}},
                "working_dir": "/",
            }
        },
    }
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc), encoding="utf-8")
PYEOF
out="$work/svc-m1-ctrl.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "service M1 ctrl fields: policy completed" policy_completed "$out"
check "service M1 ctrl fields: sanitized service_id and unit_flavour with no raw ESC/CR/TAB or split lines" \
    python3 - "$out" <<'PYEOF'
import pathlib, re, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
assert b"\x1b" not in raw, f"raw ESC leaked: {raw!r}"
lines = raw.decode("utf-8", errors="replace").splitlines()
assert not any(line.startswith("R: INJECTED_") for line in lines), f"split R: line injected: {lines!r}"
r_lines = [line for line in lines if line.startswith("R:")]
for line in r_lines:
    assert "\r" not in line and "\t" not in line and "\x1b" not in line, f"control char in R: line: {line!r}"
svc_re = re.compile(r"^R: tendcf: service 'svc\?R:\?INJECTED_SVC\?\?(?:u001b)?X\?id' refused: unit flavour 'fl\?R:\?INJECTED_FLV\?\?(?:u001b)?X\?name' is not implemented on this host ")
assert any(svc_re.match(line) for line in r_lines), f"sanitized service refusal not found in {r_lines!r}"
PYEOF

for bsvc in bracket empty; do
    python3 - "$work/data/host_specific.json" "$bsvc" <<'PYEOF'
import json, pathlib, sys
out_path, kind = sys.argv[1:3]
bad_id = "svc\nR: INJECTED_BKT\r\x1b[31m\tid" if kind == "bracket" else ""
doc = {
    "vars": {
        "tendcf_interlock": {},
        "tendcf_service": {
            bad_id: {
                "bundle": "demo",
                "command": ["/bin/sleep", "1"],
                "run_as": "nobody",
                "state": "present",
                "unit": {"runit": {"enabled": True}},
                "working_dir": "/",
            },
            "sibling-runit": {
                "bundle": "other",
                "command": ["/bin/sleep", "1"],
                "run_as": "nobody",
                "state": "present",
                "unit": {"runit": {"enabled": True}},
                "working_dir": "/",
            },
        },
    }
}
pathlib.Path(out_path).write_text(json.dumps(doc), encoding="utf-8")
PYEOF
    out="$work/svc-m1-$bsvc.out"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "service M1 ($bsvc id): policy completed" policy_completed "$out"
    check "service M1 ($bsvc id): no Broken variable expression error" \
        bash -c "! grep -q 'Broken variable expression' '$out'"
    check "service M1 ($bsvc id): sibling service not processed" \
        bash -c "! grep -Eq \"Executing|Created file|launchctl|systemctl|tendcf: service 'sibling-runit'\" '$out'"
    check "service M1 ($bsvc id): sanitized refusal line with no raw ESC/CR/TAB or split lines" \
        python3 - "$out" "$bsvc" <<'PYEOF'
import pathlib, re, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
kind = sys.argv[2]
assert b"\x1b" not in raw, f"raw ESC leaked: {raw!r}"
lines = raw.decode("utf-8", errors="replace").splitlines()
assert not any(line.startswith("R: INJECTED_") for line in lines), f"split R: line injected: {lines!r}"
r_lines = [line for line in lines if line.startswith("R:")]
if kind == "bracket":
    pat = re.compile(r"^R: tendcf: service 'svc\?R:\?INJECTED_BKT\?\?(?:u001b)?\?31m\?id' id is empty or contains bracket characters; refusing all service actuation$")
else:
    pat = re.compile(r"^R: tendcf: service '' id is empty or contains bracket characters; refusing all service actuation$")
assert any(pat.match(line) for line in r_lines), f"sanitized malformed service id refusal not found in {r_lines!r}"
PYEOF
done

# 8m. Darwin real-actuation positive controls for R1 L2 / Codex NB2 / M1:
#     (1) positive control without bad interlock/service creates LaunchAgents,
#         renders plist, and bootstraps;
#     (2) with bracketed CSI interlock id, colliding interlock id, 1010-char
#         interlock bundle, or bracketed service id, LaunchAgents is NOT
#         created and launchctl is NEVER called;
#     (3) hostile run_as on a valid launchd service id is sanitized in R: report.
if [ "$(uname -s)" = Darwin ]; then
    for r1_gate_case in pos_control csi_ilk col_ilk bundle_1010 bracket_svc; do
        r1_home="$work/r1-home-$r1_gate_case"
        mkdir -p "$r1_home/Library"
        cat > "$work/inputs/r1-gate-$r1_gate_case.cf" <<EOF
body common control
{
      inputs => { "$repo/policy/tendcf_services.cf", "$repo/tests/policy/fixtures/test-done.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_test_r1_gate", "tendcf_test_done" };
}
bundle agent tendcf_test_r1_gate
{
  vars:
      "service_raw_ids" slist => getindices("data:variables.tendcf_service");
      "service_safe_ids" slist => grep("(?s)^[^\[\]]+$", "service_raw_ids");
      "service_unsafe_ids" slist => difference("service_raw_ids", "service_safe_ids");
  classes:
      "tendcf_service_id_malformed"
        expression => isgreaterthan(length("service_unsafe_ids"), 0),
        scope => "namespace";
  methods:
      "ensure"
        usebundle => tendcf_ensure_user_launchagents("$r1_home", "$test_user");
      "apply"
        usebundle => tendcf_services_apply("user", "$r1_home/Library/LaunchAgents", "$launchctl_stub", "$test_user", "$test_gid", "$test_user", "$test_uid");
}
EOF
        python3 - "$work/data/host_specific.json" "$r1_gate_case" "$test_user" <<'PYEOF'
import json, pathlib, sys
out_path, case, user = sys.argv[1:4]
ilks = {}
svcs = {
    "com.tendcf.r1.gate": {
        "bundle": "demo",
        "command": ["/usr/bin/true"],
        "run_as": user,
        "state": "present",
        "unit": {"launchd": {"domain": "user-gui", "keep_alive": False, "run_at_load": True}},
        "working_dir": "/tmp",
    }
}
if case == "csi_ilk":
    ilks["ilk\x1b[31m"] = {"blocks": "enclosing-bundle", "bundle": "other", "defines_class": "ok1", "pre_action": {"command": ["/usr/bin/true"], "expect_exit": 0, "timeout_seconds": 5}, "report": True, "state": "present"}
elif case == "col_ilk":
    ilks["a-b"] = {"blocks": "enclosing-bundle", "bundle": "other", "defines_class": "ok1", "pre_action": {"command": ["/usr/bin/true"], "expect_exit": 0, "timeout_seconds": 5}, "report": True, "state": "present"}
    ilks["a.b"] = {"blocks": "enclosing-bundle", "bundle": "other", "defines_class": "ok2", "pre_action": {"command": ["/usr/bin/false"], "expect_exit": 0, "timeout_seconds": 5}, "report": True, "state": "present"}
elif case == "bundle_1010":
    ilks["long-bnd"] = {"blocks": "enclosing-bundle", "bundle": "b" * 1010, "defines_class": "ok1", "pre_action": {"command": ["/usr/bin/true"], "expect_exit": 0, "timeout_seconds": 5}, "report": True, "state": "present"}
elif case == "bracket_svc":
    svcs["svc\x1b[31m"] = {"bundle": "other", "command": ["/usr/bin/true"], "run_as": user, "state": "present", "unit": {"launchd": {"domain": "user-gui", "keep_alive": False, "run_at_load": True}}, "working_dir": "/tmp"}
pathlib.Path(out_path).write_text(json.dumps({"vars": {"tendcf_interlock": ilks, "tendcf_service": svcs}}), encoding="utf-8")
PYEOF
        : > "$launchctl_log"
        rm -f "$launchctl_state/gui.com.tendcf.r1.gate" "$launchctl_state/user.com.tendcf.r1.gate"
        out="$work/r1-gate-$r1_gate_case.out"
        "$cf_agent" -K -I -f "$work/inputs/r1-gate-$r1_gate_case.cf" >"$out" 2>&1 || true
        check "Darwin R1 gate ($r1_gate_case): policy completed" policy_completed "$out"
        if [ "$r1_gate_case" = pos_control ]; then
            check "Darwin R1 gate (pos_control): LaunchAgents created and plist rendered" \
                bash -c "[ -d '$r1_home/Library/LaunchAgents' ] && [ -f '$r1_home/Library/LaunchAgents/com.tendcf.r1.gate.plist' ]"
            check "Darwin R1 gate (pos_control): launchctl bootstrap ran" \
                grep -q "bootstrap	gui/$test_uid	$r1_home/Library/LaunchAgents/com.tendcf.r1.gate.plist" "$launchctl_log"
        else
            check "Darwin R1 gate ($r1_gate_case): LaunchAgents NOT created" \
                bash -c "[ ! -e '$r1_home/Library/LaunchAgents' ]"
            check "Darwin R1 gate ($r1_gate_case): zero launchctl calls" \
                bash -c "[ ! -s '$launchctl_log' ]"
        fi
    done

    # Hostile run_as sanitization on a valid launchd service id
    python3 - "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = {
    "vars": {
        "tendcf_interlock": {},
        "tendcf_service": {
            "com.tendcf.r1.badrunas": {
                "bundle": "demo",
                "command": ["/usr/bin/true"],
                "run_as": "u\nR: INJECTED_RUNAS\r\x1b[31m\tx",
                "state": "present",
                "unit": {"launchd": {"domain": "user-gui", "keep_alive": False, "run_at_load": True}},
                "working_dir": "/tmp",
            }
        },
    }
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc), encoding="utf-8")
PYEOF
    : > "$launchctl_log"
    out="$work/r1-m1-runas.out"
    "$cf_agent" -K -I -f "$work/inputs/launchd-user-harness.cf" >"$out" 2>&1 || true
    check "Darwin M1 hostile run_as: policy completed" policy_completed "$out"
    check "Darwin M1 hostile run_as: zero launchctl calls" bash -c "[ ! -s '$launchctl_log' ]"
    check "Darwin M1 hostile run_as: sanitized R: report with no raw ESC/CR/TAB or split lines" \
        python3 - "$out" "$test_user" <<'PYEOF'
import pathlib, re, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
user = sys.argv[2]
assert b"\x1b" not in raw, f"raw ESC leaked: {raw!r}"
lines = raw.decode("utf-8", errors="replace").splitlines()
assert not any(line.startswith("R: INJECTED_") for line in lines), f"split R: line injected: {lines!r}"
r_lines = [line for line in lines if line.startswith("R:")]
for line in r_lines:
    assert "\r" not in line and "\t" not in line and "\x1b" not in line, f"control char in R: line: {line!r}"
pat = re.compile(r"^R: tendcf: service 'com\.tendcf\.r1\.badrunas' refused: user-domain service run_as 'u\?R:\?INJECTED_RUNAS\?\?(?:u001b)?\?31m\?x' does not match running user '" + re.escape(user) + r"'$")
assert any(pat.match(line) for line in r_lines), f"sanitized run_as refusal not found in {r_lines!r}"
PYEOF
fi

echo "# 9. CMDB cross-check, the agent's real loader"
cp "$repo/tests/policy/fixtures/interlock-malformed.json" "$work/data/host_specific.json"
out="$work/xc-malformed.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "malformed interlock: refusal reported" refusal_reported "$out"
check "malformed interlock: the container the loader did not install is named" \
    key_not_loaded "$out" tendcf_interlock
# All-or-nothing: the valid sibling container is not installed either (the
# pre-R13 fork installed it, which was the fail-open; the Mac dev build rejects
# the whole `vars`, so it agrees).
fork_only "malformed interlock: the sibling tendcf_service is not installed either (all-or-nothing)" \
    key_not_loaded "$out" tendcf_service
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

# A `variables` section naming `tendcf_interlock` again, with a pre_action that
# passes (the file's own vars say /usr/bin/false). The fork at the pin refuses the
# whole file: two entries naming one variable are a duplicate (cmdb.c
# CMDBPendingCheckNoDuplicates, fork commit 61065e551), so the loader logs the
# duplicate, installs none of the file and the policy sees every `vars` key
# missing. (A loader that applied `variables` after `vars` and replaced the
# container, as upstream CFEngine does, would leave the same ids with another
# command; that content difference is the cross-check's whole-container
# comparison, tested in check 10 against the stand-in loader, "service|interlock
# value changed under the same id", and in check 11 against a replaced file.)
cp "$repo/tests/policy/fixtures/cmdb-variables-collision.json" "$work/data/host_specific.json"
out="$work/xc-collision.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "variables-section collision: refusal reported" refusal_reported "$out"
fork_only "variables-section collision: the loader refuses the duplicate variable" \
    grep -q "Invalid variable specification in CMDB data: 'tendcf_interlock' names the variable 'data:variables.tendcf_interlock' that another entry names too" "$out"
fork_only "variables-section collision: the loader installs none of the file" \
    grep -q "installing none of its contents" "$out"
fork_only "variables-section collision: tendcf_interlock is reported not installed" \
    key_not_loaded "$out" tendcf_interlock
fork_only "variables-section collision: nothing was loaded to differ in content" \
    bash -c "! grep -q 'content differs' '$out'"
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
for k in default:tendcf_interlocks.interlock_ids default:tendcf_services_apply.interlock_ids default:tendcf_services_apply.service_ids; do
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
check "scoped-key preset (control): the loader installed default:tendcf_services_apply.service_ids" \
    bash -c "grep 'default:tendcf_services_apply.service_ids' '$work/xc-preset-vars.out' | grep -q demo-runit"

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

# A key that is a plain identifier longer than 64 characters (issue #60 I1 / I1
# extended, Astra round 3 A2): `safe_keys` and `tendcf_cmdb_problem_foreign_var`
# bound identifier keys to `[A-Za-z0-9_]{1,64}` so per-key class names stay at
# most 98 chars (well below EvalContextClassPutTagsSet's 1024-char limit).
# Boundary check: 64 chars passes with no refusal and actuates normally;
# 65, 70 and 995 chars (the L >= 994 silent-drop window of I1 extended) trip
# `tendcf_cmdb_problem_badkey`, `tendcf_cmdb_problem_foreign_var` and
# `tendcf_cmdb_refused` with zero actuation and report only the first 64 chars.
key64="$(printf 'k%.0s' $(seq 1 64))"
printf '{"vars":{"tendcf_interlock":{"demo-check":{"blocks":"enclosing-bundle","bundle":"demo","defines_class":"demo_ok","pre_action":{"command":["/usr/bin/true"],"expect_exit":0,"timeout_seconds":5},"report":true,"state":"present"}},"tendcf_service":{},"%s":{}}}\n' "$key64" >"$work/data/host_specific.json"
out="$work/xc-key64.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "64-char vars key (boundary): no cross-check refusal" no_crosscheck "$out"
check "64-char vars key (boundary): actuates normally (pre_action ran)" \
    grep -q "Executing .*'/usr/bin/true'" "$out"

for key_len in 65 70 995; do
    long_key="$(printf 'k%.0s' $(seq 1 "$key_len"))"
    long_head="${long_key:0:64}"
    printf '{"vars":{"tendcf_interlock":{"demo-check":{"blocks":"enclosing-bundle","bundle":"demo","defines_class":"demo_ok","pre_action":{"command":["/usr/bin/true"],"expect_exit":0,"timeout_seconds":5},"report":true,"state":"present"}},"tendcf_service":{},"%s":{}}}\n' "$long_key" >"$work/data/host_specific.json"
    out="$work/xc-longkey-$key_len.out"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    check "long key ($key_len chars): refusal reported" refusal_reported "$out"
    check "long key ($key_len chars): refusal reported once" refusal_once "$out"
    check "long key ($key_len chars): badkey report shows first 64 chars" \
        grep -q "key '$long_head' under 'vars' in .* is not a plain identifier (\[A-Za-z0-9_\]{1,64}" "$out"
    check "long key ($key_len chars): foreign_var reported symmetrically" foreign_var_reported "$out"
    check "long key ($key_len chars): no report line shows more than 64 chars of it" \
        bash -c "! grep -q 'key .${long_head}[A-Za-z0-9_]' '$out'"
    check "long key ($key_len chars): nothing actuated" no_actuation "$out"
done

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
# Issue #59: installed cf-agent entry points also pass `--no-augments` so
# def.json is never loaded at all, while tendcf_cmdb keeps its
# `source=augments_file` refusal guard as defense in depth.
cp "$repo/tests/policy/fixtures/interlock-refused.json" "$work/data/host_specific.json"
printf '%s\n' '{"classes":{"interlock_ok_demo_check":["any"]},"vars":{"probe":"x"}}' >"$work/inputs/def.json"
out="$work/xc-augments.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "augments: refusal reported" refusal_reported "$out"
check "augments: the foreign variable is reported" foreign_var_reported "$out"
check "augments: the foreign class is reported" foreign_class_reported "$out"
check "augments: nothing actuated (the class would have unblocked the bundle)" no_actuation "$out"

out="$work/xc-no-augments.out"
"$cf_agent" --no-augments -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
rm -f "$work/inputs/def.json"
check "augments with --no-augments: policy completed" policy_completed "$out"
check "augments with --no-augments: def.json not loaded (no CMDB cross-check refusal)" no_crosscheck "$out"
check "augments with --no-augments: def.json class did not unblock the failing interlock" \
    grep -q "tendcf: interlock 'demo-check' not satisfied, bundle 'demo' refused" "$out"
check "augments with --no-augments: nothing rendered and no launchctl/systemctl" no_render_start "$out"

# Hostile control-character report sanitization fixture (issue #59 item 1):
# real control characters (\n, \r, \x1b ESC, \t) inside a refused vars key
# (`bad_keys` / `missing_keys`) and a refused top-level section name
# (`extra_sections`). Both must trip tendcf_cmdb_refused with zero actuation,
# and raw stdout/stderr must contain NO raw ESC (\x1b) and NO split/injected R:
# line — every control char must become `?` on the single R: report line.
python3 - "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = {
    "vars": {
        "tendcf_interlock": {
            "demo-check": {
                "blocks": "enclosing-bundle",
                "bundle": "demo",
                "defines_class": "demo_ok",
                "pre_action": {"command": ["/usr/bin/true"], "expect_exit": 0, "timeout_seconds": 5},
                "report": True,
                "state": "present",
            }
        },
        "tendcf_service": {},
        "bad\nR: INJECTED_KEY\r\x1b[31m\tkey": {},
    },
    "sec\nR: INJECTED_SEC\r\x1b[31m\tname": {},
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc), encoding="utf-8")
PYEOF
out="$work/xc-ctrl-keysec.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "hostile control chars (bad_keys + extra_sections): refusal reported" refusal_reported "$out"
check "hostile control chars (bad_keys + extra_sections): refusal reported once" refusal_once "$out"
check "hostile control chars (bad_keys + extra_sections): nothing actuated" no_actuation "$out"
check "hostile control chars (bad_keys + extra_sections): no raw ESC, no split R: line, sanitized markers present" \
    python3 - "$out" <<'PYEOF'
import pathlib, re, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
marker = b"R: tendcf: CMDB cross-check failed: refusing to actuate anything"
pos = raw.find(marker)
assert pos != -1, f"refusal summary not found in output: {raw!r}"
report_raw = raw[pos:]
assert b"\x1b" not in report_raw, f"raw ESC byte leaked in report block: {report_raw!r}"
assert b"\r" not in report_raw, f"raw CR byte leaked in report block: {report_raw!r}"
assert b"\t" not in report_raw, f"raw TAB byte leaked in report block: {report_raw!r}"
report_lines = report_raw.decode("utf-8", errors="replace").splitlines()
assert all(
    line.startswith(("R: tendcf: CMDB cross-check", "R: tendcf-test-done:"))
    for line in report_lines
), f"unexpected or split line inside report block: {report_lines!r}"
# Note: \u001b decodes to 0x1b on the B-13 fork (one `?`) and stays `\u001b` on
# non-B-13 builds (`?u001b`), so match either sanitized form on the single R: line.
key_re = re.compile(r"^R: tendcf: CMDB cross-check: key 'bad\?R:\?INJECTED_KEY\?\?(?:u001b)?\?31m\?key' under 'vars'")
missing_re = re.compile(r"^R: tendcf: CMDB cross-check: key 'bad\?R:\?INJECTED_KEY\?\?(?:u001b)?\?31m\?key' is under 'vars' in .* but CFEngine did not load")
sec_re = re.compile(r"^R: tendcf: CMDB cross-check: .* has top-level section 'sec\?R:\?INJECTED_SEC\?\?(?:u001b)?\?31m\?name' besides 'vars'")
assert any(key_re.search(line) for line in report_lines), f"sanitized bad_keys line not found in: {report_lines!r}"
assert any(missing_re.search(line) for line in report_lines), f"sanitized missing_keys line not found in: {report_lines!r}"
assert any(sec_re.search(line) for line in report_lines), f"sanitized extra_sections line not found in: {report_lines!r}"
PYEOF

# Positive control (review B3): a `vars` container that is a list of strings
# round-trips through the loader's slist, so it is accepted and the run actuates.
printf '%s\n' '{"vars":{"tendcf_interlock":{"demo-check":{"blocks":"enclosing-bundle","bundle":"demo","defines_class":"demo_ok","pre_action":{"command":["/usr/bin/true"],"expect_exit":0,"timeout_seconds":5},"report":true,"state":"present"}},"tendcf_service":{},"plain_strings":["a","b"]}}' >"$work/data/host_specific.json"
out="$work/xc-strlist.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "list of strings in vars: no cross-check report" no_crosscheck "$out"
check "list of strings in vars: actuates normally (the pre_action ran)" \
    grep -q "Executing .*'/usr/bin/true'" "$out"

echo "# 9b. the real loader's strict parse and class handling (fork 4443504), policy level"
# What the pinned loader does with each file is read from libpromises/cmdb.c at
# 4443504 (line numbers there), and each case asserts it. The cross-check's
# refusal and the absence of actuation are asserted unconditionally only where
# the policy refuses on its own (class-space, class-exists: a `classes` section)
# or where nothing can actuate (the empty-view controls). For a repeated member,
# a repeated `vars` and trailing input they are loader+policy integration
# assertions (strict_case POLICY=fork): a lenient loader and the lenient readjson
# see the same surviving data, the cross-check has nothing to refuse, and the
# interlock or the service guard acts, so they SKIP on a non-fork loader.
# Where the loader refuses the file, `key_not_loaded` reports each key of the
# file the cross-check could read: it reads with readjson, which stays lenient,
# so after a repeated member or a repeated `vars` section it sees the LAST one
# only, and an earlier container (here the interlock of case b) is not named.
# That is the limit of the cross-check's independence from the loader's parser.
# POLICY is `any` when the cross-check refuses on any loader (the file has a
# `classes` section, which it refuses on its own), `fork` when the refusal and
# the absence of actuation depend on the strict loader: a lenient loader and the
# lenient readjson read the same surviving member, section or prefix, so the
# cross-check sees no difference, and the interlock (whose pre_action fails) or
# the service's own guard actuates or reports. Those are loader+policy
# integration assertions and SKIP on a non-fork loader.
strict_case() {  # strict_case NAME FIXTURE LOADER-ERROR-PATTERN INSTALL-NONE POLICY LENIENT-LINE KEY...
    local name="$1" fixture="$2" pattern="$3" none="$4" policy="$5" lenient="$6"; shift 6
    case "$policy" in
        any|fork) ;;
        *) echo "strict_case $name: bad POLICY '$policy' (any|fork)" >&2; exit 2 ;;
    esac
    local pcheck=check
    [ "$policy" = fork ] && pcheck=fork_only
    out="$work/strict-$name.out"
    cp "$repo/tests/policy/fixtures/$fixture" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    # Same output file, any loader: this run evaluated both tendcf bundles (the
    # test-only marker bundle runs after them). The marker ensures the negative
    # greps below cannot pass on an invocation that never reached the policy.
    check "$name: this run evaluated the policy to the end (test-only marker)" policy_completed "$out"
    "$pcheck" "$name: the policy refuses and reports it" refusal_reported "$out"
    "$pcheck" "$name: the policy reports it once" refusal_once "$out"
    fork_only "$name: the loader refuses the file" grep -q "$pattern" "$out"
    if [ "$none" = yes ]; then
        fork_only "$name: the loader installs none of the file" \
            grep -q "installing none of its contents" "$out"
    fi
    local k
    for k in "$@"; do
        fork_only "$name: $k reported not installed" key_not_loaded "$out" "$k"
    done
    "$pcheck" "$name: nothing actuated (no service, no interlock, no render)" no_actuation "$out"
    # On any loader: nothing rendered and nothing started (a plain `check`, so a
    # non-fork run still asserts a safety property for the fork-only cases)
    check "$name: nothing rendered, nothing started" no_render_start "$out"
    # A lenient loader (not the fork's) keeps the last member / the last `vars` /
    # the document before the trailing input and the policy acts on it: the
    # expected line is the one a run on that data prints (LENIENT-LINE, a grep
    # pattern; `-` for none, where the policy refuses on any loader).
    if [ "$lenient" != - ]; then
        lenient_only "$name: the lenient loader's data reaches the policy: $lenient" \
            grep -q "$lenient" "$out"
    fi
    probe "$fixture" "$work/probe-strict-$name.out"
    fork_only "$name: no tendcf_interlock variable" \
        grep -q "cmdb-probe: tendcf_interlock absent" "$work/probe-strict-$name.out"
    fork_only "$name: no tendcf_service variable" \
        grep -q "cmdb-probe: tendcf_service absent" "$work/probe-strict-$name.out"
}
# What a LENIENT loader's data makes the policy print (derived from the fixtures
# and policy/tendcf_services.cf reports, not run on a lenient build): a repeated
# member and trailing input leave the valid interlock whose pre_action fails (the
# line check 2 asserts for the same entry); a repeated `vars` leaves only the
# runit service, refused by name on every host (check 4).
interlock_line="tendcf: interlock 'demo-check' not satisfied, bundle 'demo' refused"
runit_line="tendcf: service 'demo-runit' refused: unit flavour 'runit' is not implemented on this host"
dup_member="Could not parse JSON file .*host_specific\\.json: Unwilling to parse json data with a duplicate object member"
# (a) a repeated member: an invalid earlier value (null), then a valid interlock.
# The lenient parser keeps the last (valid) one; the strict parse the loader reads
# with (cmdb.c:73-96 ReadJsonFileMode, :1185-1191) refuses the file before any
# validation, so the first value is no longer discarded unseen.
strict_case dup-member loader-dup-member.json "$dup_member" no fork "$interlock_line" tendcf_interlock tendcf_service
# (b) `vars` twice at the top level, the later one without the interlock
strict_case dup-vars loader-dup-vars.json "$dup_member" no fork "$runit_line" tendcf_service
# (c) a complete valid document, then more input (the lenient parser stops after
# the first document and ignores the rest)
strict_case trailing loader-trailing.json \
    "Could not parse JSON file .*host_specific\\.json: Unwilling to parse json data with trailing non-whitespace characters" \
    no fork "$interlock_line" tendcf_interlock tendcf_service
# (d) a default-namespace class whose name is whitespace only: refused in
# validation (CheckCMDBClassName, cmdb.c:790-), so nothing is installed, where it
# used to reach insertion, fail, and be taken for "a class that exists already"
strict_case class-space loader-class-space.json \
    "Invalid CMDB class 'default: ': the class name starts or ends with whitespace" yes any - \
    tendcf_interlock tendcf_service
check "class-space: the classes section is named by the policy" \
    grep -q "has top-level section 'classes' besides 'vars'" "$out"

# (e) a class that exists already, beside good vars. The loader leaves it as it
# is and goes on (InstallCMDBPending, cmdb.c:1109-1116: CMDBClassExists by
# canonical identity, logged at VERBOSE only), so both containers are installed;
# the policy refuses all the same, for the `classes` section. `linux` is a hard
# class on the Linux legs (`darwin` on a Mac), set before the loader runs
# (generic_agent.c:1234); a CMDB class of a name that is taken is not installed,
# so it is not reported as a class the CMDB defined.
hardclass=linux
[ "$(uname)" = Darwin ] && hardclass=darwin
exists_json=$(cat "$repo/tests/policy/fixtures/loader-class-exists.json")
printf '%s\n' "${exists_json//default:linux/default:$hardclass}" >"$work/data/host_specific.json"
out="$work/strict-class-exists.out"
"$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
check "class-exists: the policy refuses and reports it" refusal_reported "$out"
check "class-exists: the policy reports it once" refusal_once "$out"
check "class-exists: the classes section is named by the policy" \
    grep -q "has top-level section 'classes' besides 'vars'" "$out"
check "class-exists: nothing actuated" no_actuation "$out"
fork_only "class-exists: the loader did not fail on the existing class" \
    bash -c "! grep -q 'Failed to add CMDB class' '$out'"
fork_only "class-exists: the loader did not refuse the rest of the file" \
    bash -c "! grep -q 'installing none of its contents' '$out'"
fork_only "class-exists: the good variables were installed" \
    bash -c "! grep -q 'but CFEngine did not load' '$out'"
fork_only "class-exists: the existing class was not redefined by the CMDB" \
    bash -c "! grep -q 'defined a class' '$out'"

# (f) empty-view controls (Astra r2 C1, adversary r2 I1). The strict loader refuses
# each file, but the lenient readjson the cross-check reads with sees an EMPTY
# `vars` (the last of two, or the prefix before the trailing input), the same as
# `{"vars":{}}` in check 9: nothing is installed, nothing actuates, and the
# cross-check has nothing to report. So there is no refusal report here, and none
# is claimed: the loader's own ERR is the only trace. On any loader the file is
# empty or lenient-empty, so no report and no actuation hold everywhere; only the
# loader's refusal is fork-only.
for spec in "empty-dup-vars:loader-empty-dup-vars.json:Unwilling to parse json data with a duplicate object member" \
            "empty-trailing:loader-empty-trailing.json:Unwilling to parse json data with trailing non-whitespace characters"; do
    name=${spec%%:*}; rest=${spec#*:}; fixture=${rest%%:*}; pattern=${rest#*:}
    out="$work/strict-$name.out"
    cp "$repo/tests/policy/fixtures/$fixture" "$work/data/host_specific.json"
    "$cf_agent" -K -I -f "$work/inputs/entry.cf" >"$out" 2>&1 || true
    # Positive control, same output file as the two negative greps below: the
    # test-only marker bundle that entry.cf runs after tendcf_interlocks and
    # tendcf_services reported, so THIS invocation evaluated the policy to the
    # end (on the fork too: the loader's refusal only logs ERR, generic_agent.c:1234
    # at 4443504, and evaluation goes on). Without it a run that died before its
    # policy would pass both negatives. (Astra r1 / adversary r1 on PR 61.)
    check "$name: this run evaluated the policy to the end (test-only marker)" policy_completed "$out"
    check "$name: the lenient view is empty, so no cross-check report" no_crosscheck "$out"
    check "$name: nothing actuated" no_actuation "$out"
    # The probe is a SECOND cf-agent process running cmdb-probe.cf only, not the
    # tendcf bundles. It proves what the data loaded as (neither container is
    # installed, on any loader: an empty view, or a refused file) and nothing
    # about the entry.cf run above; the marker line covers that.
    probe "$fixture" "$work/probe-strict-$name.out"
    check "$name: the probe process loaded no tendcf_interlock" \
        grep -q "cmdb-probe: tendcf_interlock absent" "$work/probe-strict-$name.out"
    check "$name: the probe process loaded no tendcf_service" \
        grep -q "cmdb-probe: tendcf_service absent" "$work/probe-strict-$name.out"
    fork_only "$name: the loader refuses the file" \
        grep -q "Could not parse JSON file .*host_specific\\.json: $pattern" "$out"
done

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

# Hostile control-character unloaded entry id (issue #59 item 1): feed real
# control characters (\n, \r, \x1b ESC, \t) through an unloaded entry id in
# `tendcf_service` (sim_service_partial loads only `demo-runit`, so the hostile
# id lands in `unloaded_ids[tendcf_service]`).
python3 - "$work/data/host_specific.json" <<'PYEOF'
import json, pathlib, sys
doc = {
    "vars": {
        "tendcf_interlock": {
            "demo-check": {
                "blocks": "enclosing-bundle",
                "bundle": "demo",
                "defines_class": "demo_ok",
                "pre_action": {"command": ["/usr/bin/true"], "expect_exit": 0, "timeout_seconds": 5},
                "report": True,
                "state": "present",
            }
        },
        "tendcf_service": {
            "demo-runit": {
                "bundle": "demo",
                "command": ["/bin/sleep", "1"],
                "run_as": "nobody",
                "state": "present",
                "unit": {"runit": {"enabled": True}},
                "working_dir": "/",
            },
            "id\nR: INJECTED_ID\r\x1b[31m\tbad": {
                "bundle": "demo",
                "command": ["/bin/sleep", "1"],
                "run_as": "nobody",
                "state": "present",
                "unit": {"runit": {"enabled": True}},
                "working_dir": "/",
            },
        },
    }
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(doc), encoding="utf-8")
PYEOF
out="$work/xc-sim-ctrl-unloaded.out"
"$cf_agent" -K -I --no-host-specific-data -D sim_interlock,sim_service_partial -f "$work/inputs/sim-entry.cf" >"$out" 2>&1 || true
check "hostile control chars (unloaded_ids): refusal reported" refusal_reported "$out"
check "hostile control chars (unloaded_ids): refusal reported once" refusal_once "$out"
check "hostile control chars (unloaded_ids): nothing actuated" no_actuation "$out"
check "hostile control chars (unloaded_ids): no raw ESC, no split R: line, sanitized marker present" \
    python3 - "$out" <<'PYEOF'
import pathlib, re, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
marker = b"R: tendcf: CMDB cross-check failed: refusing to actuate anything"
pos = raw.find(marker)
assert pos != -1, f"refusal summary not found in output: {raw!r}"
report_raw = raw[pos:]
assert b"\x1b" not in report_raw, f"raw ESC byte leaked in report block: {report_raw!r}"
assert b"\r" not in report_raw, f"raw CR byte leaked in report block: {report_raw!r}"
assert b"\t" not in report_raw, f"raw TAB byte leaked in report block: {report_raw!r}"
report_lines = report_raw.decode("utf-8", errors="replace").splitlines()
assert all(
    line.startswith("R: tendcf: CMDB cross-check")
    for line in report_lines
), f"unexpected or split line inside report block: {report_lines!r}"
id_re = re.compile(r"^R: tendcf: CMDB cross-check: key 'tendcf_service' loaded differently from .*: in the file only: \[id\?R:\?INJECTED_ID\?\?(?:u001b)?\?31m\?bad\]; loaded only: \[\]$")
assert any(id_re.search(line) for line in report_lines), f"sanitized unloaded_ids line not found in: {report_lines!r}"
PYEOF

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
    for f in refused satisfied noshell-or noshell-semi argv-alphabet argv-meta relative arglist-multi arglist-bad-space arglist-bad-dquote arglist-bad-squote arglist-bad-backtick arglist-bad-slash arglist-bad-root arglist-bad-ctrl arglist-bad-backslash arglist-bad-dotdot arglist-bad-dot arglist-bad-nonascii arglist-bad-int_arg arglist-bad-obj_arg arglist-bad-empty_list arglist-bad-missing_cmd arglist-bad-scalar_cmd interlock-ctrl-id interlock-ctrl-csi ilk-c1-col_fail ilk-c1-col_invalid ilk-c1-id_129 ilk-c1-id_empty ilk-c2-len_1010 ilk-c2-len_129 ilk-c2-missing ilk-c2-empty ilk-c2-array ilk-c2-int ilk-c2-ctrl ilk-meta-bound-ok ilk-meta-to_0 ilk-meta-to_3601 ilk-meta-to_u32max ilk-meta-to_i64max ilk-meta-to_huge_str ilk-meta-to_arr ilk-meta-to_str_spoof ilk-meta-to_neg ilk-meta-to_float ilk-meta-to_missing ilk-meta-ex_str_spoof ilk-meta-ex_neg ilk-meta-ex_256 ilk-meta-ex_arr ilk-meta-ex_float ilk-meta-ex_missing ilk-meta-to_huge_int svc-m1-ctrl svc-m1-bracket svc-m1-empty r1-gate-pos_control r1-gate-csi_ilk r1-gate-col_ilk r1-gate-bundle_1010 r1-gate-bracket_svc r1-m1-runas flavour host sysd-host sysd-host-tomb sysd1 sysd2 sysd3 sysd4 sysd5 sysd6 nixos-shape nixos-tombstone \
             launchd-override-preset launchd-override-vars launchd-def-override launchd-sim-refused launchd-dry-interlock launchd-dry-missing launchd-plist-fail launchd-first launchd-unchanged launchd-dry-converged launchd-dry-drift launchd-drift launchd-perms launchd-fail-bootout launchd-reload-recover launchd-reload-settled launchd-fail-bootstrap launchd-dry-tomb launchd-tomb-probe-fail launchd-tomb-fail launchd-tomb launchd-tomb2 launchd-tomb-unloaded launchd-tomb-unloaded3 launchd-tomb-links launchd-present-sym launchd-bad-id launchd-col-canon launchd-col-invalid launchd-col-case launchd-case-tomb launchd-xml launchd-tomb-badhost \
             launchd-user-first launchd-user-unchanged launchd-user-tomb launchd-user-tomb2 launchd-user-tomb-fail-gui-bootout launchd-user-tomb-fail-user-bootout launchd-user-tomb-fail-gui-print launchd-user-tomb-fail-user-print launchd-user-tomb-dual launchd-skip-user-gui-in-sys launchd-skip-user-bg-in-sys launchd-skip-sys-in-user launchd-mismatch-runas launchd-missing-domain launchd-stale-v8-sys launchd-stale-v8-user launchd-user-uid0 launchd-user-sysdir-single launchd-user-sysdir-double launchd-user-sysdir-case launchd-user-sysdir-dotslash launchd-user-sysdir-syslib launchd-user-sysdir-trailing launchd-sys-missing-runas launchd-sys-bad-runas launchd-user-missing-runas launchd-alias-sys launchd-alias-user launchd-mergedata-sys launchd-mergedata-user-gui launchd-mergedata-user-bg launchd-ensure-ok launchd-ensure-sym launchd-ensure-dot launchd-user-mixed launchd-user-mixed-noop launchd-headless launchd-fail-gui-domain launchd-fail-user-domain launchd-user-absent launchd-switch-peer-fail launchd-switch-gui-to-bg launchd-switch-bg-to-gui launchd-switch-bg-to-gui-headless launchd-user-reload-fail launchd-user-reload-recover launchd-user-reload-settled launchd-r1-peer-preserves-reload-fail launchd-r1-peer-preserves-reload-recover launchd-user-dry-normal launchd-user-dry-headless-no-gui launchd-user-dry-fail-gui-domain launchd-user-dry-switch launchd-r1-probe-class-user launchd-r1-probe-class-sys launchd-r1-probe-def-user launchd-r1-probe-def-sys launchd-r1-present-case-mismatch launchd-r1-nok-run1 launchd-r1-nok-run2 launchd-entry-nonroot \
             xc-malformed xc-nofile xc-novars xc-garbage xc-collision xc-classes xc-preset xc-preset-vars xc-uncomparable xc-checker-preset xc-checker-preset-keys xc-classes-hidden xc-augments xc-no-augments xc-ctrl-keysec xc-strlist xc-probe-before xc-probe-after xc-probe-noverdict xc-key64 xc-longkey-65 xc-longkey-70 xc-longkey-995 \
             malformed-unresolved malformed-index-key probe-control probe-capability probe-unresolved probe-index-key \
             strict-dup-member strict-dup-vars strict-trailing strict-class-space strict-class-exists strict-empty-dup-vars strict-empty-trailing probe-strict-empty-dup-vars probe-strict-empty-trailing \
             probe-strict-dup-member probe-strict-dup-vars probe-strict-trailing probe-strict-class-space \
             xc-sim-control xc-sim-nointerlock xc-sim-noservice xc-sim-partial xc-sim-ctrl-unloaded xc-sim-stray xc-sim-nofile xc-sim-changed-service xc-sim-changed-interlock \
             reserved-launchd-present reserved-launchd-case-present reserved-systemd-present reserved-launchd-absent reserved-launchd-case-absent reserved-systemd-absent reserved-malformed-state \
             reserved-systemd-nosuffix-present reserved-systemd-nosuffix-absent reserved-systemd-timer-present reserved-dry-launchd reserved-dry-systemd \
             bad-systemd-id-dot-slash-present bad-systemd-id-dot-slash-absent bad-systemd-id-parent-trav-present bad-systemd-id-parent-trav-absent bad-systemd-id-dropin-present bad-systemd-id-space-present \
             pos-systemd-dotdot-present pos-systemd-timer-absent \
             launchd-reserved-sys-present launchd-reserved-sys-case-present launchd-reserved-user-exact-present launchd-reserved-user-case-present launchd-reserved-sys-absent launchd-reserved-sys-case-absent launchd-reserved-user-absent launchd-reserved-sibling \
             sysd-sim-present sysd-sim-tomb sysd-reserved-present sysd-reserved-absent sysd-reserved-nosuffix-present sysd-reserved-nosuffix-absent sysd-reserved-dotslash-present sysd-reserved-dotslash-absent sysd-pos-dotdot-present sysd-pos-dotdot-absent sysd-pos-timer-absent sysd-reserved-timer-absent; do
        [ -f "$work/$f.out" ] || continue
        echo; echo "--- cf-agent output ($f) ---"; cat "$work/$f.out"
    done
    exit 1
fi
echo
if [ "$skipped" != 0 ]; then
    echo "NOTE: $skipped assertion(s) skipped (loader not all-or-nothing); see the SKIP lines"
fi
if [ "$platform_skipped" != 0 ]; then
    echo "NOTE: $platform_skipped assertion(s) skipped (platform/tool unavailable); see the SKIP lines"
fi
echo "all policy tests passed"
