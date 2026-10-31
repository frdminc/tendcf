#!/usr/bin/env bash
# The root install on a host that has no librsync/libb2 of its own.
#
# pastebin (2026-10-31) had neither library. The cf-* binaries carry a RUNPATH
# for /opt/tendcf/lib, but RUNPATH is not inherited by a library's own
# dependencies, so libpromises.so could not find the bundled copies and
# cf-promises would not start. CI never noticed because apt installs librsync
# on its runners. This test removes both libraries from the system, proves the
# premise (the binary really does fail without a library path), and then runs
# the installer, which has to supply the path itself.
#
# Run as root in a throwaway container with the tree at /opt/tendcf (the
# debian-13 job, after the artifact is packaged: the bundled copies must
# already be in /opt/tendcf/lib). It needs no init system. It moves system
# files aside and puts them back on exit.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
repo="$(cd "$(dirname "$0")/../.." && pwd)"
installer="$repo/deploy/linux/tendcf-install.sh"
canary="$repo/deploy/linux/canary"
fail=0
check() {  # check NAME COND...
    local name="$1"; shift
    if "$@"; then echo "ok   $name"; else echo "FAIL $name"; fail=1; fi
}

for lib in librsync.so.2 libb2.so.1; do
    [ -e "/opt/tendcf/lib/$lib" ] || { echo "/opt/tendcf/lib/$lib is not bundled" >&2; exit 2; }
done

aside="$(mktemp -d)"
restore() {
    local f
    for f in "$aside"/*; do
        [ -e "$f" ] || continue
        mv -f "$f" "$(cat "$f.from")" 2>/dev/null || true
    done
    ldconfig
    rm -rf "$aside"
}
trap restore EXIT

# Move every system copy aside, remembering where each came from.
while read -r path; do
    [ -n "$path" ] || continue
    real="$(readlink -f "$path")"
    for p in "$path" "$real"; do
        [ -e "$p" ] || [ -L "$p" ] || continue
        n="$(basename "$p")"
        [ -e "$aside/$n" ] || [ -L "$aside/$n" ] && continue
        echo "$p" > "$aside/$n.from"
        mv "$p" "$aside/$n"
    done
done < <(ldconfig -p | awk '/librsync\.so\.2|libb2\.so\.1/ { print $NF }' | sort -u)
ldconfig

echo "# premise: no system librsync/libb2"
check "ldconfig knows neither library" bash -c "! ldconfig -p | grep -Eq 'librsync\\.so\\.2|libb2\\.so\\.1'"
check "cf-promises does not start without a library path" \
    bash -c "! env -u LD_LIBRARY_PATH /opt/tendcf/bin/cf-promises --version >/dev/null 2>&1"
check "cf-promises starts with the bundled directory on the path" \
    env LD_LIBRARY_PATH=/opt/tendcf/lib /opt/tendcf/bin/cf-promises --version

echo "# the installer has to supply the path itself"
check "install succeeds with the caller's LD_LIBRARY_PATH unset" \
    env -u LD_LIBRARY_PATH "$installer" install --data "$canary/host_specific.json"
wd="$(env -u LD_LIBRARY_PATH "$installer" workdir)"
check "data validated and placed" test -s "$wd/data/host_specific.json"
check "a hostile inherited LD_LIBRARY_PATH is replaced, not used" \
    env LD_LIBRARY_PATH=/nonexistent "$installer" install --data "$canary/host_specific.json"
check "no binary the root run loads is unresolved" \
    bash -c "! LD_LIBRARY_PATH=/opt/tendcf/lib ldd /opt/tendcf/bin/cf-agent /opt/tendcf/bin/cf-execd /opt/tendcf/bin/cf-promises /opt/tendcf/bin/cf-key | grep -q 'not found'"

if [ "$fail" != 0 ]; then exit 1; fi
echo; echo "all bare-host tests passed"
