#!/bin/sh
# State 1 VM: system-wide python.org Python (issue 70 answer 5, slice A).
# Runs as root inside the guest: sudo -n /bin/sh install-python.sh VERSION URL SHA256 SIGNER
# One install per image, from the python.org package, never uv per-user copies.
# Idempotent: exits 0 without downloading when that exact version is installed.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
[ "$(id -u)" -eq 0 ] || { echo "install-python.sh: must run as root" >&2; exit 1; }
[ "$#" -eq 4 ] || { echo "usage: install-python.sh VERSION URL SHA256 SIGNER" >&2; exit 2; }
version=$1 url=$2 sha256=$3 signer=$4
minor=${version%.*}
fw=/Library/Frameworks/Python.framework/Versions/$minor
py=$fw/bin/python$minor

installed() {
    [ -x "$py" ] || return 1
    [ "$("$py" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' </dev/null)" = "$version" ]
}

if installed; then
    echo "python $version already installed at $fw"
else
    work=$(mktemp -d /var/tmp/tendcf-python.XXXXXX)
    trap 'rm -rf "$work"' EXIT
    pkg=$work/python.pkg
    curl -fsSL --retry 3 --max-time 900 -o "$pkg" "$url" </dev/null
    echo "$sha256  $pkg" | shasum -a 256 -c - >/dev/null || { echo "install-python.sh: sha256 mismatch for $url" >&2; exit 1; }
    pkgutil --check-signature "$pkg" | grep -F -- "$signer" >/dev/null \
        || { echo "install-python.sh: package is not signed by $signer" >&2; exit 1; }
    installer -pkg "$pkg" -target / </dev/null
    installed || { echo "install-python.sh: $py does not report $version after install" >&2; exit 1; }
fi

# Root-owned and not group/world writable (checklist step 3's rule, applied to this install).
owner=$(stat -f '%Su' "$fw")
mode=$(stat -f '%Lp' "$fw")
[ "$owner" = root ] || { echo "install-python.sh: $fw owned by $owner" >&2; exit 1; }
case $mode in *[2367][0-7]|*[0-7][2367]) echo "install-python.sh: $fw mode $mode is group/world writable" >&2; exit 1 ;; esac
echo "INSTALL-PYTHON-RESULT version=$version path=$py"
