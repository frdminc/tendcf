#!/bin/sh
# State 1 VM: system-wide python.org Python (issue 70 answer 5, slice A).
# Runs as root inside the guest: sudo -n /bin/sh install-python.sh VERSION URL SHA256 SIGNER
# One install per image, from the python.org package, never uv per-user copies.
# Idempotent: downloads nothing when that exact version is installed. The ownership
# fix-up and its whole-tree assertion run every time.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
[ "$(id -u)" -eq 0 ] || { echo "install-python.sh: must run as root" >&2; exit 1; }
[ "$#" -eq 4 ] || { echo "usage: install-python.sh VERSION URL SHA256 SIGNER" >&2; exit 2; }
version=$1 url=$2 sha256=$3 signer=$4
minor=${version%.*}
fwroot=/Library/Frameworks/Python.framework
fw=$fwroot/Versions/$minor
py=$fw/bin/python$minor

die() { echo "install-python.sh: $*" >&2; exit 1; }

installed() {
    [ -x "$py" ] || return 1
    [ "$("$py" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' </dev/null)" = "$version" ]
}

# pkgutil --check-signature must exit 0, report Apple's distribution-certificate status and
# name the leaf certificate exactly "Developer ID Installer: <signer>". The sha256 pin is the
# real control; this is the second one. Lines are compared whole, after trimming.
check_signature() {
    sig=$(pkgutil --check-signature "$1" </dev/null) || die "pkgutil --check-signature failed for $1"
    got_status=0 got_signer=0
    while IFS= read -r line; do
        line=${line#"${line%%[![:space:]]*}"}
        case $line in
            "Status: signed by a developer certificate issued by Apple for distribution") got_status=1 ;;
            "1. Developer ID Installer: $signer") got_signer=1 ;;
        esac
    done <<EOF
$sig
EOF
    [ "$got_status" -eq 1 ] || die "package status is not 'signed by a developer certificate issued by Apple for distribution'"
    [ "$got_signer" -eq 1 ] || die "package leaf certificate is not 'Developer ID Installer: $signer'"
}

if installed; then
    echo "python $version already installed at $fw"
else
    work=$(mktemp -d /var/tmp/tendcf-python.XXXXXX)
    trap 'rm -rf "$work"' EXIT
    pkg=$work/python.pkg
    curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 --max-time 900 -o "$pkg" "$url" </dev/null
    echo "$sha256  $pkg" | shasum -a 256 -c - >/dev/null || die "sha256 mismatch for $url"
    check_signature "$pkg"
    installer -pkg "$pkg" -target / </dev/null
    installed || die "$py does not report $version after install"
fi

# python.org's installer leaves the framework root:admin with group write (775), and the
# parents Versions/ and Versions/Current too (CPython build-installer.py "Fix file modes"
# walks the whole staged framework; postflight.framework repeats it for Versions/X.Y).
# Checklist step 3's rule is root:wheel and not group/world writable, and an admin-group user
# who can write Versions/ can rename Versions/X.Y aside. So fix and assert the WHOLE framework
# (Versions/, Versions/Current and the top-level links included; -h: symlinks themselves,
# symlink modes are not meaningful and are not tested).
chown -hR root:wheel "$fwroot"
chmod -R go-w "$fwroot"
bad=$(find "$fwroot" \( ! -user root -o ! -group wheel \) -print </dev/null | head -n 5)
[ -z "$bad" ] || die "not root:wheel: $bad"
bad=$(find "$fwroot" ! -type l \( -perm -020 -o -perm -002 \) -print </dev/null | head -n 5)
[ -z "$bad" ] || die "group or world writable: $bad"
echo "INSTALL-PYTHON-RESULT version=$version path=$py"
