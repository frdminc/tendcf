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
# notarization trust strictly before `Certificate Chain:`, and name the leaf certificate
# uniquely as `1. Developer ID Installer: <signer>` strictly inside `Certificate Chain:`.
# Output goes through a temp file + `LC_ALL=C tr` so NUL and CR bytes fail closed.
check_signature() {
    sig_tmp=$(mktemp "${work:-/var/tmp}/tendcf-pkgutil.XXXXXX")
    sig_rc=0
    pkgutil --check-signature "$1" </dev/null >"$sig_tmp" || sig_rc=$?
    if [ "$sig_rc" -ne 0 ]; then
        rm -f -- "$sig_tmp"
        die "pkgutil --check-signature failed for $1 (rc $sig_rc)"
    fi
    sig_err=$(LC_ALL=C tr '\000' '\001' <"$sig_tmp" | SIGNER="$signer" LC_ALL=C awk '
        function fail(msg) { if (!bad) print msg; bad = 1; exit }
        index($0, "\001") > 0 { fail("pkgutil output contains NUL byte") }
        index($0, "\r") > 0 { fail("pkgutil output contains carriage return") }
        {
            line = $0
            sub(/^[ \t]+/, "", line)
            if (line == "Certificate Chain:") {
                chain_hdr++
                in_chain = 1
                next
            }
            if (line ~ /^Status:/) {
                status_n++
                if (in_chain) fail("Status line appeared inside Certificate Chain")
                if (line == "Status: signed by a developer certificate issued by Apple for distribution") status_ok++
                next
            }
            if (line ~ /^Notarization:/) {
                notary_n++
                if (in_chain) fail("Notarization line appeared inside Certificate Chain")
                if (line == "Notarization: trusted by the Apple notary service") notary_ok++
                next
            }
            if (line ~ /^1\. /) {
                leaf_n++
                if (!in_chain) fail("leaf certificate line appeared outside Certificate Chain")
                if (line == "1. Developer ID Installer: " ENVIRON["SIGNER"]) leaf_ok++
                next
            }
        }
        END {
            if (bad) exit
            if (chain_hdr + 0 != 1) { print "expected exactly 1 Certificate Chain section, saw " (chain_hdr + 0); exit }
            if (status_n + 0 != 1 || status_ok + 0 != 1) { print "package status is not uniquely '\''signed by a developer certificate issued by Apple for distribution'\''"; exit }
            if (notary_n + 0 != 1 || notary_ok + 0 != 1) { print "package notarization is not uniquely '\''trusted by the Apple notary service'\''"; exit }
            if (leaf_n + 0 != 1 || leaf_ok + 0 != 1) { print "package leaf certificate is not uniquely '\''Developer ID Installer: " ENVIRON["SIGNER"] "'\''"; exit }
        }')
    rm -f -- "$sig_tmp"
    [ -z "$sig_err" ] || die "$sig_err"
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
