#!/usr/bin/env bash
# Root-owned tendcf install on a macOS host (issue 70, C-deploy-01). Run as root.
#
# Counterpart of deploy/linux/tendcf-install.sh: binaries and policy root-owned
# (root:wheel, no group/world write on the tree or any ancestor up to /), the
# work directory inside the same root-owned tree (read from cf-promises, never
# assumed), and a root cf-execd LaunchDaemon (org.tendcf.execd) that runs
# cf-agent on a schedule. Nothing here leaves a sudoers rule behind and nothing
# a non-root user can write is read by root.
#
#   install [--tarball FILE] [--sha256 FILE] [--data FILE] [--policy-src DIR] [--enable]
#                    verify and extract the PR 95 macOS fork tarball (clearing
#                    com.apple.quarantine), enforce root:wheel and go-w on
#                    /opt/tendcf and verify ancestors up to /, verify Mach-O
#                    dependencies and code signatures, lay out the work
#                    directory, place the policy and promises.cf, optionally
#                    install CMDB data (validated by cf-promises first) and
#                    optionally enable org.tendcf.execd. Re-running when
#                    converged is a no-op that reports `no change`.
#   data FILE        replace the CMDB data (validated first; the old file is
#                    restored if cf-promises rejects the new one)
#   run-once         one `cf-agent -K -I` pass over the installed policy
#   enable           write /Library/LaunchDaemons/org.tendcf.execd.plist
#                    (root:wheel 0644, plutil -lint) and bootstrap it
#                    idempotently (launchctl print exit-code probe)
#   disable          bootout and remove org.tendcf.execd
#   status           what is installed and loaded
#   workdir          print the compiled-in work directory
set -euo pipefail
umask 022

# Strip all DYLD_* variables before running any root binary: SIP strips them
# for Apple binaries, not for ad-hoc-signed binaries under /opt/tendcf.
unset DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH DYLD_INSERT_LIBRARIES \
      DYLD_FRAMEWORK_PATH DYLD_FALLBACK_FRAMEWORK_PATH DYLD_IMAGE_SUFFIX \
      DYLD_PRINT_LIBRARIES DYLD_PRINT_LIBRARIES_POST_LAUNCH DYLD_PRINT_RPATHS \
      DYLD_SHARED_CACHE_DIR

prefix=/opt/tendcf
workdir=""   # set by init_paths
label=org.tendcf.execd
launchd_dir=/Library/LaunchDaemons
plist_path="$launchd_dir/$label.plist"
installed_sha_file="$prefix/share/tendcf/INSTALLED_TARBALL.sha256"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
policy_src="$here/../../policy"

cf_agent="$prefix/bin/cf-agent"
cf_promises="$prefix/bin/cf-promises"
cf_key="$prefix/bin/cf-key"
cf_execd="$prefix/bin/cf-execd"
entry=""     # set by init_paths
data=""      # set by init_paths

stage_dir=""
changed=0

die() { echo "tendcf-install: $*" >&2; exit 1; }
say() { echo "tendcf-install: $*"; }

cleanup_stage() {
    if [ -n "$stage_dir" ] && [ -d "$stage_dir" ]; then
        /bin/rm -rf "$stage_dir"
    fi
}
trap cleanup_stage EXIT

[ "$(/usr/bin/id -u)" = 0 ] || die "run as root"
[ "$(/usr/bin/uname -s)" = Darwin ] || die "Darwin only"

make_stage() {
    if [ -z "$stage_dir" ]; then
        local old_umask raw_stage
        old_umask="$(umask)"
        umask 077
        raw_stage="$(/usr/bin/mktemp -d /var/tmp/tendcf-install.XXXXXX)"
        umask "$old_umask"
        /usr/sbin/chown root:wheel "$raw_stage"
        /bin/chmod 0700 "$raw_stage"
        stage_dir="$(cd "$raw_stage" && pwd -P)"
    fi
}

# Verify one path is a real directory (not a symlink), owned by root:wheel,
# and has no group or world write bits.
check_dir_root_unwritable() {
    local dir="$1" meta owner group mode mode_oct
    [ -L "$dir" ] && die "$dir is a symlink; refusing"
    [ -d "$dir" ] || die "$dir is not a directory"
    meta="$(/usr/bin/stat -f '%Su %Sg %Lp' "$dir")" || die "cannot stat $dir"
    read -r owner group mode <<< "$meta"
    [ "$owner" = root ] || die "$dir owned by $owner, expected root"
    [ "$group" = wheel ] || die "$dir group is $group, expected wheel"
    mode_oct=$((8#$mode))
    if [ $((mode_oct & 8#022)) -ne 0 ]; then
        die "$dir mode $mode is group- or world-writable"
    fi
}

# Verify every ancestor of PATH up to / (excluding PATH itself) is a real
# directory owned by root:wheel with no group/world write.
check_ancestors() {
    local p="$1" parent
    case "$p" in
        /*) ;;
        *) die "expected absolute path, got $p" ;;
    esac
    parent="$p"
    while [ "$parent" != "/" ]; do
        parent="$(/usr/bin/dirname "$parent")"
        check_dir_root_unwritable "$parent"
    done
}

# Check ownership and go-w across a whole tree. Returns 0 if already clean,
# 1 if anything needs repair.
tree_is_clean() {
    local root="$1"
    [ ! -L "$root" ] || return 1
    [ -d "$root" ] || return 1
    local bad_owner bad_mode
    bad_owner="$(/usr/bin/find "$root" \( ! -user root -o ! -group wheel \) -print | /usr/bin/head -n 1)"
    [ -z "$bad_owner" ] || return 1
    bad_mode="$(/usr/bin/find "$root" ! -type l \( -perm -020 -o -perm -002 \) -print | /usr/bin/head -n 1)"
    [ -z "$bad_mode" ] || return 1
    return 0
}

# Locate a real Python 3 interpreter (avoiding /usr/bin/python3 when Xcode CLT
# is absent, since that binary is an xcrun stub on vanilla macOS).
find_real_python() {
    local cand
    for cand in \
        /Library/Frameworks/Python.framework/Versions/Current/bin/python3 \
        /Library/Frameworks/Python.framework/Versions/3.14/bin/python3 \
        /Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14; do
        if [ -x "$cand" ]; then
            echo "$cand"
            return 0
        fi
    done
    if /usr/bin/xcode-select -p >/dev/null 2>&1 && [ -x /usr/bin/python3 ]; then
        echo /usr/bin/python3
        return 0
    fi
    return 1
}

# Verify Mach-O load paths, LC_RPATH, and code signatures under TREE_ROOT.
# Every non-system library reference must be under /opt/tendcf/ and must exist
# in TREE_ROOT. Uses otool when Xcode CLT is present; otherwise parses Mach-O
# load commands directly with stdlib Python (so vanilla macOS without CLT works).
verify_macho_tree() {
    local tree_root="$1"
    local has_otool=0 py=""
    if /usr/bin/xcode-select -p >/dev/null 2>&1 && /usr/bin/otool -L "$tree_root/bin/cf-agent" >/dev/null 2>&1; then
        has_otool=1
    else
        py="$(find_real_python)" || die "cannot verify Mach-O dependencies: neither Xcode CLT (otool) nor Python 3 found"
    fi

    local machos=() f file_out
    while IFS= read -r -d '' f; do
        file_out="$(/usr/bin/file -b "$f" 2>/dev/null || true)"
        case "$file_out" in
            *Mach-O*) machos+=("$f") ;;
        esac
    done < <(/usr/bin/find "$tree_root/bin" "$tree_root/lib" -type f -print0 2>/dev/null)

    [ "${#machos[@]}" -gt 0 ] || die "no Mach-O files found under $tree_root/{bin,lib}"

    local bin lib rel rp
    for bin in "${machos[@]}"; do
        if ! /usr/bin/codesign --verify --strict "$bin" >/dev/null 2>&1; then
            die "codesign verification failed for $bin"
        fi
        if [ "$has_otool" -eq 1 ]; then
            while IFS= read -r lib; do
                [ -n "$lib" ] || continue
                case "$lib" in
                    "$prefix"/*)
                        rel="${lib#"$prefix"/}"
                        [ -e "$tree_root/$rel" ] || die "$bin links missing in-prefix library $lib"
                        ;;
                    /usr/lib/*|/System/Library/*) ;;
                    *) die "$bin loads $lib, outside $prefix and the system library directories" ;;
                esac
            done < <(/usr/bin/otool -L "$bin" | /usr/bin/awk 'NR > 1 && /^\t/ { sub(/^[ \t]+/, ""); sub(/ \(compatibility version .*\)$/, ""); print }')

            while IFS= read -r rp; do
                [ -n "$rp" ] || continue
                case "$rp" in
                    "$prefix"|"$prefix"/*) ;;
                    *) die "$bin carries forbidden LC_RPATH: $rp" ;;
                esac
            done < <(/usr/bin/otool -l "$bin" | /usr/bin/awk '$1 == "cmd" { c = $2 } c == "LC_RPATH" && $1 == "path" { sub(/^[ \t]*path[ \t]+/, ""); sub(/ \(offset .*\)$/, ""); print }')
        fi
    done

    if [ "$has_otool" -eq 0 ]; then
        "$py" - "$prefix" "$tree_root" "${machos[@]}" <<'PY'
import pathlib
import struct
import sys

prefix = sys.argv[1].rstrip("/")
prefix_slash = prefix + "/"
tree_root = pathlib.Path(sys.argv[2])
files = sys.argv[3:]

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

DYLIB_CMDS = {
    0x0C,        # LC_LOAD_DYLIB
    0x0D,        # LC_ID_DYLIB
    0x80000018,  # LC_LOAD_WEAK_DYLIB
    0x8000001F,  # LC_REEXPORT_DYLIB
    0x20,        # LC_LAZY_LOAD_DYLIB
    0x80000023,  # LC_LOAD_UPWARD_DYLIB
}
LC_RPATH = 0x8000001C

def parse_slice(data: bytes, base: int, path: str) -> None:
    magic = struct.unpack_from("<I", data, base)[0]
    if magic == MH_MAGIC_64:
        endian = "<"
    elif magic == MH_CIGAM_64:
        endian = ">"
    else:
        raise SystemExit(f"tendcf-install: unsupported Mach-O magic 0x{magic:08x} in {path}")
    _magic, _cpu, _sub, _ft, ncmds, sizeofcmds, _flags, _res = struct.unpack_from(
        endian + "IIIIIIII", data, base
    )
    off = base + 32
    end = off + sizeofcmds
    if end > len(data):
        raise SystemExit(f"tendcf-install: truncated Mach-O load commands in {path}")
    for _ in range(ncmds):
        if off + 8 > end:
            raise SystemExit(f"tendcf-install: truncated load command in {path}")
        cmd, cmdsize = struct.unpack_from(endian + "II", data, off)
        if cmdsize < 8 or off + cmdsize > end:
            raise SystemExit(f"tendcf-install: invalid load command size in {path}")
        if cmd in DYLIB_CMDS:
            str_off = struct.unpack_from(endian + "I", data, off + 8)[0]
            if str_off >= cmdsize:
                raise SystemExit(f"tendcf-install: invalid dylib string offset in {path}")
            raw = data[off + str_off : off + cmdsize].split(b"\x00", 1)[0]
            dep = raw.decode("utf-8", "strict")
            if dep.startswith(prefix_slash):
                rel = dep[len(prefix_slash):]
                if not (tree_root / rel).exists():
                    raise SystemExit(f"tendcf-install: {path} links missing in-prefix library {dep}")
            elif dep.startswith(("/usr/lib/", "/System/Library/")):
                pass
            else:
                raise SystemExit(
                    f"tendcf-install: {path} loads {dep}, outside {prefix} and the system library directories"
                )
        elif cmd == LC_RPATH:
            str_off = struct.unpack_from(endian + "I", data, off + 8)[0]
            if str_off >= cmdsize:
                raise SystemExit(f"tendcf-install: invalid LC_RPATH offset in {path}")
            raw = data[off + str_off : off + cmdsize].split(b"\x00", 1)[0]
            rp = raw.decode("utf-8", "strict")
            if rp != prefix and not rp.startswith(prefix_slash):
                raise SystemExit(f"tendcf-install: {path} carries forbidden LC_RPATH: {rp}")
        off += cmdsize

for p in files:
    buf = pathlib.Path(p).read_bytes()
    if len(buf) < 32:
        raise SystemExit(f"tendcf-install: truncated Mach-O file {p}")
    m = struct.unpack_from(">I", buf, 0)[0]
    if m in (FAT_MAGIC, FAT_MAGIC_64):
        nfat = struct.unpack_from(">I", buf, 4)[0]
        entry_sz = 20 if m == FAT_MAGIC else 32
        for i in range(nfat):
            eoff = 8 + i * entry_sz
            if m == FAT_MAGIC:
                _c, _s, sl_off, _sz, _al = struct.unpack_from(">IIIII", buf, eoff)
            else:
                _c, _s, sl_off, _sz, _al, _r = struct.unpack_from(">IIQQII", buf, eoff)
            parse_slice(buf, sl_off, p)
    else:
        parse_slice(buf, 0, p)
PY
    fi
}

# Verify a tarball against its .sha256 file in a root-only staging dir (no TOCTOU),
# clear quarantine, validate tar entries, stage-extract, verify Mach-O + codesign,
# and install under /opt/tendcf. Skips re-extraction when already installed with the
# same verified sha256 and an intact tree.
install_tarball() {
    local src_tar="$1" src_sha="$2"
    [ -f "$src_tar" ] || die "tarball not found: $src_tar"
    [ -f "$src_sha" ] || die "sha256 file not found: $src_sha"

    local tar_base
    tar_base="$(/usr/bin/basename "$src_tar")"

    make_stage
    local staged_tar="$stage_dir/$tar_base"
    local staged_sha="$stage_dir/$tar_base.sha256"
    /usr/bin/install -m 0600 -o root -g wheel "$src_tar" "$staged_tar"
    /usr/bin/install -m 0600 -o root -g wheel "$src_sha" "$staged_sha"

    # Clear quarantine on staged inputs if present.
    if /usr/bin/xattr -p com.apple.quarantine "$staged_tar" >/dev/null 2>&1; then
        /usr/bin/xattr -d com.apple.quarantine "$staged_tar"
    fi
    if /usr/bin/xattr -p com.apple.quarantine "$staged_sha" >/dev/null 2>&1; then
        /usr/bin/xattr -d com.apple.quarantine "$staged_sha"
    fi

    # Parse the .sha256 file strictly: exactly one non-empty line with a 64-hex digest
    # and a filename whose basename matches the tarball.
    local sha_lines expected_sha sha_name actual_sha
    sha_lines="$(/usr/bin/awk 'NF > 0 { n++ } END { print n + 0 }' "$staged_sha")"
    [ "$sha_lines" -eq 1 ] || die "$src_sha must contain exactly one non-empty sha256 line (found $sha_lines)"

    local line
    line="$(/usr/bin/awk 'NF > 0 { print; exit }' "$staged_sha")"
    if [[ ! "$line" =~ ^([0-9A-Fa-f]{64})[[:space:]]+\*?([^[:space:]]+)$ ]]; then
        die "$src_sha is not a valid sha256 line"
    fi
    expected_sha="$(printf '%s' "${BASH_REMATCH[1]}" | /usr/bin/tr '[:upper:]' '[:lower:]')"
    sha_name="${BASH_REMATCH[2]}"
    if [ "$(/usr/bin/basename "$sha_name")" != "$tar_base" ]; then
        die "$src_sha names '$sha_name', expected '$tar_base'"
    fi

    actual_sha="$(/usr/bin/shasum -a 256 "$staged_tar" | /usr/bin/awk '{ print tolower($1) }')"
    if [ "$actual_sha" != "$expected_sha" ]; then
        die "sha256 mismatch for $tar_base: expected $expected_sha, got $actual_sha"
    fi

    # Ensure /opt exists (vanilla macOS may not have /opt yet) and ancestors are root:wheel go-w.
    if [ ! -e /opt ] && [ ! -L /opt ]; then
        /usr/bin/install -d -m 0755 -o root -g wheel /opt
        changed=1
    fi
    check_ancestors "$prefix"
    [ ! -L "$prefix" ] || die "$prefix is a symlink; refusing"

    # Fast no-op path: exact same verified tarball already installed and core binaries exist.
    if [ -f "$installed_sha_file" ] \
        && [ "$(/bin/cat "$installed_sha_file" 2>/dev/null || true)" = "$expected_sha" ] \
        && [ -x "$cf_agent" ] && [ -x "$cf_promises" ] && [ -x "$cf_key" ] && [ -x "$cf_execd" ]; then
        return 0
    fi

    # Inspect tar entries before extracting: only paths under tendcf/, no .., no devices/FIFOs/hardlinks,
    # no symlinks escaping /opt/tendcf.
    local entry_line mode_char name
    while IFS= read -r entry_line; do
        [ -n "$entry_line" ] || continue
        mode_char="${entry_line:0:1}"
        case "$mode_char" in
            -|d|l) ;;
            *) die "refusing unsafe tar entry type '$mode_char': $entry_line" ;;
        esac
    done < <(/usr/bin/tar -tvzf "$staged_tar")

    while IFS= read -r name; do
        [ -n "$name" ] || continue
        case "$name" in
            /*|*/..|../*|*/../*|..)
                die "refusing unsafe tar path: $name" ;;
            tendcf|tendcf/*) ;;
            *) die "refusing tar entry outside tendcf/: $name" ;;
        esac
    done < <(/usr/bin/tar -tzf "$staged_tar")

    local extract_dir="$stage_dir/extract"
    /bin/mkdir -p "$extract_dir"
    /bin/chmod 0700 "$extract_dir"
    COPYFILE_DISABLE=1 /usr/bin/tar --no-same-owner --no-xattrs -C "$extract_dir" -xzf "$staged_tar"

    local staged_tree="$extract_dir/tendcf"
    [ -d "$staged_tree" ] || die "tarball did not extract a tendcf/ directory"
    [ ! -L "$staged_tree" ] || die "tarball extracted a symlink at tendcf"

    # Reject any extracted symlink whose resolved target escapes the staged tree or /opt/tendcf.
    local sl link_target resolved_parent resolved_dir
    while IFS= read -r -d '' sl; do
        link_target="$(/usr/bin/readlink "$sl")"
        case "$link_target" in
            /*)
                case "$link_target" in
                    "$prefix"/*) ;;
                    *) die "refusing extracted symlink $sl -> $link_target (outside $prefix)" ;;
                esac
                ;;
            *../*|..|*/..)
                # Resolve relative link inside staged tree using parent dir.
                resolved_parent="$(cd "$(/usr/bin/dirname "$sl")" && pwd -P)"
                resolved_dir="$(cd "$resolved_parent" && cd "$(/usr/bin/dirname "$link_target")" 2>/dev/null && pwd -P || true)"
                case "$resolved_dir" in
                    "$staged_tree"|"$staged_tree"/*) ;;
                    *) die "refusing escaping relative symlink $sl -> $link_target" ;;
                esac
                ;;
        esac
    done < <(/usr/bin/find "$staged_tree" -type l -print0)

    # Clear quarantine recursively (without following symlinks), enforce root:wheel and go-w,
    # and verify Mach-O + codesign BEFORE placing the tree at /opt/tendcf.
    /usr/bin/xattr -drs com.apple.quarantine "$staged_tree"
    /usr/sbin/chown -hR root:wheel "$staged_tree"
    /bin/chmod -R go-w "$staged_tree"
    verify_macho_tree "$staged_tree"

    /usr/bin/install -d -m 0755 -o root -g wheel "$staged_tree/share/tendcf"
    printf '%s\n' "$expected_sha" > "$staged_tree/share/tendcf/INSTALLED_TARBALL.sha256"
    /usr/sbin/chown root:wheel "$staged_tree/share/tendcf/INSTALLED_TARBALL.sha256"
    /bin/chmod 0644 "$staged_tree/share/tendcf/INSTALLED_TARBALL.sha256"

    if [ ! -e "$prefix" ]; then
        /bin/mv "$staged_tree" "$prefix"
    else
        # Upgrade in place while preserving an existing workdir ($prefix/var).
        local backup_prefix="$prefix.old.$$"
        /bin/rm -rf "$backup_prefix"
        /bin/mv "$prefix" "$backup_prefix"
        if [ -d "$backup_prefix/var" ]; then
            /bin/rm -rf "${staged_tree:?}/var"
            /bin/mv "$backup_prefix/var" "$staged_tree/var"
        fi
        if ! /bin/mv "$staged_tree" "$prefix"; then
            if [ -d "$staged_tree/var" ] && [ ! -e "$backup_prefix/var" ]; then
                /bin/mv "$staged_tree/var" "$backup_prefix/var" || true
            fi
            /bin/mv "$backup_prefix" "$prefix" || true
            die "failed to install new tree at $prefix; previous tree restored"
        fi
        /bin/rm -rf "$backup_prefix"
    fi
    changed=1
}

init_paths() {
    [ -x "$cf_promises" ] || die "$cf_promises missing: pass --tarball FILE --sha256 FILE or install $prefix first"
    local probe out
    probe="$(/usr/bin/mktemp /var/tmp/tendcf-probe.XXXXXX)"
    printf 'bundle agent main {}\n' > "$probe"
    out="$("$cf_promises" --show-vars -f "$probe" 2>/dev/null | /usr/bin/awk '$1 == "default:sys.workdir" { print $2; exit }')" || true
    /bin/rm -f "$probe"
    case "$out" in
        "$prefix"/*) ;;
        *) die "cannot read the work directory from $cf_promises (got '${out:-nothing}'); it must be under $prefix" ;;
    esac
    if [[ ! "$out" =~ ^/opt/tendcf/[A-Za-z0-9._/-]+$ ]] || [[ "$out" == *..* ]]; then
        die "unsafe work directory from $cf_promises: $out"
    fi
    workdir="$out"
    entry="$workdir/inputs/promises.cf"
    data="$workdir/data/host_specific.json"
}

check_tree() {
    check_ancestors "$prefix"
    [ ! -L "$prefix" ] || die "$prefix is a symlink; refusing"
    [ -x "$cf_agent" ] || die "$cf_agent missing: pass --tarball FILE --sha256 FILE or install $prefix first"
    [ -x "$cf_promises" ] || die "$cf_promises missing"
    [ -x "$cf_key" ] || die "$cf_key missing"
    [ -x "$cf_execd" ] || die "$cf_execd missing"

    if ! tree_is_clean "$prefix"; then
        /usr/sbin/chown -hR root:wheel "$prefix"
        /bin/chmod -R go-w "$prefix"
        changed=1
    fi
    # Clear any stray quarantine xattr on the installed tree (without following symlinks).
    if [ -n "$(/usr/bin/xattr -rs "$prefix" 2>/dev/null | /usr/bin/awk '/com\.apple\.quarantine/ { print; exit }')" ]; then
        /usr/bin/xattr -drs com.apple.quarantine "$prefix"
        changed=1
    fi
    verify_macho_tree "$prefix"
}

ensure_dir() {  # ensure_dir MODE PATH
    local want_mode="$1" dir="$2"
    [ ! -L "$dir" ] || die "$dir is a symlink; refusing"
    if [ -d "$dir" ]; then
        local cur
        cur="$(/usr/bin/stat -f '%Su:%Sg %Lp' "$dir")"
        if [ "$cur" = "root:wheel $want_mode" ]; then
            return 0
        fi
    fi
    /usr/bin/install -d -m "0$want_mode" -o root -g wheel "$dir"
    changed=1
}

lay_out() {
    local d
    for d in "$workdir" "$workdir/bin" "$workdir/inputs" "$workdir/outputs" "$workdir/modules" "$workdir/state"; do
        ensure_dir 755 "$d"
    done
    ensure_dir 700 "$workdir/ppkeys"
    ensure_dir 700 "$workdir/data"

    local f link_path cur_target
    for f in "$prefix"/bin/cf-*; do
        [ -e "$f" ] || continue
        link_path="$workdir/bin/$(/usr/bin/basename "$f")"
        cur_target="$(/usr/bin/readlink "$link_path" 2>/dev/null || true)"
        if [ ! -L "$link_path" ] || [ "$cur_target" != "$f" ]; then
            /bin/ln -sfn "$f" "$link_path"
            /usr/sbin/chown -h root:wheel "$link_path"
            changed=1
        fi
    done

    if [ ! -f "$workdir/ppkeys/localhost.priv" ] || [ ! -f "$workdir/ppkeys/localhost.pub" ]; then
        /bin/rm -f "$workdir/ppkeys/localhost.priv" "$workdir/ppkeys/localhost.pub"
        local keyout=""
        if ! keyout="$("$cf_key" 2>&1)"; then
            die "cf-key failed: $keyout"
        fi
        /usr/sbin/chown root:wheel "$workdir/ppkeys/localhost.priv" "$workdir/ppkeys/localhost.pub"
        /bin/chmod 0600 "$workdir/ppkeys/localhost.priv"
        /bin/chmod 0644 "$workdir/ppkeys/localhost.pub"
        changed=1
    fi
    [ -f "$workdir/ppkeys/localhost.pub" ] || die "cf-key wrote no key under $workdir/ppkeys"
}

place_policy() {
    [ -f "$policy_src/tendcf_services.cf" ] || die "no policy at $policy_src (use --policy-src DIR)"
    local new="$workdir/inputs/.tendcf.new"
    /bin/rm -rf "$new"
    /bin/cp -R "$policy_src" "$new"
    /usr/sbin/chown -hR root:wheel "$new"
    /bin/chmod -R go-w "$new"

    local policy_differs=0
    if [ ! -d "$workdir/inputs/tendcf" ] || [ -L "$workdir/inputs/tendcf" ]; then
        policy_differs=1
    elif ! /usr/bin/diff -rq "$new" "$workdir/inputs/tendcf" >/dev/null 2>&1; then
        policy_differs=1
    elif ! tree_is_clean "$workdir/inputs/tendcf"; then
        policy_differs=1
    fi
    if [ "$policy_differs" -eq 1 ]; then
        /bin/rm -rf "$workdir/inputs/tendcf"
        /bin/mv "$new" "$workdir/inputs/tendcf"
        changed=1
    else
        /bin/rm -rf "$new"
    fi

    /bin/cat > "$entry.new" <<'EOF'
# Written by deploy/darwin/tendcf-install.sh. The tendcf generic bundle, run by
# cf-execd on its schedule and by `tendcf-install.sh run-once`. No masterfiles
# policy framework: the policy is copied in by the installer, as root.
body common control
{
      inputs => { "$(sys.inputdir)/tendcf/tendcf_services.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_services" };
}

body executor control
{
      exec_command => "$(sys.cf_agent) -f $(sys.inputdir)/promises.cf";
}
EOF
    /usr/sbin/chown root:wheel "$entry.new"
    /bin/chmod 0644 "$entry.new"

    local entry_differs=0
    if [ ! -f "$entry" ] || [ -L "$entry" ]; then
        entry_differs=1
    elif ! /usr/bin/cmp -s "$entry.new" "$entry"; then
        entry_differs=1
    elif [ "$(/usr/bin/stat -f '%Su:%Sg %Lp' "$entry")" != "root:wheel 644" ]; then
        entry_differs=1
    fi
    if [ "$entry_differs" -eq 1 ]; then
        /bin/mv -f "$entry.new" "$entry"
        changed=1
    else
        /bin/rm -f "$entry.new"
    fi
}

put_data() {  # put_data FILE
    local src="$1" backup=""
    [ -f "$src" ] || die "no such data file: $src"
    [ -f "$entry" ] || die "not installed: run install first"
    if [ -L "$data" ] || [ -d "$data" ]; then
        die "$data is not a regular file; refusing"
    fi

    # Idempotent fast path: identical bytes and root:wheel 600.
    if [ -f "$data" ] \
        && /usr/bin/cmp -s "$src" "$data" \
        && [ "$(/usr/bin/stat -f '%Su:%Sg %Lp' "$data")" = "root:wheel 600" ]; then
        if ! "$cf_promises" -f "$entry" >/dev/null; then
            die "cf-promises rejected existing $data"
        fi
        return 0
    fi

    if [ -f "$data" ] && [ ! -L "$data" ]; then
        backup="$data.previous"
        /bin/cp -p "$data" "$backup"
    fi
    local tmp="$data.new"
    if ! /usr/bin/install -m 0600 -o root -g wheel "$src" "$tmp"; then
        /bin/rm -f "$tmp" "$backup"
        die "could not write $tmp"
    fi
    /bin/mv -f "$tmp" "$data"
    if ! "$cf_promises" -f "$entry" >/dev/null; then
        if [ -n "$backup" ]; then
            /bin/mv -f "$backup" "$data"
        else
            /bin/rm -f "$data"
        fi
        die "cf-promises rejected $src; previous data restored"
    fi
    /bin/rm -f "$backup"
    changed=1
    say "data installed: $data ($(/usr/bin/wc -c < "$data" | /usr/bin/tr -d ' ') bytes)"
}

check_launchd_dir() {
    check_ancestors "$launchd_dir"
    check_dir_root_unwritable "$launchd_dir"
    if [ -L "$plist_path" ] || [ -d "$plist_path" ]; then
        die "$plist_path is not a regular file; refusing"
    fi
}

render_execd_plist() {  # render_execd_plist DEST
    local dest="$1"
    /bin/cat > "$dest" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$label</string>
    <key>ProgramArguments</key>
    <array>
        <string>$cf_execd</string>
        <string>--no-fork</string>
    </array>
    <key>UserName</key>
    <string>root</string>
    <key>WorkingDirectory</key>
    <string>$prefix</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$workdir/outputs/cf-execd.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$workdir/outputs/cf-execd.stderr.log</string>
</dict>
</plist>
EOF
    /usr/sbin/chown root:wheel "$dest"
    /bin/chmod 0644 "$dest"
    /usr/bin/plutil -lint "$dest" >/dev/null || die "plutil -lint rejected generated $label plist"
}

execd_is_loaded() {
    # Classify strictly by exit code (0 = loaded, non-zero = not loaded),
    # never by parsing `launchctl print` output (launchctl(1), PR 96).
    /bin/launchctl print "system/$label" >/dev/null 2>&1
}

enable_execd() {
    check_launchd_dir
    [ -f "$entry" ] || die "not installed: run install first"

    make_stage
    local staged_plist="$stage_dir/$label.plist"
    render_execd_plist "$staged_plist"

    local plist_changed=0
    if [ ! -f "$plist_path" ]; then
        plist_changed=1
    elif ! /usr/bin/cmp -s "$staged_plist" "$plist_path"; then
        plist_changed=1
    elif [ "$(/usr/bin/stat -f '%Su:%Sg %Lp' "$plist_path")" != "root:wheel 644" ]; then
        plist_changed=1
    fi

    if [ "$plist_changed" -eq 1 ]; then
        local tmp="$plist_path.new.$$"
        if ! /usr/bin/install -m 0644 -o root -g wheel "$staged_plist" "$tmp"; then
            /bin/rm -f "$tmp"
            die "could not write $tmp"
        fi
        /bin/mv -f "$tmp" "$plist_path"
        changed=1
    fi

    if execd_is_loaded; then
        if [ "$plist_changed" -eq 1 ]; then
            /bin/launchctl bootout "system/$label" || die "launchctl bootout system/$label failed"
            /bin/launchctl bootstrap system "$plist_path" || die "launchctl bootstrap system $plist_path failed"
        fi
    else
        /bin/launchctl bootstrap system "$plist_path" || die "launchctl bootstrap system $plist_path failed"
        changed=1
    fi
}

cmd_install() {
    local tarball="" sha256_file="" datafile="" do_enable=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --tarball) [ $# -ge 2 ] || die "install: --tarball needs a path"; tarball="$2"; shift 2 ;;
            --sha256) [ $# -ge 2 ] || die "install: --sha256 needs a path"; sha256_file="$2"; shift 2 ;;
            --data) [ $# -ge 2 ] || die "install: --data needs a path"; datafile="$2"; shift 2 ;;
            --policy-src) [ $# -ge 2 ] || die "install: --policy-src needs a path"; policy_src="$2"; shift 2 ;;
            --enable) do_enable=1; shift ;;
            *) die "install: unknown argument $1" ;;
        esac
    done
    if [ -n "$sha256_file" ] && [ -z "$tarball" ]; then
        die "install: --sha256 requires --tarball"
    fi
    if [ -n "$tarball" ]; then
        if [ -z "$sha256_file" ]; then
            sha256_file="${tarball}.sha256"
        fi
        install_tarball "$tarball" "$sha256_file"
    fi
    check_tree
    init_paths
    lay_out
    place_policy
    if [ -n "$datafile" ]; then
        put_data "$datafile"
    fi
    if [ "$do_enable" -eq 1 ]; then
        enable_execd
    fi
    if [ "$changed" -eq 0 ]; then
        say "no change ($("$cf_agent" --version | /usr/bin/sed -n 1p))"
    else
        say "installed: $("$cf_agent" --version | /usr/bin/sed -n 1p)"
    fi
}

cmd_run_once() {
    [ -f "$entry" ] || die "not installed: run install first"
    [ -f "$data" ] || die "no CMDB data: run install --data FILE or data FILE first"
    "$cf_agent" -K -I -f "$entry"
}

cmd_enable() {
    enable_execd
    if [ "$changed" -eq 0 ]; then
        say "no change ($label already loaded)"
    else
        say "enabled: $label"
    fi
}

cmd_disable() {
    check_launchd_dir
    if execd_is_loaded; then
        /bin/launchctl bootout "system/$label" || die "launchctl bootout system/$label failed"
        changed=1
    fi
    if [ -f "$plist_path" ]; then
        /bin/rm -f "$plist_path"
        changed=1
    fi
    if [ "$changed" -eq 0 ]; then
        say "no change ($label already disabled)"
    else
        say "disabled: $label"
    fi
}

cmd_status() {
    local loaded_state="not loaded"
    if execd_is_loaded; then
        loaded_state="loaded"
    fi
    echo "tree:     $(/usr/bin/stat -f '%Su:%Sg %Lp' "$prefix" 2>/dev/null || echo missing)"
    echo "entry:    $([ -f "$entry" ] && echo present || echo missing)"
    echo "data:     $([ -f "$data" ] && /usr/bin/stat -f '%Su:%Sg %Lp %z bytes' "$data" || echo missing)"
    echo "$label: $([ -f "$plist_path" ] && /usr/bin/stat -f '%Su:%Sg %Lp' "$plist_path" || echo missing) / $loaded_state"
}

[ $# -ge 1 ] || die "usage: $0 install|data|run-once|enable|disable|status|workdir ..."
sub="$1"; shift
case "$sub" in
    install) cmd_install "$@" ;;
    disable) cmd_disable ;;
    workdir) init_paths; echo "$workdir" ;;
    data)
        init_paths
        [ $# -eq 1 ] || die "usage: $0 data FILE"
        put_data "$1"
        if [ "$changed" -eq 0 ]; then say "no change ($data)"; fi
        ;;
    run-once) init_paths; cmd_run_once ;;
    enable) init_paths; cmd_enable ;;
    status) init_paths; cmd_status ;;
    *) die "unknown command: $sub" ;;
esac
