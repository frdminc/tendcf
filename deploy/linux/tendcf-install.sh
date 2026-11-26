#!/bin/bash -p
# Root-owned tendcf install on a Linux host booted by systemd
# (docs/architecture/linux-targets.md, step 7). Run as root directly via a
# trusted parent/loader so /bin/bash -p suppresses BASH_ENV, ENV, and exported
# BASH_FUNC_* functions before the script's own env -i re-exec.
#
# Shape, which is CFEngine's own (the book's ch. 19/21/23, cf-execd and MPF
# docs): binaries and policy root-owned, the work directory inside the same
# root-owned tree, and a root cf-execd that runs cf-agent on a schedule. The
# work directory is whatever the binaries compile in (this fork build:
# /opt/tendcf/var/libntech, libntech's own configure names it), read from
# cf-promises, never assumed. Nothing here leaves a sudoers rule behind and
# nothing a non-root user can write is read by root.
#
#   install [--data FILE] [--policy-src DIR] [--projector-src FILE] [--projector-sha256 HEX]
#                    make /opt/tendcf root-owned, lay out the work directory, put the
#                    policy, promises.cf and projector.py in place (projector source
#                    must either be root-owned and non-writable or match --projector-sha256),
#                    optionally install the CMDB data (validated by python3 -I -S
#                    projector.py and cf-promises --show-classes before publication)
#   data FILE        replace the CMDB data (serialized via flock, validated by
#                    projector.py and cf-promises --show-classes requiring positive
#                    tendcf_cmdb_evaluated source=promise and zero refusal classes,
#                    with atomic rollback on post-publish failure or catchable
#                    SIGTERM/SIGINT interruption; uncatchable SIGKILL/power loss does
#                    not run traps)
#   run-once         one `cf-agent --no-augments -K -I` pass over the installed policy
#   enable           install and start tendcf-execd.service (root cf-execd)
#   disable          stop and remove it
#   status           what is installed and running
#
# The tree at /opt/tendcf is a CI build made with --prefix=/opt/tendcf, so its
# runtime library path is a root-owned directory; `install` refuses a binary
# whose libraries resolve anywhere an unprivileged user could place one.
set -euo pipefail

# Re-exec once under a completely clean environment (`env -i`) so no caller
# variables (LD_*, PYTHON*, TMPDIR, CFENGINE_*, CF_*, PATH, LC_ALL) can
# influence root execution. Also verify via `compgen -e` that no extra exported
# variables remain even if a caller pre-set TENDCF_CLEAN_ENV=1.
_env_clean=1
while IFS= read -r _k; do
    case "$_k" in
        TENDCF_CLEAN_ENV|PATH|LC_ALL|PWD|SHLVL|_) ;;
        *) _env_clean=0; break ;;
    esac
done < <(compgen -e)
if [ "${TENDCF_CLEAN_ENV:-}" != 1 ] \
    || [ "${PATH:-}" != "/usr/sbin:/usr/bin:/sbin:/bin" ] \
    || [ "${LC_ALL:-}" != C ] \
    || [ "$_env_clean" -ne 1 ]; then
    exec /usr/bin/env -i TENDCF_CLEAN_ENV=1 PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /bin/bash -p "$0" "$@"
fi
unset _env_clean _k

umask 022

prefix=/opt/tendcf
# RUNPATH is not inherited by a library's own dependencies: libpromises.so
# needs librsync/libb2, which the artifact bundles in $prefix/lib, and only
# a library path finds them on a host that does not have them installed
# (pastebin, 2026-10-31). Passed strictly per-invocation to CFEngine binaries
# (and ldd) rather than exported globally, so python3 -I -S never loads bundled
# libraries from $prefix/lib.
cf_lib_path="$prefix/lib"
workdir=""   # set by init_paths
unit=tendcf-execd.service
unit_path=/etc/systemd/system/$unit
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
policy_src="$here/../../policy"
projector_src=""
projector_sha256=""
installed_projector="$prefix/share/tendcf/bin/projector.py"

probe_tmp=""
place_projector_stage=""
place_projector_tmp=""
prepared_projector_stage=""
prepared_projector_file=""
projector_prepared=0
installed_projector_originally_clean=0
put_data_stage_wd=""
put_data_tmp=""
put_data_backup=""
put_data_rollback_armed=0
put_data_had_prev=0

die() { echo "tendcf-install: $*" >&2; exit 1; }
say() { echo "tendcf-install: $*"; }

# Roll back any in-flight Gate 3 publication while STILL holding FD 9, clean up
# private staging/temp files, and only then release FD 9.
cleanup_put_data() {
    if [ "${put_data_rollback_armed:-0}" -eq 1 ]; then
        if [ "${put_data_had_prev:-0}" -eq 1 ] && [ -n "${put_data_backup:-}" ] && [ -f "$put_data_backup" ]; then
            if mv -f "$put_data_backup" "$data"; then
                put_data_backup=""
                echo "tendcf-install: interrupted during post-publish validation; previous data restored" >&2
            else
                echo "tendcf-install: interrupted during post-publish validation and rollback failed; backup preserved at $put_data_backup" >&2
                put_data_backup=""
            fi
        elif [ "${put_data_had_prev:-0}" -eq 0 ] && [ -n "${data:-}" ]; then
            if rm -f "$data" && [ ! -e "$data" ] && [ ! -L "$data" ]; then
                echo "tendcf-install: removed unverified first-time data $data after failure" >&2
            else
                echo "tendcf-install: ERROR: rollback could not remove unverified data at $data; inspect manually" >&2
            fi
        fi
        put_data_rollback_armed=0
    fi
    if [ -n "${put_data_tmp:-}" ]; then
        rm -f "$put_data_tmp" || true
        put_data_tmp=""
    fi
    if [ -n "${put_data_backup:-}" ]; then
        rm -f "$put_data_backup" || true
        put_data_backup=""
    fi
    if [ -n "${put_data_stage_wd:-}" ] && [ -d "$put_data_stage_wd" ]; then
        rm -rf "$put_data_stage_wd" || true
        put_data_stage_wd=""
    fi
    exec 9>&-
}

cleanup_temp() {
    cleanup_put_data
    if [ -n "${place_projector_tmp:-}" ]; then
        rm -f "$place_projector_tmp" || true
        place_projector_tmp=""
    fi
    if [ -n "${place_projector_stage:-}" ] && [ -d "$place_projector_stage" ]; then
        rm -rf "$place_projector_stage" || true
        place_projector_stage=""
    fi
    if [ -n "${prepared_projector_stage:-}" ] && [ -d "$prepared_projector_stage" ]; then
        rm -rf "$prepared_projector_stage" || true
        prepared_projector_stage=""
        prepared_projector_file=""
    fi
    if [ -n "${probe_tmp:-}" ]; then
        rm -f "$probe_tmp" || true
        probe_tmp=""
    fi
}
trap cleanup_temp EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(id -u)" = 0 ] || die "run as root"
[ "$(uname)" = Linux ] || die "Linux only"
# install, data and run-once need no init system (a container can run them,
# which is how CI exercises them on a host without system libraries);
# only the scheduler unit does.
need_systemd() { [ -d /run/systemd/system ] || die "host is not booted by systemd"; }

cf_agent="$prefix/bin/cf-agent"
cf_promises="$prefix/bin/cf-promises"
cf_key="$prefix/bin/cf-key"
cf_execd="$prefix/bin/cf-execd"
entry=""     # set by init_paths
data=""      # set by init_paths

check_dir_root_unwritable() {
    local dir="$1" meta uid gid mode mode_oct
    [ ! -L "$dir" ] || die "$dir is a symlink; refusing"
    [ -d "$dir" ] || die "$dir is not a directory"
    meta="$(stat -c '%u %g %a' "$dir")" || die "cannot stat $dir"
    read -r uid gid mode <<< "$meta"
    [ "$uid" = 0 ] || die "$dir owned by uid $uid, expected root"
    [ "$gid" = 0 ] || die "$dir group is gid $gid, expected root"
    mode_oct=$((8#$mode))
    if [ $((mode_oct & 8#022)) -ne 0 ]; then
        die "$dir mode $mode is group- or world-writable"
    fi
}

check_regular_file_root_unwritable() {
    local f="$1" meta uid gid mode mode_oct
    [ -f "$f" ] && [ ! -L "$f" ] || die "$f is missing or not a regular non-symlink file"
    meta="$(stat -c '%u %g %a' "$f")" || die "cannot stat $f"
    read -r uid gid mode <<< "$meta"
    [ "$uid" = 0 ] || die "$f owned by uid $uid, expected root"
    [ "$gid" = 0 ] || die "$f group is gid $gid, expected root"
    mode_oct=$((8#$mode))
    if [ $((mode_oct & 8#6022)) -ne 0 ]; then
        die "$f mode $mode is group/world-writable or SUID/SGID"
    fi
}

# Non-fatal trust check: regular non-symlink file, uid 0, not group/world-writable
# or SUID/SGID, and all ancestors + symlink hops up to / are root-owned and not go-w.
source_file_root_trusted_ok() {
    local f="$1" meta uid mode mode_oct
    [ -f "$f" ] && [ ! -L "$f" ] || return 1
    check_ancestors_ok "$f" || return 1
    meta="$(stat -c '%u %a' "$f" 2>/dev/null)" || return 1
    read -r uid mode <<< "$meta"
    [ "$uid" = 0 ] || return 1
    mode_oct=$((8#$mode))
    [ $((mode_oct & 8#6022)) -eq 0 ] || return 1
    return 0
}

# Verify a regular non-symlink file is root-owned (uid 0, any root/system group)
# and not group/world-writable or SUID/SGID, and all ancestors up to / are safe.
check_source_file_root_trusted() {
    local f="$1"
    source_file_root_trusted_ok "$f" \
        || die "$f is not a root-owned non-writable regular file with trusted ancestors (or pass --projector-sha256)"
}

# Verify every directory component from $prefix down to TARGET is a real
# non-symlink root:root directory that is not group- or world-writable.
check_dir_chain_strict_under_prefix() {
    local target="$1" rel cur comp
    local comps=()
    case "$target" in
        "$prefix")
            check_dir_root_unwritable "$prefix"
            return 0
            ;;
        "$prefix"/*) ;;
        *) die "$target is outside $prefix" ;;
    esac
    check_dir_root_unwritable "$prefix"
    rel="${target#"$prefix"/}"
    IFS=/ read -r -a comps <<< "$rel"
    cur="$prefix"
    for comp in "${comps[@]}"; do
        [ -n "$comp" ] || continue
        cur="$cur/$comp"
        check_dir_root_unwritable "$cur"
    done
}

# Iteratively verify DIR and every ancestor up to / are root-owned and not
# group/world-writable, walking every symlink hop (up to 40 hops) and checking
# every intermediate directory along every hop.
check_dir_chain_ok() {
    local p="$1" hops=0 cur="/" comp target rest meta uid mode mode_oct
    case "$p" in
        /*) ;;
        *) return 1 ;;
    esac
    meta="$(stat -c '%u %a' / 2>/dev/null)" || return 1
    read -r uid mode <<< "$meta"
    [ "$uid" = 0 ] || return 1
    mode_oct=$((8#$mode))
    [ $((mode_oct & 8#022)) -eq 0 ] || return 1

    rest="${p#/}"
    while [ -n "$rest" ]; do
        comp="${rest%%/*}"
        if [ "$comp" = "$rest" ]; then
            rest=""
        else
            rest="${rest#*/}"
        fi
        if [ -z "$comp" ] || [ "$comp" = "." ]; then
            continue
        fi
        if [ "$comp" = ".." ]; then
            cur="$(dirname "$cur")"
            continue
        fi
        if [ "$cur" = "/" ]; then
            cur="/$comp"
        else
            cur="$cur/$comp"
        fi
        if [ -L "$cur" ]; then
            hops=$((hops + 1))
            [ "$hops" -le 40 ] || return 1
            uid="$(stat -c '%u' "$cur" 2>/dev/null)" || return 1
            [ "$uid" = 0 ] || return 1
            target="$(readlink "$cur")" || return 1
            [ -n "$target" ] || return 1
            if [ -n "$rest" ]; then
                rest="${target#/}/$rest"
            else
                rest="${target#/}"
            fi
            case "$target" in
                /*) cur="/" ;;
                *) cur="$(dirname "$cur")" ;;
            esac
            continue
        fi
        [ -d "$cur" ] || return 1
        meta="$(stat -c '%u %a' "$cur" 2>/dev/null)" || return 1
        read -r uid mode <<< "$meta"
        [ "$uid" = 0 ] || return 1
        mode_oct=$((8#$mode))
        [ $((mode_oct & 8#022)) -eq 0 ] || return 1
    done
    return 0
}

check_ancestor_dir_ok() {
    check_dir_chain_ok "$1"
}

check_ancestors_ok() {
    local p="$1"
    case "$p" in
        /*) ;;
        *) return 1 ;;
    esac
    check_dir_chain_ok "$(dirname "$p")"
}

resolve_safe_python_ok() {
    local p="$1" hops=0 target real_p meta uid mode mode_oct py_dir py_parent
    [ -e "$p" ] || return 1
    case "$p" in
        /*) ;;
        *) return 1 ;;
    esac
    while [ -L "$p" ]; do
        hops=$((hops + 1))
        [ "$hops" -le 40 ] || return 1
        check_ancestors_ok "$p" || return 1
        uid="$(stat -c '%u' "$p" 2>/dev/null)" || return 1
        [ "$uid" = 0 ] || return 1
        target="$(readlink "$p")" || return 1
        [ -n "$target" ] || return 1
        case "$target" in
            /*) p="$target" ;;
            *) p="$(dirname "$p")/$target" ;;
        esac
    done
    [ -f "$p" ] && [ ! -L "$p" ] && [ -x "$p" ] || return 1
    check_ancestors_ok "$p" || return 1
    real_p="$(readlink -f "$p" 2>/dev/null)" || return 1
    [ -f "$real_p" ] && [ ! -L "$real_p" ] && [ -x "$real_p" ] || return 1
    case "$real_p" in
        /usr/bin/*|/bin/*|/usr/lib/*|/usr/lib64/*) ;;
        *) return 1 ;;
    esac
    check_ancestors_ok "$real_p" || return 1
    meta="$(stat -c '%u %a' "$real_p" 2>/dev/null)" || return 1
    read -r uid mode <<< "$meta"
    [ "$uid" = 0 ] || return 1
    mode_oct=$((8#$mode))
    [ $((mode_oct & 8#6022)) -eq 0 ] || return 1
    py_dir="$(dirname "$real_p")"
    py_parent="$(dirname "$py_dir")"
    if [ -e "$py_dir/pyvenv.cfg" ] || [ -L "$py_dir/pyvenv.cfg" ] \
        || [ -e "$py_parent/pyvenv.cfg" ] || [ -L "$py_parent/pyvenv.cfg" ]; then
        return 1
    fi
    printf '%s\n' "$real_p"
}

find_trusted_python() {
    local cand real_py
    for cand in /usr/bin/python3 /bin/python3; do
        [ -x "$cand" ] || continue
        if real_py="$(resolve_safe_python_ok "$cand")"; then
            printf '%s\n' "$real_py"
            return 0
        fi
    done
    return 1
}

resolve_projector_src() {
    if [ -z "$projector_src" ]; then
        if [ -e "$here/bin/projector.py" ] || [ -L "$here/bin/projector.py" ]; then
            projector_src="$here/bin/projector.py"
        elif [ -e "$here/../../tools/projector.py" ] || [ -L "$here/../../tools/projector.py" ]; then
            projector_src="$here/../../tools/projector.py"
        elif [ -e "$here/../../bin/projector.py" ] || [ -L "$here/../../bin/projector.py" ]; then
            projector_src="$here/../../bin/projector.py"
        else
            die "projector.py not found (use --projector-src FILE)"
        fi
    fi
    [ -f "$projector_src" ] && [ ! -L "$projector_src" ] \
        || die "projector-src must be a regular non-symlink file: $projector_src"
    # Normalize relative paths to a logical absolute path (preserving any symlink
    # components in cwd/path so check_ancestors_ok inspects every hop from /).
    case "$projector_src" in
        /*) ;;
        *)
            local cwd_l
            cwd_l="$(pwd -L)"
            if [ "$cwd_l" = "/" ]; then
                projector_src="/${projector_src#./}"
            else
                projector_src="${cwd_l}/${projector_src#./}"
            fi
            ;;
    esac
}

verify_installed_projector() {
    check_ancestors_ok "$prefix" || die "unsafe ancestor above $prefix"
    check_dir_chain_strict_under_prefix "$prefix/share/tendcf/bin"
    check_regular_file_root_unwritable "$installed_projector"
}

init_paths() {
    check_ancestors_ok "$prefix" || die "unsafe ancestor above $prefix"
    check_dir_root_unwritable "$prefix"
    [ -x "$cf_promises" ] && [ ! -L "$cf_promises" ] \
        || die "$cf_promises missing: extract the CFEngine tree to $prefix first"
    local old_umask probe out
    old_umask="$(umask)"
    umask 077
    probe="$(mktemp /tmp/tendcf-probe.XXXXXX)"
    umask "$old_umask"
    probe_tmp="$probe"
    printf 'bundle agent main {}\n' > "$probe"
    out="$(LD_LIBRARY_PATH="$cf_lib_path" "$cf_promises" --show-vars -f "$probe" 2>/dev/null 9>&- | awk '$1 == "default:sys.workdir" { print $2; exit }')" || true
    rm -f "$probe"
    probe_tmp=""
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
    check_ancestors_ok "$prefix" || die "unsafe ancestor above $prefix"
    [ ! -L "$prefix" ] && [ -d "$prefix" ] || die "$prefix must be a real directory"
    [ -x "$cf_agent" ] && [ ! -L "$cf_agent" ] || die "$cf_agent missing: extract the CFEngine tree to $prefix first"
    chown -R root:root "$prefix"
    chmod -R go-w "$prefix"
    # Every library the root-run binaries load must come from the system or
    # from this tree. A build-time library path pointing into /tmp would let
    # any local user plant code that root then runs.
    local bin lib
    for bin in "$cf_agent" "$cf_execd" "$cf_promises" "$cf_key"; do
        while read -r lib; do
            case "$lib" in
                "$prefix"/*|/lib/*|/lib64/*|/usr/lib/*|/usr/lib64/*) ;;
                "") ;;
                *) die "$bin loads $lib, outside $prefix and the system library directories" ;;
            esac
        done < <(LD_LIBRARY_PATH="$cf_lib_path" ldd "$bin" 9>&- | awk '$2 == "=>" && $3 ~ /^\// { print $3 }')
    done
}

lay_out() {
    install -d -m 0755 "$workdir" "$workdir/bin" "$workdir/inputs" "$workdir/outputs" \
        "$workdir/modules" "$workdir/state"
    install -d -m 0700 "$workdir/ppkeys" "$workdir/data"
    local f
    for f in "$prefix"/bin/cf-*; do
        ln -sfn "$f" "$workdir/bin/$(basename "$f")"
    done
    if [ ! -f "$workdir/ppkeys/localhost.priv" ] || [ ! -f "$workdir/ppkeys/localhost.pub" ]; then
        # A half pair (a build step can leave one file) is not a key: start over.
        rm -f "$workdir/ppkeys/localhost.priv" "$workdir/ppkeys/localhost.pub"
        if ! keyout="$(LD_LIBRARY_PATH="$cf_lib_path" "$cf_key" 2>&1 9>&-)"; then
            die "cf-key failed: $keyout"
        fi
    fi
    [ -f "$workdir/ppkeys/localhost.pub" ] || {
        ls -la "$workdir" "$workdir/ppkeys" >&2 || true
        die "cf-key wrote no key under $workdir/ppkeys (output: ${keyout:-none})"
    }
}

place_policy() {
    [ -f "$policy_src/tendcf_services.cf" ] || die "no policy at $policy_src (use --policy-src DIR)"
    local new="$workdir/inputs/.tendcf.new"
    rm -rf "$new"
    cp -R "$policy_src" "$new"
    chown -R root:root "$new"
    chmod -R go-w "$new"
    rm -rf "$workdir/inputs/tendcf"
    mv "$new" "$workdir/inputs/tendcf"
    cat > "$entry.new" <<'EOF'
# Written by deploy/linux/tendcf-install.sh. The tendcf generic bundle, run by
# cf-execd on its schedule and by `tendcf-install.sh run-once`. No masterfiles
# policy framework: the policy is copied in by the installer, as root.
body common control
{
      inputs => { "$(sys.inputdir)/tendcf/tendcf_services.cf" };
      bundlesequence => { "tendcf_interlocks", "tendcf_services" };
}

body executor control
{
      exec_command => "$(sys.cf_agent) --no-augments -f $(sys.inputdir)/promises.cf";
}
EOF
    chmod 0644 "$entry.new"
    mv -f "$entry.new" "$entry"
}

# Non-fatal check: $installed_projector is already a completely clean, trusted
# regular non-symlink file (root:root 0644) under real non-symlink root:root
# non-writable directories up to /.
installed_projector_clean_ok() {
    check_ancestors_ok "$prefix" || return 1
    local d meta uid gid mode
    for d in "$prefix" "$prefix/share" "$prefix/share/tendcf" "$prefix/share/tendcf/bin"; do
        [ ! -L "$d" ] && [ -d "$d" ] || return 1
        meta="$(stat -c '%u %g %a' "$d" 2>/dev/null)" || return 1
        read -r uid gid mode <<< "$meta"
        [ "$uid" = 0 ] && [ "$gid" = 0 ] || return 1
        [ $((8#$mode & 8#022)) -eq 0 ] || return 1
    done
    [ -f "$installed_projector" ] && [ ! -L "$installed_projector" ] || return 1
    meta="$(stat -c '%u %g %a' "$installed_projector" 2>/dev/null)" || return 1
    read -r uid gid mode <<< "$meta"
    [ "$uid" = 0 ] && [ "$gid" = 0 ] && [ $((8#$mode)) -eq $((8#644)) ] || return 1
    return 0
}

# Establish projector source trust and stage bytes into a private root-only
# 0700 temp file BEFORE check_tree() repairs permissions under $prefix (so a
# formerly writable/non-root source can never be laundered to root-owned, and
# hash verification happens once against the private copy).
prepare_projector_source() {
    resolve_projector_src
    if [ -n "$projector_sha256" ] && [[ ! "$projector_sha256" =~ ^[0-9a-f]{64}$ ]]; then
        die "install: --projector-sha256 must be 64 lowercase hex characters"
    fi
    local src_trusted=0
    if source_file_root_trusted_ok "$projector_src"; then
        src_trusted=1
    fi
    if [ -z "$projector_sha256" ] && [ "$src_trusted" -ne 1 ]; then
        die "$projector_src is not a root-owned non-writable regular file with trusted ancestors (or pass --projector-sha256)"
    fi

    if [ -n "${prepared_projector_stage:-}" ] && [ -d "$prepared_projector_stage" ]; then
        rm -rf "$prepared_projector_stage"
        prepared_projector_stage=""
        prepared_projector_file=""
    fi
    local old_umask stage_d staged_p actual_sha
    old_umask="$(umask)"
    umask 077
    stage_d="$(mktemp -d /tmp/tendcf-proj-stage.XXXXXX)"
    umask "$old_umask"
    prepared_projector_stage="$stage_d"
    chown root:root "$stage_d"
    chmod 0700 "$stage_d"

    staged_p="$stage_d/projector.py"
    old_umask="$(umask)"
    umask 077
    cat "$projector_src" > "$staged_p"
    umask "$old_umask"
    chown root:root "$staged_p"
    chmod 0600 "$staged_p"
    prepared_projector_file="$staged_p"

    if [ -n "$projector_sha256" ]; then
        actual_sha="$(sha256sum "$staged_p" | awk '{ print tolower($1) }')"
        if [ "$actual_sha" != "$projector_sha256" ]; then
            die "projector sha256 mismatch for $projector_src: expected $projector_sha256, got $actual_sha"
        fi
    fi
    projector_prepared=1
}

# Refuse ANY unsafe existing directory in $prefix..$prefix/share/tendcf/bin
# BEFORE mutating permissions or running check_tree() (zero directory mutation,
# eliminating TOCTOU/SIGKILL parent-laundering windows), and detach any unsafe
# existing leaf inside an already-trusted parent chain.
detach_unsafe_installed_projector() {
    check_ancestors_ok "$prefix" || die "unsafe ancestor above $prefix"
    installed_projector_originally_clean=0
    local d
    for d in "$prefix" "$prefix/share" "$prefix/share/tendcf" "$prefix/share/tendcf/bin"; do
        if [ ! -e "$d" ] && [ ! -L "$d" ]; then
            break
        fi
        check_dir_root_unwritable "$d"
    done
    if [ -e "$installed_projector" ] || [ -L "$installed_projector" ]; then
        if installed_projector_clean_ok; then
            installed_projector_originally_clean=1
            return 0
        fi
        if [ -d "$installed_projector" ] && [ ! -L "$installed_projector" ]; then
            die "$installed_projector is a directory; refusing"
        fi
        rm -f "$installed_projector"
        if [ -e "$installed_projector" ] || [ -L "$installed_projector" ]; then
            die "could not remove untrusted $installed_projector"
        fi
    fi
}

place_projector() {
    [ "${projector_prepared:-0}" -eq 1 ] \
        && [ -n "${prepared_projector_file:-}" ] \
        && [ -f "$prepared_projector_file" ] \
        && [ ! -L "$prepared_projector_file" ] \
        || die "projector source was not prepared or staged copy is missing"
    check_ancestors_ok "$prefix" || die "unsafe ancestor above $prefix"
    local d
    for d in "$prefix/share" "$prefix/share/tendcf" "$prefix/share/tendcf/bin"; do
        [ ! -L "$d" ] || die "$d is a symlink; refusing"
        if [ -e "$d" ] && [ ! -d "$d" ]; then
            die "$d is not a directory; refusing"
        fi
        install -d -m 0755 -o root -g root "$d"
        check_dir_root_unwritable "$d"
    done
    if [ -L "$installed_projector" ] || [ -d "$installed_projector" ]; then
        die "$installed_projector is not a regular file; refusing"
    fi

    # Operate exclusively from $prepared_projector_file (never re-resolve or
    # re-read $projector_src). Keep the existing inode ONLY when it was already
    # proven clean before check_tree(), matches $prepared_projector_file byte
    # for byte, and still passes installed_projector_clean_ok.
    if [ "${installed_projector_originally_clean:-0}" -eq 1 ] \
        && [ -f "$installed_projector" ] && [ ! -L "$installed_projector" ] \
        && cmp -s "$prepared_projector_file" "$installed_projector" \
        && installed_projector_clean_ok; then
        :
    else
        local old_umask tmp
        old_umask="$(umask)"
        umask 022
        tmp="$(mktemp "$prefix/share/tendcf/bin/.projector.py.new.XXXXXX")"
        umask "$old_umask"
        place_projector_tmp="$tmp"
        cat "$prepared_projector_file" > "$tmp"
        chown root:root "$tmp"
        chmod 0644 "$tmp"
        mv -f "$tmp" "$installed_projector"
        place_projector_tmp=""
    fi

    if [ -n "${prepared_projector_stage:-}" ] && [ -d "$prepared_projector_stage" ]; then
        rm -rf "$prepared_projector_stage"
        prepared_projector_stage=""
        prepared_projector_file=""
    fi
    projector_prepared=0
    verify_installed_projector
}

# Validate CMDB data in WD using cf-promises --show-classes (issue #57).
# Captures stdout to a 0600 file in TMP_DIR (never pipes cf-promises directly),
# closes FD 9 in the child, and runs a single status-checked awk scanner that:
#   - rejects any tendcf_cmdb_refused or tendcf_cmdb_problem_* class (exit 2),
#   - requires positive tendcf_cmdb_evaluated with source=promise (exit 3),
#   - fails closed on any non-zero cf-promises or awk exit status.
validate_cmdb_workdir() {  # validate_cmdb_workdir WD ENTRY_FILE TMP_DIR
    local wd="$1" entry_file="$2" tmp_dir="$3"
    local old_umask classes_file err_file parse_msg="" awk_rc=0
    old_umask="$(umask)"
    umask 077
    classes_file="$(mktemp "$tmp_dir/.cf-classes.XXXXXX")"
    err_file="$(mktemp "$tmp_dir/.cf-err.XXXXXX")"
    umask "$old_umask"
    chmod 0600 "$classes_file" "$err_file"

    if ! LD_LIBRARY_PATH="$cf_lib_path" "$cf_promises" --workdir "$wd" -f "$entry_file" --show-classes >"$classes_file" 2>"$err_file" 9>&-; then
        if [ -s "$err_file" ]; then
            cat "$err_file" >&2
        fi
        rm -f "$classes_file" "$err_file"
        echo "tendcf-install: cf-promises failed validating $wd" >&2
        return 1
    fi

    parse_msg="$(awk '
        $1 == "tendcf_cmdb_evaluated" && $0 ~ /(^|[[:space:],])source=promise([[:space:],]|$)/ { saw_eval = 1 }
        $1 == "tendcf_cmdb_refused" || $1 ~ /^tendcf_cmdb_problem_/ {
            if (!($1 in seen)) {
                seen[$1] = 1
                bad[++nbad] = $1
            }
        }
        END {
            if (nbad > 0) {
                for (i = 1; i <= nbad; i++) {
                    printf "%s%s", (i > 1 ? " " : ""), bad[i]
                }
                printf "\n"
                exit 2
            }
            if (!saw_eval) {
                print "missing positive tendcf_cmdb_evaluated (source=promise) marker"
                exit 3
            }
            exit 0
        }
    ' "$classes_file")" || awk_rc=$?
    rm -f "$classes_file" "$err_file"

    if [ "$awk_rc" -eq 2 ]; then
        echo "tendcf-install: CMDB policy refused data in $wd (classes: $parse_msg)" >&2
        return 1
    elif [ "$awk_rc" -eq 3 ]; then
        echo "tendcf-install: cf-promises --show-classes invalid for $wd: $parse_msg" >&2
        return 1
    elif [ "$awk_rc" -ne 0 ]; then
        echo "tendcf-install: failed to parse cf-promises --show-classes output for $wd (awk exit $awk_rc)" >&2
        return 1
    fi
    return 0
}

check_policy_tree_root_unwritable() {
    local bad_pol
    bad_pol="$(find "$workdir/inputs/tendcf" \( ! -type f ! -type d -o ! -user 0 -o ! -group 0 -o -perm -020 -o -perm -002 -o -perm -4000 -o -perm -2000 \) -print -quit)"
    [ -z "$bad_pol" ] || die "unsafe entry in $workdir/inputs/tendcf: $bad_pol"
}

put_data() {  # put_data FILE
    local src="$1"
    [ -f "$src" ] && [ ! -L "$src" ] || die "data file must be a regular non-symlink file: $src"
    check_ancestors_ok "$prefix" || die "unsafe ancestor above $prefix"
    check_dir_chain_strict_under_prefix "$workdir"
    check_dir_chain_strict_under_prefix "$workdir/data"
    check_dir_chain_strict_under_prefix "$workdir/inputs"
    check_dir_chain_strict_under_prefix "$workdir/inputs/tendcf"
    check_regular_file_root_unwritable "$entry"
    check_policy_tree_root_unwritable
    verify_installed_projector

    local py
    py="$(find_trusted_python)" || die "cannot validate projection: no trusted root-owned python3 found"

    # Serialize concurrent publishers on an exclusive lock (issue #58).
    # Pre-check against symlinks, directories, FIFOs, sockets, and devices so
    # opening FD 9 can never block on a FIFO or follow a symlink.
    local lockfile="$workdir/data/.publish.lock"
    if [ -e "$lockfile" ] || [ -L "$lockfile" ]; then
        [ -f "$lockfile" ] && [ ! -L "$lockfile" ] || die "$lockfile is not a regular file; refusing"
    fi
    local old_umask
    old_umask="$(umask)"
    umask 077
    exec 9>>"$lockfile"
    umask "$old_umask"
    if ! flock -x 9; then
        exec 9>&-
        die "failed to acquire publish lock $lockfile"
    fi
    if [ -L "$lockfile" ] || [ ! -f "$lockfile" ]; then
        exec 9>&-
        die "$lockfile is not a regular file; refusing"
    fi
    chown root:root "$lockfile"
    chmod 0600 "$lockfile"

    if [ -e "$data" ] || [ -L "$data" ]; then
        if [ -L "$data" ] || [ ! -f "$data" ]; then
            exec 9>&-
            die "$data is not a regular file; refusing"
        fi
    fi

    # Stage candidate bytes ONCE into a private 0700 workdir under verified
    # root-owned $workdir (never $TMPDIR / /tmp; zero TOCTOU, zero pre-validation
    # exposure to cf-execd; issues #53, #57).
    local stage_wd staged_data data_bytes
    old_umask="$(umask)"
    umask 077
    stage_wd="$(mktemp -d "$workdir/.putdata.XXXXXX")"
    umask "$old_umask"
    put_data_stage_wd="$stage_wd"
    chown root:root "$stage_wd"
    chmod 0700 "$stage_wd"

    install -d -m 0755 -o root -g root \
        "$stage_wd/bin" "$stage_wd/outputs" "$stage_wd/modules" "$stage_wd/state"
    install -d -m 0700 -o root -g root "$stage_wd/ppkeys" "$stage_wd/data"
    cp -pRP "$workdir/inputs" "$stage_wd/inputs"

    staged_data="$stage_wd/data/host_specific.json"
    old_umask="$(umask)"
    umask 077
    cat "$src" > "$staged_data"
    umask "$old_umask"
    chown root:root "$staged_data"
    chmod 0600 "$staged_data"

    # Gate 1 (#53): projector contract check (stdlib-only isolated python3 -I -S,
    # FD 9 closed in child, no LD_LIBRARY_PATH, site-packages disabled).
    if ! "$py" -I -S "$installed_projector" --check "$staged_data" 9>&-; then
        die "projector rejected $src; live $data untouched"
    fi

    # Gate 2 (#57): pre-publish cf-promises --show-classes check on staged workdir.
    if ! validate_cmdb_workdir "$stage_wd" "$stage_wd/inputs/promises.cf" "$stage_wd"; then
        die "pre-publish CMDB validation rejected $src; live $data untouched"
    fi

    data_bytes="$(wc -c < "$staged_data" | tr -d ' ')"

    # Idempotent fast path (under lock, after Gates 1 & 2).
    if [ -f "$data" ] && [ ! -L "$data" ] \
        && cmp -s "$staged_data" "$data" \
        && [ "$(stat -c '%U:%G %a' "$data")" = "root:root 600" ]; then
        if ! validate_cmdb_workdir "$workdir" "$entry" "$stage_wd"; then
            die "existing live $data failed CMDB validation"
        fi
        cleanup_put_data
        say "data unchanged: $data ($data_bytes bytes)"
        return 0
    fi

    # Atomic publish using unique same-directory mktemp staging/backup paths (#58).
    local tmp backup=""
    put_data_had_prev=0
    put_data_rollback_armed=0
    old_umask="$(umask)"
    umask 077
    tmp="$(mktemp "$workdir/data/.host_specific.new.XXXXXX")"
    umask "$old_umask"
    put_data_tmp="$tmp"
    cat "$staged_data" > "$tmp"
    chown root:root "$tmp"
    chmod 0600 "$tmp"

    if [ -f "$data" ] && [ ! -L "$data" ]; then
        old_umask="$(umask)"
        umask 077
        backup="$(mktemp "$workdir/data/.host_specific.prev.XXXXXX")"
        umask "$old_umask"
        put_data_backup="$backup"
        put_data_had_prev=1
        cat "$data" > "$backup"
        chown root:root "$backup"
        chmod 0600 "$backup"
    fi

    # Arm rollback right before atomic swap so any failure or catchable
    # SIGTERM/SIGINT during Gate 3 restores $backup (or removes first-time $data)
    # under FD 9 instead of deleting the backup.
    put_data_rollback_armed=1
    mv -f "$tmp" "$data"
    put_data_tmp=""

    # Gate 3 (#57): post-publish verification on live workdir with atomic rollback.
    if ! validate_cmdb_workdir "$workdir" "$entry" "$stage_wd"; then
        if [ "$put_data_had_prev" -eq 1 ]; then
            if ! mv -f "$backup" "$data"; then
                put_data_backup=""
                put_data_rollback_armed=0
                die "cf-promises rejected $src and rollback failed; backup preserved at $backup"
            fi
            put_data_backup=""
            put_data_rollback_armed=0
            die "post-publish CMDB validation rejected $src; previous data restored"
        else
            if rm -f "$data" && [ ! -e "$data" ] && [ ! -L "$data" ]; then
                put_data_rollback_armed=0
                die "post-publish CMDB validation rejected $src; new data removed"
            else
                put_data_rollback_armed=0
                die "post-publish CMDB validation rejected $src and rollback could not remove unverified data at $data; inspect manually"
            fi
        fi
    fi

    put_data_rollback_armed=0
    if [ -n "$backup" ]; then
        rm -f "$backup"
        put_data_backup=""
    fi
    cleanup_put_data
    say "data installed: $data ($data_bytes bytes)"
}

prevalidate_install_inputs() {
    local datafile="$1"
    [ ! -L "$policy_src" ] && [ -d "$policy_src" ] \
        || die "policy-src must be a real directory (not a symlink): $policy_src"
    [ -f "$policy_src/tendcf_services.cf" ] && [ ! -L "$policy_src/tendcf_services.cf" ] \
        || die "no regular tendcf_services.cf at $policy_src (use --policy-src DIR)"
    resolve_projector_src
    if [ -n "$projector_sha256" ] && [[ ! "$projector_sha256" =~ ^[0-9a-f]{64}$ ]]; then
        die "install: --projector-sha256 must be 64 lowercase hex characters"
    fi
    if [ -n "$datafile" ]; then
        [ ! -L "$datafile" ] && [ -f "$datafile" ] \
            || die "data file must be a regular non-symlink file: $datafile"
    fi
}

cmd_install() {
    local datafile=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --data) [ $# -ge 2 ] && [ -n "$2" ] || die "install: --data needs a non-empty path"; datafile="$2"; shift 2 ;;
            --policy-src) [ $# -ge 2 ] && [ -n "$2" ] || die "install: --policy-src needs a non-empty path"; policy_src="$2"; shift 2 ;;
            --projector-src) [ $# -ge 2 ] && [ -n "$2" ] || die "install: --projector-src needs a non-empty path"; projector_src="$2"; shift 2 ;;
            --projector-sha256) [ $# -ge 2 ] && [ -n "$2" ] || die "install: --projector-sha256 needs a 64-hex sha256"; projector_sha256="$2"; shift 2 ;;
            *) die "install: unknown argument $1" ;;
        esac
    done
    prevalidate_install_inputs "$datafile"
    prepare_projector_source
    detach_unsafe_installed_projector
    check_tree
    init_paths
    lay_out
    place_policy
    place_projector
    if [ -n "$datafile" ]; then put_data "$datafile"; fi
    say "installed: $(LD_LIBRARY_PATH="$cf_lib_path" "$cf_agent" --version | head -1)"
}

cmd_run_once() {
    [ -f "$entry" ] || die "not installed: run install first"
    [ -f "$data" ] || die "no CMDB data: run install --data FILE or data FILE first"
    LD_LIBRARY_PATH="$cf_lib_path" "$cf_agent" --no-augments -K -I -f "$entry"
}

cmd_enable() {
    need_systemd
    [ -f "$entry" ] || die "not installed: run install first"
    cat > "$unit_path.new" <<EOF
# Written by deploy/linux/tendcf-install.sh
[Unit]
Description=tendcf agent scheduler (cf-execd runs cf-agent on schedule)
After=network.target

[Service]
Type=simple
Environment=LD_LIBRARY_PATH=$prefix/lib
ExecStart=$cf_execd --no-fork
Restart=on-failure
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$unit_path.new"
    mv -f "$unit_path.new" "$unit_path"
    systemctl daemon-reload
    systemctl enable --now "$unit"
    say "enabled: $unit"
}

cmd_disable() {
    need_systemd
    systemctl disable --now "$unit" 2>/dev/null || true
    rm -f "$unit_path"
    systemctl daemon-reload
    say "disabled: $unit"
}

cmd_status() {
    echo "tree:     $(stat -c '%U:%G %a' "$prefix" 2>/dev/null || echo missing)"
    echo "entry:    $([ -f "$entry" ] && echo present || echo missing)"
    echo "data:     $([ -f "$data" ] && stat -c '%U:%G %a %s bytes' "$data" || echo missing)"
    echo "$unit: $(systemctl is-enabled "$unit" 2>&1 || true) / $(systemctl is-active "$unit" 2>&1 || true)"
}

[ $# -ge 1 ] || die "usage: $0 install|data|run-once|enable|disable|status ..."
sub="$1"; shift
case "$sub" in
    install) cmd_install "$@" ;;
    disable) cmd_disable ;;
    workdir) init_paths; echo "$workdir" ;;
    data) init_paths; [ $# -eq 1 ] && [ -n "$1" ] || die "usage: $0 data FILE"; put_data "$1" ;;
    run-once) init_paths; cmd_run_once ;;
    enable) init_paths; cmd_enable ;;
    status) init_paths; cmd_status ;;
    *) die "unknown command: $sub" ;;
esac
