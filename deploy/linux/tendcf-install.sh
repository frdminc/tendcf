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
#           [--audit-log-src FILE] [--audit-log-sha256 HEX] [--lock-auditd]
#                    make /opt/tendcf root-owned, lay out the work directory, put the
#                    policy, promises.cf, projector.py and audit_log.py in place
#                    (projector and audit_log sources must either be root-owned and
#                    non-writable or match --projector-sha256 / --audit-log-sha256),
#                    create private audit spool/config directories and install
#                    auditd + AIDE tripwire rules (pass --lock-auditd to include
#                    immutable `-e 2` in auditd rules), and optionally install CMDB
#                    data (validated by python3 -I -S projector.py and cf-promises
#                    --show-classes before publication)
#   data FILE        replace the CMDB data (serialized via flock, validated by
#                    projector.py and cf-promises --show-classes requiring positive
#                    tendcf_cmdb_evaluated source=promise and zero refusal classes,
#                    with atomic rollback on post-publish failure or catchable
#                    SIGTERM/SIGINT interruption; uncatchable SIGKILL/power loss does
#                    not run traps)
#   run-once         one `cf-agent --no-augments -K -I` pass over the installed policy
#   enable           install and start tendcf-execd.service (root cf-execd) and,
#                    when audit_log.py is installed, tendcf-audit-shipper.{service,timer}
#   disable          stop and remove tendcf-execd.service and tendcf-audit-shipper.{service,timer}
#   uninstall [--purge-spool]
#                    disable/remove scheduler + audit shipper units, remove installed
#                    auditd/AIDE tripwire rules, shipper config and audit_log.py
#                    (preserves /opt/tendcf/var/audit-spool unless --purge-spool)
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
shipper_service=tendcf-audit-shipper.service
shipper_timer=tendcf-audit-shipper.timer
shipper_service_path=/etc/systemd/system/$shipper_service
shipper_timer_path=/etc/systemd/system/$shipper_timer
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
policy_src="$here/../../policy"
projector_src=""
projector_sha256=""
installed_projector="$prefix/share/tendcf/bin/projector.py"
audit_log_src=""
audit_log_sha256=""
audit_log_explicit=0
installed_audit_log="$prefix/share/tendcf/bin/audit_log.py"
audit_etc_dir="$prefix/etc"
audit_shipper_cfg="$audit_etc_dir/audit-shipper.json"
audit_spool_dir="$prefix/var/audit-spool"
tripwire_share_dir="$prefix/share/tendcf/tripwire"
auditd_rules_dir=/etc/audit/rules.d
auditd_rules_path="$auditd_rules_dir/99-tendcf-tripwire.rules"
aide_rules_dir=/etc/aide/aide.conf.d
aide_rules_path="$aide_rules_dir/99-tendcf-tripwire"
lock_auditd=0

probe_tmp=""
place_projector_stage=""
place_projector_tmp=""
prepared_projector_stage=""
prepared_projector_file=""
projector_prepared=0
installed_projector_originally_clean=0
place_audit_log_tmp=""
prepared_audit_log_stage=""
prepared_audit_log_file=""
audit_log_prepared=0
installed_audit_log_originally_clean=0
lifecycle_lock_held=0
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
    if [ -n "${place_audit_log_tmp:-}" ]; then
        rm -f "$place_audit_log_tmp" || true
        place_audit_log_tmp=""
    fi
    if [ -n "${prepared_audit_log_stage:-}" ] && [ -d "$prepared_audit_log_stage" ]; then
        rm -rf "$prepared_audit_log_stage" || true
        prepared_audit_log_stage=""
        prepared_audit_log_file=""
    fi
    if [ -n "${probe_tmp:-}" ]; then
        rm -f "$probe_tmp" || true
        probe_tmp=""
    fi
    if [ "${lifecycle_lock_held:-0}" -eq 1 ]; then
        exec 8>&-
        lifecycle_lock_held=0
    fi
}
trap cleanup_temp EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Serialize all mutating lifecycle operations (install, data, enable, disable,
# uninstall) on one fixed root-controlled lock outside $prefix (FD 8; distinct
# from put_data's FD 9 data-publish lock so nested install --data never
# self-deadlocks; H1/M1). Never falls back to a shared writable directory.
lifecycle_lock_parent=/run
lifecycle_lock_dir="$lifecycle_lock_parent/tendcf"
lifecycle_lock_file="$lifecycle_lock_dir/install.lock"

acquire_lifecycle_lock() {
    if [ "${lifecycle_lock_held:-0}" -eq 1 ]; then
        return 0
    fi
    if [ ! -d "$lifecycle_lock_parent" ] || [ -L "$lifecycle_lock_parent" ] \
        || ! check_dir_chain_ok "$lifecycle_lock_parent"; then
        die "lifecycle lock parent $lifecycle_lock_parent is missing or untrusted; refusing"
    fi
    if [ -e "$lifecycle_lock_dir" ] || [ -L "$lifecycle_lock_dir" ]; then
        check_private_dir_exact "$lifecycle_lock_dir"
    else
        install -d -m 0700 -o root -g root "$lifecycle_lock_dir"
        check_private_dir_exact "$lifecycle_lock_dir"
    fi
    if [ -e "$lifecycle_lock_file" ] || [ -L "$lifecycle_lock_file" ]; then
        check_private_file_exact "$lifecycle_lock_file"
    fi
    local old_umask fd_meta path_id
    old_umask="$(umask)"
    umask 077
    exec 8>>"$lifecycle_lock_file"
    umask "$old_umask"
    if ! flock -x 8; then
        exec 8>&-
        die "failed to acquire lifecycle lock $lifecycle_lock_file"
    fi
    # Descriptor-bound verification: never chown/chmod by pathname after open.
    fd_meta="$(stat -L -c '%u:%g %a %h %d:%i' /proc/self/fd/8 2>/dev/null || true)"
    path_id="$(stat -c '%d:%i' "$lifecycle_lock_file" 2>/dev/null || true)"
    if [ -L "$lifecycle_lock_file" ] || [ ! -f "$lifecycle_lock_file" ] \
        || [ -z "$path_id" ] || [ "$fd_meta" != "0:0 600 1 $path_id" ]; then
        exec 8>&-
        die "lifecycle lock $lifecycle_lock_file failed descriptor verification (got '${fd_meta:-none}')"
    fi
    lifecycle_lock_held=1
}

release_lifecycle_lock() {
    if [ "${lifecycle_lock_held:-0}" -eq 1 ]; then
        exec 8>&-
        lifecycle_lock_held=0
    fi
}

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
    out="$(LD_LIBRARY_PATH="$cf_lib_path" "$cf_promises" --show-vars -f "$probe" 2>/dev/null 8>&- 9>&- | awk '$1 == "default:sys.workdir" { print $2; exit }')" || true
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
    # Repair ownership/mode on the install tree while explicitly excluding
    # private audit state ($audit_etc_dir, $audit_spool_dir) and any Python
    # bytecode cache (__pycache__) so pre-existing untrusted state can never
    # be laundered into root-owned trust (H1, H2).
    find "$prefix" \
        \( -path "$audit_etc_dir" -o -path "$audit_spool_dir" -o -name __pycache__ \) -prune -o \
        -exec chown -h root:root {} +
    find "$prefix" \
        \( -path "$audit_etc_dir" -o -path "$audit_spool_dir" -o -name __pycache__ \) -prune -o \
        ! -type l -exec chmod go-w {} +
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
        done < <(LD_LIBRARY_PATH="$cf_lib_path" ldd "$bin" 8>&- 9>&- | awk '$2 == "=>" && $3 ~ /^\// { print $3 }')
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
        if ! keyout="$(LD_LIBRARY_PATH="$cf_lib_path" "$cf_key" 2>&1 8>&- 9>&-)"; then
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

resolve_audit_log_src() {
    if [ -z "$audit_log_src" ]; then
        if [ -e "$here/bin/audit_log.py" ] || [ -L "$here/bin/audit_log.py" ]; then
            audit_log_src="$here/bin/audit_log.py"
        elif [ -e "$here/../../tools/audit_log.py" ] || [ -L "$here/../../tools/audit_log.py" ]; then
            audit_log_src="$here/../../tools/audit_log.py"
        elif [ -e "$here/../../bin/audit_log.py" ] || [ -L "$here/../../bin/audit_log.py" ]; then
            audit_log_src="$here/../../bin/audit_log.py"
        else
            if [ "${audit_log_explicit:-0}" -eq 1 ] || [ -n "$audit_log_sha256" ]; then
                die "audit_log.py not found (use --audit-log-src FILE)"
            fi
            return 1
        fi
    fi
    [ -f "$audit_log_src" ] && [ ! -L "$audit_log_src" ] \
        || die "audit-log-src must be a regular non-symlink file: $audit_log_src"
    case "$audit_log_src" in
        /*) ;;
        *)
            local cwd_l
            cwd_l="$(pwd -L)"
            if [ "$cwd_l" = "/" ]; then
                audit_log_src="/${audit_log_src#./}"
            else
                audit_log_src="${cwd_l}/${audit_log_src#./}"
            fi
            ;;
    esac
    return 0
}

verify_installed_audit_log() {
    check_ancestors_ok "$prefix" || die "unsafe ancestor above $prefix"
    check_dir_chain_strict_under_prefix "$prefix/share/tendcf/bin"
    check_regular_file_root_unwritable "$installed_audit_log"
}

installed_audit_log_clean_ok() {
    check_ancestors_ok "$prefix" || return 1
    local d meta uid gid mode
    for d in "$prefix" "$prefix/share" "$prefix/share/tendcf" "$prefix/share/tendcf/bin"; do
        [ ! -L "$d" ] && [ -d "$d" ] || return 1
        meta="$(stat -c '%u %g %a' "$d" 2>/dev/null)" || return 1
        read -r uid gid mode <<< "$meta"
        [ "$uid" = 0 ] && [ "$gid" = 0 ] || return 1
        [ $((8#$mode & 8#022)) -eq 0 ] || return 1
    done
    [ -f "$installed_audit_log" ] && [ ! -L "$installed_audit_log" ] || return 1
    meta="$(stat -c '%u %g %a' "$installed_audit_log" 2>/dev/null)" || return 1
    read -r uid gid mode <<< "$meta"
    [ "$uid" = 0 ] && [ "$gid" = 0 ] && [ $((8#$mode)) -eq $((8#644)) ] || return 1
    return 0
}

prepare_audit_log_source() {
    audit_log_prepared=0
    if ! resolve_audit_log_src; then
        return 0
    fi
    if [ -n "$audit_log_sha256" ] && [[ ! "$audit_log_sha256" =~ ^[0-9a-f]{64}$ ]]; then
        die "install: --audit-log-sha256 must be 64 lowercase hex characters"
    fi
    local src_trusted=0
    if source_file_root_trusted_ok "$audit_log_src"; then
        src_trusted=1
    fi
    if [ -z "$audit_log_sha256" ] && [ "$src_trusted" -ne 1 ]; then
        die "$audit_log_src is not a root-owned non-writable regular file with trusted ancestors (or pass --audit-log-sha256)"
    fi

    if [ -n "${prepared_audit_log_stage:-}" ] && [ -d "$prepared_audit_log_stage" ]; then
        rm -rf "$prepared_audit_log_stage"
        prepared_audit_log_stage=""
        prepared_audit_log_file=""
    fi
    local old_umask stage_d staged_a actual_sha
    old_umask="$(umask)"
    umask 077
    stage_d="$(mktemp -d /tmp/tendcf-audit-stage.XXXXXX)"
    umask "$old_umask"
    prepared_audit_log_stage="$stage_d"
    chown root:root "$stage_d"
    chmod 0700 "$stage_d"

    staged_a="$stage_d/audit_log.py"
    old_umask="$(umask)"
    umask 077
    cat "$audit_log_src" > "$staged_a"
    umask "$old_umask"
    chown root:root "$staged_a"
    chmod 0600 "$staged_a"
    prepared_audit_log_file="$staged_a"

    if [ -n "$audit_log_sha256" ]; then
        actual_sha="$(sha256sum "$staged_a" | awk '{ print tolower($1) }')"
        if [ "$actual_sha" != "$audit_log_sha256" ]; then
            die "audit_log sha256 mismatch for $audit_log_src: expected $audit_log_sha256, got $actual_sha"
        fi
    fi
    audit_log_prepared=1
}

# Validate any pre-existing audit config/spool state BEFORE check_tree() so an
# untrusted owner/mode/hardlink/symlink can never be laundered into root trust (H1).
check_private_dir_exact() {  # check_private_dir_exact DIR
    local d="$1" meta uid gid mode
    [ ! -L "$d" ] && [ -d "$d" ] || die "$d is not a real directory; refusing"
    meta="$(stat -c '%u %g %a' "$d")" || die "cannot stat $d"
    read -r uid gid mode <<< "$meta"
    [ "$uid" = 0 ] && [ "$gid" = 0 ] && [ $((8#$mode)) -eq $((8#700)) ] \
        || die "$d has untrusted ownership/mode ($uid:$gid $mode), expected 0:0 700"
}

check_private_file_exact() {  # check_private_file_exact FILE
    local f="$1" meta uid gid mode nlink
    [ ! -L "$f" ] && [ -f "$f" ] || die "$f is not a regular non-symlink file; refusing"
    meta="$(stat -c '%u %g %a %h' "$f")" || die "cannot stat $f"
    read -r uid gid mode nlink <<< "$meta"
    [ "$uid" = 0 ] && [ "$gid" = 0 ] && [ $((8#$mode)) -eq $((8#600)) ] && [ "$nlink" = 1 ] \
        || die "$f has untrusted ownership/mode/links ($uid:$gid $mode links=$nlink), expected 0:0 600 links=1"
}

validate_existing_audit_state_before_repair() {
    check_ancestors_ok "$prefix" || die "unsafe ancestor above $prefix"
    if [ -e "$prefix" ] || [ -L "$prefix" ]; then
        check_dir_root_unwritable "$prefix"
    fi
    if [ -e "$prefix/share/tendcf/bin/__pycache__" ] || [ -L "$prefix/share/tendcf/bin/__pycache__" ]; then
        die "unexpected bytecode cache at $prefix/share/tendcf/bin/__pycache__; refusing"
    fi
    if [ -e "$audit_etc_dir" ] || [ -L "$audit_etc_dir" ]; then
        check_private_dir_exact "$audit_etc_dir"
        if [ -e "$audit_shipper_cfg" ] || [ -L "$audit_shipper_cfg" ]; then
            check_private_file_exact "$audit_shipper_cfg"
        fi
    fi
    if [ -e "$audit_spool_dir" ] || [ -L "$audit_spool_dir" ]; then
        check_dir_root_unwritable "$prefix/var"
        check_private_dir_exact "$audit_spool_dir"
        local had_nullglob=0 had_dotglob=0 ent
        shopt -q nullglob && had_nullglob=1
        shopt -q dotglob && had_dotglob=1
        shopt -s nullglob dotglob
        for ent in "$audit_spool_dir"/*; do
            local base="${ent##*/}"
            [ "$base" != "." ] && [ "$base" != ".." ] || continue
            check_private_file_exact "$ent"
        done
        if [ "$had_nullglob" -eq 0 ]; then shopt -u nullglob; fi
        if [ "$had_dotglob" -eq 0 ]; then shopt -u dotglob; fi
    fi
}

detach_unsafe_installed_audit_log() {
    # Validate complete parent chain BEFORE touching or unlinking any leaf (H3).
    check_ancestors_ok "$prefix" || die "unsafe ancestor above $prefix"
    installed_audit_log_originally_clean=0
    local d
    for d in "$prefix" "$prefix/share" "$prefix/share/tendcf" "$prefix/share/tendcf/bin"; do
        if [ ! -e "$d" ] && [ ! -L "$d" ]; then
            break
        fi
        check_dir_root_unwritable "$d"
    done
    if [ -e "$installed_audit_log" ] || [ -L "$installed_audit_log" ]; then
        if installed_audit_log_clean_ok; then
            installed_audit_log_originally_clean=1
            return 0
        fi
        if [ -d "$installed_audit_log" ] && [ ! -L "$installed_audit_log" ]; then
            die "$installed_audit_log is a directory; refusing"
        fi
        rm -f "$installed_audit_log"
        if [ -e "$installed_audit_log" ] || [ -L "$installed_audit_log" ]; then
            die "could not remove untrusted $installed_audit_log"
        fi
    fi
}

place_audit_log() {
    if [ "${audit_log_prepared:-0}" -ne 1 ]; then
        return 0
    fi
    [ -n "${prepared_audit_log_file:-}" ] \
        && [ -f "$prepared_audit_log_file" ] \
        && [ ! -L "$prepared_audit_log_file" ] \
        || die "audit_log source was not prepared or staged copy is missing"
    check_ancestors_ok "$prefix" || die "unsafe ancestor above $prefix"
    check_dir_chain_strict_under_prefix "$prefix/share/tendcf/bin"
    if [ -L "$installed_audit_log" ] || [ -d "$installed_audit_log" ]; then
        die "$installed_audit_log is not a regular file; refusing"
    fi
    if [ "${installed_audit_log_originally_clean:-0}" -eq 1 ] \
        && [ -f "$installed_audit_log" ] && [ ! -L "$installed_audit_log" ] \
        && cmp -s "$prepared_audit_log_file" "$installed_audit_log" \
        && installed_audit_log_clean_ok; then
        :
    else
        local old_umask tmp
        old_umask="$(umask)"
        umask 022
        tmp="$(mktemp "$prefix/share/tendcf/bin/.audit_log.py.new.XXXXXX")"
        umask "$old_umask"
        place_audit_log_tmp="$tmp"
        cat "$prepared_audit_log_file" > "$tmp"
        chown root:root "$tmp"
        chmod 0644 "$tmp"
        mv -f "$tmp" "$installed_audit_log"
        place_audit_log_tmp=""
    fi
    if [ -n "${prepared_audit_log_stage:-}" ] && [ -d "$prepared_audit_log_stage" ]; then
        rm -rf "$prepared_audit_log_stage"
        prepared_audit_log_stage=""
        prepared_audit_log_file=""
    fi
    audit_log_prepared=0
    verify_installed_audit_log
}

place_audit_shipper_state() {
    check_ancestors_ok "$prefix" || die "unsafe ancestor above $prefix"
    check_dir_root_unwritable "$prefix"
    local d
    for d in "$audit_etc_dir" "$prefix/var" "$audit_spool_dir"; do
        [ ! -L "$d" ] || die "$d is a symlink; refusing"
        if [ -e "$d" ] && [ ! -d "$d" ]; then
            die "$d is not a directory; refusing"
        fi
    done
    if [ -d "$audit_etc_dir" ]; then
        check_private_dir_exact "$audit_etc_dir"
    else
        install -d -m 0700 -o root -g root "$audit_etc_dir"
        check_private_dir_exact "$audit_etc_dir"
    fi
    if [ -d "$prefix/var" ]; then
        check_dir_root_unwritable "$prefix/var"
    else
        install -d -m 0755 -o root -g root "$prefix/var"
        check_dir_root_unwritable "$prefix/var"
    fi
    if [ -d "$audit_spool_dir" ]; then
        check_private_dir_exact "$audit_spool_dir"
    else
        install -d -m 0700 -o root -g root "$audit_spool_dir"
        check_private_dir_exact "$audit_spool_dir"
    fi
    if [ -e "$audit_shipper_cfg" ] || [ -L "$audit_shipper_cfg" ]; then
        check_private_file_exact "$audit_shipper_cfg"
    else
        local host_name old_umask tmp_cfg
        host_name="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo localhost)"
        if [[ ! "$host_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]]; then
            host_name="localhost"
        fi
        old_umask="$(umask)"
        umask 077
        tmp_cfg="$(mktemp "$audit_etc_dir/.audit-shipper.json.new.XXXXXX")"
        umask "$old_umask"
        printf '{"enabled":false,"host":"%s","spool_dir":"%s","src":"tendcf"}\n' \
            "$host_name" "$audit_spool_dir" > "$tmp_cfg"
        chown root:root "$tmp_cfg"
        chmod 0600 "$tmp_cfg"
        mv -f "$tmp_cfg" "$audit_shipper_cfg"
    fi
}

render_linux_tripwire_auditd() {  # render_linux_tripwire_auditd DEST [INCLUDE_LOCK]
    local dest="$1" include_lock="${2:-0}"
    local unit_dir seen="|" p
    unit_dir="$(dirname "$unit_path")"
    emit_watch() {
        local wp="$1"
        case "$seen" in
            *"|$wp|"*) return 0 ;;
        esac
        seen="${seen}${wp}|"
        printf -- '-w %s -p wa -k tendcf_tripwire\n' "$wp" >> "$dest"
    }
    # Watch validated existing directories/files (falling back to an existing
    # trusted parent whenever an optional sensitive leaf is absent; M3/M5).
    cat > "$dest" <<EOF
# Managed by deploy/linux/tendcf-install.sh (issue #119 Slice 2).
# Watches tendcf binaries, policy, CMDB data dir, shipper config dir, systemd unit dir,
# sudoers, and root authorized_keys for writes or attribute changes.
EOF
    for p in "$prefix/bin" "$prefix/lib" "$prefix/share/tendcf" \
        "$workdir/inputs" "$workdir/data" "$audit_etc_dir" "$unit_dir"; do
        if [ -d "$p" ] && [ ! -L "$p" ]; then
            emit_watch "$p"
        fi
    done
    if [ -e /etc/sudoers ] && [ ! -L /etc/sudoers ]; then
        emit_watch /etc/sudoers
    elif [ -d /etc ] && [ ! -L /etc ]; then
        emit_watch /etc
    fi
    if [ -d /etc/sudoers.d ] && [ ! -L /etc/sudoers.d ]; then
        emit_watch /etc/sudoers.d
    elif [ -d /etc ] && [ ! -L /etc ]; then
        emit_watch /etc
    fi
    if [ -e /root/.ssh/authorized_keys ] && [ ! -L /root/.ssh/authorized_keys ]; then
        emit_watch /root/.ssh/authorized_keys
    elif [ -d /root/.ssh ] && [ ! -L /root/.ssh ]; then
        emit_watch /root/.ssh
    elif [ -d /root ] && [ ! -L /root ]; then
        emit_watch /root
    fi
    if [ "$include_lock" -eq 1 ]; then
        printf '# Immutable auditd lock requested via --lock-auditd (requires reboot to change)\n-e 2\n' >> "$dest"
    else
        printf '# To lock kernel audit rules until reboot, re-run install with --lock-auditd (adds -e 2)\n' >> "$dest"
    fi
}

render_linux_tripwire_aide() {  # render_linux_tripwire_aide DEST
    local dest="$1"
    cat > "$dest" <<EOF
# Managed by deploy/linux/tendcf-install.sh (issue #119 Slice 2).
# AIDE integrity rules for tendcf binaries, policy, CMDB data, units, sudoers, authorized_keys.
$prefix/bin p+i+n+u+g+s+m+c+sha256
$prefix/lib p+i+n+u+g+s+m+c+sha256
$prefix/share/tendcf p+i+n+u+g+s+m+c+sha256
$workdir/inputs p+i+n+u+g+s+m+c+sha256
$workdir/data/host_specific.json p+i+n+u+g+s+m+c+sha256
$audit_shipper_cfg p+i+n+u+g+s+m+c+sha256
$unit_path p+i+n+u+g+s+m+c+sha256
$shipper_service_path p+i+n+u+g+s+m+c+sha256
$shipper_timer_path p+i+n+u+g+s+m+c+sha256
/etc/sudoers p+i+n+u+g+s+m+c+sha256
/etc/sudoers.d p+i+n+u+g+s+m+c+sha256
/root/.ssh/authorized_keys p+i+n+u+g+s+m+c+sha256
EOF
}

# Compare the complete normalized expected watch set in RULES_FILE against
# active kernel rules from `auditctl -l`. Accepts ONLY the exact installed
# watch syntax or the exact proven-equivalent unconditional kernel-normalized
# syscall-watch form (rejecting extra subject/arch/syscall filters and
# file-vs-dir scope mismatches; H2). Prints missing watch paths (if any) and
# exits non-zero if any expected watch is missing or RULES_FILE has none.
verify_auditd_expected_watches() {  # verify_auditd_expected_watches RULES_FILE ACTL_BIN
    local rules_file="$1" actl="$2" active_rules exp_spec="" line wp kind
    active_rules="$("$actl" -l 8>&- 9>&- 2>/dev/null)" || return 1
    while IFS= read -r line; do
        case "$line" in
            "-w "*" -p wa -k tendcf_tripwire")
                wp="${line#-w }"
                wp="${wp% -p wa -k tendcf_tripwire}"
                if [ -d "$wp" ] && [ ! -L "$wp" ]; then
                    kind="dir"
                else
                    kind="file"
                fi
                exp_spec="${exp_spec}${kind}=${wp}|"
                ;;
        esac
    done < "$rules_file"
    awk -v exp_spec="$exp_spec" '
        function norm(p) {
            if (p != "/") sub(/\/+$/, "", p)
            return p
        }
        BEGIN {
            exp_n = 0
            n_lines = split(exp_spec, elines, "|")
            for (i = 1; i <= n_lines; i++) {
                if (elines[i] == "") continue
                eq = index(elines[i], "=")
                if (eq <= 1) continue
                k = substr(elines[i], 1, eq - 1)
                p = norm(substr(elines[i], eq + 1))
                if (p != "" && !((k ":" p) in exp_seen)) {
                    exp_seen[k ":" p] = 1
                    exp_kind[++exp_n] = k
                    exp_path[exp_n] = p
                }
            }
        }
        {
            # Shape 1: exact unconditional watch syntax: -w PATH -p (wa|aw) -k tendcf_tripwire
            if (NF == 6 && $1 == "-w" && $3 == "-p" && ($4 == "wa" || $4 == "aw") && $5 == "-k" && $6 == "tendcf_tripwire") {
                p = norm($2)
                active_dir[p] = 1
                active_file[p] = 1
                next
            }
            # Shape 2: exact unconditional kernel-normalized watch syntax:
            # -a always,exit [-S all] with ONLY -F (dir=P|path=P), -F perm=(wa|aw), -F key=tendcf_tripwire.
            if (NF < 8 || $1 != "-a" || ($2 != "always,exit" && $2 != "exit,always")) next
            idx = 3
            if ($idx == "-S") {
                if (idx + 1 > NF || $(idx + 1) != "all") next
                idx += 2
            }
            bad = 0; seen_target = 0; target_kind = ""; target_path = ""
            seen_perm = 0; seen_key = 0
            while (idx <= NF) {
                if ($idx != "-F" || idx + 1 > NF) { bad = 1; break }
                pred = $(idx + 1)
                idx += 2
                if (pred ~ /^dir=/) {
                    if (seen_target) { bad = 1; break }
                    seen_target = 1; target_kind = "dir"
                    target_path = norm(substr(pred, 5))
                } else if (pred ~ /^path=/) {
                    if (seen_target) { bad = 1; break }
                    seen_target = 1; target_kind = "file"
                    target_path = norm(substr(pred, 6))
                } else if (pred == "perm=wa" || pred == "perm=aw") {
                    if (seen_perm) { bad = 1; break }
                    seen_perm = 1
                } else if (pred == "key=tendcf_tripwire") {
                    if (seen_key) { bad = 1; break }
                    seen_key = 1
                } else {
                    # Any extra filter (uid=, auid=, arch=, success=, etc.) weakens/narrows semantics: reject!
                    bad = 1; break
                }
            }
            if (!bad && seen_target && seen_perm && seen_key && target_path != "") {
                if (target_kind == "dir") active_dir[target_path] = 1
                else active_file[target_path] = 1
            }
        }
        END {
            if (exp_n == 0) { print "no-expected-watches"; exit 1 }
            miss = ""
            for (i = 1; i <= exp_n; i++) {
                k = exp_kind[i]; p = exp_path[i]
                ok = (k == "dir") ? (p in active_dir) : (p in active_file)
                if (!ok) miss = (miss == "" ? k ":" p : miss "," k ":" p)
            }
            if (miss != "") { print miss; exit 1 }
            exit 0
        }
    ' <<< "$active_rules"
}

# Check that EVERY *.rules entry in $auditd_rules_dir resolves to a readable
# regular file (supporting symlinks to regular files, rejecting FIFOs/broken
# links before open) and contains NO uncommented `-e 2` directive using a
# single pipe-free awk pass (zero SIGPIPE under pipefail; H1).
# Exit codes:
#   0 = positively safe (every entry inspected cleanly, none requests -e 2)
#   1 = confirmed -e 2 lock directive found
#   2 = error / non-regular / unreadable / parser failure (fail closed)
check_auditd_rules_dir_safe_to_load() {
    local f awk_rc=0 had_ng=0
    [ -d "$auditd_rules_dir" ] || return 2
    shopt -q nullglob && had_ng=1
    shopt -s nullglob
    for f in "$auditd_rules_dir"/*.rules; do
        if [ ! -f "$f" ] || [ ! -r "$f" ]; then
            if [ "$had_ng" -eq 0 ]; then shopt -u nullglob; fi
            return 2
        fi
        awk_rc=0
        awk '
            {
                gsub(/\r/, "")
                if ($0 ~ /^[[:space:]]*-e[[:space:]]+2([[:space:]#]|$)/) found = 1
            }
            END { exit (found ? 10 : 0) }
        ' "$f" 2>/dev/null || awk_rc=$?
        if [ "$awk_rc" -eq 10 ]; then
            if [ "$had_ng" -eq 0 ]; then shopt -u nullglob; fi
            return 1
        elif [ "$awk_rc" -ne 0 ]; then
            if [ "$had_ng" -eq 0 ]; then shopt -u nullglob; fi
            return 2
        fi
    done
    if [ "$had_ng" -eq 0 ]; then shopt -u nullglob; fi
    return 0
}

write_auditd_rule_files() {  # write_auditd_rule_files INCLUDE_LOCK
    local include_lock="${1:-0}" old_umask tmp_share tmp_etc
    old_umask="$(umask)"
    umask 022
    tmp_share="$(mktemp "$tripwire_share_dir/.auditd.new.XXXXXX")"
    umask "$old_umask"
    render_linux_tripwire_auditd "$tmp_share" "$include_lock"
    chown root:root "$tmp_share"
    chmod 0640 "$tmp_share"
    mv -f "$tmp_share" "$tripwire_share_dir/99-tendcf-tripwire.rules"

    tmp_etc="$(mktemp "$auditd_rules_dir/.99-tendcf-tripwire.rules.new.XXXXXX")"
    cp -p "$tripwire_share_dir/99-tendcf-tripwire.rules" "$tmp_etc"
    chown root:root "$tmp_etc"
    chmod 0640 "$tmp_etc"
    mv -f "$tmp_etc" "$auditd_rules_path"
}

# Append ONLY the immutable lock directive (-e 2) to the ALREADY-VERIFIED frozen
# rule file bytes (never re-rendering optional paths between verification and
# lock; H2).
append_lock_to_frozen_auditd_rules() {
    local old_umask tmp_share tmp_etc
    old_umask="$(umask)"
    umask 022
    tmp_share="$(mktemp "$tripwire_share_dir/.auditd.lock.XXXXXX")"
    umask "$old_umask"
    grep -Ev '^[[:space:]]*-e[[:space:]]+2([[:space:]#]|$)' "$auditd_rules_path" > "$tmp_share"
    printf '# Immutable auditd lock requested via --lock-auditd (requires reboot to change)\n-e 2\n' >> "$tmp_share"
    chown root:root "$tmp_share"
    chmod 0640 "$tmp_share"
    mv -f "$tmp_share" "$tripwire_share_dir/99-tendcf-tripwire.rules"

    tmp_etc="$(mktemp "$auditd_rules_dir/.99-tendcf-tripwire.lock.XXXXXX")"
    cp -p "$tripwire_share_dir/99-tendcf-tripwire.rules" "$tmp_etc"
    chown root:root "$tmp_etc"
    chmod 0640 "$tmp_etc"
    mv -f "$tmp_etc" "$auditd_rules_path"
}

reload_auditd_tripwire() {
    local augen="" actl="" missing="" already_locked=0
    if [ -x /sbin/augenrules ]; then augen=/sbin/augenrules; elif [ -x /usr/sbin/augenrules ]; then augen=/usr/sbin/augenrules; fi
    if [ -x /sbin/auditctl ]; then actl=/sbin/auditctl; elif [ -x /usr/sbin/auditctl ]; then actl=/usr/sbin/auditctl; fi

    if [ -n "$augen" ] && [ -d /run/systemd/system ] \
        && systemctl is-active --quiet auditd 8>&- 9>&- 2>/dev/null; then
        if [ -n "$actl" ] && "$actl" -s 8>&- 9>&- 2>/dev/null | grep -Eq '^enabled[[:space:]]+2$'; then
            already_locked=1
        fi
        if [ "$already_locked" -eq 0 ]; then
            local safe_rc=0
            check_auditd_rules_dir_safe_to_load || safe_rc=$?
            if [ "$safe_rc" -ne 0 ]; then
                if [ "${lock_auditd:-0}" -eq 1 ]; then
                    die "--lock-auditd requested, but auditd rules preflight failed (rc=$safe_rc: drop-in requests -e 2 or is non-regular/unreadable); refusing premature lock before verifying tendcf_tripwire coverage"
                fi
                say "tripwire: warning: auditd rules preflight failed (rc=$safe_rc: drop-in requests -e 2 or is non-regular/unreadable); rules staged at $auditd_rules_path without running augenrules --load"
                return 0
            fi
        fi
        if [ "$already_locked" -eq 0 ]; then
            if ! "$augen" --load 8>&- 9>&- >/dev/null 2>&1; then
                if [ "${lock_auditd:-0}" -eq 1 ]; then
                    die "--lock-auditd requested, but augenrules --load failed"
                fi
                say "tripwire: auditd rules staged at $auditd_rules_path (augenrules --load returned non-zero; rules may already be immutable)"
                return 0
            fi
        fi
        if [ -z "$actl" ]; then
            if [ "${lock_auditd:-0}" -eq 1 ]; then
                die "--lock-auditd requested, but auditctl is unavailable to verify complete watch coverage"
            fi
            say "tripwire: incomplete auditd verification at $auditd_rules_path (auditctl not found)"
            return 0
        fi
        if ! missing="$(verify_auditd_expected_watches "$auditd_rules_path" "$actl")"; then
            if [ "${lock_auditd:-0}" -eq 1 ]; then
                die "--lock-auditd requested, but expected tripwire watches are missing from auditctl -l (${missing:-query-failed}); refusing to lock"
            fi
            say "tripwire: incomplete auditd coverage at $auditd_rules_path (missing active watches: ${missing:-query-failed})"
            return 0
        fi
        if [ "${lock_auditd:-0}" -eq 1 ]; then
            # Freeze the verified rule bytes and append ONLY -e 2 (never re-render; H2).
            append_lock_to_frozen_auditd_rules
            if [ "$already_locked" -eq 0 ]; then
                if ! "$augen" --load 8>&- 9>&- >/dev/null 2>&1; then
                    die "--lock-auditd requested, but augenrules --load failed while applying -e 2"
                fi
            fi
            if ! missing="$(verify_auditd_expected_watches "$auditd_rules_path" "$actl")"; then
                die "--lock-auditd requested, but expected tripwire watches disappeared after lock (${missing:-query-failed})"
            fi
            if ! "$actl" -s 8>&- 9>&- 2>/dev/null | grep -Eq '^enabled[[:space:]]+2$'; then
                die "--lock-auditd requested, but auditctl -s did not confirm immutable mode (enabled 2)"
            fi
            say "tripwire: all expected auditd watches verified active and locked immutable (-e 2)"
        else
            say "tripwire: all expected auditd watches verified active ($auditd_rules_path)"
        fi
    else
        if [ "${lock_auditd:-0}" -eq 1 ]; then
            die "--lock-auditd requested, but active auditd + augenrules/auditctl are not available on this host"
        fi
        say "tripwire: auditd rules staged only at $auditd_rules_path (auditd not active)"
    fi
}

place_tripwire_rules() {
    check_ancestors_ok "$prefix" || die "unsafe ancestor above $prefix"
    check_dir_chain_strict_under_prefix "$prefix/share/tendcf"
    [ ! -L "$tripwire_share_dir" ] || die "$tripwire_share_dir is a symlink; refusing"
    if [ -e "$tripwire_share_dir" ] && [ ! -d "$tripwire_share_dir" ]; then
        die "$tripwire_share_dir is not a directory; refusing"
    fi
    install -d -m 0755 -o root -g root "$tripwire_share_dir"
    check_dir_root_unwritable "$tripwire_share_dir"

    local old_umask tmp_aide
    old_umask="$(umask)"
    umask 022
    tmp_aide="$(mktemp "$tripwire_share_dir/.aide.new.XXXXXX")"
    umask "$old_umask"

    render_linux_tripwire_aide "$tmp_aide"
    chown root:root "$tmp_aide"
    chmod 0644 "$tmp_aide"
    mv -f "$tmp_aide" "$tripwire_share_dir/99-tendcf-tripwire.aide"

    # Install system-level auditd and AIDE drop-in rules into trusted /etc trees,
    # preserving existing package directory modes/permissions (M3).
    check_dir_chain_ok /etc || die "/etc is not a trusted root-owned non-writable directory"
    local d
    for d in /etc/audit "$auditd_rules_dir"; do
        [ ! -L "$d" ] || die "$d is a symlink; refusing"
        if [ -e "$d" ] && [ ! -d "$d" ]; then
            die "$d is not a directory; refusing"
        fi
        if [ ! -d "$d" ]; then
            install -d -m 0750 -o root -g root "$d"
        fi
        check_dir_root_unwritable "$d"
    done
    [ ! -L "$auditd_rules_path" ] && [ ! -d "$auditd_rules_path" ] \
        || die "$auditd_rules_path is not a regular file; refusing"
    # Always stage watch rules without -e 2 first; reload_auditd_tripwire only
    # writes -e 2 after confirming complete expected watch coverage (M5).
    write_auditd_rule_files 0

    for d in /etc/aide "$aide_rules_dir"; do
        [ ! -L "$d" ] || die "$d is a symlink; refusing"
        if [ -e "$d" ] && [ ! -d "$d" ]; then
            die "$d is not a directory; refusing"
        fi
        if [ ! -d "$d" ]; then
            install -d -m 0755 -o root -g root "$d"
        fi
        check_dir_root_unwritable "$d"
    done
    [ ! -L "$aide_rules_path" ] && [ ! -d "$aide_rules_path" ] \
        || die "$aide_rules_path is not a regular file; refusing"
    tmp_aide="$(mktemp "$aide_rules_dir/.99-tendcf-tripwire.new.XXXXXX")"
    cp -p "$tripwire_share_dir/99-tendcf-tripwire.aide" "$tmp_aide"
    chown root:root "$tmp_aide"
    chmod 0644 "$tmp_aide"
    mv -f "$tmp_aide" "$aide_rules_path"

    reload_auditd_tripwire
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

    if ! LD_LIBRARY_PATH="$cf_lib_path" "$cf_promises" --workdir "$wd" -f "$entry_file" --show-classes >"$classes_file" 2>"$err_file" 8>&- 9>&-; then
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
    if ! "$py" -I -S "$installed_projector" --check "$staged_data" 8>&- 9>&-; then
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
    if [ -n "${audit_log_sha256:-}" ] && [[ ! "$audit_log_sha256" =~ ^[0-9a-f]{64}$ ]]; then
        die "install: --audit-log-sha256 must be 64 lowercase hex characters"
    fi
    if [ "${audit_log_explicit:-0}" -eq 1 ] || [ -n "${audit_log_sha256:-}" ]; then
        resolve_audit_log_src || die "audit_log.py not found (use --audit-log-src FILE)"
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
            --audit-log-src) [ $# -ge 2 ] && [ -n "$2" ] || die "install: --audit-log-src needs a non-empty path"; audit_log_src="$2"; audit_log_explicit=1; shift 2 ;;
            --audit-log-sha256) [ $# -ge 2 ] && [ -n "$2" ] || die "install: --audit-log-sha256 needs a 64-hex sha256"; audit_log_sha256="$2"; audit_log_explicit=1; shift 2 ;;
            --lock-auditd) lock_auditd=1; shift ;;
            *) die "install: unknown argument $1" ;;
        esac
    done
    prevalidate_install_inputs "$datafile"
    acquire_lifecycle_lock
    prepare_projector_source
    prepare_audit_log_source
    validate_existing_audit_state_before_repair
    detach_unsafe_installed_projector
    detach_unsafe_installed_audit_log
    check_tree
    init_paths
    lay_out
    place_policy
    place_projector
    place_audit_log
    place_audit_shipper_state
    if [ -n "$datafile" ]; then put_data "$datafile"; fi
    place_tripwire_rules
    release_lifecycle_lock
    say "installed: $(LD_LIBRARY_PATH="$cf_lib_path" "$cf_agent" --version | head -1)"
}

cmd_run_once() {
    [ -f "$entry" ] || die "not installed: run install first"
    [ -f "$data" ] || die "no CMDB data: run install --data FILE or data FILE first"
    LD_LIBRARY_PATH="$cf_lib_path" "$cf_agent" --no-augments -K -I -f "$entry"
}

enable_audit_shipper() {
    if [ ! -f "$installed_audit_log" ] || [ -L "$installed_audit_log" ]; then
        return 0
    fi
    verify_installed_projector
    verify_installed_audit_log
    place_audit_shipper_state
    local py old_umask tmp_svc tmp_tmr
    py="$(find_trusted_python)" || die "cannot enable audit shipper: no trusted root-owned python3 found"
    check_dir_root_unwritable /etc/systemd/system
    [ ! -L "$shipper_service_path" ] && [ ! -d "$shipper_service_path" ] \
        || die "$shipper_service_path is not a regular file; refusing"
    [ ! -L "$shipper_timer_path" ] && [ ! -d "$shipper_timer_path" ] \
        || die "$shipper_timer_path is not a regular file; refusing"
    old_umask="$(umask)"
    umask 022
    tmp_svc="$(mktemp /etc/systemd/system/.tendcf-audit-shipper.service.new.XXXXXX)"
    umask "$old_umask"
    cat > "$tmp_svc" <<EOF
# Written by deploy/linux/tendcf-install.sh (issue #119 Slice 2)
[Unit]
Description=tendcf tamper-evident audit log shipper
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
ExecStart=$py -I -S $installed_audit_log ship --config $audit_shipper_cfg --expected-spool-dir $audit_spool_dir
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=$audit_spool_dir
EOF
    chown root:root "$tmp_svc"
    chmod 0644 "$tmp_svc"
    mv -f "$tmp_svc" "$shipper_service_path"

    old_umask="$(umask)"
    umask 022
    tmp_tmr="$(mktemp /etc/systemd/system/.tendcf-audit-shipper.timer.new.XXXXXX)"
    umask "$old_umask"
    cat > "$tmp_tmr" <<EOF
# Written by deploy/linux/tendcf-install.sh (issue #119 Slice 2)
[Unit]
Description=Periodic tendcf audit log shipper timer

[Timer]
OnBootSec=60s
OnUnitActiveSec=5m
RandomizedDelaySec=15s
Persistent=true
Unit=$shipper_service

[Install]
WantedBy=timers.target
EOF
    chown root:root "$tmp_tmr"
    chmod 0644 "$tmp_tmr"
    mv -f "$tmp_tmr" "$shipper_timer_path"
}

cmd_enable() {
    need_systemd
    acquire_lifecycle_lock
    init_paths
    [ -f "$entry" ] || die "not installed: run install first"
    check_dir_root_unwritable /etc/systemd/system
    [ ! -L "$unit_path" ] && [ ! -d "$unit_path" ] \
        || die "$unit_path is not a regular file; refusing"
    local old_umask tmp_unit
    old_umask="$(umask)"
    umask 022
    tmp_unit="$(mktemp /etc/systemd/system/.tendcf-execd.service.new.XXXXXX)"
    umask "$old_umask"
    cat > "$tmp_unit" <<EOF
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
    chown root:root "$tmp_unit"
    chmod 0644 "$tmp_unit"
    mv -f "$tmp_unit" "$unit_path"
    enable_audit_shipper
    systemctl daemon-reload 8>&- 9>&-
    systemctl enable --now "$unit" 8>&- 9>&-
    if [ -f "$shipper_timer_path" ]; then
        systemctl enable --now "$shipper_timer" 8>&- 9>&-
        say "enabled: $unit and $shipper_timer"
    else
        say "enabled: $unit"
    fi
    if [ -f "$auditd_rules_path" ]; then
        reload_auditd_tripwire
    fi
    release_lifecycle_lock
}

stop_and_disable_unit() {  # stop_and_disable_unit UNIT UNIT_PATH
    local u="$1" upath="$2" load_state="" active_state=""
    load_state="$(systemctl show -p LoadState --value "$u" 8>&- 9>&- 2>/dev/null)" \
        || die "systemctl show LoadState failed for $u; refusing to remove unit or state"
    if [ "$load_state" = "not-found" ] && [ ! -e "$upath" ] && [ ! -L "$upath" ]; then
        return 0
    fi
    if systemctl is-enabled --quiet "$u" 8>&- 9>&- 2>/dev/null || systemctl is-active --quiet "$u" 8>&- 9>&- 2>/dev/null; then
        systemctl disable --now "$u" 8>&- 9>&- || die "failed to stop/disable $u"
    elif [ -e "$upath" ]; then
        systemctl disable "$u" 8>&- 9>&- >/dev/null 2>&1 || true
        systemctl stop "$u" 8>&- 9>&- || die "failed to stop $u"
    fi
    active_state="$(systemctl show -p ActiveState --value "$u" 8>&- 9>&- 2>/dev/null)" \
        || die "systemctl show ActiveState failed for $u; refusing to remove unit or state"
    case "$active_state" in
        inactive|failed) ;;
        *) die "$u ActiveState is '${active_state:-unknown}' after stop; refusing to remove unit or state" ;;
    esac
}

disable_units() {
    if [ -d /run/systemd/system ]; then
        stop_and_disable_unit "$shipper_timer" "$shipper_timer_path"
        stop_and_disable_unit "$shipper_service" "$shipper_service_path"
        stop_and_disable_unit "$unit" "$unit_path"
    fi
    local u
    for u in "$shipper_timer_path" "$shipper_service_path" "$unit_path"; do
        if [ -e "$u" ] || [ -L "$u" ]; then
            check_ancestors_ok "$u" || die "unsafe ancestor for $u; refusing removal"
            [ ! -L "$u" ] && [ -f "$u" ] || die "$u is not a regular file; refusing removal"
            rm -f "$u"
        fi
    done
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload 8>&- 9>&-
    fi
}

cmd_disable() {
    need_systemd
    acquire_lifecycle_lock
    disable_units
    release_lifecycle_lock
    say "disabled: $unit and $shipper_timer"
}

remove_managed_file_safe() {  # remove_managed_file_safe PATH
    local target="$1"
    if [ ! -e "$target" ] && [ ! -L "$target" ]; then
        return 0
    fi
    check_ancestors_ok "$target" || die "unsafe ancestor for $target; refusing removal"
    [ ! -L "$target" ] && [ -f "$target" ] || die "$target is not a regular file; refusing removal"
    rm -f "$target"
}

# Validate a single complete mountinfo snapshot and test whether TARGET_PATH
# appears as a mount point. Exit codes:
#   0 = confirmed mount match
#   1 = valid non-empty mountinfo with root '/' confirmed, target NOT mounted
#   2 = unreadable, empty, or malformed mountinfo (missing evidence; fail closed; M1)
mountinfo_contains_target() {  # mountinfo_contains_target MOUNTINFO_FILE TARGET_PATH
    local mi_file="$1" target="$2" snapshot=""
    [ -r "$mi_file" ] || return 2
    snapshot="$(cat "$mi_file" 2>/dev/null)" || return 2
    [ -n "$snapshot" ] || return 2
    awk -v target="$target" '
        /^[[:space:]]*$/ { next }
        {
            if (NF < 7 || $1 !~ /^[0-9]+$/ || $2 !~ /^[0-9]+$/) { bad=1; exit 2 }
            rows++
            if ($5 == "/") has_root = 1
            if ($5 == target) found = 1
        }
        END {
            if (bad || rows == 0 || !has_root) exit 2
            exit (found ? 0 : 1)
        }
    ' <<< "$snapshot"
}

purge_audit_spool_safe() {
    if [ ! -e "$audit_spool_dir" ] && [ ! -L "$audit_spool_dir" ]; then
        return 0
    fi
    check_ancestors_ok "$audit_spool_dir" || die "unsafe ancestor for $audit_spool_dir; refusing purge"
    check_private_dir_exact "$audit_spool_dir"
    local parent_dev spool_dev mi_rc=0
    parent_dev="$(stat -c '%d' "$(dirname "$audit_spool_dir")")" || die "cannot stat parent of $audit_spool_dir"
    spool_dev="$(stat -c '%d' "$audit_spool_dir")" || die "cannot stat $audit_spool_dir"
    [ "$spool_dev" = "$parent_dev" ] || die "$audit_spool_dir crosses a mount boundary; refusing purge"
    # Bind production entry point directly to /proc/self/mountinfo (no env/var
    # override) and fail closed on unreadable/empty/corrupt mountinfo (M1).
    local real_spool
    real_spool="$(readlink -f "$audit_spool_dir" 2>/dev/null)" || die "cannot resolve realpath of $audit_spool_dir; refusing purge"
    mi_rc=0
    mountinfo_contains_target /proc/self/mountinfo "$real_spool" || mi_rc=$?
    if [ "$mi_rc" -eq 0 ]; then
        die "$audit_spool_dir is a mount point (including bind mount); refusing purge"
    elif [ "$mi_rc" -ne 1 ]; then
        die "cannot verify /proc/self/mountinfo evidence for $audit_spool_dir; refusing purge"
    fi
    local had_nullglob=0 had_dotglob=0 ent base ent_dev real_ent
    local to_remove=()
    shopt -q nullglob && had_nullglob=1
    shopt -q dotglob && had_dotglob=1
    shopt -s nullglob dotglob
    # Preflight EVERY managed leaf (allowlist matching tools/audit_log.py AuditSpool:
    # audit.jsonl, cursor.json, .spool.lock) and its mount status BEFORE deleting anything (M1).
    for ent in "$audit_spool_dir"/*; do
        base="${ent##*/}"
        [ "$base" != "." ] && [ "$base" != ".." ] || continue
        case "$base" in
            audit.jsonl|cursor.json|.spool.lock) ;;
            *)
                if [ "$had_nullglob" -eq 0 ]; then shopt -u nullglob; fi
                if [ "$had_dotglob" -eq 0 ]; then shopt -u dotglob; fi
                die "unexpected entry in $audit_spool_dir ($base); refusing purge"
                ;;
        esac
        check_private_file_exact "$ent"
        ent_dev="$(stat -c '%d' "$ent")" || die "cannot stat $ent"
        [ "$ent_dev" = "$spool_dev" ] || die "$ent crosses a mount boundary; refusing purge"
        real_ent="$(readlink -f "$ent" 2>/dev/null)" || die "cannot resolve realpath of $ent; refusing purge"
        mi_rc=0
        mountinfo_contains_target /proc/self/mountinfo "$real_ent" || mi_rc=$?
        if [ "$mi_rc" -ne 1 ]; then
            if [ "$had_nullglob" -eq 0 ]; then shopt -u nullglob; fi
            if [ "$had_dotglob" -eq 0 ]; then shopt -u dotglob; fi
            if [ "$mi_rc" -eq 0 ]; then
                die "$ent is a mount point (including bind mount); refusing purge"
            fi
            die "cannot verify /proc/self/mountinfo evidence for $ent; refusing purge"
        fi
        to_remove+=("$ent")
    done
    if [ "$had_nullglob" -eq 0 ]; then shopt -u nullglob; fi
    if [ "$had_dotglob" -eq 0 ]; then shopt -u dotglob; fi
    if [ "${#to_remove[@]}" -gt 0 ]; then
        for ent in "${to_remove[@]}"; do
            rm -f "$ent"
        done
    fi
    rmdir "$audit_spool_dir" || die "could not remove $audit_spool_dir (not empty or busy)"
}

cmd_uninstall() {
    local purge_spool=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --purge-spool) purge_spool=1; shift ;;
            *) die "uninstall: unknown argument $1" ;;
        esac
    done
    acquire_lifecycle_lock
    disable_units
    remove_managed_file_safe "$auditd_rules_path"
    remove_managed_file_safe "$aide_rules_path"
    if [ -x /sbin/augenrules ] && [ -d /run/systemd/system ] \
        && systemctl is-active --quiet auditd 8>&- 9>&- 2>/dev/null; then
        /sbin/augenrules --load 8>&- 9>&- >/dev/null 2>&1 || say "warning: augenrules --load returned non-zero (audit rules may be locked with -e 2)"
    fi
    remove_managed_file_safe "$installed_audit_log"
    remove_managed_file_safe "$audit_shipper_cfg"
    # Remove ONLY the two managed tripwire files; rmdir if empty (never blind rm -rf; H5).
    if [ -e "$tripwire_share_dir" ] || [ -L "$tripwire_share_dir" ]; then
        check_ancestors_ok "$tripwire_share_dir" || die "unsafe ancestor for $tripwire_share_dir; refusing removal"
        [ ! -L "$tripwire_share_dir" ] && [ -d "$tripwire_share_dir" ] \
            || die "$tripwire_share_dir is not a real directory; refusing removal"
        remove_managed_file_safe "$tripwire_share_dir/99-tendcf-tripwire.rules"
        remove_managed_file_safe "$tripwire_share_dir/99-tendcf-tripwire.aide"
        rmdir "$tripwire_share_dir" 2>/dev/null || true
    fi
    if [ "$purge_spool" -eq 1 ]; then
        purge_audit_spool_safe
    fi
    release_lifecycle_lock
    say "uninstalled: scheduler, audit shipper, and tripwire rules removed"
}

cmd_status() {
    echo "tree:     $(stat -c '%U:%G %a' "$prefix" 2>/dev/null || echo missing)"
    echo "entry:    $([ -f "$entry" ] && echo present || echo missing)"
    echo "data:     $([ -f "$data" ] && stat -c '%U:%G %a %s bytes' "$data" || echo missing)"
    echo "$unit: $(systemctl is-enabled "$unit" 2>&1 || true) / $(systemctl is-active "$unit" 2>&1 || true)"
    echo "$shipper_timer: $(systemctl is-enabled "$shipper_timer" 2>&1 || true) / $(systemctl is-active "$shipper_timer" 2>&1 || true)"
    echo "audit-config: $([ -f "$audit_shipper_cfg" ] && stat -c '%U:%G %a' "$audit_shipper_cfg" || echo missing)"
    echo "auditd-tripwire: $([ -f "$auditd_rules_path" ] && stat -c '%U:%G %a' "$auditd_rules_path" || echo missing)"
    echo "aide-tripwire: $([ -f "$aide_rules_path" ] && stat -c '%U:%G %a' "$aide_rules_path" || echo missing)"
}

[ $# -ge 1 ] || die "usage: $0 install|data|run-once|enable|disable|uninstall|status|workdir ..."
sub="$1"; shift
case "$sub" in
    install) cmd_install "$@" ;;
    disable) cmd_disable ;;
    uninstall) cmd_uninstall "$@" ;;
    workdir) init_paths; echo "$workdir" ;;
    data)
        [ $# -eq 1 ] && [ -n "$1" ] || die "usage: $0 data FILE"
        acquire_lifecycle_lock
        init_paths
        put_data "$1"
        release_lifecycle_lock
        ;;
    run-once) init_paths; cmd_run_once ;;
    enable) cmd_enable ;;
    status) init_paths; cmd_status ;;
    *) die "unknown command: $sub" ;;
esac
