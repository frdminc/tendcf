#!/bin/bash -p
# Root-owned tendcf install on a macOS host (issue 70, C-deploy-01). Run as root
# directly via a trusted parent/loader so /bin/bash -p suppresses BASH_ENV, ENV,
# and exported BASH_FUNC_* functions before the script's own env -i re-exec.
#
# Counterpart of deploy/linux/tendcf-install.sh: binaries and policy root-owned
# (root:wheel, no group/world write, no SUID/SGID, no ACLs; every ancestor up
# to / root-owned with no group/world write and no ACLs), the work directory
# inside the same root-owned tree (read from cf-promises, never assumed), and a
# root cf-execd LaunchDaemon (org.tendcf.execd) that runs cf-agent on a
# schedule. Nothing here leaves a sudoers rule behind and nothing a non-root
# user can write is read by root.
#
# Integrity vs provenance: the `.sha256` file and ad-hoc `codesign --verify`
# prove archive/binary integrity against corruption or post-download tampering;
# provenance (that the tarball came from frdminc/tendcf's `macos-fork-build.yml`
# workflow, not a fork PR) is enforced by the caller (`state1_vm.py
# --artifact-run` checks the GitHub Actions run metadata before downloading).
#
# Schema v8 declares `org.tendcf.execd` as an exact launchd unit-writer entry
# under `writer: "tendcf-install"` (`deploy/darwin/canary/goal-file*.json`,
# `examples/launchd-writers.yml`, issue #99).
#
#   install [--tarball FILE] [--sha256 FILE] [--data FILE] [--policy-src DIR] [--projector-src FILE] [--projector-sha256 HEX] [--enable]
#                    verify and extract the PR 95 macOS fork tarball (clearing
#                    com.apple.quarantine, ACLs, flags, SUID/SGID), enforce
#                    root:wheel and go-w on /opt/tendcf and verify ancestors up
#                    to /, verify Mach-O dependencies and code signatures, lay
#                    out the work directory, place the policy, promises.cf and
#                    projector.py (requiring root-owned non-writable source or
#                    --projector-sha256), optionally install CMDB data (validated
#                    by python3 -I -S projector.py and cf-promises --show-classes
#                    before publication) and optionally enable org.tendcf.execd.
#                    Re-running when converged is a no-op that reports `no change`.
#   data FILE        replace the CMDB data (serialized via lockf, validated by
#                    projector.py and cf-promises --show-classes requiring
#                    tendcf_cmdb_evaluated source=promise and zero refusals, with
#                    atomic rollback on post-publish failure or catchable
#                    SIGTERM/SIGINT interruption; uncatchable SIGKILL/power loss
#                    does not run traps)
#   run-once         one `cf-agent --no-augments -K -I` pass over the installed policy
#   enable           write /Library/LaunchDaemons/org.tendcf.execd.plist
#                    (root:wheel 0644, plutil -lint) and bootstrap it
#                    idempotently (launchctl print exit-code probe)
#   disable          bootout and remove org.tendcf.execd
#   status           what is installed and loaded (works on fresh/partial hosts)
#   workdir          print the compiled-in work directory
set -euo pipefail

# Re-exec once under a completely clean environment (`env -i`) so no caller
# variables (DYLD_*, DEVELOPER_DIR, SDKROOT, TOOLCHAINS, PERL5LIB/PERL5OPT,
# PYTHON*, CFENGINE_*, CF_*, PATH, LC_ALL) can influence root execution. Also
# verify via `compgen -e` that no extra exported variables remain even if a
# caller pre-set TENDCF_CLEAN_ENV=1.
_env_clean=1
while IFS= read -r _k; do
    case "$_k" in
        TENDCF_CLEAN_ENV|PATH|LC_ALL|PWD|SHLVL|_) ;;
        *) _env_clean=0; break ;;
    esac
done < <(compgen -e)
if [ "${TENDCF_CLEAN_ENV:-}" != 1 ] \
    || [ "${PATH:-}" != "/usr/bin:/bin:/usr/sbin:/sbin" ] \
    || [ "${LC_ALL:-}" != C ] \
    || [ "$_env_clean" -ne 1 ]; then
    exec /usr/bin/env -i TENDCF_CLEAN_ENV=1 PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C /bin/bash -p "$0" "$@"
fi
unset _env_clean _k

# Belt-and-suspenders unset of DYLD_* even after env -i.
unset DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH DYLD_INSERT_LIBRARIES \
      DYLD_FRAMEWORK_PATH DYLD_FALLBACK_FRAMEWORK_PATH DYLD_IMAGE_SUFFIX \
      DYLD_PRINT_LIBRARIES DYLD_PRINT_LIBRARIES_POST_LAUNCH DYLD_PRINT_RPATHS \
      DYLD_SHARED_CACHE_DIR

umask 022

prefix=/opt/tendcf
workdir=""   # set by init_paths
label=org.tendcf.execd
launchd_dir=/Library/LaunchDaemons
plist_path="$launchd_dir/$label.plist"
installed_sha_file="$prefix/share/tendcf/INSTALLED_TARBALL.sha256"
here="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd -P)"
policy_src="$here/../../policy"
projector_src=""
projector_sha256=""
installed_projector="$prefix/share/tendcf/bin/projector.py"

cf_agent="$prefix/bin/cf-agent"
cf_promises="$prefix/bin/cf-promises"
cf_key="$prefix/bin/cf-key"
cf_execd="$prefix/bin/cf-execd"
entry=""     # set by init_paths
data=""      # set by init_paths

stage_dir=""
place_projector_tmp=""
prepared_projector_file=""
projector_prepared=0
installed_projector_originally_clean=0
upgrade_prefix_swapped=0
put_data_stage_wd=""
put_data_tmp=""
put_data_backup=""
put_data_rollback_armed=0
put_data_had_prev=0
publish_lock_held=0
changed=0
upgrade_needs_execd_restart=0
upgrade_rollback_armed=0
upgrade_backup_prefix=""
upgrade_staged_tree=""
upgrade_moved_var=0
upgrade_was_loaded=0
upgrade_had_plist=0
upgrade_snapshot_taken=0
upgrade_saved_workdir=""
upgrade_saved_inputs=0
upgrade_saved_data=0

die() { echo "tendcf-install: $*" >&2; exit 1; }
say() { echo "tendcf-install: $*"; }

bootout_execd() {
    /bin/launchctl bootout "system/$label" 9>&-
}

cleanup_stage() {
    # Roll back any in-flight Gate 3 data publication AND any armed upgrade
    # while STILL holding FD 9 (passing 9>&- to launchctl), and release FD 9
    # only AFTER all rollbacks and temp cleanup finish.
    if [ "${put_data_rollback_armed:-0}" -eq 1 ]; then
        if [ "${put_data_had_prev:-0}" -eq 1 ] && [ -n "${put_data_backup:-}" ] && [ -f "$put_data_backup" ]; then
            if /bin/mv -f "$put_data_backup" "$data"; then
                put_data_backup=""
                echo "tendcf-install: interrupted during post-publish validation; previous data restored" >&2
            else
                echo "tendcf-install: interrupted during post-publish validation and rollback failed; backup preserved at $put_data_backup" >&2
                put_data_backup=""
            fi
        elif [ "${put_data_had_prev:-0}" -eq 0 ] && [ -n "${data:-}" ]; then
            if /bin/rm -f "$data" && [ ! -e "$data" ] && [ ! -L "$data" ]; then
                echo "tendcf-install: removed unverified first-time data $data after failure" >&2
            else
                echo "tendcf-install: ERROR: rollback could not remove unverified data at $data; inspect manually" >&2
            fi
        fi
        put_data_rollback_armed=0
    fi
    if [ "$upgrade_rollback_armed" -eq 1 ]; then
        local restored_prefix=0
        if [ -n "$upgrade_backup_prefix" ] && [ -d "$upgrade_backup_prefix" ]; then
            if execd_is_loaded; then
                bootout_execd >/dev/null 2>&1 || true
                wait_execd_unloaded || true
            fi
            local failed_prefix="$prefix.failed.$$"
            /bin/rm -rf "$failed_prefix" || true
            if [ -e "$prefix" ] || [ -L "$prefix" ]; then
                /bin/mv "$prefix" "$failed_prefix" || true
            fi
            if [ "$upgrade_moved_var" -eq 1 ] && [ ! -e "$upgrade_backup_prefix/var" ]; then
                if [ -d "$failed_prefix/var" ]; then
                    /bin/mv "$failed_prefix/var" "$upgrade_backup_prefix/var" || true
                elif [ -n "$upgrade_staged_tree" ] && [ -d "$upgrade_staged_tree/var" ]; then
                    /bin/mv "$upgrade_staged_tree/var" "$upgrade_backup_prefix/var" || true
                fi
            fi
            if [ ! -e "$prefix" ] && [ ! -L "$prefix" ]; then
                if /bin/mv "$upgrade_backup_prefix" "$prefix"; then
                    restored_prefix=1
                fi
            fi
            if [ "$upgrade_moved_var" -eq 0 ] || [ ! -e "$failed_prefix/var" ]; then
                /bin/rm -rf "$failed_prefix" || true
            fi
            if [ "$upgrade_snapshot_taken" -eq 1 ] && [ -n "$upgrade_saved_workdir" ]; then
                if [ "$upgrade_saved_inputs" -eq 1 ] && [ -d "$stage_dir/upgrade-var-backup/inputs" ]; then
                    /bin/rm -rf "$upgrade_saved_workdir/inputs" || true
                    /bin/mv "$stage_dir/upgrade-var-backup/inputs" "$upgrade_saved_workdir/inputs" || true
                fi
                if [ "$upgrade_saved_data" -eq 1 ] && [ -f "$stage_dir/upgrade-var-backup/host_specific.json" ]; then
                    /bin/mkdir -p "$upgrade_saved_workdir/data" || true
                    if /bin/cp -p "$stage_dir/upgrade-var-backup/host_specific.json" \
                        "$upgrade_saved_workdir/data/host_specific.json.rollback.$$"; then
                        /bin/mv -f "$upgrade_saved_workdir/data/host_specific.json.rollback.$$" \
                            "$upgrade_saved_workdir/data/host_specific.json" || true
                        /bin/chmod 0600 "$upgrade_saved_workdir/data/host_specific.json" || true
                        /usr/sbin/chown root:wheel "$upgrade_saved_workdir/data/host_specific.json" 2>/dev/null || true
                    fi
                elif [ "$upgrade_saved_data" -eq 0 ] && [ -e "$upgrade_saved_workdir/data/host_specific.json" ]; then
                    /bin/rm -f "$upgrade_saved_workdir/data/host_specific.json" || true
                fi
            fi
        fi
        if [ "${upgrade_had_plist:-0}" -eq 0 ] && [ "$upgrade_was_loaded" -eq 0 ] \
            && [ -f "$plist_path" ] && [ ! -L "$plist_path" ]; then
            if execd_is_loaded; then
                bootout_execd >/dev/null 2>&1 || true
                wait_execd_unloaded || true
            fi
            /bin/rm -f "$plist_path" || true
        fi
        if [ "$upgrade_was_loaded" -eq 1 ] && [ -f "$plist_path" ] && ! execd_is_loaded; then
            bootstrap_execd_with_retry >/dev/null 2>&1 || true
        fi
        if [ "$restored_prefix" -eq 1 ]; then
            echo "tendcf-install: rolled back failed upgrade to previous $prefix" >&2
        elif [ "$upgrade_was_loaded" -eq 1 ]; then
            echo "tendcf-install: restarted $label after aborted upgrade" >&2
        fi
        upgrade_rollback_armed=0
    fi
    if [ -n "$stage_dir" ] && [ -d "$stage_dir" ]; then
        /bin/rm -rf "$stage_dir" || true
    fi
    if [ -n "${put_data_tmp:-}" ]; then
        /bin/rm -f "$put_data_tmp" || true
        put_data_tmp=""
    fi
    if [ -n "${put_data_backup:-}" ]; then
        /bin/rm -f "$put_data_backup" || true
        put_data_backup=""
    fi
    if [ -n "${put_data_stage_wd:-}" ] && [ -d "$put_data_stage_wd" ]; then
        /bin/rm -rf "$put_data_stage_wd" || true
        put_data_stage_wd=""
    fi
    if [ -n "${place_projector_tmp:-}" ]; then
        /bin/rm -f "$place_projector_tmp" || true
        place_projector_tmp=""
    fi
    if [ "${publish_lock_held:-0}" -eq 1 ]; then
        exec 9>&-
        publish_lock_held=0
    fi
}
trap cleanup_stage EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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

# Return 0 if PATH has any macOS extended ACL entry, 1 if none.
# Never exits awk early (avoids SIGPIPE under set -o pipefail).
has_acl_path() {
    local out
    out="$(/bin/ls -lde "$1" 2>/dev/null)" || return 0
    printf '%s\n' "$out" | /usr/bin/awk '/^ [0-9]+: / { found=1 } END { exit !found }'
}

# Return 0 if anything under ROOT has a macOS extended ACL entry, 1 if none.
has_acl_tree() {
    local out
    out="$(/bin/ls -lRe "$1" 2>/dev/null)" || return 0
    printf '%s\n' "$out" | /usr/bin/awk '/^ [0-9]+: / { found=1 } END { exit !found }'
}

# Non-fatal check: ancestor directory is a real directory (not a symlink),
# owned by root (any group, e.g. wheel or admin, matching state1_vm.py),
# not group- or world-writable, and has no extended ACLs.
check_ancestor_dir_ok() {
    local dir="$1" meta owner mode mode_oct
    [ ! -L "$dir" ] || return 1
    [ -d "$dir" ] || return 1
    meta="$(/usr/bin/stat -f '%Su %Lp' "$dir" 2>/dev/null)" || return 1
    read -r owner mode <<< "$meta"
    [ "$owner" = root ] || return 1
    mode_oct=$((8#$mode))
    [ $((mode_oct & 8#022)) -eq 0 ] || return 1
    if has_acl_path "$dir"; then
        return 1
    fi
    return 0
}

# Fatal check on a directory tendcf directly owns/trusts (e.g. /opt/tendcf,
# /Library/LaunchDaemons): real directory, root:wheel, no group/world write,
# and no extended ACLs.
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
    if has_acl_path "$dir"; then
        die "$dir has an extended ACL; refusing"
    fi
}

# Non-fatal check on every ancestor of absolute PATH up to / (excluding PATH).
check_ancestors_ok() {
    local p="$1" parent
    case "$p" in
        /*) ;;
        *) return 1 ;;
    esac
    parent="$p"
    while [ "$parent" != "/" ]; do
        parent="$(/usr/bin/dirname "$parent")"
        check_ancestor_dir_ok "$parent" || return 1
    done
    return 0
}

# Fatal check on every ancestor of absolute PATH up to / (excluding PATH).
check_ancestors() {
    local p="$1" parent
    case "$p" in
        /*) ;;
        *) die "expected absolute path, got $p" ;;
    esac
    parent="$p"
    while [ "$parent" != "/" ]; do
        parent="$(/usr/bin/dirname "$parent")"
        if ! check_ancestor_dir_ok "$parent"; then
            die "ancestor $parent is not a root-owned, non-symlink, non-group/world-writable, ACL-free directory"
        fi
    done
}

# Check ownership (root:wheel), no go-w, no SUID/SGID, no ACLs across a tree.
# With optional 2nd arg `no_symlinks`, also rejects any non-regular/non-dir entry.
# Uses `find ... -print -quit` to avoid SIGPIPE under `set -o pipefail`.
tree_is_clean() {
    local root="$1" mode_opt="${2:-}"
    [ ! -L "$root" ] || return 1
    [ -d "$root" ] || return 1
    local bad
    bad="$(/usr/bin/find "$root" \( ! -user root -o ! -group wheel \) -print -quit)"
    [ -z "$bad" ] || return 1
    bad="$(/usr/bin/find "$root" ! -type l \( -perm -020 -o -perm -002 -o -perm -4000 -o -perm -2000 \) -print -quit)"
    [ -z "$bad" ] || return 1
    if has_acl_tree "$root"; then
        return 1
    fi
    if [ "$mode_opt" = no_symlinks ]; then
        bad="$(/usr/bin/find "$root" ! -type f ! -type d -print -quit)"
        [ -z "$bad" ] || return 1
    fi
    return 0
}

# Verify a root-owned tree (any group, e.g. Python.framework or CLT python)
# has root ownership, no go-w, no SUID/SGID, no ACLs, and no symlinks escaping ROOT.
root_tree_safe_ok() {
    local root="$1" bad
    [ ! -L "$root" ] || return 1
    [ -d "$root" ] || return 1
    bad="$(/usr/bin/find "$root" ! -user root -print -quit)"
    [ -z "$bad" ] || return 1
    bad="$(/usr/bin/find "$root" ! -type l \( -perm -020 -o -perm -002 -o -perm -4000 -o -perm -2000 \) -print -quit)"
    [ -z "$bad" ] || return 1
    if has_acl_tree "$root"; then
        return 1
    fi
    validate_tree_symlinks_ok "$root" "$root" || return 1
    return 0
}

# Resolve a symlink path (up to 40 hops) inside TREE_ROOT, mapping any absolute
# prefix LOGICAL_ROOT/* to TREE_ROOT/*. Returns 0 if every hop and the final
# resolved target (dir + basename) stay strictly within TREE_ROOT, 1 otherwise.
resolve_symlink_in_tree_ok() {
    local tree_root="$1" logical_root="$2" cur="$3"
    local hops=0 target dir base next norm_dir
    while [ -L "$cur" ]; do
        hops=$((hops + 1))
        [ "$hops" -le 40 ] || return 1
        target="$(/usr/bin/readlink "$cur")" || return 1
        [ -n "$target" ] || return 1
        case "$target" in
            /*)
                # Reject any .. or . segment in an absolute symlink target.
                case "$target" in
                    */..|*/../*|*/.|*/./*|*//*) return 1 ;;
                esac
                if [ "$target" = "$logical_root" ]; then
                    next="$tree_root"
                elif [ "${target#"$logical_root"/}" != "$target" ]; then
                    next="$tree_root/${target#"$logical_root"/}"
                else
                    return 1
                fi
                ;;
            *)
                dir="$(/usr/bin/dirname "$cur")"
                next="$dir/$target"
                ;;
        esac
        # Normalize parent directory and verify final path (parent + basename) stays
        # strictly inside tree_root, even if the basename itself is a symlink or absent.
        base="$(/usr/bin/basename "$next")"
        case "$base" in
            ..|.)
                norm_dir="$(cd "$next" 2>/dev/null && pwd -P)" || return 1
                cur="$norm_dir"
                ;;
            *)
                norm_dir="$(cd "$(/usr/bin/dirname "$next")" 2>/dev/null && pwd -P)" || return 1
                cur="$norm_dir/$base"
                ;;
        esac
        case "$cur" in
            "$tree_root"|"$tree_root"/*) ;;
            *) return 1 ;;
        esac
    done
    # Final non-symlink target must also stay inside tree_root.
    if [ -d "$cur" ]; then
        norm_dir="$(cd "$cur" 2>/dev/null && pwd -P)" || return 1
        cur="$norm_dir"
    elif [ -e "$cur" ]; then
        norm_dir="$(cd "$(/usr/bin/dirname "$cur")" 2>/dev/null && pwd -P)" || return 1
        cur="$norm_dir/$(/usr/bin/basename "$cur")"
    fi
    case "$cur" in
        "$tree_root"|"$tree_root"/*) return 0 ;;
        *) return 1 ;;
    esac
}

# Validate every symlink under TREE_ROOT stays within TREE_ROOT (mapping
# LOGICAL_ROOT/* to TREE_ROOT/*). Non-fatal (returns 0 ok, 1 bad).
validate_tree_symlinks_ok() {
    local tree_root="$1" logical_root="$2"
    local canon_root sl list_file rc=0
    canon_root="$(cd "$tree_root" 2>/dev/null && pwd -P)" || return 1
    make_stage
    list_file="$stage_dir/symlinks.$$.txt"
    /usr/bin/find "$canon_root" -type l -print0 > "$list_file" || return 1
    while IFS= read -r -d '' sl; do
        [ -n "$sl" ] || continue
        if ! resolve_symlink_in_tree_ok "$canon_root" "$logical_root" "$sl"; then
            rc=1
            break
        fi
    done < "$list_file"
    /bin/rm -f "$list_file"
    return "$rc"
}

# Resolve a binary's realpath via readlink loop (pure Bash/POSIX, bounded).
resolve_realpath_ok() {
    local p="$1" hops=0 target dir
    [ -e "$p" ] || return 1
    while [ -L "$p" ]; do
        hops=$((hops + 1))
        [ "$hops" -le 40 ] || return 1
        target="$(/usr/bin/readlink "$p")" || return 1
        case "$target" in
            /*) p="$target" ;;
            *) p="$(/usr/bin/dirname "$p")/$target" ;;
        esac
    done
    dir="$(cd "$(/usr/bin/dirname "$p")" 2>/dev/null && pwd -P)" || return 1
    printf '%s/%s\n' "$dir" "$(/usr/bin/basename "$p")"
}

# Resolve a candidate binary up to 16 symlink hops, verifying every hop's
# parent ancestors are root-owned + go-w + ACL-free and every symlink itself
# is uid 0 and not go-w, and verifying the final regular file is uid 0,
# not go-w, not SUID/SGID, and ACL-free. Prints the canonical path on success.
resolve_safe_binary_ok() {
    local p="$1" hops=0 target dir real_p meta uid mode mode_oct
    [ -e "$p" ] || return 1
    while [ -L "$p" ]; do
        hops=$((hops + 1))
        [ "$hops" -le 16 ] || return 1
        check_ancestors_ok "$p" || return 1
        meta="$(/usr/bin/stat -f '%u %Lp' "$p" 2>/dev/null)" || return 1
        read -r uid mode <<< "$meta"
        [ "$uid" = 0 ] || return 1
        mode_oct=$((8#$mode))
        [ $((mode_oct & 8#022)) -eq 0 ] || return 1
        target="$(/usr/bin/readlink "$p")" || return 1
        case "$target" in
            /*) p="$target" ;;
            *) p="$(/usr/bin/dirname "$p")/$target" ;;
        esac
    done
    [ -f "$p" ] && [ ! -L "$p" ] || return 1
    dir="$(cd "$(/usr/bin/dirname "$p")" 2>/dev/null && pwd -P)" || return 1
    real_p="$dir/$(/usr/bin/basename "$p")"
    [ -f "$real_p" ] && [ ! -L "$real_p" ] || return 1
    check_ancestors_ok "$real_p" || return 1
    meta="$(/usr/bin/stat -f '%u %Lp' "$real_p" 2>/dev/null)" || return 1
    read -r uid mode <<< "$meta"
    [ "$uid" = 0 ] || return 1
    mode_oct=$((8#$mode))
    [ $((mode_oct & 8#6022)) -eq 0 ] || return 1
    if has_acl_path "$real_p"; then
        return 1
    fi
    printf '%s\n' "$real_p"
}

# Locate a directly verified, root-owned otool binary (NEVER the /usr/bin/otool
# xcrun shim, which delegates to an active user-owned Xcode.app on dev hosts).
find_safe_otool() {
    local dev_dir cand real_otool
    local cands=(/Library/Developer/CommandLineTools/usr/bin/otool)
    dev_dir="$(/usr/bin/xcode-select -p 2>/dev/null || true)"
    if [ -n "$dev_dir" ]; then
        cands+=(
            "$dev_dir/usr/bin/otool"
            "$dev_dir/Toolchains/XcodeDefault.xctoolchain/usr/bin/otool"
        )
    fi
    for cand in "${cands[@]}"; do
        [ -x "$cand" ] || continue
        check_ancestors_ok "$cand" || continue
        real_otool="$(resolve_safe_binary_ok "$cand")" || continue
        if "$real_otool" -L /bin/ls >/dev/null 2>&1; then
            printf '%s\n' "$real_otool"
            return 0
        fi
    done
    return 1
}

# Verify a candidate Python 3 interpreter is safe to execute as root:
# ancestors up to / are root-owned + go-w + ACL-free, resolved binary is
# root-owned + go-w + ACL-free + no SUID/SGID, and its enclosing framework/tree
# is root-owned + go-w + ACL-free + no escaping symlinks.
verify_python_candidate_ok() {
    local cand="$1" real_py fw_root dev_dir py_root
    [ -x "$cand" ] || return 1
    check_ancestors_ok "$cand" || return 1
    real_py="$(resolve_safe_binary_ok "$cand")" || return 1
    case "$real_py" in
        /Library/Frameworks/Python.framework/*)
            fw_root=/Library/Frameworks/Python.framework
            check_ancestors_ok "$fw_root" || return 1
            root_tree_safe_ok "$fw_root" || return 1
            ;;
        /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/*)
            fw_root=/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework
            check_ancestors_ok "$fw_root" || return 1
            root_tree_safe_ok "$fw_root" || return 1
            ;;
        /usr/bin/python3)
            dev_dir="$(/usr/bin/xcode-select -p 2>/dev/null)" || return 1
            [ -d "$dev_dir" ] && [ ! -L "$dev_dir" ] || return 1
            check_ancestors_ok "$dev_dir" || return 1
            check_ancestor_dir_ok "$dev_dir" || return 1
            py_root="$dev_dir/Library/Frameworks/Python3.framework"
            if [ -d "$py_root" ] && [ ! -L "$py_root" ]; then
                check_ancestors_ok "$py_root" || return 1
                root_tree_safe_ok "$py_root" || return 1
            else
                return 1
            fi
            local dev_py="$dev_dir/usr/bin/python3" real_dev_py
            [ -x "$dev_py" ] || return 1
            check_ancestor_dir_ok "$dev_dir/usr" || return 1
            check_ancestor_dir_ok "$dev_dir/usr/bin" || return 1
            check_ancestors_ok "$dev_py" || return 1
            real_dev_py="$(resolve_safe_binary_ok "$dev_py")" || return 1
            case "$real_dev_py" in
                "$py_root"/*|"$dev_dir/usr/bin"/*) ;;
                *) return 1 ;;
            esac
            ;;
        *)
            return 1
            ;;
    esac
    return 0
}

# Locate a verified, root-owned Python 3 interpreter (avoiding /usr/bin/python3
# when Xcode CLT is absent, since that binary is an xcrun stub on vanilla macOS).
find_real_python() {
    local cand
    for cand in \
        /Library/Frameworks/Python.framework/Versions/Current/bin/python3 \
        /Library/Frameworks/Python.framework/Versions/3.14/bin/python3 \
        /Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14 \
        /Library/Developer/CommandLineTools/usr/bin/python3; do
        if verify_python_candidate_ok "$cand"; then
            echo "$cand"
            return 0
        fi
    done
    if /usr/bin/xcode-select -p >/dev/null 2>&1 && verify_python_candidate_ok /usr/bin/python3; then
        echo /usr/bin/python3
        return 0
    fi
    return 1
}

# Reject any dylib/rpath string containing .. or . segments, duplicate //, or control chars.
check_macho_path_syntax() {
    local bin="$1" what="$2" p="$3"
    case "$p" in
        ""|*/..|*/../*|../*|..|*/.|*/./*|./*|.|*//*)
            die "$bin carries unsafe $what path: $p" ;;
    esac
    if printf '%s' "$p" | /usr/bin/awk 'BEGIN { bad=0 } /[\001-\037\177]/ { bad=1 } END { exit !bad }'; then
        die "$bin carries control character in $what path"
    fi
}

# Verify Mach-O load paths, LC_RPATH, LC_DYLD_ENVIRONMENT, LC_LOAD_DYLINKER, and
# code signatures across ALL files under TREE_ROOT. Uses a directly verified
# root-owned otool when present; otherwise parses Mach-O load commands directly
# with isolated stdlib Python (`-I -S`) verified root-owned (so vanilla macOS works).
verify_macho_tree() {
    local tree_root="$1"
    local canon_root
    canon_root="$(cd "$tree_root" && pwd -P)"

    # Required binaries must exist as regular non-symlink files.
    local req_name
    for req_name in cf-agent cf-promises cf-key cf-execd; do
        [ -f "$canon_root/bin/$req_name" ] && [ ! -L "$canon_root/bin/$req_name" ] \
            || die "required binary missing or symlink: $canon_root/bin/$req_name"
    done

    # Create stage_dir in the main shell BEFORE command-substitution subshells
    # (find_safe_otool / find_real_python) so no subshell leaks a /var/tmp dir.
    make_stage

    local otool_bin="" py=""
    otool_bin="$(find_safe_otool || true)"
    if [ -z "$otool_bin" ]; then
        py="$(find_real_python)" || die "cannot verify Mach-O dependencies: neither verified root-owned otool nor verified root-owned Python 3 found"
    fi

    local files_list="$stage_dir/tree-files.$$.txt"
    /usr/bin/find "$canon_root" -type f -print0 > "$files_list" || die "find failed scanning $canon_root"

    local machos=() f file_out
    while IFS= read -r -d '' f; do
        [ -n "$f" ] || continue
        file_out="$(/usr/bin/file -b "$f")" || die "file(1) failed on $f"
        case "$file_out" in
            *Mach-O*) machos+=("$f") ;;
        esac
    done < "$files_list"
    /bin/rm -f "$files_list"

    [ "${#machos[@]}" -gt 0 ] || die "no Mach-O files found under $canon_root"

    # Build a newline-delimited lookup set of canonical Mach-O paths so we can
    # assert required binaries and every in-prefix dylib target are verified Mach-Os.
    local macho_set_file="$stage_dir/macho-set.$$.txt"
    printf '%s\n' "${machos[@]}" > "$macho_set_file"
    for req_name in cf-agent cf-promises cf-key cf-execd; do
        if ! /usr/bin/grep -qxF "$canon_root/bin/$req_name" "$macho_set_file"; then
            /bin/rm -f "$macho_set_file"
            die "required binary is not a Mach-O file: $canon_root/bin/$req_name"
        fi
    done

    local bin otool_L otool_l libs_list rpaths_list dylinker_list dyld_env_list lib rel resolved_lib rp dl
    for bin in "${machos[@]}"; do
        if ! /usr/bin/codesign --verify --strict "$bin" >/dev/null 2>&1 9>&-; then
            /bin/rm -f "$macho_set_file"
            die "codesign verification failed for $bin"
        fi
        if [ -n "$otool_bin" ]; then
            otool_L="$("$otool_bin" -L "$bin" 9>&-)" || die "otool -L failed on $bin"
            otool_l="$("$otool_bin" -l "$bin" 9>&-)" || die "otool -l failed on $bin"

            libs_list="$(printf '%s\n' "$otool_L" | /usr/bin/awk 'NR > 1 && /^\t/ { sub(/^\t/, ""); sub(/ \(compatibility version [0-9.]+, current version [0-9.]+\)$/, ""); print }')"
            while IFS= read -r lib; do
                [ -n "$lib" ] || continue
                check_macho_path_syntax "$bin" "dylib" "$lib"
                case "$lib" in
                    "$prefix"/*)
                        rel="${lib#"$prefix"/}"
                        [ -e "$canon_root/$rel" ] || die "$bin links missing in-prefix library $lib"
                        resolved_lib="$(resolve_realpath_ok "$canon_root/$rel")" || die "$bin links unresolvable in-prefix library $lib"
                        case "$resolved_lib" in
                            "$canon_root"/*) ;;
                            *) die "$bin links escaping in-prefix library $lib -> $resolved_lib" ;;
                        esac
                        if ! /usr/bin/grep -qxF "$resolved_lib" "$macho_set_file"; then
                            die "$bin links non-Mach-O target $lib ($resolved_lib)"
                        fi
                        ;;
                    /usr/lib/*|/System/Library/*) ;;
                    *) die "$bin loads $lib, outside $prefix and the system library directories" ;;
                esac
            done <<< "$libs_list"

            # Reject LC_DYLD_ENVIRONMENT outright.
            dyld_env_list="$(printf '%s\n' "$otool_l" | /usr/bin/awk '$1 == "cmd" && $2 == "LC_DYLD_ENVIRONMENT" { print $2 }')"
            [ -z "$dyld_env_list" ] || die "$bin carries forbidden LC_DYLD_ENVIRONMENT"

            # Reject any LC_LOAD_DYLINKER other than /usr/lib/dyld.
            dylinker_list="$(printf '%s\n' "$otool_l" | /usr/bin/awk '$1 == "cmd" { c = $2 } c == "LC_LOAD_DYLINKER" && $1 == "name" { sub(/^[ \t]*name[ \t]+/, ""); sub(/ \(offset [0-9]+\)$/, ""); print }')"
            while IFS= read -r dl; do
                [ -n "$dl" ] || continue
                [ "$dl" = "/usr/lib/dyld" ] || die "$bin carries forbidden LC_LOAD_DYLINKER: $dl"
            done <<< "$dylinker_list"

            # Reject external or unsafe LC_RPATH.
            rpaths_list="$(printf '%s\n' "$otool_l" | /usr/bin/awk '$1 == "cmd" { c = $2 } c == "LC_RPATH" && $1 == "path" { sub(/^[ \t]*path[ \t]+/, ""); sub(/ \(offset [0-9]+\)$/, ""); print }')"
            while IFS= read -r rp; do
                [ -n "$rp" ] || continue
                check_macho_path_syntax "$bin" "LC_RPATH" "$rp"
                case "$rp" in
                    "$prefix"|"$prefix"/*) ;;
                    *) die "$bin carries forbidden LC_RPATH: $rp" ;;
                esac
            done <<< "$rpaths_list"
        fi
    done
    /bin/rm -f "$macho_set_file"

    if [ -z "$otool_bin" ]; then
        9>&- "$py" -I -S - "$prefix" "$canon_root" "${machos[@]}" <<'PY'
import pathlib
import struct
import sys

prefix = sys.argv[1].rstrip("/")
prefix_slash = prefix + "/"
tree_root = pathlib.Path(sys.argv[2]).resolve()
tree_root_str = str(tree_root)
files = sys.argv[3:]
verified_set = {str(pathlib.Path(p).resolve()) for p in files}

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

DYLIB_CMDS = {
    0x0C,        # LC_LOAD_DYLIB
    0x0D,        # LC_ID_DYLIB
    0x80000018,  # LC_LOAD_WEAK_DYLIB
    0x8000001F,  # LC_REEXPORT_DYLIB
    0x20,        # LC_LAZY_LOAD_DYLIB
    0x80000023,  # LC_LOAD_UPWARD_DYLIB
}
LC_LOAD_DYLINKER = 0x0E
LC_DYLD_ENVIRONMENT = 0x27
LC_RPATH = 0x8000001C


def check_safe_path(path_str: str, what: str, bin_path: str) -> None:
    if not path_str or "//" in path_str:
        raise SystemExit(f"tendcf-install: {bin_path} carries unsafe {what} path: {path_str!r}")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in path_str):
        raise SystemExit(f"tendcf-install: {bin_path} carries control char in {what} path")
    parts = path_str.split("/")
    if ".." in parts or "." in parts:
        raise SystemExit(f"tendcf-install: {bin_path} carries unsafe traversal in {what} path: {path_str!r}")


def read_lc_string(data: bytes, off: int, cmdsize: int, min_off: int, endian: str, path: str, what: str) -> str:
    if cmdsize < min_off:
        raise SystemExit(f"tendcf-install: truncated {what} cmdsize {cmdsize} in {path}")
    str_off = struct.unpack_from(endian + "I", data, off + 8)[0]
    if str_off < min_off or str_off >= cmdsize:
        raise SystemExit(f"tendcf-install: invalid {what} string offset {str_off} (cmdsize {cmdsize}) in {path}")
    raw = data[off + str_off : off + cmdsize].split(b"\x00", 1)[0]
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"tendcf-install: non-UTF-8 {what} string in {path}: {exc}") from exc


def parse_slice(data: bytes, path: str) -> None:
    if len(data) < 32:
        raise SystemExit(f"tendcf-install: truncated Mach-O slice in {path}")
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == MH_MAGIC_64:
        endian = "<"
    elif magic == MH_CIGAM_64:
        endian = ">"
    else:
        raise SystemExit(f"tendcf-install: unsupported Mach-O magic 0x{magic:08x} in {path}")
    _magic, _cpu, _sub, _ft, ncmds, sizeofcmds, _flags, _res = struct.unpack_from(
        endian + "IIIIIIII", data, 0
    )
    off = 32
    end = off + sizeofcmds
    if end > len(data):
        raise SystemExit(f"tendcf-install: truncated Mach-O load commands in {path}")
    for _ in range(ncmds):
        if off + 8 > end:
            raise SystemExit(f"tendcf-install: truncated load command header in {path}")
        cmd, cmdsize = struct.unpack_from(endian + "II", data, off)
        if cmdsize < 8 or off + cmdsize > end:
            raise SystemExit(f"tendcf-install: invalid load command size {cmdsize} in {path}")
        if cmd in DYLIB_CMDS:
            dep = read_lc_string(data, off, cmdsize, 24, endian, path, "dylib")
            check_safe_path(dep, "dylib", path)
            if dep.startswith(prefix_slash):
                rel = dep[len(prefix_slash):]
                cand = tree_root / rel
                if not cand.exists():
                    raise SystemExit(f"tendcf-install: {path} links missing in-prefix library {dep}")
                resolved = str(cand.resolve())
                if not (resolved.startswith(tree_root_str + "/")):
                    raise SystemExit(f"tendcf-install: {path} links escaping in-prefix library {dep} -> {resolved}")
                if resolved not in verified_set:
                    raise SystemExit(f"tendcf-install: {path} links non-Mach-O target {dep} ({resolved})")
            elif dep.startswith(("/usr/lib/", "/System/Library/")):
                pass
            else:
                raise SystemExit(
                    f"tendcf-install: {path} loads {dep}, outside {prefix} and the system library directories"
                )
        elif cmd == LC_RPATH:
            rp = read_lc_string(data, off, cmdsize, 12, endian, path, "LC_RPATH")
            check_safe_path(rp, "LC_RPATH", path)
            if rp != prefix and not rp.startswith(prefix_slash):
                raise SystemExit(f"tendcf-install: {path} carries forbidden LC_RPATH: {rp}")
        elif cmd == LC_DYLD_ENVIRONMENT:
            raise SystemExit(f"tendcf-install: {path} carries forbidden LC_DYLD_ENVIRONMENT")
        elif cmd == LC_LOAD_DYLINKER:
            dl = read_lc_string(data, off, cmdsize, 12, endian, path, "LC_LOAD_DYLINKER")
            if dl != "/usr/lib/dyld":
                raise SystemExit(f"tendcf-install: {path} carries forbidden LC_LOAD_DYLINKER: {dl}")
        off += cmdsize


for p in files:
    try:
        buf = pathlib.Path(p).read_bytes()
        if len(buf) < 8:
            raise SystemExit(f"tendcf-install: truncated Mach-O file {p}")
        m = struct.unpack_from(">I", buf, 0)[0]
        if m in (FAT_MAGIC, FAT_MAGIC_64):
            nfat = struct.unpack_from(">I", buf, 4)[0]
            if nfat == 0:
                raise SystemExit(f"tendcf-install: empty fat Mach-O (nfat=0) in {p}")
            entry_sz = 20 if m == FAT_MAGIC else 32
            if 8 + nfat * entry_sz > len(buf):
                raise SystemExit(f"tendcf-install: truncated fat Mach-O header in {p}")
            for i in range(nfat):
                eoff = 8 + i * entry_sz
                if m == FAT_MAGIC:
                    _c, _s, sl_off, sl_sz, _al = struct.unpack_from(">IIIII", buf, eoff)
                else:
                    _c, _s, sl_off, sl_sz, _al, _r = struct.unpack_from(">IIQQII", buf, eoff)
                if sl_sz < 32 or sl_off + sl_sz > len(buf):
                    raise SystemExit(f"tendcf-install: out-of-bounds fat slice {i} in {p}")
                parse_slice(buf[sl_off : sl_off + sl_sz], p)
        else:
            parse_slice(buf, p)
    except struct.error as exc:
        raise SystemExit(f"tendcf-install: malformed Mach-O struct in {p}: {exc}") from exc
PY
    fi
}

execd_is_loaded() {
    # Classify strictly by exit code (0 = loaded, non-zero = not loaded),
    # never by parsing `launchctl print` output (launchctl(1), PR 96).
    /bin/launchctl print "system/$label" >/dev/null 2>&1 9>&-
}

wait_execd_unloaded() {
    local i=0
    while [ "$i" -lt 20 ]; do
        if ! execd_is_loaded; then
            return 0
        fi
        /bin/sleep 0.5
        i=$((i + 1))
    done
    return 1
}

# Verify a tarball against its .sha256 file in a root-only staging dir (no TOCTOU),
# clear quarantine, validate tar entries, stage-extract with all metadata stripped,
# verify symlinks/Mach-O/codesign, and install under /opt/tendcf.
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

    # Ensure /opt exists (vanilla macOS may not have /opt yet) and ancestors are safe.
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

    # Capture tar listings to files in $stage_dir (never mask exit status via < <(...)).
    local tar_tv="$stage_dir/tar-tv.txt"
    local tar_t="$stage_dir/tar-t.txt"
    /usr/bin/tar -tvzf "$staged_tar" > "$tar_tv" 9>&- || die "tar -tvzf failed on $tar_base"
    /usr/bin/tar -tzf "$staged_tar" > "$tar_t" 9>&- || die "tar -tzf failed on $tar_base"

    local n_tv n_t
    n_tv="$(/usr/bin/wc -l < "$tar_tv" | /usr/bin/tr -d ' ')"
    n_t="$(/usr/bin/wc -l < "$tar_t" | /usr/bin/tr -d ' ')"
    [ "$n_tv" -gt 0 ] && [ "$n_tv" -eq "$n_t" ] || die "tarball listing count mismatch (embedded newline or empty archive)"

    if /usr/bin/awk 'BEGIN { bad=0 } /[\001-\037\177]/ { bad=1 } END { exit !bad }' "$tar_t"; then
        die "refusing tar entry containing control characters"
    fi

    local entry_line mode_char name
    while IFS= read -r entry_line; do
        [ -n "$entry_line" ] || continue
        mode_char="${entry_line:0:1}"
        case "$mode_char" in
            -|d|l) ;;
            *) die "refusing unsafe tar entry type '$mode_char': $entry_line" ;;
        esac
        # Reject BSD tar hardlinks whether flagged with 'h' or '-' + ' link to '.
        case "$entry_line" in
            *" link to "*) die "refusing hardlink tar entry: $entry_line" ;;
        esac
    done < "$tar_tv"

    while IFS= read -r name; do
        [ -n "$name" ] || continue
        case "$name" in
            /*|*/..|../*|*/../*|..|*/.|./*|*/./*|.|*//*)
                die "refusing unsafe tar path: $name" ;;
            tendcf|tendcf/*) ;;
            *) die "refusing tar entry outside tendcf/: $name" ;;
        esac
    done < "$tar_t"

    local extract_dir="$stage_dir/extract"
    /bin/mkdir -p "$extract_dir"
    /bin/chmod 0700 "$extract_dir"
    COPYFILE_DISABLE=1 /usr/bin/tar \
        --no-same-owner --no-same-permissions --no-acls --no-fflags \
        --no-mac-metadata --no-xattrs \
        -C "$extract_dir" -xzf "$staged_tar" 9>&-

    local staged_tree="$extract_dir/tendcf"
    [ -d "$staged_tree" ] || die "tarball did not extract a tendcf/ directory"
    [ ! -L "$staged_tree" ] || die "tarball extracted a symlink at tendcf"

    # Reject any non-(file|dir|symlink), hardlinked file, or filename containing
    # a newline/control character after extraction (guards against bsdtar escaping).
    local bad_ent ents_list="$stage_dir/extracted-ents.$$.txt"
    /usr/bin/find "$staged_tree" -print0 > "$ents_list" || die "find failed scanning $staged_tree"
    if [ "$(LC_ALL=C /usr/bin/tr -cd '\001-\037\177' < "$ents_list" | /usr/bin/wc -c | /usr/bin/tr -d ' ')" != 0 ]; then
        /bin/rm -f "$ents_list"
        die "refusing extracted entry containing newline or control character"
    fi
    /bin/rm -f "$ents_list"
    bad_ent="$(/usr/bin/find "$staged_tree" ! -type f ! -type d ! -type l -print -quit)"
    [ -z "$bad_ent" ] || die "refusing non-regular extracted entry: $bad_ent"
    bad_ent="$(/usr/bin/find "$staged_tree" -type f -links +1 -print -quit)"
    [ -z "$bad_ent" ] || die "refusing hardlinked extracted file: $bad_ent"

    # Validate EVERY symlink (including multi-hop chains and basenames) stays inside $staged_tree.
    if ! validate_tree_symlinks_ok "$staged_tree" "$prefix"; then
        die "refusing escaping or cyclic symlink in extracted archive"
    fi

    # Clear quarantine, flags (before ACLs/modes so uchg/schg cannot block chmod),
    # ACLs; enforce root:wheel and strip SUID/SGID/go-w, then verify Mach-O +
    # codesign BEFORE placing the tree at /opt/tendcf.
    /usr/bin/xattr -drs com.apple.quarantine "$staged_tree"
    /usr/bin/chflags -R 0 "$staged_tree"
    /bin/chmod -RN "$staged_tree" 2>/dev/null || true
    /usr/sbin/chown -hR root:wheel "$staged_tree"
    /bin/chmod -R a-s,go-w "$staged_tree"
    verify_macho_tree "$staged_tree"

    /usr/bin/install -d -m 0755 -o root -g wheel "$staged_tree/share/tendcf"
    printf '%s\n' "$expected_sha" > "$staged_tree/share/tendcf/INSTALLED_TARBALL.sha256"
    /usr/sbin/chown root:wheel "$staged_tree/share/tendcf/INSTALLED_TARBALL.sha256"
    /bin/chmod 0644 "$staged_tree/share/tendcf/INSTALLED_TARBALL.sha256"

    if [ ! -e "$prefix" ]; then
        /bin/mv "$staged_tree" "$prefix"
        upgrade_prefix_swapped=1
    else
        # Upgrade in place: fail fast if $prefix/var is a symlink BEFORE touching
        # any running cf-execd, then arm the EXIT-trap rollback across the swap
        # and all post-swap cmd_install steps (backup_prefix is deleted only in
        # cmd_install after every post-upgrade step and enable_execd succeed).
        if [ -L "$prefix/var" ]; then
            die "existing $prefix/var is a symlink; refusing upgrade"
        fi
        if [ -f "$plist_path" ] && [ ! -L "$plist_path" ]; then
            upgrade_had_plist=1
        else
            upgrade_had_plist=0
        fi
        local was_loaded=0
        if execd_is_loaded; then
            was_loaded=1
            upgrade_was_loaded=1
            upgrade_rollback_armed=1
            /bin/launchctl bootout "system/$label" 9>&- || die "launchctl bootout system/$label failed before upgrade"
            wait_execd_unloaded || die "org.tendcf.execd remained loaded after bootout before upgrade"
        fi
        local backup_prefix="$prefix.old.$$"
        /bin/rm -rf "$backup_prefix"
        /bin/mv "$prefix" "$backup_prefix" || die "failed to move existing $prefix aside for upgrade"
        upgrade_backup_prefix="$backup_prefix"
        upgrade_staged_tree="$staged_tree"
        upgrade_rollback_armed=1
        # Belt-and-suspenders check after move (concurrent symlink swap): EXIT trap
        # restores $upgrade_backup_prefix -> $prefix and restarts org.tendcf.execd.
        if [ -L "$backup_prefix/var" ]; then
            die "existing $prefix/var is a symlink; refusing upgrade"
        fi
        if [ -d "$backup_prefix/var" ]; then
            /bin/rm -rf "${staged_tree:?}/var"
            /bin/mv "$backup_prefix/var" "$staged_tree/var" \
                || die "failed to preserve $prefix/var during upgrade"
            upgrade_moved_var=1
        fi
        /bin/mv "$staged_tree" "$prefix" \
            || die "failed to install new tree at $prefix"
        upgrade_prefix_swapped=1
        if [ "$was_loaded" -eq 1 ]; then
            upgrade_needs_execd_restart=1
        fi
    fi
    changed=1
}

# Verify every directory component from $prefix down to $workdir is not a symlink.
check_no_symlink_components_under_prefix() {
    local target="$1" rel cur comp
    rel="${target#"$prefix"/}"
    cur="$prefix"
    local old_ifs="$IFS"
    IFS=/
    for comp in $rel; do
        [ -n "$comp" ] || continue
        cur="$cur/$comp"
        if [ -L "$cur" ]; then
            IFS="$old_ifs"
            return 1
        fi
    done
    IFS="$old_ifs"
    return 0
}

# Non-fatal workdir discovery (used by cmd_status on partial/fresh hosts).
try_init_paths() {
    check_ancestors_ok "$prefix" || return 1
    [ ! -L "$prefix" ] || return 1
    tree_is_clean "$prefix" || return 1
    [ -x "$cf_promises" ] && [ ! -L "$cf_promises" ] || return 1
    make_stage
    local probe="$stage_dir/probe.cf" out
    printf 'bundle agent main {}\n' > "$probe"
    out="$("$cf_promises" --show-vars -f "$probe" 2>/dev/null 9>&- | /usr/bin/awk '$1 == "default:sys.workdir" { print $2; exit }')" || true
    /bin/rm -f "$probe"
    case "$out" in
        "$prefix"/*) ;;
        *) return 1 ;;
    esac
    if [[ ! "$out" =~ ^/opt/tendcf/[A-Za-z0-9._/-]+$ ]] || [[ "$out" == *..* ]]; then
        return 1
    fi
    check_no_symlink_components_under_prefix "$out" || return 1
    workdir="$out"
    entry="$workdir/inputs/promises.cf"
    data="$workdir/data/host_specific.json"
    return 0
}

init_paths() {
    check_ancestors "$prefix"
    [ ! -L "$prefix" ] || die "$prefix is a symlink; refusing"
    [ -x "$cf_promises" ] && [ ! -L "$cf_promises" ] || die "$cf_promises missing: pass --tarball FILE --sha256 FILE or install $prefix first"
    tree_is_clean "$prefix" || die "$prefix failed root:wheel / mode / ACL check; run install first"
    make_stage
    local probe="$stage_dir/probe.cf" out
    printf 'bundle agent main {}\n' > "$probe"
    out="$("$cf_promises" --show-vars -f "$probe" 2>/dev/null 9>&- | /usr/bin/awk '$1 == "default:sys.workdir" { print $2; exit }')" || true
    /bin/rm -f "$probe"
    case "$out" in
        "$prefix"/*) ;;
        *) die "cannot read the work directory from $cf_promises (got '${out:-nothing}'); it must be under $prefix" ;;
    esac
    if [[ ! "$out" =~ ^/opt/tendcf/[A-Za-z0-9._/-]+$ ]] || [[ "$out" == *..* ]]; then
        die "unsafe work directory from $cf_promises: $out"
    fi
    check_no_symlink_components_under_prefix "$out" || die "symlink component inside workdir path: $out"
    workdir="$out"
    entry="$workdir/inputs/promises.cf"
    data="$workdir/data/host_specific.json"
}

check_tree() {
    check_ancestors "$prefix"
    check_dir_root_unwritable "$prefix"
    [ -x "$cf_agent" ] && [ ! -L "$cf_agent" ] || die "$cf_agent missing: pass --tarball FILE --sha256 FILE or install $prefix first"
    [ -x "$cf_promises" ] && [ ! -L "$cf_promises" ] || die "$cf_promises missing"
    [ -x "$cf_key" ] && [ ! -L "$cf_key" ] || die "$cf_key missing"
    [ -x "$cf_execd" ] && [ ! -L "$cf_execd" ] || die "$cf_execd missing"

    if ! tree_is_clean "$prefix"; then
        /usr/bin/chflags -R 0 "$prefix"
        /bin/chmod -RN "$prefix" 2>/dev/null || true
        /usr/sbin/chown -hR root:wheel "$prefix"
        /bin/chmod -R a-s,go-w "$prefix"
        tree_is_clean "$prefix" || die "$prefix still failed root:wheel / mode / ACL check after repair"
        changed=1
    fi
    # Fail closed if xattr fails; skip Unix domain sockets (-type s, e.g.
    # cf-execd's var/libntech/state/cf-execd.sockets/runagent.socket where
    # macOS xattr fails with Errno 102 EOPNOTSUPP). Clear stray quarantine
    # only on entries that carry it so xattr -ds never fails with No such xattr.
    local xattr_out
    xattr_out="$(/usr/bin/find "$prefix" ! -type s -exec /usr/bin/xattr -s {} +)" \
        || die "xattr check on $prefix failed"
    if printf '%s\n' "$xattr_out" | /usr/bin/awk '/com\.apple\.quarantine/ { found=1 } END { exit !found }'; then
        make_stage
        local xattr_list="$stage_dir/xattr-paths.$$.txt" xattr_p xattr_a xattr_rc=0
        /usr/bin/find "$prefix" ! -type s -print0 > "$xattr_list" \
            || die "find failed listing $prefix for quarantine cleanup"
        while IFS= read -r -d '' xattr_p; do
            xattr_a="$(/usr/bin/xattr -s "$xattr_p")" || { xattr_rc=1; break; }
            case "$xattr_a" in
                *com.apple.quarantine*)
                    /usr/bin/xattr -ds com.apple.quarantine "$xattr_p" || { xattr_rc=1; break; }
                    ;;
            esac
        done < "$xattr_list"
        /bin/rm -f "$xattr_list"
        [ "$xattr_rc" -eq 0 ] || die "failed to clear com.apple.quarantine under $prefix"
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
        if [ "$cur" = "root:wheel $want_mode" ] && ! has_acl_path "$dir"; then
            return 0
        fi
    fi
    /usr/bin/install -d -m "0$want_mode" -o root -g wheel "$dir"
    /bin/chmod -N "$dir" 2>/dev/null || true
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
        if ! keyout="$("$cf_key" 2>&1 9>&-)"; then
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
    [ ! -L "$policy_src" ] && [ -d "$policy_src" ] \
        || die "policy-src must be a real directory (not a symlink): $policy_src"
    [ -f "$policy_src/tendcf_services.cf" ] && [ ! -L "$policy_src/tendcf_services.cf" ] \
        || die "no regular tendcf_services.cf at $policy_src (use --policy-src DIR)"

    # Refuse any symlink, FIFO, device, or socket under $policy_src BEFORE copying.
    local bad_src
    bad_src="$(/usr/bin/find "$policy_src" ! -type f ! -type d -print -quit)"
    [ -z "$bad_src" ] || die "refusing non-regular/non-directory entry in policy-src: $bad_src"

    make_stage
    local staged_pol="$stage_dir/tendcf-policy"
    /bin/rm -rf "$staged_pol"
    /bin/cp -RP "$policy_src" "$staged_pol"

    # Re-verify after copy (guards against concurrent races in untrusted $policy_src).
    local bad_new
    bad_new="$(/usr/bin/find "$staged_pol" ! -type f ! -type d -print -quit)"
    [ -z "$bad_new" ] || die "refusing non-regular/non-directory entry in staged policy: $bad_new"

    /usr/bin/xattr -drs com.apple.quarantine "$staged_pol"
    /usr/bin/chflags -R 0 "$staged_pol"
    /bin/chmod -RN "$staged_pol" 2>/dev/null || true
    /usr/sbin/chown -hR root:wheel "$staged_pol"
    /bin/chmod -R a-s,go-w "$staged_pol"

    local policy_differs=0
    if [ ! -d "$workdir/inputs/tendcf" ] || [ -L "$workdir/inputs/tendcf" ]; then
        policy_differs=1
    elif ! /usr/bin/diff -rq "$staged_pol" "$workdir/inputs/tendcf" >/dev/null 2>&1; then
        policy_differs=1
    elif ! tree_is_clean "$workdir/inputs/tendcf" no_symlinks; then
        policy_differs=1
    fi
    if [ "$policy_differs" -eq 1 ]; then
        local new="$workdir/inputs/.tendcf.new.$$"
        /bin/rm -rf "$new"
        /bin/mv "$staged_pol" "$new"
        /bin/rm -rf "$workdir/inputs/tendcf"
        /bin/mv "$new" "$workdir/inputs/tendcf"
        changed=1
    else
        /bin/rm -rf "$staged_pol"
    fi

    # Stage promises.cf inside $stage_dir (never directly in $workdir/inputs).
    if [ -L "$entry" ] || [ -d "$entry" ]; then
        die "$entry is not a regular file; refusing"
    fi
    local staged_entry="$stage_dir/promises.cf"
    /bin/cat > "$staged_entry" <<'EOF'
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
      exec_command => "$(sys.cf_agent) --no-augments -f $(sys.inputdir)/promises.cf";
}
EOF
    local entry_differs=0
    if [ ! -f "$entry" ]; then
        entry_differs=1
    elif ! /usr/bin/cmp -s "$staged_entry" "$entry"; then
        entry_differs=1
    elif [ "$(/usr/bin/stat -f '%Su:%Sg %Lp' "$entry")" != "root:wheel 644" ] || has_acl_path "$entry"; then
        entry_differs=1
    fi
    if [ "$entry_differs" -eq 1 ]; then
        local tmp_entry="$entry.new.$$"
        if ! /usr/bin/install -m 0644 -o root -g wheel "$staged_entry" "$tmp_entry"; then
            /bin/rm -f "$tmp_entry"
            die "could not write $tmp_entry"
        fi
        /bin/mv -f "$tmp_entry" "$entry"
        changed=1
    fi
}

# Acquire exclusive lock outside the replaceable $prefix tree so upgrades,
# rollbacks, and standalone `data` publications serialize on one stable inode.
acquire_publish_lock() {
    if [ "${publish_lock_held:-0}" -eq 1 ]; then
        return 0
    fi
    local lock_dir lockfile old_umask
    lock_dir="$(/usr/bin/dirname "$prefix")"
    if [ ! -e "$lock_dir" ] && [ ! -L "$lock_dir" ] && [ "$lock_dir" = "/opt" ]; then
        /usr/bin/install -d -m 0755 -o root -g wheel /opt
        changed=1
    fi
    check_ancestors "$lock_dir"
    check_dir_root_unwritable "$lock_dir"
    lockfile="$lock_dir/.tendcf-publish.lock"
    if [ -e "$lockfile" ] || [ -L "$lockfile" ]; then
        [ -f "$lockfile" ] && [ ! -L "$lockfile" ] || die "$lockfile is not a regular file; refusing"
    fi
    old_umask="$(umask)"
    umask 077
    exec 9>>"$lockfile"
    umask "$old_umask"
    if ! /usr/bin/lockf 9; then
        exec 9>&-
        die "failed to acquire publish lock $lockfile"
    fi
    if [ -L "$lockfile" ] || [ ! -f "$lockfile" ]; then
        exec 9>&-
        die "$lockfile is not a regular file; refusing"
    fi
    /usr/sbin/chown root:wheel "$lockfile"
    /bin/chmod 0600 "$lockfile"
    /bin/chmod -N "$lockfile" 2>/dev/null || true
    publish_lock_held=1
}

release_publish_lock() {
    if [ "${publish_lock_held:-0}" -eq 1 ]; then
        exec 9>&-
        publish_lock_held=0
    fi
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
    [ ! -L "$projector_src" ] && [ -f "$projector_src" ] \
        || die "projector-src must be a regular non-symlink file: $projector_src"
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

# Non-fatal trust check: regular non-symlink file, root:wheel, not
# group/world-writable or SUID/SGID, no extended ACLs, and every ancestor
# up to / is a root-owned non-symlink non-writable ACL-free directory.
source_file_root_trusted_ok() {
    local f="$1" meta owner group mode mode_oct
    [ ! -L "$f" ] && [ -f "$f" ] || return 1
    check_ancestors_ok "$f" || return 1
    meta="$(/usr/bin/stat -f '%Su %Sg %Lp' "$f" 2>/dev/null)" || return 1
    read -r owner group mode <<< "$meta"
    [ "$owner" = root ] || return 1
    [ "$group" = wheel ] || return 1
    mode_oct=$((8#$mode))
    [ $((mode_oct & 8#6022)) -eq 0 ] || return 1
    if has_acl_path "$f"; then
        return 1
    fi
    return 0
}

check_source_file_root_trusted() {
    local f="$1"
    source_file_root_trusted_ok "$f" \
        || die "$f is not a root:wheel non-writable ACL-free regular file with trusted ancestors (or pass --projector-sha256)"
}

verify_installed_projector() {
    check_ancestors "$installed_projector"
    local d meta owner group mode mode_oct
    for d in "$prefix" "$prefix/share" "$prefix/share/tendcf" "$prefix/share/tendcf/bin"; do
        check_dir_root_unwritable "$d"
    done
    [ -f "$installed_projector" ] && [ ! -L "$installed_projector" ] \
        || die "installed projector missing or symlink: $installed_projector (run install first)"
    meta="$(/usr/bin/stat -f '%Su %Sg %Lp' "$installed_projector")" || die "cannot stat $installed_projector"
    read -r owner group mode <<< "$meta"
    [ "$owner" = root ] || die "$installed_projector owned by $owner, expected root"
    [ "$group" = wheel ] || die "$installed_projector group is $group, expected wheel"
    mode_oct=$((8#$mode))
    if [ $((mode_oct & 8#6022)) -ne 0 ]; then
        die "$installed_projector mode $mode is group/world-writable or SUID/SGID"
    fi
    if has_acl_path "$installed_projector"; then
        die "$installed_projector has an extended ACL; refusing"
    fi
    if /usr/bin/xattr -p com.apple.quarantine "$installed_projector" >/dev/null 2>&1; then
        die "$installed_projector has com.apple.quarantine; refusing"
    fi
}

# Non-fatal check: $installed_projector is already a completely clean, trusted
# regular non-symlink file (root:wheel 0644, flags=0, no ACLs, no quarantine)
# under real non-symlink root:wheel non-writable ACL-free dirs up to /.
installed_projector_clean_ok() {
    check_ancestors_ok "$prefix" || return 1
    local d meta owner group mode
    for d in "$prefix" "$prefix/share" "$prefix/share/tendcf" "$prefix/share/tendcf/bin"; do
        [ ! -L "$d" ] && [ -d "$d" ] || return 1
        meta="$(/usr/bin/stat -f '%Su %Sg %Lp' "$d" 2>/dev/null)" || return 1
        read -r owner group mode <<< "$meta"
        [ "$owner" = root ] && [ "$group" = wheel ] || return 1
        [ $((8#$mode & 8#022)) -eq 0 ] || return 1
        if has_acl_path "$d"; then
            return 1
        fi
    done
    [ -f "$installed_projector" ] && [ ! -L "$installed_projector" ] || return 1
    [ "$(/usr/bin/stat -f '%f' "$installed_projector" 2>/dev/null)" = "0" ] || return 1
    meta="$(/usr/bin/stat -f '%Su %Sg %Lp' "$installed_projector" 2>/dev/null)" || return 1
    read -r owner group mode <<< "$meta"
    [ "$owner" = root ] && [ "$group" = wheel ] && [ $((8#$mode)) -eq $((8#644)) ] || return 1
    if has_acl_path "$installed_projector"; then
        return 1
    fi
    if /usr/bin/xattr -p com.apple.quarantine "$installed_projector" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# Establish projector source trust and stage bytes ONCE into a private
# root-only 0700 file BEFORE install_tarball() and check_tree() mutate or
# repair permissions under $prefix (prevents laundering a writable/non-root
# source into root-owned and verifies --projector-sha256 before any mutation).
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
        die "$projector_src is not a root:wheel non-writable ACL-free regular file with trusted ancestors (or pass --projector-sha256)"
    fi

    make_stage
    local staged_proj="$stage_dir/prepared-projector.py"
    local old_umask actual_sha
    old_umask="$(umask)"
    umask 077
    /bin/cat "$projector_src" > "$staged_proj"
    umask "$old_umask"
    /usr/sbin/chown root:wheel "$staged_proj"
    /bin/chmod 0600 "$staged_proj"
    prepared_projector_file="$staged_proj"

    if [ -n "$projector_sha256" ]; then
        actual_sha="$(/usr/bin/shasum -a 256 "$staged_proj" | /usr/bin/awk '{ print tolower($1) }')"
        if [ "$actual_sha" != "$projector_sha256" ]; then
            /bin/rm -f "$staged_proj"
            prepared_projector_file=""
            die "projector sha256 mismatch for $projector_src: expected $projector_sha256, got $actual_sha"
        fi
    fi
    projector_prepared=1
}

# Refuse ANY unsafe existing directory in $prefix..$prefix/share/tendcf/bin
# BEFORE mutating permissions/ACLs or running check_tree() (zero directory
# mutation, eliminating TOCTOU/SIGKILL parent-laundering windows), and detach
# any unsafe existing leaf inside an already-trusted parent chain.
detach_unsafe_installed_projector() {
    check_ancestors "$prefix"
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
        if [ -f "$installed_projector" ] && [ ! -L "$installed_projector" ]; then
            /usr/bin/chflags 0 "$installed_projector"
        fi
        /bin/rm -f "$installed_projector"
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
    ensure_dir 755 "$prefix/share"
    ensure_dir 755 "$prefix/share/tendcf"
    ensure_dir 755 "$prefix/share/tendcf/bin"

    if [ -L "$installed_projector" ] || [ -d "$installed_projector" ]; then
        die "$installed_projector is not a regular file; refusing"
    fi

    # Operate exclusively from $prepared_projector_file (never re-resolve or
    # re-read $projector_src). Preserve the existing inode (no change) ONLY when
    # no tarball prefix swap occurred, $installed_projector was already clean
    # before check_tree(), bytes match $prepared_projector_file, and current
    # metadata is clean.
    local proj_differs=1 dst_flags=0
    if [ "${upgrade_prefix_swapped:-0}" -eq 0 ] \
        && [ "${installed_projector_originally_clean:-0}" -eq 1 ] \
        && [ -f "$installed_projector" ] && [ ! -L "$installed_projector" ] \
        && /usr/bin/cmp -s "$prepared_projector_file" "$installed_projector" \
        && installed_projector_clean_ok; then
        proj_differs=0
    elif [ -e "$installed_projector" ] && [ ! -L "$installed_projector" ]; then
        dst_flags="$(/usr/bin/stat -f '%f' "$installed_projector")"
    fi

    if [ "$proj_differs" -eq 1 ]; then
        local old_umask tmp_proj
        old_umask="$(umask)"
        umask 022
        tmp_proj="$(/usr/bin/mktemp "$prefix/share/tendcf/bin/.projector.py.new.XXXXXX")"
        umask "$old_umask"
        place_projector_tmp="$tmp_proj"
        /bin/cat "$prepared_projector_file" > "$tmp_proj"
        /usr/bin/chflags 0 "$tmp_proj"
        if /usr/bin/xattr -p com.apple.quarantine "$tmp_proj" >/dev/null 2>&1; then
            /usr/bin/xattr -d com.apple.quarantine "$tmp_proj"
        fi
        /bin/chmod -N "$tmp_proj" 2>/dev/null || true
        /usr/sbin/chown root:wheel "$tmp_proj"
        /bin/chmod 0644 "$tmp_proj"
        if [ -e "$installed_projector" ] && [ "$dst_flags" != "0" ]; then
            /usr/bin/chflags 0 "$installed_projector"
        fi
        /bin/mv -f "$tmp_proj" "$installed_projector"
        place_projector_tmp=""
        changed=1
    fi
    /bin/rm -f "$prepared_projector_file"
    prepared_projector_file=""
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
    classes_file="$(/usr/bin/mktemp "$tmp_dir/.cf-classes.XXXXXX")"
    err_file="$(/usr/bin/mktemp "$tmp_dir/.cf-err.XXXXXX")"
    umask "$old_umask"
    /bin/chmod 0600 "$classes_file" "$err_file"

    if ! "$cf_promises" --workdir "$wd" -f "$entry_file" --show-classes >"$classes_file" 2>"$err_file" 9>&-; then
        if [ -s "$err_file" ]; then
            /bin/cat "$err_file" >&2
        fi
        /bin/rm -f "$classes_file" "$err_file"
        echo "tendcf-install: cf-promises failed validating $wd" >&2
        return 1
    fi

    parse_msg="$(/usr/bin/awk '
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
    /bin/rm -f "$classes_file" "$err_file"

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

put_data() {  # put_data FILE
    local src="$1"
    [ ! -L "$src" ] && [ -f "$src" ] || die "data file must be a regular non-symlink file: $src"

    # Acquire the shared publish lock outside $prefix BEFORE inspecting any
    # live paths under $prefix (including verify_installed_projector) so
    # direct put_data calls also serialize cleanly with upgrades/rollbacks.
    local acquired_lock=0
    if [ "${publish_lock_held:-0}" -eq 0 ]; then
        acquire_publish_lock
        acquired_lock=1
    fi

    [ -f "$entry" ] && [ ! -L "$entry" ] || die "not installed: run install first"
    [ -d "$workdir/inputs" ] && [ ! -L "$workdir/inputs" ] || die "$workdir/inputs missing or symlink"
    check_dir_root_unwritable "$workdir/data"

    # Create stage_dir in the main shell BEFORE command-substitution subshells
    # (find_real_python) so no subshell leaks a /var/tmp directory.
    make_stage
    verify_installed_projector

    local py
    py="$(find_real_python)" || die "cannot validate projection: no verified root-owned Python 3 found"

    if [ -e "$data" ] || [ -L "$data" ]; then
        if [ -L "$data" ] || [ ! -f "$data" ]; then
            if [ "$acquired_lock" -eq 1 ]; then release_publish_lock; fi
            die "$data is not a regular file; refusing"
        fi
    fi

    # Stage candidate bytes ONCE into a private 0700 workdir (zero TOCTOU, zero
    # pre-validation exposure to cf-execd; issues #53, #57).
    local old_umask stage_wd staged_data data_bytes
    old_umask="$(umask)"
    umask 077
    stage_wd="$(/usr/bin/mktemp -d "$stage_dir/putdata.XXXXXX")"
    umask "$old_umask"
    put_data_stage_wd="$stage_wd"
    /usr/sbin/chown root:wheel "$stage_wd"
    /bin/chmod 0700 "$stage_wd"

    /usr/bin/install -d -m 0755 -o root -g wheel \
        "$stage_wd/bin" "$stage_wd/outputs" "$stage_wd/modules" "$stage_wd/state"
    /usr/bin/install -d -m 0700 -o root -g wheel "$stage_wd/ppkeys" "$stage_wd/data"
    /bin/cp -pRP "$workdir/inputs" "$stage_wd/inputs"

    staged_data="$stage_wd/data/host_specific.json"
    old_umask="$(umask)"
    umask 077
    /bin/cat "$src" > "$staged_data"
    umask "$old_umask"
    /usr/sbin/chown root:wheel "$staged_data"
    /bin/chmod 0600 "$staged_data"
    /bin/chmod -N "$staged_data" 2>/dev/null || true

    # Gate 1 (#53): projector contract check (stdlib-only isolated python3 -I -S,
    # FD 9 closed in child, site-packages disabled).
    if ! "$py" -I -S "$installed_projector" --check "$staged_data" 9>&-; then
        die "projector rejected $src; live $data untouched"
    fi

    # Gate 2 (#57): pre-publish cf-promises --show-classes check on staged workdir.
    if ! validate_cmdb_workdir "$stage_wd" "$stage_wd/inputs/promises.cf" "$stage_wd"; then
        die "pre-publish CMDB validation rejected $src; live $data untouched"
    fi

    data_bytes="$(/usr/bin/wc -c < "$staged_data" | /usr/bin/tr -d ' ')"

    # Idempotent fast path (under lock, after Gates 1 & 2): identical bytes,
    # root:wheel 600, no ACLs.
    if [ -f "$data" ] && [ ! -L "$data" ] \
        && /usr/bin/cmp -s "$staged_data" "$data" \
        && [ "$(/usr/bin/stat -f '%Su:%Sg %Lp' "$data")" = "root:wheel 600" ] \
        && ! has_acl_path "$data"; then
        if ! validate_cmdb_workdir "$workdir" "$entry" "$stage_wd"; then
            die "existing live $data failed CMDB validation"
        fi
        /bin/rm -rf "$stage_wd"
        put_data_stage_wd=""
        if [ "$acquired_lock" -eq 1 ]; then
            release_publish_lock
        fi
        return 0
    fi

    # Atomic publish using unique same-directory mktemp staging/backup paths (#58).
    local tmp backup=""
    put_data_had_prev=0
    put_data_rollback_armed=0
    old_umask="$(umask)"
    umask 077
    tmp="$(/usr/bin/mktemp "$workdir/data/.host_specific.new.XXXXXX")"
    umask "$old_umask"
    put_data_tmp="$tmp"
    /bin/cat "$staged_data" > "$tmp"
    /usr/sbin/chown root:wheel "$tmp"
    /bin/chmod 0600 "$tmp"
    /bin/chmod -N "$tmp" 2>/dev/null || true

    if [ -f "$data" ] && [ ! -L "$data" ]; then
        old_umask="$(umask)"
        umask 077
        backup="$(/usr/bin/mktemp "$workdir/data/.host_specific.prev.XXXXXX")"
        umask "$old_umask"
        put_data_backup="$backup"
        put_data_had_prev=1
        /bin/cat "$data" > "$backup"
        /usr/sbin/chown root:wheel "$backup"
        /bin/chmod 0600 "$backup"
        /bin/chmod -N "$backup" 2>/dev/null || true
    fi

    # Arm rollback right before atomic swap so any failure or catchable
    # SIGTERM/SIGINT during Gate 3 restores $backup (or removes first-time $data)
    # while still holding FD 9.
    put_data_rollback_armed=1
    /bin/mv -f "$tmp" "$data"
    put_data_tmp=""

    # Gate 3 (#57): post-publish verification on live workdir with atomic rollback.
    if ! validate_cmdb_workdir "$workdir" "$entry" "$stage_wd"; then
        if [ "$put_data_had_prev" -eq 1 ]; then
            if ! /bin/mv -f "$backup" "$data"; then
                put_data_backup=""
                put_data_rollback_armed=0
                die "cf-promises rejected $src and rollback failed; backup preserved at $backup"
            fi
            put_data_backup=""
            put_data_rollback_armed=0
            die "post-publish CMDB validation rejected $src; previous data restored"
        else
            if /bin/rm -f "$data" && [ ! -e "$data" ] && [ ! -L "$data" ]; then
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
        /bin/rm -f "$backup"
        put_data_backup=""
    fi
    /bin/rm -rf "$stage_wd"
    put_data_stage_wd=""
    if [ "$acquired_lock" -eq 1 ]; then
        release_publish_lock
    fi
    changed=1
    say "data installed: $data ($data_bytes bytes)"
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

bootstrap_execd_with_retry() {
    if /bin/launchctl bootstrap system "$plist_path" 9>&-; then
        return 0
    fi
    /bin/sleep 1
    /bin/launchctl bootstrap system "$plist_path" 9>&-
}

enable_execd() {
    check_launchd_dir
    [ -f "$entry" ] || die "not installed: run install first"

    make_stage
    local staged_plist="$stage_dir/$label.plist"
    local prev_plist="$stage_dir/$label.plist.prev"
    local had_prev=0
    render_execd_plist "$staged_plist"

    local plist_changed=0
    if [ ! -f "$plist_path" ]; then
        plist_changed=1
    elif ! /usr/bin/cmp -s "$staged_plist" "$plist_path"; then
        plist_changed=1
    elif [ "$(/usr/bin/stat -f '%Su:%Sg %Lp' "$plist_path")" != "root:wheel 644" ] || has_acl_path "$plist_path"; then
        plist_changed=1
    fi

    if [ "$plist_changed" -eq 1 ]; then
        if [ -f "$plist_path" ]; then
            /usr/bin/install -m 0644 -o root -g wheel "$plist_path" "$prev_plist"
            had_prev=1
        fi
        local tmp="$plist_path.new.$$"
        if ! /usr/bin/install -m 0644 -o root -g wheel "$staged_plist" "$tmp"; then
            /bin/rm -f "$tmp"
            die "could not write $tmp"
        fi
        /bin/mv -f "$tmp" "$plist_path"
        changed=1
    fi

    /bin/launchctl enable "system/$label" 9>&- || die "launchctl enable system/$label failed"

    if execd_is_loaded; then
        if [ "$plist_changed" -eq 1 ]; then
            /bin/launchctl bootout "system/$label" 9>&- || die "launchctl bootout system/$label failed"
            wait_execd_unloaded || die "org.tendcf.execd remained loaded after bootout"
            if ! bootstrap_execd_with_retry; then
                if [ "$had_prev" -eq 1 ]; then
                    /usr/bin/install -m 0644 -o root -g wheel "$prev_plist" "$plist_path.rollback.$$" \
                        && /bin/mv -f "$plist_path.rollback.$$" "$plist_path"
                    /bin/launchctl bootstrap system "$plist_path" >/dev/null 2>&1 9>&- || true
                fi
                die "launchctl bootstrap system $plist_path failed; previous plist restored"
            fi
        fi
    else
        if ! bootstrap_execd_with_retry; then
            if [ "$plist_changed" -eq 1 ]; then
                if [ "$had_prev" -eq 1 ]; then
                    /usr/bin/install -m 0644 -o root -g wheel "$prev_plist" "$plist_path.rollback.$$" \
                        && /bin/mv -f "$plist_path.rollback.$$" "$plist_path"
                else
                    /bin/rm -f "$plist_path"
                fi
            fi
            die "launchctl bootstrap system $plist_path failed"
        fi
        changed=1
    fi
}

# L2 (issue #99): fail closed if a previous interrupted upgrade (SIGKILL or
# power loss) left /opt/tendcf.old.* or /opt/tendcf.failed.* behind, so var/
# identity is never stranded or overwritten silently.
check_no_stale_upgrade_dirs() {
    local had_nullglob=0 stale=() p
    shopt -q nullglob && had_nullglob=1
    shopt -s nullglob
    for p in "$prefix".old.* "$prefix".failed.*; do
        stale+=("$p")
    done
    if [ "$had_nullglob" -eq 0 ]; then
        shopt -u nullglob
    fi
    if [ "${#stale[@]}" -gt 0 ]; then
        die "stale upgrade directory(ies) found (possible interrupted upgrade): ${stale[*]}; inspect and recover/remove manually before installing"
    fi
}

prevalidate_install_inputs() {
    local datafile="$1"
    [ ! -L "$policy_src" ] && [ -d "$policy_src" ] \
        || die "policy-src must be a real directory (not a symlink): $policy_src"
    [ -f "$policy_src/tendcf_services.cf" ] && [ ! -L "$policy_src/tendcf_services.cf" ] \
        || die "no regular tendcf_services.cf at $policy_src (use --policy-src DIR)"
    local bad_src
    bad_src="$(/usr/bin/find "$policy_src" ! -type f ! -type d -print -quit)"
    [ -z "$bad_src" ] || die "refusing non-regular/non-directory entry in policy-src: $bad_src"
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
    local tarball="" sha256_file="" datafile="" do_enable=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --tarball) [ $# -ge 2 ] && [ -n "$2" ] || die "install: --tarball needs a non-empty path"; tarball="$2"; shift 2 ;;
            --sha256) [ $# -ge 2 ] && [ -n "$2" ] || die "install: --sha256 needs a non-empty path"; sha256_file="$2"; shift 2 ;;
            --data) [ $# -ge 2 ] && [ -n "$2" ] || die "install: --data needs a non-empty path"; datafile="$2"; shift 2 ;;
            --policy-src) [ $# -ge 2 ] && [ -n "$2" ] || die "install: --policy-src needs a non-empty path"; policy_src="$2"; shift 2 ;;
            --projector-src) [ $# -ge 2 ] && [ -n "$2" ] || die "install: --projector-src needs a non-empty path"; projector_src="$2"; shift 2 ;;
            --projector-sha256) [ $# -ge 2 ] && [ -n "$2" ] || die "install: --projector-sha256 needs a 64-hex sha256"; projector_sha256="$2"; shift 2 ;;
            --enable) do_enable=1; shift ;;
            *) die "install: unknown argument $1" ;;
        esac
    done
    if [ -n "$sha256_file" ] && [ -z "$tarball" ]; then
        die "install: --sha256 requires --tarball"
    fi
    # Fail fast on bad --policy-src, --projector-src, --projector-sha256 or --data,
    # then serialize the entire install/upgrade/rollback transaction under the
    # shared lock outside $prefix BEFORE checking stale dirs or booting out execd.
    prevalidate_install_inputs "$datafile"
    acquire_publish_lock
    check_no_stale_upgrade_dirs
    prepare_projector_source
    if [ -n "$tarball" ]; then
        if [ -z "$sha256_file" ]; then
            sha256_file="${tarball}.sha256"
        fi
        install_tarball "$tarball" "$sha256_file"
    fi
    detach_unsafe_installed_projector
    check_tree
    init_paths
    if [ "$upgrade_rollback_armed" -eq 1 ]; then
        make_stage
        local var_bak="$stage_dir/upgrade-var-backup"
        /bin/rm -rf "$var_bak"
        /usr/bin/install -d -m 0700 -o root -g wheel "$var_bak"
        upgrade_saved_workdir="$workdir"
        upgrade_saved_inputs=0
        upgrade_saved_data=0
        if [ -d "$workdir/inputs" ] && [ ! -L "$workdir/inputs" ]; then
            /bin/cp -pRP "$workdir/inputs" "$var_bak/inputs"
            upgrade_saved_inputs=1
        fi
        if [ -f "$workdir/data/host_specific.json" ] && [ ! -L "$workdir/data/host_specific.json" ]; then
            /bin/cp -p "$workdir/data/host_specific.json" "$var_bak/host_specific.json"
            upgrade_saved_data=1
        fi
        upgrade_snapshot_taken=1
    fi
    lay_out
    place_policy
    place_projector
    if [ -n "$datafile" ]; then
        put_data "$datafile"
    fi
    if [ "$do_enable" -eq 1 ] || [ "$upgrade_needs_execd_restart" -eq 1 ]; then
        enable_execd
        if [ "$upgrade_needs_execd_restart" -eq 1 ]; then
            say "restarted: $label after upgrade"
        fi
    fi
    # All post-upgrade steps and daemon restart succeeded; disarm rollback,
    # remove the pre-upgrade backup tree, and only then release the shared lock.
    upgrade_rollback_armed=0
    if [ -n "$upgrade_backup_prefix" ]; then
        /bin/rm -rf "$upgrade_backup_prefix"
        upgrade_backup_prefix=""
    fi
    upgrade_staged_tree=""
    upgrade_moved_var=0
    upgrade_was_loaded=0
    upgrade_had_plist=0
    upgrade_snapshot_taken=0
    upgrade_saved_workdir=""
    upgrade_saved_inputs=0
    upgrade_saved_data=0
    upgrade_prefix_swapped=0
    release_publish_lock
    if [ "$changed" -eq 0 ]; then
        say "no change ($("$cf_agent" --version | /usr/bin/sed -n 1p))"
    else
        say "installed: $("$cf_agent" --version | /usr/bin/sed -n 1p)"
    fi
}

cmd_run_once() {
    [ -f "$entry" ] || die "not installed: run install first"
    [ -f "$data" ] || die "no CMDB data: run install --data FILE or data FILE first"
    "$cf_agent" --no-augments -K -I -f "$entry"
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
        wait_execd_unloaded || die "org.tendcf.execd remained loaded after bootout"
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
    local tree_str entry_str data_str plist_str loaded_state="not loaded"
    if [ -L "$prefix" ]; then
        tree_str="symlink (refused)"
    elif [ ! -e "$prefix" ]; then
        tree_str="missing"
    else
        tree_str="$(/usr/bin/stat -f '%Su:%Sg %Lp' "$prefix" 2>/dev/null || echo unknown)"
    fi

    if try_init_paths; then
        entry_str="$( [ -f "$entry" ] && echo present || echo missing )"
        data_str="$( [ -f "$data" ] && /usr/bin/stat -f '%Su:%Sg %Lp %z bytes' "$data" || echo missing )"
    elif [ ! -e "$prefix" ] && [ ! -L "$prefix" ]; then
        entry_str="missing"
        data_str="missing"
    else
        entry_str="unknown (tree not verified)"
        data_str="unknown (tree not verified)"
    fi

    if [ -L "$plist_path" ]; then
        plist_str="symlink (refused)"
    elif [ -f "$plist_path" ]; then
        plist_str="$(/usr/bin/stat -f '%Su:%Sg %Lp' "$plist_path")"
    else
        plist_str="missing"
    fi
    if execd_is_loaded; then
        loaded_state="loaded"
    fi
    local had_nullglob=0 stale=() p
    shopt -q nullglob && had_nullglob=1
    shopt -s nullglob
    for p in "$prefix".old.* "$prefix".failed.*; do
        stale+=("$p")
    done
    if [ "$had_nullglob" -eq 0 ]; then
        shopt -u nullglob
    fi
    echo "tree:     $tree_str"
    echo "entry:    $entry_str"
    echo "data:     $data_str"
    echo "$label: $plist_str / $loaded_state"
    if [ "${#stale[@]}" -gt 0 ]; then
        echo "stale:    ${stale[*]} (interrupted upgrade artifact; inspect before installing)"
    fi
}

[ $# -ge 1 ] || die "usage: $0 install|data|run-once|enable|disable|status|workdir ..."
sub="$1"; shift
case "$sub" in
    install) cmd_install "$@" ;;
    disable) cmd_disable ;;
    workdir) init_paths; echo "$workdir" ;;
    data)
        [ $# -eq 1 ] && [ -n "$1" ] || die "usage: $0 data FILE"
        acquire_publish_lock
        init_paths
        put_data "$1"
        release_publish_lock
        if [ "$changed" -eq 0 ]; then say "no change ($data)"; fi
        ;;
    run-once) init_paths; cmd_run_once ;;
    enable) init_paths; cmd_enable ;;
    status) cmd_status ;;
    *) die "unknown command: $sub" ;;
esac
