#!/usr/bin/env bash
# Root-owned tendcf install on a Linux host booted by systemd
# (docs/architecture/linux-targets.md, step 7). Run as root.
#
# Shape, which is CFEngine's own (the book's ch. 19/21/23, cf-execd and MPF
# docs): binaries and policy root-owned, the work directory inside the same
# root-owned tree, and a root cf-execd that runs cf-agent on a schedule. The
# work directory is whatever the binaries compile in (this fork build:
# /opt/tendcf/var/libntech, libntech's own configure names it), read from
# cf-promises, never assumed. Nothing here leaves a sudoers rule behind and
# nothing a non-root user can write is read by root.
#
#   install [--data FILE] [--policy-src DIR] [--projector-src FILE]
#                    make /opt/tendcf root-owned, lay out the work directory, put the
#                    policy, promises.cf and projector.py in place, optionally install
#                    the CMDB data (validated by projector.py and cf-promises before
#                    publication)
#   data FILE        replace the CMDB data (serialized via flock, validated by
#                    projector.py and cf-promises --show-classes before publication,
#                    verified post-publish with atomic rollback on failure)
#   run-once         one `cf-agent -K -I` pass over the installed policy
#   enable           install and start tendcf-execd.service (root cf-execd)
#   disable          stop and remove it
#   status           what is installed and running
#
# The tree at /opt/tendcf is a CI build made with --prefix=/opt/tendcf, so its
# runtime library path is a root-owned directory; `install` refuses a binary
# whose libraries resolve anywhere an unprivileged user could place one.
set -euo pipefail
umask 022

prefix=/opt/tendcf
# RUNPATH is not inherited by a library's own dependencies: libpromises.so
# needs librsync/libb2, which the artifact bundles in $prefix/lib, and only
# a library path finds them on a host that does not have them installed
# (pastebin, 2026-10-31). Set here, to the root-owned directory, replacing
# any inherited value so a caller's environment cannot choose what root loads.
export LD_LIBRARY_PATH="$prefix/lib"
workdir=""   # set by init_paths
unit=tendcf-execd.service
unit_path=/etc/systemd/system/$unit
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
policy_src="$here/../../policy"
projector_src=""
installed_projector="$prefix/share/tendcf/bin/projector.py"

probe_tmp=""
place_projector_tmp=""
put_data_stage_wd=""
put_data_tmp=""
put_data_backup=""

die() { echo "tendcf-install: $*" >&2; exit 1; }
say() { echo "tendcf-install: $*"; }

cleanup_put_data() {
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
}

cleanup_temp() {
    cleanup_put_data
    if [ -n "${place_projector_tmp:-}" ]; then
        rm -f "$place_projector_tmp" || true
        place_projector_tmp=""
    fi
    if [ -n "${probe_tmp:-}" ]; then
        rm -f "$probe_tmp" || true
        probe_tmp=""
    fi
}
trap cleanup_temp EXIT

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

check_ancestor_dir_ok() {
    local dir="$1" meta uid mode mode_oct
    [ -d "$dir" ] || return 1
    if [ -L "$dir" ]; then
        uid="$(stat -c '%u' "$dir" 2>/dev/null)" || return 1
        [ "$uid" = 0 ] || return 1
        dir="$(readlink -f "$dir" 2>/dev/null)" || return 1
        [ -d "$dir" ] && [ ! -L "$dir" ] || return 1
    fi
    meta="$(stat -c '%u %a' "$dir" 2>/dev/null)" || return 1
    read -r uid mode <<< "$meta"
    [ "$uid" = 0 ] || return 1
    mode_oct=$((8#$mode))
    [ $((mode_oct & 8#022)) -eq 0 ] || return 1
    return 0
}

check_ancestors_ok() {
    local p="$1" parent
    case "$p" in
        /*) ;;
        *) return 1 ;;
    esac
    parent="$p"
    while [ "$parent" != "/" ]; do
        parent="$(dirname "$parent")"
        check_ancestor_dir_ok "$parent" || return 1
    done
    return 0
}

resolve_safe_python_ok() {
    local p="$1" hops=0 target real_p meta uid mode mode_oct
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
        case "$target" in
            /*) p="$target" ;;
            *) p="$(dirname "$p")/$target" ;;
        esac
    done
    [ -f "$p" ] && [ ! -L "$p" ] && [ -x "$p" ] || return 1
    real_p="$(readlink -f "$p" 2>/dev/null)" || return 1
    [ -f "$real_p" ] && [ ! -L "$real_p" ] && [ -x "$real_p" ] || return 1
    check_ancestors_ok "$real_p" || return 1
    meta="$(stat -c '%u %a' "$real_p" 2>/dev/null)" || return 1
    read -r uid mode <<< "$meta"
    [ "$uid" = 0 ] || return 1
    mode_oct=$((8#$mode))
    [ $((mode_oct & 8#6022)) -eq 0 ] || return 1
    printf '%s\n' "$real_p"
}

find_trusted_python() {
    local cand real_py path_py=""
    local cands=(/usr/bin/python3 /bin/python3)
    path_py="$(command -v python3 2>/dev/null || true)"
    if [ -n "$path_py" ] && [ "$path_py" != /usr/bin/python3 ] && [ "$path_py" != /bin/python3 ]; then
        cands+=("$path_py")
    fi
    for cand in "${cands[@]}"; do
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
        if [ -e "$here/../../bin/projector.py" ] || [ -L "$here/../../bin/projector.py" ]; then
            projector_src="$here/../../bin/projector.py"
        elif [ -e "$here/bin/projector.py" ] || [ -L "$here/bin/projector.py" ]; then
            projector_src="$here/bin/projector.py"
        else
            die "projector.py not found (use --projector-src FILE)"
        fi
    fi
    [ -f "$projector_src" ] && [ ! -L "$projector_src" ] \
        || die "projector-src must be a regular non-symlink file: $projector_src"
}

verify_installed_projector() {
    local d meta uid gid mode mode_oct
    for d in "$prefix" "$prefix/share" "$prefix/share/tendcf" "$prefix/share/tendcf/bin"; do
        check_dir_root_unwritable "$d"
    done
    [ -f "$installed_projector" ] && [ ! -L "$installed_projector" ] \
        || die "installed projector missing or symlink: $installed_projector (run install first)"
    meta="$(stat -c '%u %g %a' "$installed_projector")" || die "cannot stat $installed_projector"
    read -r uid gid mode <<< "$meta"
    [ "$uid" = 0 ] || die "$installed_projector owned by uid $uid, expected root"
    [ "$gid" = 0 ] || die "$installed_projector group is gid $gid, expected root"
    mode_oct=$((8#$mode))
    if [ $((mode_oct & 8#6022)) -ne 0 ]; then
        die "$installed_projector mode $mode is group/world-writable or SUID/SGID"
    fi
}

init_paths() {
    [ -x "$cf_promises" ] || die "$cf_promises missing: extract the CFEngine tree to $prefix first"
    local probe out
    probe="$(mktemp)"
    probe_tmp="$probe"
    printf 'bundle agent main {}\n' > "$probe"
    out="$("$cf_promises" --show-vars -f "$probe" 2>/dev/null | awk '$1 == "default:sys.workdir" { print $2; exit }')" || true
    rm -f "$probe"
    probe_tmp=""
    case "$out" in
        "$prefix"/*) ;;
        *) die "cannot read the work directory from $cf_promises (got '${out:-nothing}'); it must be under $prefix" ;;
    esac
    workdir="$out"
    entry="$workdir/inputs/promises.cf"
    data="$workdir/data/host_specific.json"
}

check_tree() {
    [ -x "$cf_agent" ] || die "$cf_agent missing: extract the CFEngine tree to $prefix first"
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
        done < <(ldd "$bin" | awk '$2 == "=>" && $3 ~ /^\// { print $3 }')
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
        if ! keyout="$("$cf_key" 2>&1)"; then
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
      exec_command => "$(sys.cf_agent) -f $(sys.inputdir)/promises.cf";
}
EOF
    chmod 0644 "$entry.new"
    mv -f "$entry.new" "$entry"
}

place_projector() {
    resolve_projector_src
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

    local src_real dst_dir_real dst_real
    src_real="$(readlink -f "$projector_src")" || die "cannot resolve $projector_src"
    dst_dir_real="$(readlink -f "$prefix/share/tendcf/bin")" || die "cannot resolve $prefix/share/tendcf/bin"
    dst_real="$dst_dir_real/projector.py"

    if [ "$src_real" = "$dst_real" ]; then
        [ -f "$installed_projector" ] && [ ! -L "$installed_projector" ] \
            || die "$installed_projector is not a regular non-symlink file"
        chown root:root "$installed_projector"
        chmod 0644 "$installed_projector"
    else
        local old_umask tmp
        old_umask="$(umask)"
        umask 022
        tmp="$(mktemp "$prefix/share/tendcf/bin/.projector.py.new.XXXXXX")"
        umask "$old_umask"
        place_projector_tmp="$tmp"
        cat "$projector_src" > "$tmp"
        chown root:root "$tmp"
        chmod 0644 "$tmp"
        mv -f "$tmp" "$installed_projector"
        place_projector_tmp=""
    fi
    verify_installed_projector
}

# Validate CMDB data in WD using cf-promises --show-classes (issue #57).
# Captures stdout to a 0600 file in TMP_DIR (never pipes cf-promises directly)
# and fails closed on non-zero exit, empty output, tendcf_cmdb_refused, or any
# tendcf_cmdb_problem_* class.
validate_cmdb_workdir() {  # validate_cmdb_workdir WD ENTRY_FILE TMP_DIR
    local wd="$1" entry_file="$2" tmp_dir="$3"
    local old_umask classes_file err_file refused refused_line
    old_umask="$(umask)"
    umask 077
    classes_file="$(mktemp "$tmp_dir/.cf-classes.XXXXXX")"
    err_file="$(mktemp "$tmp_dir/.cf-err.XXXXXX")"
    umask "$old_umask"
    chmod 0600 "$classes_file" "$err_file"

    if ! "$cf_promises" --workdir "$wd" -f "$entry_file" --show-classes >"$classes_file" 2>"$err_file"; then
        if [ -s "$err_file" ]; then
            cat "$err_file" >&2
        fi
        rm -f "$classes_file" "$err_file"
        echo "tendcf-install: cf-promises failed validating $wd" >&2
        return 1
    fi
    if [ ! -s "$classes_file" ] || ! awk 'NF > 0 { n++ } END { exit (n == 0) }' "$classes_file"; then
        rm -f "$classes_file" "$err_file"
        echo "tendcf-install: cf-promises --show-classes produced empty output for $wd" >&2
        return 1
    fi
    refused="$(awk '$1 == "tendcf_cmdb_refused" || $1 ~ /^tendcf_cmdb_problem_/ { seen[$1]=1 } END { for (c in seen) print c }' "$classes_file" | sort)"
    rm -f "$classes_file" "$err_file"
    if [ -n "$refused" ]; then
        refused_line="$(printf '%s\n' "$refused" | tr '\n' ' ')"
        echo "tendcf-install: CMDB policy refused data in $wd (classes: ${refused_line% })" >&2
        return 1
    fi
    return 0
}

put_data() {  # put_data FILE
    local src="$1"
    [ -f "$src" ] && [ ! -L "$src" ] || die "data file must be a regular non-symlink file: $src"
    [ -f "$entry" ] && [ ! -L "$entry" ] || die "not installed: run install first"
    [ -d "$workdir/inputs" ] && [ ! -L "$workdir/inputs" ] || die "$workdir/inputs missing or symlink"
    check_dir_root_unwritable "$workdir/data"
    verify_installed_projector

    local py
    py="$(find_trusted_python)" || die "cannot validate projection: no trusted root-owned python3 found"

    # Serialize concurrent publishers on an exclusive lock (issue #58).
    local lockfile="$workdir/data/.publish.lock"
    if [ -L "$lockfile" ] || [ -d "$lockfile" ]; then
        die "$lockfile is not a regular file; refusing"
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

    if [ -L "$data" ] || [ -d "$data" ]; then
        exec 9>&-
        die "$data is not a regular file; refusing"
    fi

    # Stage candidate bytes ONCE into a private 0700 workdir (zero TOCTOU, zero
    # pre-validation exposure to cf-execd; issues #53, #57).
    local stage_wd staged_data
    old_umask="$(umask)"
    umask 077
    stage_wd="$(mktemp -d "${TMPDIR:-/tmp}/tendcf-putdata.XXXXXX")"
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

    # Gate 1 (#53): projector contract check (stdlib-only isolated python3 -I).
    if ! "$py" -I "$installed_projector" --check "$staged_data"; then
        die "projector rejected $src; live $data untouched"
    fi

    # Gate 2 (#57): pre-publish cf-promises --show-classes check on staged workdir.
    if ! validate_cmdb_workdir "$stage_wd" "$stage_wd/inputs/promises.cf" "$stage_wd"; then
        die "pre-publish CMDB validation rejected $src; live $data untouched"
    fi

    # Idempotent fast path (under lock, after Gates 1 & 2).
    if [ -f "$data" ] && [ ! -L "$data" ] \
        && cmp -s "$staged_data" "$data" \
        && [ "$(stat -c '%U:%G %a' "$data")" = "root:root 600" ]; then
        if ! validate_cmdb_workdir "$workdir" "$entry" "$stage_wd"; then
            die "existing live $data failed CMDB validation"
        fi
        cleanup_put_data
        exec 9>&-
        say "data unchanged: $data ($(wc -c < "$data") bytes)"
        return 0
    fi

    # Atomic publish using unique same-directory mktemp staging/backup paths (#58).
    local tmp backup=""
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
        cat "$data" > "$backup"
        chown root:root "$backup"
        chmod 0600 "$backup"
    fi

    mv -f "$tmp" "$data"
    put_data_tmp=""

    # Gate 3 (#57): post-publish verification on live workdir with atomic rollback.
    if ! validate_cmdb_workdir "$workdir" "$entry" "$stage_wd"; then
        if [ -n "$backup" ]; then
            mv -f "$backup" "$data"
            put_data_backup=""
            die "post-publish CMDB validation rejected $src; previous data restored"
        else
            rm -f "$data"
            die "post-publish CMDB validation rejected $src; new data removed"
        fi
    fi

    if [ -n "$backup" ]; then
        rm -f "$backup"
        put_data_backup=""
    fi
    cleanup_put_data
    exec 9>&-
    say "data installed: $data ($(wc -c < "$data") bytes)"
}

cmd_install() {
    local datafile=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --data) [ $# -ge 2 ] || die "install: --data needs a path"; datafile="$2"; shift 2 ;;
            --policy-src) [ $# -ge 2 ] || die "install: --policy-src needs a path"; policy_src="$2"; shift 2 ;;
            --projector-src) [ $# -ge 2 ] || die "install: --projector-src needs a path"; projector_src="$2"; shift 2 ;;
            *) die "install: unknown argument $1" ;;
        esac
    done
    check_tree
    init_paths
    lay_out
    place_policy
    place_projector
    if [ -n "$datafile" ]; then put_data "$datafile"; fi
    say "installed: $("$cf_agent" --version | head -1)"
}

cmd_run_once() {
    [ -f "$entry" ] || die "not installed: run install first"
    [ -f "$data" ] || die "no CMDB data: run install --data FILE or data FILE first"
    "$cf_agent" -K -I -f "$entry"
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
    data) init_paths; [ $# -eq 1 ] || die "usage: $0 data FILE"; put_data "$1" ;;
    run-once) init_paths; cmd_run_once ;;
    enable) init_paths; cmd_enable ;;
    status) init_paths; cmd_status ;;
    *) die "unknown command: $sub" ;;
esac
