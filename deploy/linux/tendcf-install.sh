#!/usr/bin/env bash
# Root-owned tendcf install on a Linux host booted by systemd
# (docs/architecture/linux-targets.md, step 7). Run as root.
#
# Shape, which is CFEngine's own (the book's ch. 19/21/23, cf-execd and MPF
# docs): binaries and policy root-owned, the work directory inside the same
# root-owned tree ($prefix/var/cfengine: a source build with --prefix puts its
# compiled-in work directory under the prefix), and a root cf-execd that runs
# cf-agent on a schedule. Nothing here leaves a
# sudoers rule behind and nothing a non-root user can write is read by root.
#
#   install [--data FILE] [--policy-src DIR]
#                    make /opt/tendcf root-owned, lay out the work directory, put the
#                    policy and promises.cf in place, optionally install the CMDB
#                    data (a projection, validated by cf-promises first)
#   data FILE        replace the CMDB data (validated first; the old file is
#                    restored if cf-promises rejects the new one)
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
workdir=$prefix/var/cfengine   # the build's compiled-in WORKDIR for --prefix=$prefix
unit=tendcf-execd.service
unit_path=/etc/systemd/system/$unit
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
policy_src="$here/../../policy"

die() { echo "tendcf-install: $*" >&2; exit 1; }
say() { echo "tendcf-install: $*"; }

[ "$(id -u)" = 0 ] || die "run as root"
[ "$(uname)" = Linux ] || die "Linux only"
[ -d /run/systemd/system ] || die "host is not booted by systemd"

cf_agent="$prefix/bin/cf-agent"
cf_promises="$prefix/bin/cf-promises"
cf_key="$prefix/bin/cf-key"
cf_execd="$prefix/bin/cf-execd"
entry="$workdir/inputs/promises.cf"
data="$workdir/data/host_specific.json"

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
        die "cf-key wrote no key under $workdir/ppkeys (output: ${keyout:-none}): these binaries use a different work directory"
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

put_data() {  # put_data FILE
    local src="$1" backup=""
    [ -f "$src" ] || die "no such data file: $src"
    if [ -f "$data" ]; then
        backup="$data.previous"
        cp -p "$data" "$backup"
    fi
    install -m 0600 -o root -g root "$src" "$data"
    if ! "$cf_promises" -f "$entry" >/dev/null; then
        if [ -n "$backup" ]; then mv -f "$backup" "$data"; else rm -f "$data"; fi
        die "cf-promises rejected $src; previous data restored"
    fi
    rm -f "$backup"
    say "data installed: $data ($(wc -c < "$data") bytes)"
}

cmd_install() {
    local datafile=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --data) datafile="$2"; shift 2 ;;
            --policy-src) policy_src="$2"; shift 2 ;;
            *) die "install: unknown argument $1" ;;
        esac
    done
    check_tree
    lay_out
    place_policy
    if [ -n "$datafile" ]; then put_data "$datafile"; fi
    say "installed: $("$cf_agent" --version | head -1)"
}

cmd_run_once() {
    [ -f "$entry" ] || die "not installed: run install first"
    [ -f "$data" ] || die "no CMDB data: run install --data FILE or data FILE first"
    "$cf_agent" -K -I -f "$entry"
}

cmd_enable() {
    [ -f "$entry" ] || die "not installed: run install first"
    cat > "$unit_path.new" <<EOF
# Written by deploy/linux/tendcf-install.sh
[Unit]
Description=tendcf agent scheduler (cf-execd runs cf-agent on schedule)
After=network.target

[Service]
Type=simple
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
    data) [ $# -eq 1 ] || die "usage: $0 data FILE"; put_data "$1" ;;
    run-once) cmd_run_once ;;
    enable) cmd_enable ;;
    disable) cmd_disable ;;
    status) cmd_status ;;
    *) die "unknown command: $sub" ;;
esac
