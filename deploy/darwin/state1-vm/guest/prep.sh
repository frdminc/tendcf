#!/bin/sh
# State 1 macOS VM image prep (issue 70 answers 1-3, slice A).
# Runs as root inside the guest, streamed there and run as one file by `state1_vm.py golden`:
#     sudo -n /bin/sh prep.sh
# The only changes to the pinned vanilla image: Spotlight off, automatic download and install off, a
# named list of unused launchd jobs disabled, Gatekeeper on, Screen Sharing off, key-only SSH
# login (with fresh host keys, printed as PREP-HOSTKEY for the driver to pin), and a random
# console password for admin that is never stored (PREP-CONSOLE-PW). No SIP change, no
# /System change, no Recovery change.
# Idempotent. Snapshots first: the original state is written once, to
# $STATE_DIR/snapshots/before-*, and every run writes after-* when it is done.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
[ "$(id -u)" -eq 0 ] || { echo "prep.sh: must run as root" >&2; exit 1; }

STATE_DIR=/var/db/tendcf-state1-prep
SNAP=$STATE_DIR/snapshots
SSH_DROPIN=/etc/ssh/sshd_config.d/050-tendcf-state1.conf
SU_PLIST=/Library/Preferences/com.apple.SoftwareUpdate
ADMIN_UID=$(id -u admin)

# Unused launchd jobs to disable: "<domain> <label>" per line. Pruned empirically on 2026-11-25
# against live macOS 27.2 (26B123, SIP enabled; issue #78 F20): all 25 original candidate plists
# existed and read back disabled in-session during `golden`, but 22 did not persist across
# shutdown/clone boot under SIP, leaving these 3 persistent labels (`user/<uid>` shares
# `/var/db/com.apple.xpc.launchd/disabled.<uid>.plist` with `gui/<uid>` and works headlessly
# even after password rotation). A label is touched only when its plist ships in one of the
# standard launchd directories. Nothing here is needed for SSH, sudo, launchd, installer,
# softwareupdate or Recovery.
DISABLE_LIST='
system com.apple.findmymac
user   com.apple.cloudpaird
user   com.apple.Siri.agent
'

log() { printf 'prep: %s\n' "$*"; }
die() { printf 'prep.sh: %s\n' "$*" >&2; exit 1; }

snapshot() { # snapshot PREFIX
    prefix=$1
    d=$SNAP/$prefix
    mkdir -p "$d"
    sw_vers >"$d/sw_vers.txt" 2>&1 || true
    launchctl list >"$d/launchctl-list.txt" 2>&1 || true
    launchctl print system >"$d/launchctl-print-system.txt" 2>&1 || true
    launchctl print "gui/$ADMIN_UID" >"$d/launchctl-print-gui.txt" 2>&1 || true
    launchctl print-disabled system >"$d/disabled-system.txt" 2>&1 || true
    launchctl print-disabled "gui/$ADMIN_UID" >"$d/disabled-gui.txt" 2>&1 || true
    launchctl print-disabled "user/$ADMIN_UID" >"$d/disabled-user.txt" 2>&1 || true
    mdutil -a -s >"$d/mdutil.txt" 2>&1 || true
    sysadminctl -secureTokenStatus admin >"$d/securetoken.txt" 2>&1 || true
    spctl --status >"$d/spctl.txt" 2>&1 || true
    defaults read "$SU_PLIST" >"$d/softwareupdate.txt" 2>&1 || true
    ls -1 /System/Library/LaunchDaemons /System/Library/LaunchAgents \
        /Library/LaunchDaemons /Library/LaunchAgents >"$d/plist-names.txt" 2>&1 || true
}

mkdir -p "$SNAP"
chmod 700 "$STATE_DIR"
if [ ! -d "$SNAP/before" ]; then
    snapshot before.partial
    mv "$SNAP/before.partial" "$SNAP/before"
    log "wrote before snapshot to $SNAP/before"
    # Evidence for the first real run: does the vanilla admin hold a Secure Token? (status only;
    # this script changes nothing about it)
    log "secure token status (before): $(LC_ALL=C tr '\r\n' '  ' <"$SNAP/before/securetoken.txt" 2>/dev/null | LC_ALL=C tr -c ' -~' '?')"
else
    log "before snapshot already present, keeping it"
fi

# 1. Spotlight off.
mdutil -a -i off >/dev/null 2>&1 || true
# mdutil -s answers kMDConfigSearchLevelTransitioning while a volume is still changing state
# after the command above (macOS 27.2 after a reboot, issue 70 run 2): ask again every 2 s until
# 120 s have passed or 65 polls (deadline / interval + 5 margin, stopping the loop after 65 polls
# — about 130 s plus mdutil's own time — if the clock steps backwards; macOS /bin/sh is bash 3.2,
# where $SECONDS is backed by time(), so printed elapsed seconds are also clamped at >= 0).
# Order, every poll: write raw mdutil output to a root-only temp file under $STATE_DIR
# (preserving mdutil's exit status and NUL bytes, which bash 3.2 command substitution would
# drop) and map NUL -> SOH via LC_ALL=C tr once into $mdutil_out under set -e; "Indexing
# enabled" anywhere is fatal; then Transitioning anywhere is retried whatever mdutil's exit
# status was (that status was never recorded); then a non-0 exit is fatal; then any line
# holding a control character other than tab (NUL included, via the SOH mapping) fails as
# unexpected, and the whole answer must be volume headers (a line starting with "/", ending
# in ":", and containing no tab), each followed by exactly one "Indexing disabled." line,
# "/:" and "/System/Volumes/Data:" among them.
# shellcheck disable=SC3028 # macOS /bin/sh is bash 3.2, which provides $SECONDS
SECONDS=0
mdutil_deadline=120
mdutil_interval=2
mdutil_max_polls=$((mdutil_deadline / mdutil_interval + 5))
mdutil_polls=0
mdutil_tmp=$(mktemp -- "$STATE_DIR/tendcf-mdutil.XXXXXX")
trap 'rm -f -- "$mdutil_tmp"' EXIT
trap 'exit 129' HUP INT TERM
while :; do
    mdutil_polls=$((mdutil_polls + 1))
    mdutil_rc=0
    mdutil -a -s >"$mdutil_tmp" 2>&1 || mdutil_rc=$?
    mdutil_out=$(LC_ALL=C tr '\000' '\001' <"$mdutil_tmp")
    case $mdutil_out in *"Indexing enabled"*) die "Spotlight indexing is still enabled (rc $mdutil_rc): $mdutil_out" ;; esac
    case $mdutil_out in *kMDConfigSearchLevelTransitioning*) ;; *) break ;; esac
    # shellcheck disable=SC3028 # macOS /bin/sh is bash 3.2 ($SECONDS; backed by time(), so clamp >= 0 and keep 65-poll cap)
    mdutil_waited=$SECONDS
    [ "$mdutil_waited" -ge 0 ] || mdutil_waited=0
    if [ "$mdutil_waited" -ge "$mdutil_deadline" ] || [ "$mdutil_polls" -ge "$mdutil_max_polls" ]; then
        die "mdutil -a -s still transitioning after $mdutil_waited s, $mdutil_polls poll(s) (rc $mdutil_rc): $mdutil_out"
    fi
    sleep "$mdutil_interval"
done
rm -f -- "$mdutil_tmp"
trap - EXIT HUP INT TERM
[ "$mdutil_rc" -eq 0 ] || die "mdutil -a -s failed (rc $mdutil_rc): $mdutil_out"
mdutil_bad=$(printf '%s\n' "$mdutil_out" | LC_ALL=C awk '
    function fail(msg) { if (!bad) print msg; bad = 1 }
    { t = $0; gsub(/\t/, "", t); if (t ~ /[[:cntrl:]]/) { fail("unexpected line: " $0); next } }
    /^[ \t]*$/ { next }
    /^[ \t]/ {
        line = $0; sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
        if (line != "Indexing disabled.") fail("unexpected line: " $0)
        else if (hdr == "") fail("status before any volume: " $0)
        else if (seen) fail("two statuses for " hdr)
        else seen = 1
        next
    }
    /^\/.*:$/ && index($0, "\t") == 0 {
        if (hdr != "" && !seen) fail("no status for " hdr)
        hdr = $0; seen = 0; headers++
        if (hdr == "/:") root = 1
        if (hdr == "/System/Volumes/Data:") data = 1
        next
    }
    { fail("unexpected line: " $0) }
    END {
        if (hdr != "" && !seen) fail("no status for " hdr)
        if (headers == 0) fail("no volume listed")
        else if (!root) fail("no / volume listed")
        else if (!data) fail("no /System/Volumes/Data volume listed")
    }')
[ -z "$mdutil_bad" ] || die "mdutil -a -s: $mdutil_bad: $mdutil_out"
# shellcheck disable=SC3028 # macOS /bin/sh is bash 3.2 ($SECONDS)
mdutil_elapsed=$SECONDS
[ "$mdutil_elapsed" -ge 0 ] || mdutil_elapsed=0
log "spotlight: off ($mdutil_polls poll(s), $mdutil_elapsed s elapsed)"

# 2. Automatic download and install off (softwareupdate itself stays usable; checking stays on).
for key in AutomaticDownload AutomaticallyInstallMacOSUpdates ConfigDataInstall CriticalUpdateInstall SplatEnabled; do
    defaults write "$SU_PLIST" "$key" -bool false
    su_val=$(defaults read "$SU_PLIST" "$key") || die "defaults read $key failed"
    [ "$su_val" = 0 ] || die "$key did not read back as 0"
done
# These keys are written and read back as 0 (and persisted across a reboot, issue 70 addendum 4,
# PR 90, and run 4 for SplatEnabled); nobody observed softwareupdated obeying them. SplatEnabled
# is believed to be the Background Security Improvements switch (inferred, not documented by Apple;
# operator ruling 2026-11-21). Automatic *checking* stays on: four root-script
# methods did not turn it off on macOS 27.2 (`softwareupdate --schedule off` changed nothing; a
# written AutomaticCheckEnabled was gone between 30 and 90 s in one run; a hand-written Managed
# Preferences plist was ignored; kickstart and bootout were refused by SIP), and the System
# Settings toggle is untried. The schedule is logged for information only (CR/LF flattened, bytes
# outside printable ASCII replaced with ?, and cut to 200 bytes under LC_ALL=C so the cut never
# splits a multibyte character).
su_rc=0
su_out=$(softwareupdate --schedule 2>&1) || su_rc=$?
[ "$su_rc" -eq 0 ] || die "softwareupdate --schedule failed (rc $su_rc): $su_out"
# written, not read back: nothing observed that this key reads 0 on the guest
defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool false
log "automatic download and install off; schedule (info, rc $su_rc): $(printf '%s' "$su_out" | LC_ALL=C tr '\r\n' '  ' | LC_ALL=C tr -c ' -~' '?' | LC_ALL=C cut -c1-200)"

# 3. Gatekeeper on (the VM matches a real owner's Mac).
spctl --global-enable 2>/dev/null || spctl --master-enable
spctl --status 2>&1 | grep -q 'assessments enabled' || die "Gatekeeper is not enabled"
log "gatekeeper: on"

# 4. Screen Sharing off. The vanilla image turns it on, with the published admin password,
# and that is a root-equivalent GUI login for anything on the vmnet. Fatal, not hygiene.
launchctl disable system/com.apple.screensharing
launchctl bootout system/com.apple.screensharing >/dev/null 2>&1 || true
is_disabled() { # is_disabled DOMAIN LABEL: print-disabled lists it as disabled
    launchctl print-disabled "$1" 2>/dev/null | grep -Eq "\"$2\"[[:space:]]*=>[[:space:]]*(disabled|true)"
}
is_disabled system com.apple.screensharing || die "com.apple.screensharing is not disabled"
# Capture netstat and its status: a failing or silent netstat must not read as "nothing listens".
netstat_out=$(netstat -an -p tcp 2>&1) || die "netstat -an -p tcp failed: $netstat_out"
[ -n "$netstat_out" ] || die "netstat -an -p tcp printed nothing"
if printf '%s\n' "$netstat_out" | grep -Eq '[.:]5900[[:space:]].*LISTEN'; then
    die "something still listens on tcp 5900 (Screen Sharing)"
fi
log "screen sharing: disabled, nothing on tcp 5900"

# 5. Named unused launchd jobs (hygiene: a failure is reported, not fatal). A label counts
# only if its plist ships in the directory matching its domain, and "disabled" means the
# print-disabled readback says so (launchctl disable itself succeeds for almost any label).
disabled=0 absent=0 failed=0
printf '%s\n' "$DISABLE_LIST" | grep -v '^$' >"$STATE_DIR/disable-list.txt"
while read -r domain label; do
    case $domain in
        system) dom=system dirs="/System/Library/LaunchDaemons /Library/LaunchDaemons" ;;
        user) dom=user/$ADMIN_UID dirs="/System/Library/LaunchAgents /Library/LaunchAgents" ;;
        *) die "bad domain in DISABLE_LIST: $domain" ;;
    esac
    present=0
    for dir in $dirs; do
        if [ -f "$dir/$label.plist" ]; then present=1; fi
    done
    if [ "$present" -eq 0 ]; then
        log "launchd $dom/$label: absent, skipped"
        absent=$((absent + 1))
        continue
    fi
    launchctl disable "$dom/$label" </dev/null >/dev/null 2>&1 || true
    if is_disabled "$dom" "$label"; then
        log "launchd $dom/$label: disabled (read back)"
        disabled=$((disabled + 1))
    else
        log "launchd $dom/$label: disable NOT confirmed by print-disabled"
        failed=$((failed + 1))
    fi
done <"$STATE_DIR/disable-list.txt"
log "launchd: disabled=$disabled absent=$absent failed=$failed"

# 6. Fresh SSH host keys, once per image: the vanilla tag's keys are the same for every
# user of that tag. sshd reads them per connection; this session is unaffected.
if [ ! -f "$STATE_DIR/hostkeys-regenerated" ]; then
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -A >/dev/null
    touch "$STATE_DIR/hostkeys-regenerated"
    log "ssh host keys: regenerated"
fi
[ -f /etc/ssh/ssh_host_ed25519_key.pub ] || die "no ed25519 host key after regeneration"

# 7. Key-only SSH login. macOS sshd_config includes sshd_config.d; first value wins.
# Check the effective config tree (sshd_config, sshd_config.d/*, and recursive Includes with
# cycle prevention) for any uncommented Match block, then assert sshd -T across loopback and
# host-facing client specs for both admin and root (exact-once keys, NUL bytes preserved via a
# root-only temp file under $STATE_DIR).
grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config \
    || die "/etc/ssh/sshd_config does not include sshd_config.d"
mkdir -p /etc/ssh/sshd_config.d
tmp=$SSH_DROPIN.new
cat >"$tmp" <<'CONF'
# tendcf state 1 VM (issue 70 answer 3, issue 87): key login only, no password login.
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
GSSAPIAuthentication no
HostbasedAuthentication no
AuthenticationMethods publickey
CONF
chown root:wheel "$tmp"
chmod 644 "$tmp"
mv -f "$tmp" "$SSH_DROPIN"
sshd_canon() {
    _p=$1 _hops=0
    while [ -L "$_p" ]; do
        _hops=$((_hops + 1))
        [ "$_hops" -le 16 ] || die "sshd config symlink loop: $1"
        _t=$(readlink "$_p") || die "readlink failed on $_p"
        case $_t in
            /*) _p=$_t ;;
            *) _p=$(dirname "$_p")/$_t ;;
        esac
    done
    _d=$(CDPATH='' cd -P -- "$(dirname "$_p")" 2>/dev/null && pwd -P) || die "cannot resolve sshd config dir for $_p"
    printf '%s/%s\n' "${_d%/}" "$(basename "$_p")"
}
check_sshd_no_match() {
    _cfg=$1
    _base=${SSHD_BASE_DIR:-/etc/ssh}
    [ -f "$_cfg" ] || die "missing sshd config: $_cfg"
    _visited=""
    _queue="0	$_cfg"
    while [ -n "$_queue" ]; do
        _entry=${_queue%%"
"*}
        case $_queue in
            *"
"*) _queue=${_queue#*"
"} ;;
            *) _queue="" ;;
        esac
        [ -n "$_entry" ] || continue
        _depth=${_entry%%"	"*}
        _f=${_entry#*"	"}
        [ "$_depth" -le 16 ] || die "sshd Include nesting exceeds 16 levels at $_f"
        if [ -L "$_f" ] && [ ! -e "$_f" ]; then
            die "dangling symlink in sshd config: $_f"
        fi
        if [ -d "$_f" ]; then
            continue
        fi
        if [ ! -f "$_f" ]; then
            die "non-regular sshd config target: $_f"
        fi
        [ -r "$_f" ] || die "unreadable sshd config file: $_f"
        _canon=$(sshd_canon "$_f")
        case $_canon in
            *"
"*) die "sshd config path contains newline: $_canon" ;;
        esac
        if [ -n "$_visited" ] && printf '%s\n' "$_visited" | LC_ALL=C grep -qxF -- "$_canon"; then
            continue
        fi
        if [ -n "$_visited" ]; then
            _visited="$_visited
$_canon"
        else
            _visited="$_canon"
        fi
        _raw_len=$(wc -c <"$_f")
        _clean_len=$(LC_ALL=C tr -d '\000' <"$_f" | wc -c)
        [ "$_raw_len" -eq "$_clean_len" ] || die "sshd config contains NUL byte: $_f"
        _awk_rc=0
        _incs=$(LC_ALL=C awk '
            function fail(code, msg) {
                printf "%s:%d: %s\n", FILENAME, FNR, msg
                bad = code
                exit code
            }
            {
                line = $0
                sub(/\r$/, "", line)
                sub(/^[ \t]+/, "", line)
                if (line == "" || substr(line, 1, 1) == "#") next
                # Refuse any remaining CR or ASCII control byte (other than tab) before
                # parsing so interior CR cannot be rewritten into whitespace and split
                # an Include filename that OpenSSH argv_split() preserves intact.
                if (line ~ /[\001-\010\013-\037\177]/) {
                    tmp = line
                    gsub(/\r/, " ", tmp)
                    sub(/^[ \t]+/, "", tmp)
                    tkey = tmp
                    sub(/[ \t=].*$/, "", tkey)
                    gsub(/["\047\\]/, "", tkey)
                    if (tolower(tkey) == "match") {
                        fail(2, line)
                    }
                    fail(3, "interior CR or control byte in sshd config: " line)
                }
                raw_first = line
                sub(/[ \t=].*$/, "", raw_first)
                was_quoted_key = 0
                if (raw_first !~ /["\047\\]/) {
                    norm_key = tolower(raw_first)
                    rest = substr(line, length(raw_first) + 1)
                } else {
                    # OpenSSH strdelim_internal() ends a quoted keyword at the closing
                    # double quote with no whitespace required after it (e.g.
                    # "Include"/path or "Match"User). Fail closed on unclosed quotes,
                    # ambiguous closing-quote boundaries, or obfuscated keywords.
                    q1 = index(line, "\"")
                    if (q1 > 0 && q1 <= length(raw_first)) {
                        q2_rel = index(substr(line, q1 + 1), "\"")
                        if (q2_rel == 0) {
                            tkey = raw_first
                            gsub(/["\047\\]/, "", tkey)
                            if (tolower(tkey) == "match") {
                                fail(2, line)
                            }
                            fail(3, "unclosed quote in sshd keyword: " line)
                        }
                        q2 = q1 + q2_rel
                        tok_q = substr(line, 1, q2)
                        after_q = substr(line, q2 + 1)
                        norm_q = tok_q
                        gsub(/["\047\\]/, "", norm_q)
                        norm_q = tolower(norm_q)
                        if (norm_q == "match") {
                            fail(2, line)
                        }
                        if (after_q != "" && substr(after_q, 1, 1) != " " && substr(after_q, 1, 1) != "\t") {
                            tkey = raw_first
                            gsub(/["\047\\]/, "", tkey)
                            if (tolower(tkey) == "match") {
                                fail(2, line)
                            }
                            fail(3, "ambiguous quoted keyword boundary: " line)
                        }
                        if (q1 != 1 || index(tok_q, "\047") > 0 || index(tok_q, "\\") > 0) {
                            if (norm_q == "include") {
                                fail(3, "obfuscated Include keyword: " line)
                            }
                            fail(3, "obfuscated sshd keyword: " line)
                        }
                        norm_key = norm_q
                        rest = after_q
                        was_quoted_key = 1
                    } else {
                        tkey = raw_first
                        gsub(/["\047\\]/, "", tkey)
                        tkey = tolower(tkey)
                        if (tkey == "match") {
                            fail(2, line)
                        }
                        if (tkey == "include") {
                            fail(3, "obfuscated Include keyword: " line)
                        }
                        fail(3, "obfuscated sshd keyword: " line)
                    }
                }
                if (norm_key == "") {
                    fail(3, "empty sshd keyword: " line)
                }
                if (norm_key == "match") {
                    fail(2, line)
                }
                if (norm_key != "include") next
                sub(/^[ \t]+/, "", rest)
                if (!was_quoted_key && substr(rest, 1, 1) == "=") {
                    rest = substr(rest, 2)
                    sub(/^[ \t]+/, "", rest)
                }
                # OpenSSH argv_split() stops at an unquoted word-initial "#", while
                # mid-token or quoted "#" remains part of the filename. Fail closed on
                # single quotes, backslashes, unclosed/mid-token double quotes, leading
                # "~", zero arguments, or characters outside a conservative path/glob charset.
                line_inc = 0
                while (rest != "") {
                    if (substr(rest, 1, 1) == "#") break
                    if (substr(rest, 1, 1) == "\"") {
                        q = index(substr(rest, 2), "\"")
                        if (q == 0) {
                            fail(3, "unclosed quote in Include: " line)
                        }
                        tok = substr(rest, 2, q - 1)
                        after = substr(rest, q + 2)
                        if (after != "" && substr(after, 1, 1) != " " && substr(after, 1, 1) != "\t") {
                            fail(3, "unsupported mid-token quote in Include: " line)
                        }
                        if (index(tok, "\047") > 0 || index(tok, "\\") > 0) {
                            fail(3, "unsupported quote/escape in Include: " line)
                        }
                        if (tok == "" || substr(tok, 1, 1) == "~") {
                            fail(3, "unsupported Include target: " line)
                        }
                        if (tok !~ /^[]A-Za-z0-9_.\/*?@+:,#[ -]+$/) {
                            fail(3, "unsafe character in quoted Include target: " line)
                        }
                        incs[++n_inc] = tok
                        line_inc++
                        rest = after
                    } else {
                        tok = rest
                        sub(/[ \t].*$/, "", tok)
                        rest = substr(rest, length(tok) + 1)
                        if (index(tok, "\"") > 0 || index(tok, "\047") > 0 || index(tok, "\\") > 0) {
                            fail(3, "unsupported quote/escape in Include: " line)
                        }
                        if (substr(tok, 1, 1) == "~") {
                            fail(3, "unsupported tilde Include target: " line)
                        }
                        if (tok !~ /^[]A-Za-z0-9_.\/*?@+:,#[-]+$/) {
                            fail(3, "unsafe character in Include target: " line)
                        }
                        incs[++n_inc] = tok
                        line_inc++
                    }
                    sub(/^[ \t]+/, "", rest)
                }
                if (line_inc == 0) {
                    fail(3, "Include directive with no arguments: " line)
                }
            }
            END {
                if (bad) exit bad
                for (k = 1; k <= n_inc; k++) print incs[k]
            }' "$_f") || _awk_rc=$?
        if [ "$_awk_rc" -eq 2 ]; then
            die "uncommented Match block in sshd config: $_incs"
        elif [ "$_awk_rc" -ne 0 ]; then
            die "unsupported sshd config syntax: $_incs"
        fi
        _next_depth=$((_depth + 1))
        set -f
        while [ -n "$_incs" ]; do
            _pat=${_incs%%"
"*}
            case $_incs in
                *"
"*) _incs=${_incs#*"
"} ;;
                *) _incs="" ;;
            esac
            [ -n "$_pat" ] || continue
            case $_pat in
                /*) _full=$_pat ;;
                *) _full="$_base/$_pat" ;;
            esac
            _old_ifs=$IFS
            IFS=''
            set +f
            # shellcheck disable=SC2086 # intentional glob expansion of sshd Include pattern with IFS='' (no word splitting)
            for _matched in $_full; do
                set -f
                IFS=$_old_ifs
                case $_matched in
                    *"
"*) die "sshd config path contains newline: $_matched" ;;
                esac
                if [ ! -e "$_matched" ] && [ ! -L "$_matched" ]; then
                    continue
                fi
                if [ -L "$_matched" ] && [ ! -e "$_matched" ]; then
                    die "dangling symlink in sshd config: $_matched"
                fi
                if [ -d "$_matched" ]; then
                    continue
                fi
                if [ ! -f "$_matched" ]; then
                    die "non-regular sshd config target: $_matched"
                fi
                if [ -n "$_queue" ]; then
                    _queue="$_queue
$_next_depth	$_matched"
                else
                    _queue="$_next_depth	$_matched"
                fi
            done
            set -f
            IFS=$_old_ifs
        done
        set +f
    done
}
check_sshd_no_match "${SSHD_CONFIG:-/etc/ssh/sshd_config}"
# Evaluate sshd -T across loopback and host-facing client/guest addresses for admin and root.
# Write raw sshd bytes to a root-only temp file under $STATE_DIR so NUL bytes are preserved
# (bash 3.2 command substitution would drop them; A8) and require each checked key to appear
# exactly once (A7). macOS 27.2's sshd prints CamelCase keys; stock OpenSSH prints lowercase.
sshd_is_ip() {
    printf '%s\n' "$1" | LC_ALL=C awk '
        /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
            n = split($0, o, ".")
            for (i = 1; i <= 4; i++) if (o[i] + 0 > 255 || length(o[i]) > 3) exit 1
            exit 0
        }
        /^[0-9A-Fa-f:]+$/ && index($0, ":") > 0 { exit 0 }
        { exit 1 }'
}
sshd_specs="user=admin,host=localhost,addr=127.0.0.1 user=root,host=localhost,addr=127.0.0.1"
sshd_extra_addrs=${SSHD_CLIENT_ADDRS:-}
set -f
if [ -z "$sshd_extra_addrs" ]; then
    sshd_gw=$(route -n get default 2>/dev/null | LC_ALL=C awk '/^[[:space:]]*gateway:[[:space:]]*/ { print $2; exit }' || true)
    sshd_en0=$(ipconfig getifaddr en0 2>/dev/null || true)
    for sshd_a in $sshd_gw $sshd_en0; do
        case $sshd_a in
            ""|127.*|::1) ;;
            *) sshd_is_ip "$sshd_a" && sshd_extra_addrs="$sshd_extra_addrs $sshd_a" || true ;;
        esac
    done
    [ -n "$sshd_extra_addrs" ] || sshd_extra_addrs="192.168.64.1"
fi
for sshd_a in $sshd_extra_addrs; do
    sshd_is_ip "$sshd_a" || continue
    case " $sshd_specs " in
        *",addr=$sshd_a "*) ;;
        *) sshd_specs="$sshd_specs user=admin,host=$sshd_a,addr=$sshd_a user=root,host=$sshd_a,addr=$sshd_a" ;;
    esac
done
sshd_tmp=$(mktemp -- "$STATE_DIR/tendcf-sshd.XXXXXX")
trap 'rm -f -- "$sshd_tmp"' EXIT
trap 'exit 129' HUP INT TERM
for sshd_spec in $sshd_specs; do
    sshd_rc=0
    /usr/sbin/sshd -T -C "$sshd_spec" >"$sshd_tmp" || sshd_rc=$?
    [ "$sshd_rc" -eq 0 ] || die "sshd -T -C $sshd_spec failed (rc $sshd_rc)"
    sshd_bad=$(LC_ALL=C tr '\000' '\001' <"$sshd_tmp" | LC_ALL=C awk '
        BEGIN {
            want["passwordauthentication"] = "passwordauthentication no"
            want["kbdinteractiveauthentication"] = "kbdinteractiveauthentication no"
            want["pubkeyauthentication"] = "pubkeyauthentication yes"
            want["permitrootlogin"] = "permitrootlogin no"
            want["gssapiauthentication"] = "gssapiauthentication no"
            want["hostbasedauthentication"] = "hostbasedauthentication no"
            want["authenticationmethods"] = "authenticationmethods publickey"
            order[1] = "passwordauthentication"
            order[2] = "kbdinteractiveauthentication"
            order[3] = "pubkeyauthentication"
            order[4] = "permitrootlogin"
            order[5] = "gssapiauthentication"
            order[6] = "hostbasedauthentication"
            order[7] = "authenticationmethods"
        }
        index($0, "\001") > 0 { nul = 1 }
        {
            lo = tolower($0)
            key = lo
            sub(/^[ \t]+/, "", key)
            sub(/[ \t=].*$/, "", key)
            if (key in want) {
                seen[key]++
                if (lo == want[key]) exact[key]++
            }
        }
        END {
            if (nul) { print "output contains NUL byte"; exit }
            for (i = 1; i <= 7; i++) {
                k = order[i]
                if (seen[k] + 0 > 1) { print "duplicate key: " k " (" seen[k] " times)"; exit }
                if (exact[k] + 0 != 1) { print "sshd -T does not show: " want[k]; exit }
            }
        }')
    [ -z "$sshd_bad" ] || die "sshd -T -C $sshd_spec: $sshd_bad"
done
set +f
rm -f -- "$sshd_tmp"
trap - EXIT HUP INT TERM
log "sshd: key login only"

# 8. Console password. The vanilla image's is the published "admin". Replace it with a random
# one made here, proved with dscl -authonly, and then dropped: it lives in a shell variable
# only, never printed, never written to a file, never sent to the host. Nothing needs it
# afterwards (ssh is key-only, sudo is NOPASSWD, Screen Sharing is off). So console login and
# the login keychain are unusable by design, and an /etc/kcpassword left by the vanilla image's
# autologin is stale; this script leaves both alone.
# First run: the vanilla password still authenticates, so use the old-and-new form, which keeps
# a Secure Token account's credentials in step (expected; unverified on a real guest). Root form only on a re-run, when the previous
# random password is unknown. The password is in dscl's argv for the length of these commands,
# inside this throwaway guest.
pw=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
[ "${#pw}" -eq 32 ] || die "could not generate a console password"
if dscl . -authonly admin admin >/dev/null 2>&1; then
    log "console password: vanilla password still authenticates, using the old-and-new dscl form"
    dscl . -passwd /Users/admin admin "$pw" || die "dscl -passwd /Users/admin (old and new) failed"
else
    log "console password: vanilla password does not authenticate (re-run), using the root dscl form"
    dscl . -passwd /Users/admin "$pw" || die "dscl -passwd /Users/admin (root form) failed"
fi
dscl . -authonly admin "$pw" || die "the new console password does not authenticate"
unset pw
# The vanilla password must be dead, and only by the wrong-password code (-14090,
# eDSAuthFailed): any other result (disabled or expired account, no directory, odd output)
# proves nothing and fails the build. A missing user is not another code on macOS 27.2 (a
# nonexistent name also prints -14090 eDSAuthFailed, observed), so this does not prove the
# account exists; the ssh login as admin does.
if auth_out=$(dscl . -authonly admin admin 2>&1); then
    die "the vanilla console password still works"
fi
auth_codes=$(printf '%s\n' "$auth_out" | grep -Eo 'eDS[A-Za-z]+' | sort -u)
[ "$auth_codes" = "eDSAuthFailed" ] || die "dscl -authonly admin admin failed for another reason, not a wrong password: $auth_out"
printf '%s\n' "$auth_out" | grep -q -- '-14090' || die "dscl -authonly admin admin did not report -14090: $auth_out"
log "console password: rotated to a random value that is not stored"
# Evidence for issue 78: does the admin account still hold its Secure Token after the rotation?
# (status only; the driver carries this line into g6's evidence)
log "secure token status (after): $(sysadminctl -secureTokenStatus admin 2>&1 | LC_ALL=C tr '\r\n' '  ' | LC_ALL=C tr -c ' -~' '?')"

snapshot after
log "wrote after snapshot to $SNAP/after"
# The authenticated copy of the new host key: the driver pins exactly this line (inside
# this ssh session), and uses ssh-keyscan only as a cross-check.
hostkey=$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)
echo "PREP-HOSTKEY $hostkey"
echo "PREP-CONSOLE-PW rotated"
echo "PREP-RESULT disabled=$disabled absent=$absent failed=$failed"
