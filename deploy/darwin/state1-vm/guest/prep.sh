#!/bin/sh
# State 1 macOS VM image prep (issue 70 answers 1-3, slice A).
# Runs as root inside the guest, streamed there and run as one file by `state1_vm.py golden`:
#     sudo -n /bin/sh prep.sh
# The only changes to the pinned vanilla image: Spotlight off, automatic updates off, a
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

# Unused launchd jobs to disable: "<domain> <label>" per line. A candidate list for a
# headless test VM, not a measured one: the first real run's before-* snapshot is the
# evidence to prune it against. A label is touched only when its plist ships in one of
# the standard launchd directories, so a name this macOS version lacks is skipped (and
# printed), not written into the disabled database. Nothing here is needed for SSH, sudo,
# launchd, installer, softwareupdate or Recovery.
DISABLE_LIST='
system com.apple.analyticsd
system com.apple.apsd
system com.apple.bluetoothd
system com.apple.findmymac
system com.apple.findmymacmessenger
system com.apple.icloud.findmydeviced
gui    com.apple.assistant_service
gui    com.apple.assistantd
gui    com.apple.bird
gui    com.apple.cloudd
gui    com.apple.cloudpaird
gui    com.apple.cloudphotod
gui    com.apple.gamed
gui    com.apple.homed
gui    com.apple.icloudmailagent
gui    com.apple.iCloudNotificationAgent
gui    com.apple.knowledge-agent
gui    com.apple.mediaanalysisd
gui    com.apple.parsecd
gui    com.apple.photoanalysisd
gui    com.apple.photolibraryd
gui    com.apple.Siri.agent
gui    com.apple.siriknowledged
gui    com.apple.suggestd
gui    com.apple.tipsd
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
    log "secure token status (before): $(tr '\n' ' ' <"$SNAP/before/securetoken.txt" 2>/dev/null)"
else
    log "before snapshot already present, keeping it"
fi

# 1. Spotlight off.
mdutil -a -i off >/dev/null 2>&1 || true
mdutil_out=$(mdutil -a -s 2>&1) || die "mdutil -a -s failed: $mdutil_out"
case $mdutil_out in *"Indexing enabled"*) die "Spotlight indexing is still enabled" ;; esac
case $mdutil_out in *"Indexing disabled"*) ;; *) die "mdutil -a -s did not report 'Indexing disabled': $mdutil_out" ;; esac
log "spotlight: off"

# 2. Automatic updates off (softwareupdate itself stays usable).
for key in AutomaticCheckEnabled AutomaticDownload AutomaticallyInstallMacOSUpdates ConfigDataInstall CriticalUpdateInstall; do
    defaults write "$SU_PLIST" "$key" -bool false
    [ "$(defaults read "$SU_PLIST" "$key")" = 0 ] || die "$key did not read back as 0"
done
defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool false
log "automatic updates: off"

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
        gui) dom=gui/$ADMIN_UID dirs="/System/Library/LaunchAgents /Library/LaunchAgents" ;;
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
grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config \
    || die "/etc/ssh/sshd_config does not include sshd_config.d"
mkdir -p /etc/ssh/sshd_config.d
tmp=$SSH_DROPIN.new
cat >"$tmp" <<'CONF'
# tendcf state 1 VM (issue 70 answer 3): key login only, no password login.
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
CONF
chown root:wheel "$tmp"
chmod 644 "$tmp"
mv -f "$tmp" "$SSH_DROPIN"
effective=$(/usr/sbin/sshd -T -C user=admin,host=localhost,addr=127.0.0.1)
# macOS 27.2's sshd (OpenSSH_10.5p1) prints the keys in CamelCase ("PasswordAuthentication no"),
# stock OpenSSH in lowercase: match the whole line, ignoring case.
for want in 'passwordauthentication no' 'kbdinteractiveauthentication no' 'pubkeyauthentication yes' 'permitrootlogin no'; do
    printf '%s\n' "$effective" | LC_ALL=C grep -qixF "$want" || die "sshd -T does not show: $want"
done
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

snapshot after
log "wrote after snapshot to $SNAP/after"
# The authenticated copy of the new host key: the driver pins exactly this line (inside
# this ssh session), and uses ssh-keyscan only as a cross-check.
hostkey=$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)
echo "PREP-HOSTKEY $hostkey"
echo "PREP-CONSOLE-PW rotated"
echo "PREP-RESULT disabled=$disabled absent=$absent failed=$failed"
