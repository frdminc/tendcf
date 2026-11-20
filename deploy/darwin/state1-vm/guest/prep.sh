#!/bin/sh
# State 1 macOS VM image prep (issue 70 answers 1-3, slice A).
# Runs as root inside the guest, copied there and run as one file by `state1_vm.py golden`:
#     sudo -n /bin/sh prep.sh
# The only changes to the pinned vanilla image: Spotlight off, automatic updates off, a
# named list of unused launchd jobs disabled, Gatekeeper on, key-only SSH login (with
# fresh host keys). No SIP change, no /System change, no Recovery change.
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
else
    log "before snapshot already present, keeping it"
fi

# 1. Spotlight off.
mdutil -a -i off >/dev/null 2>&1 || true
if mdutil -a -s 2>&1 | grep -q 'Indexing enabled'; then die "Spotlight indexing is still enabled"; fi
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

# 4. Named unused launchd jobs.
disabled=0 absent=0 failed=0
printf '%s\n' "$DISABLE_LIST" | grep -v '^$' >"$STATE_DIR/disable-list.txt"
while read -r domain label; do
    present=0
    for dir in /System/Library/LaunchDaemons /System/Library/LaunchAgents /Library/LaunchDaemons /Library/LaunchAgents; do
        if [ -f "$dir/$label.plist" ]; then present=1; fi
    done
    if [ "$present" -eq 0 ]; then
        log "launchd $domain/$label: absent, skipped"
        absent=$((absent + 1))
        continue
    fi
    case $domain in
        system) target=system/$label ;;
        gui) target=gui/$ADMIN_UID/$label ;;
        *) die "bad domain in DISABLE_LIST: $domain" ;;
    esac
    if launchctl disable "$target" >/dev/null 2>&1; then
        log "launchd $target: disabled"
        disabled=$((disabled + 1))
    else
        log "launchd $target: disable FAILED"
        failed=$((failed + 1))
    fi
done <"$STATE_DIR/disable-list.txt"
log "launchd: disabled=$disabled absent=$absent failed=$failed"

# 5. Fresh SSH host keys, once per image: the vanilla tag's keys are the same for every
# user of that tag. sshd reads them per connection; this session is unaffected.
if [ ! -f "$STATE_DIR/hostkeys-regenerated" ]; then
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -A >/dev/null
    touch "$STATE_DIR/hostkeys-regenerated"
    log "ssh host keys: regenerated"
fi
[ -f /etc/ssh/ssh_host_ed25519_key.pub ] || die "no ed25519 host key after regeneration"

# 6. Key-only SSH login. macOS sshd_config includes sshd_config.d; first value wins.
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
for want in 'passwordauthentication no' 'kbdinteractiveauthentication no' 'pubkeyauthentication yes'; do
    printf '%s\n' "$effective" | grep -qx "$want" || die "sshd -T does not show: $want"
done
log "sshd: key login only"

snapshot after
log "wrote after snapshot to $SNAP/after"
echo "PREP-RESULT disabled=$disabled absent=$absent failed=$failed"
