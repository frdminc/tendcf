#!/usr/bin/env python3
"""Record what systemd and dpkg actually do, for spec section 3.5 items 1-9.

Root, Linux, booted by systemd, and TENDCF_TEST_SYSTEMD=1 (it writes unit files
under /etc/systemd/system, /run/systemd/system, /usr/lib/systemd/system, plus
/run/systemd/system-generators and /etc/init.d for item 3, all removed again).
Prints a markdown record to stdout; run it in CI and paste the observed rows
into the spec's section 3.5 results. Dpkg behaviour is measured on a private
admindir under /var/tmp with real dpkg, never on the host database.
"""
import glob
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from s1lib import CLASSIFIER, REPO, Sandbox, TestDb, daemon_reload, sh  # noqa: E402

PROPS = "Id,Names,LoadState,UnitFileState,FragmentPath,SourcePath,DropInPaths,Transient"
U = "/usr/lib/systemd/system"
E = "/etc/systemd/system"
R = "/run/systemd/system"
SVC = "[Unit]\nDescription=tendcf s1 probe\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n"


def out(s=""):
    print(s, flush=True)


# Unexpected failures of this run: a command whose exit status is outside what the
# observation expects, a step that raised, a classifier or cleanup that failed. main()
# returns nonzero when any exist, after every step and every cleanup has run.
FAILURES = []
OBSERVED_NONZERO = (0, 1)   # for commands whose refusal or miss IS the observation


def fail(what):
    FAILURES.append(what)
    out("**UNEXPECTED FAILURE: %s**\n" % what)


def rec(title, argv, ok=(0,), lines=None, grep=None, sort=False, **kw):
    """Run ONE command (argv list, no shell) and record it. `ok` lists the exit statuses that are
    the observation; any other status is an unexpected failure (a template `show` refusal or a
    dpkg miss passes ok=OBSERVED_NONZERO). Trimming is done here, in Python, never by a pipeline
    that would hide the producer's status: `lines` keeps the first N lines, `grep` the lines
    containing a substring, `sort` sorts them."""
    if not isinstance(argv, list):
        raise TypeError("rec takes an argv list: one command per observation, status checked individually")
    r = sh(argv, **kw)
    out("**%s**\n\n`$ %s`  (rc=%d)\n\n```" % (title, " ".join(argv), r.returncode))
    if r.returncode not in ok:
        FAILURES.append("%s: rc=%d, expected one of %s" % (title, r.returncode, list(ok)))
    text = r.stdout.rstrip()
    ls = text.splitlines() if text else []
    if grep is not None:
        ls = [x for x in ls if grep in x]
    if sort:
        ls = sorted(ls)
    if lines is not None:
        ls = ls[:lines]
    out("\n".join(ls))
    if r.stderr.strip():
        out("[stderr] " + r.stderr.rstrip())
    out("```\n")
    return r


def show(unit, *extra, ok=(0,)):
    return rec("show " + unit, ["systemctl", "show", "--no-pager", "-p", PROPS] + list(extra) + [unit], ok=ok)


def env_info():
    out("## Environment\n")
    rec("systemd", ["systemctl", "--version"], lines=2)
    rec("dpkg", ["dpkg", "--version"], lines=1)
    rec("os-release", ["grep", "-E", "^(PRETTY_NAME|VERSION_ID)=", "/etc/os-release"])
    rec("machine", ["uname", "-m"])
    rec("usr-merge links", ["ls", "-ld", "/lib", "/bin", "/sbin"])
    rec("PID 1", ["readlink", "/proc/1/exe"])
    rec("manager runtime directory", ["ls", "-d", "/run/systemd/system"])
    rec("sysv generator present", ["ls", "-l", "/usr/lib/systemd/system-generators/systemd-sysv-generator"])
    # `ls` exits 2 for a path that does not exist: that is the observation for the units that are absent
    for f in ("ssh.service", "sshd.service", "kmod.service", "hwclock.service", "getty@.service"):
        rec("where %s lies" % f, ["ls", "-l", "--time-style=+", "/usr/lib/systemd/system/" + f, "/etc/systemd/system/" + f], ok=(0, 2))
    rec("owners of the units the S1 rows name (host database)",
        ["dpkg-query", "-S", "/usr/lib/systemd/system/ssh.service", "/usr/lib/systemd/system/kmod.service",
         "/usr/lib/systemd/system/hwclock.service", "/usr/lib/systemd/system/getty@.service"])


def item7_paths():
    out("## Item 7: systemd-analyze unit-paths\n")
    rec("default", ["systemd-analyze", "unit-paths"])
    rec("--system", ["systemd-analyze", "--system", "unit-paths"])
    r = sh(["systemd-analyze", "unit-paths"])
    if r.returncode != 0:
        FAILURES.append("existing vs listed: systemd-analyze unit-paths rc=%d" % r.returncode)
    out("**existing vs listed**\n\n```")
    out("\n".join(("exists " if os.path.exists(d) else "absent ") + d for d in r.stdout.split()))
    out("```\n")


def item1():
    out("## Item 1: systemctl show on templates and non-loaded units\n")
    show("getty@.service", ok=OBSERVED_NONZERO)
    show("tendcf-s1-nonexistent.service")
    rec("show of two names (order, blank-line separation)",
        ["systemctl", "show", "--no-pager", "-p", "Id,LoadState", "getty@.service", "tendcf-s1-nonexistent.service", "systemd-journald.service"],
        ok=OBSERVED_NONZERO)
    rec("show instance of a template", ["systemctl", "show", "--no-pager", "-p", PROPS, "getty@tty63.service"])
    rec("list-unit-files for getty", ["systemctl", "list-unit-files", "--no-pager", "--no-legend", "getty*"])
    rec("list-units --all for getty", ["systemctl", "list-units", "--all", "--no-pager", "--no-legend", "--plain", "getty*"])


def item2_8_masks_alias_transient():
    out("## Items 2 and 8: masks, alias names, instances, transient units\n")
    with Sandbox() as sb:
        sb.write(U + "/tendcf-s1-p2.service", SVC)
        sb.symlink(E + "/tendcf-s1-p2.service", "/dev/null")
        daemon_reload()
        out("### persistent mask (/etc link to /dev/null) over a vendor fragment\n")
        show("tendcf-s1-p2.service")
        rec("list-unit-files", ["systemctl", "list-unit-files", "--no-pager", "--no-legend", "tendcf-s1-p2*"])
        rec("cat", ["systemctl", "cat", "--no-pager", "tendcf-s1-p2.service"])
        sb.remove(E + "/tendcf-s1-p2.service")
        sb.symlink(R + "/tendcf-s1-p2.service", "/dev/null")
        daemon_reload()
        out("### runtime mask (/run link to /dev/null)\n")
        show("tendcf-s1-p2.service")
        rec("list-unit-files", ["systemctl", "list-unit-files", "--no-pager", "--no-legend", "tendcf-s1-p2*"])
        sb.remove(R + "/tendcf-s1-p2.service")
        sb.symlink(E + "/tendcf-s1-p2alias.service", U + "/tendcf-s1-p2.service")
        daemon_reload()
        out("### alias name (link /etc/.../tendcf-s1-p2alias.service -> the vendor fragment)\n")
        show("tendcf-s1-p2alias.service")
        show("tendcf-s1-p2.service")
        rec("list-unit-files", ["systemctl", "list-unit-files", "--no-pager", "--no-legend", "tendcf-s1-p2*"])
    with Sandbox() as sb:
        sb.write(U + "/tendcf-s1-tpl@.service", "[Unit]\nDescription=tpl\n[Service]\nExecStart=/bin/sleep 600\n")
        sb.symlink(E + "/multi-user.target.wants/tendcf-s1-tpl@x.service", U + "/tendcf-s1-tpl@.service")
        daemon_reload()
        out("### instance reached only through a .wants link of a loaded target\n")
        rec("list-unit-files", ["systemctl", "list-unit-files", "--no-pager", "--no-legend", "tendcf-s1-tpl*"])
        rec("list-units --all", ["systemctl", "list-units", "--all", "--no-pager", "--no-legend", "--plain", "tendcf-s1-tpl*"])
        show("tendcf-s1-tpl@x.service")
    with Sandbox() as sb:
        sb.write(U + "/tendcf-s1-tpl@.service", "[Unit]\nDescription=tpl\n[Service]\nExecStart=/bin/sleep 600\n")
        daemon_reload()
        out("### instance with only a .d directory, not started\n")
        sb.write(E + "/tendcf-s1-tpl@y.service.d/x.conf", "[Service]\nEnvironment=A=1\n")
        daemon_reload()
        rec("list-units --all", ["systemctl", "list-units", "--all", "--no-pager", "--no-legend", "--plain", "tendcf-s1-tpl*"])
        show("tendcf-s1-tpl@y.service")
        rec("list-units --all after show", ["systemctl", "list-units", "--all", "--no-pager", "--no-legend", "--plain", "tendcf-s1-tpl*"])
    out("### systemd-run transient unit (item 8)\n")
    rec("run", ["systemd-run", "--unit=tendcf-s1-trans", "--remain-after-exit", "--collect", "/bin/true"])
    show("tendcf-s1-trans.service")
    rec("list-unit-files", ["systemctl", "list-unit-files", "--no-pager", "--no-legend", "tendcf-s1-trans*"])
    rec("list-units --all", ["systemctl", "list-units", "--all", "--no-pager", "--no-legend", "--plain", "tendcf-s1-trans*"])
    rec("where the transient fragment lies", ["ls", "-l", "/run/systemd/transient/"], grep="tendcf-s1")
    rec("stop the transient unit", ["systemctl", "stop", "tendcf-s1-trans.service"])
    rec("reset-failed (rc 1 when nothing failed)", ["systemctl", "reset-failed", "tendcf-s1-trans.service"], ok=OBSERVED_NONZERO)


def link_outside():
    out("## A vendor-directory symlink whose target lies elsewhere\n")
    ext = "/var/tmp/tendcf-s1-extc"
    with Sandbox(extra_roots=(ext,)) as sb:
        for tag, tgt in (("a", R + "/tendcf-s1-ext/tendcf-s1-exta.service"), ("b", E + "/tendcf-s1-extb/tendcf-s1-extb.service"),
                         ("c", ext + "/tendcf-s1-extc.service")):
            sb.write(tgt, SVC)
            sb.symlink(U + "/tendcf-s1-ext%s.service" % tag, tgt)
        daemon_reload()
        for tag in "abc":
            show("tendcf-s1-ext%s.service" % tag)
        rec("list-unit-files", ["systemctl", "list-unit-files", "--no-pager", "--no-legend", "tendcf-s1-ext*"])
        rec("systemctl link of a file elsewhere (what a hand-made linked unit looks like)",
            ["systemctl", "link", "--no-reload", ext + "/tendcf-s1-extc.service"])
        rec("what link created", ["ls", "-l", "/etc/systemd/system/tendcf-s1-extc.service"])
        rec("disable the linked unit", ["systemctl", "disable", "--no-reload", "tendcf-s1-extc.service"])
        if os.path.islink(E + "/tendcf-s1-extc.service"):
            os.unlink(E + "/tendcf-s1-extc.service")
    daemon_reload()
    shutil.rmtree(ext, ignore_errors=True)


def item3_generated():
    out("## Item 3: SourcePath of a generated unit\n")
    gen_dir = "/run/systemd/system-generators"
    script = ("#!/bin/sh\n"
              "printf '[Unit]\\nDescription=tendcf s1 gen\\nSourcePath=/etc/tendcf-s1-gensrc\\n[Service]\\nExecStart=/bin/true\\n' > \"$1/tendcf-s1-gen.service\"\n"
              "printf '[Unit]\\nDescription=tendcf s1 gen without source\\n[Service]\\nExecStart=/bin/true\\n' > \"$1/tendcf-s1-gen-nosrc.service\"\n")
    with Sandbox(extra_roots=(gen_dir, "/etc/init.d", "/etc/rc3.d", "/etc/rc2.d", "/etc/rc5.d")) as sb:
        sb.write(gen_dir + "/tendcf-s1-gen", script, mode=0o755)
        daemon_reload()
        out("### a generator of our own (/run/systemd/system-generators/tendcf-s1-gen)\n")
        show("tendcf-s1-gen.service")
        show("tendcf-s1-gen-nosrc.service")
        rec("list-unit-files", ["systemctl", "list-unit-files", "--no-pager", "--no-legend", "tendcf-s1-gen*"])
        gen_dirs = sorted(glob.glob("/run/systemd/generator*"))
        rec("where the generated fragments lie", ["ls", "-l"] + gen_dirs, grep="tendcf-s1")
        rec("a second daemon-reload", ["systemctl", "daemon-reload"])
        rec("do the generated fragments survive it?", ["ls"] + gen_dirs, grep="tendcf-s1")
    daemon_reload()
    if os.path.exists("/usr/lib/systemd/system-generators/systemd-sysv-generator"):
        out("### the real sysv generator (init script plus rc link)\n")
        with Sandbox(extra_roots=("/etc/init.d", "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d")) as sb:
            sb.write("/etc/init.d/tendcf-s1-sysv",
                     "#!/bin/sh\n### BEGIN INIT INFO\n# Provides: tendcf-s1-sysv\n# Required-Start: $remote_fs\n"
                     "# Required-Stop: $remote_fs\n# Default-Start: 2 3 4 5\n# Default-Stop: 0 1 6\n"
                     "# Short-Description: tendcf s1\n### END INIT INFO\nexit 0\n", mode=0o755)
            for rc in ("rc2.d", "rc3.d", "rc4.d", "rc5.d"):
                sb.symlink("/etc/%s/S99tendcf-s1-sysv" % rc, "../init.d/tendcf-s1-sysv")
            daemon_reload()
            show("tendcf-s1-sysv.service")
            rec("list-unit-files", ["systemctl", "list-unit-files", "--no-pager", "--no-legend", "tendcf-s1-sysv*"])
            rec("dpkg owner of an init script (host database)", ["dpkg-query", "-S", "/etc/init.d/cron", "/etc/init.d/tendcf-s1-sysv"], ok=OBSERVED_NONZERO)
    else:
        out("systemd-sysv-generator is absent on this host: no sysv unit can be generated.\n")
    daemon_reload()


def item6_7_dropins():
    out("## Items 6 and 7: DropInPaths against what a name lookup finds\n")
    unit = U + "/tendcf-s1-p7.service"
    with Sandbox() as sb:
        sb.write(unit, SVC)
        sb.write(U + "/tendcfs1p7-bar.service", SVC)
        sb.write(U + "/tendcf-s1-tpl@.service", "[Unit]\nDescription=tpl\n[Service]\nExecStart=/bin/sleep 600\n")
        sb.write(E + "/service.d/tendcf-s1-typewide.conf", "[Service]\nEnvironment=S1_TYPEWIDE=1\n")
        sb.write(E + "/tendcf-s1-p7.service.d/a.conf", "[Service]\nEnvironment=A=etc\n")
        sb.write(U + "/tendcf-s1-p7.service.d/a.conf", "[Service]\nEnvironment=A=usr\n")
        sb.write(U + "/tendcf-s1-p7.service.d/b.conf", "[Service]\nEnvironment=B=usr\n")
        sb.symlink(E + "/tendcf-s1-p7.service.d/b.conf", "/dev/null")
        sb.write(E + "/tendcf-s1-p7.service.d/notconf.txt", "[Service]\nEnvironment=C=1\n")
        sb.write(E + "/tendcf-s1-p7.service.d/empty.conf", "")
        sb.write(E + "/tendcfs1p7-.service.d/dash.conf", "[Service]\nEnvironment=D=1\n")
        sb.write(E + "/tendcf-s1-tpl@.service.d/tpl.conf", "[Service]\nEnvironment=T=1\n")
        sb.write(E + "/tendcf-s1-tpl@z.service.d/inst.conf", "[Service]\nEnvironment=I=1\n")
        sb.symlink(E + "/multi-user.target.wants/tendcf-s1-tpl@z.service", U + "/tendcf-s1-tpl@.service")
        daemon_reload()
        show("tendcf-s1-p7.service")
        rec("probe-side listing for tendcf-s1-p7", ["ls", "-l", "--time-style=+", "/etc/systemd/system/tendcf-s1-p7.service.d", "/usr/lib/systemd/system/tendcf-s1-p7.service.d"])
        show("tendcfs1p7-bar.service")
        show("tendcf-s1-tpl@z.service")
        rec("is the type-wide drop-in in an arbitrary vendor unit's DropInPaths? (item 6)",
            ["systemctl", "show", "--no-pager", "-p", "DropInPaths", "systemd-journald.service", "ssh.service", "cron.service"])
        rec("systemctl cat of tendcf-s1-p7", ["systemctl", "cat", "--no-pager", "tendcf-s1-p7.service"])


def item9_alias_in_dropin():
    out("## Item 9: Alias= set in a drop-in\n")
    with Sandbox() as sb:
        sb.write(U + "/tendcfs1p9-x.service", SVC)
        sb.write(E + "/tendcfs1p9-x.service.d/a.conf", "[Install]\nAlias=tendcfs1p9-viadropin.service\n")
        sb.write(E + "/tendcfs1p9-.service.d/b.conf", "[Install]\nAlias=tendcfs1p9-viadash.service\n")
        sb.write(E + "/service.d/tendcfs1p9-typewide.conf", "[Install]\nAlias=tendcfs1p9-viatype.service\n")
        daemon_reload()
        rec("systemctl cat", ["systemctl", "cat", "--no-pager", "tendcfs1p9-x.service"])
        rec("before enable", ["find", "/etc/systemd/system", "-name", "tendcfs1p9*"], sort=True)
        rec("enable", ["systemctl", "enable", "--no-reload", "tendcfs1p9-x.service"])
        rec("after enable (links created)", ["find", "/etc/systemd/system", "-name", "tendcfs1p9*", "-type", "l", "-printf", "%p -> %l\\n"], sort=True)
        # unlink what enable made, so the sandbox teardown has nothing to trip on
        rec("disable", ["systemctl", "disable", "--no-reload", "tendcfs1p9-x.service"])
        rec("after disable", ["find", "/etc/systemd/system", "-name", "tendcfs1p9*", "-type", "l", "-printf", "%p -> %l\\n"], sort=True)
        r = rec("leftover links to remove", ["find", "/etc/systemd/system", "-name", "tendcfs1p9*", "-type", "l"])
        for p in r.stdout.split():
            os.unlink(p)


def dpkg_items():
    out("## Items 4 and 5: dpkg-query on a private database built by real dpkg\n")
    arch = sh(["dpkg", "--print-architecture"], check=True).stdout.strip()
    root = tempfile.mkdtemp(prefix="tendcf-s1-dpkgroot-", dir="/var/tmp")
    admin = os.path.join(root, "var/lib/dpkg")
    for d in ("info", "updates", "triggers"):
        os.makedirs(os.path.join(admin, d))
    for f in ("status", "available"):
        open(os.path.join(admin, f), "w").close()

    def build(name, files, conffiles=(), extra=""):
        pk = os.path.join(root, "build-" + name)
        os.makedirs(os.path.join(pk, "DEBIAN"))
        for f in files + list(conffiles):
            fp = pk + f
            os.makedirs(os.path.dirname(fp), exist_ok=True)
            open(fp, "w").write("x\n")
        archf = "all" if "Multi-Arch" not in extra else arch
        ctrl = ("Package: %s\nVersion: 1\nArchitecture: %s\nMaintainer: t <t@invalid>\n"
                "Description: tendcf s1 probe\n%s" % (name, archf, extra))
        open(os.path.join(pk, "DEBIAN/control"), "w").write(ctrl)
        if conffiles:
            open(os.path.join(pk, "DEBIAN/conffiles"), "w").write("".join(c + "\n" for c in conffiles))
        deb = os.path.join(root, name + ".deb")
        sh(["dpkg-deb", "--build", "-Zgzip", pk, deb], check=True)
        return deb

    dp = ["dpkg", "--admindir", admin, "--instdir", root, "--force-not-root", "--force-overwrite", "--no-triggers"]
    q = lambda *p: ["dpkg-query", "--admindir", admin, "-S"] + list(p)
    rec("dpkg and admindir sanity", ["dpkg", "--admindir", admin, "--instdir", root, "--print-architecture"])
    a = build("tendcf-s1-a", ["/usr/lib/tendcf-s1/shared", "/usr/lib/tendcf-s1/only-a"], ["/etc/tendcf-s1/a.conf"])
    b = build("tendcf-s1-b", ["/usr/lib/tendcf-s1/shared"])
    m = build("tendcf-s1-m", ["/usr/lib/tendcf-s1/multi"], extra="Multi-Arch: same\n")
    rec("install a", dp + ["-i", a])
    rec("install b (second owner of shared, force-overwrite)", dp + ["-i", b])
    rec("install m (Multi-Arch: same)", dp + ["-i", m])
    out("### Item 5: output forms, exit status\n")
    rec("one owner", q("/usr/lib/tendcf-s1/only-a"))
    rec("two owners", q("/usr/lib/tendcf-s1/shared"))
    rec("arch-qualified (Multi-Arch: same)", q("/usr/lib/tendcf-s1/multi"))
    rec("no match", q("/usr/lib/tendcf-s1/nothing"), ok=OBSERVED_NONZERO)
    rec("mixed batch: match, no match, match", q("/usr/lib/tendcf-s1/only-a", "/usr/lib/tendcf-s1/nothing", "/usr/lib/tendcf-s1/multi"), ok=OBSERVED_NONZERO)
    rec("a directory", q("/usr/lib/tendcf-s1"))
    rec("glob-escaped literal", q("/usr/lib/tendcf-s1/only\\-a"))
    rec("unusable admindir", ["dpkg-query", "--admindir", "/nonexistent/tendcf-s1", "-S", "/usr/bin/ls"], ok=OBSERVED_NONZERO)
    out("### Item 4: conffile of a removed (not purged) package, then purged\n")
    rec("status after install", ["dpkg-query", "--admindir", admin, "-W", "-f", "${Package} ${Status}\\n", "tendcf-s1-a"])
    rec("remove a", dp + ["-r", "tendcf-s1-a"])
    rec("status after remove", ["dpkg-query", "--admindir", admin, "-W", "-f", "${Package} ${Status}\\n", "tendcf-s1-a"])
    rec("conffile of the removed package", q("/etc/tendcf-s1/a.conf"))
    rec("program file of the removed package", q("/usr/lib/tendcf-s1/only-a"), ok=OBSERVED_NONZERO)
    rec("shared file, one owner removed", q("/usr/lib/tendcf-s1/shared"))
    rec("info/*.list of the removed package", ["cat", "%s/info/tendcf-s1-a.list" % admin])
    rec("purge a", dp + ["-P", "tendcf-s1-a"])
    rec("conffile after purge", q("/etc/tendcf-s1/a.conf"), ok=OBSERVED_NONZERO)
    out("### Item 5: diversions\n")
    dv = ["dpkg-divert", "--admindir", admin, "--instdir", root]
    rec("add a package diversion (no rename)", dv + ["--no-rename", "--package", "tendcf-s1-b", "--add", "--divert", "/usr/lib/tendcf-s1/shared.distrib", "/usr/lib/tendcf-s1/shared"])
    rec("query the diverted path", q("/usr/lib/tendcf-s1/shared"))
    rec("query the diversion target", q("/usr/lib/tendcf-s1/shared.distrib"))
    rec("query a diverted path next to an ordinary one", q("/usr/lib/tendcf-s1/multi", "/usr/lib/tendcf-s1/shared"))
    rec("add a local diversion", dv + ["--no-rename", "--local", "--add", "--divert", "/usr/lib/tendcf-s1/multi.local", "/usr/lib/tendcf-s1/multi"])
    rec("query the locally diverted path", q("/usr/lib/tendcf-s1/multi"))
    rec("diversions file", ["cat", "%s/diversions" % admin])
    out("### the hand-written database of s1lib.TestDb, same questions\n")
    db = build_handwritten_db()
    try:
        handwritten_db_items(db)
    finally:
        db.close()
    real_db_spellings()
    shutil.rmtree(root, ignore_errors=True)


HANDWRITTEN_QUERIES = (("two owners", "/usr/lib/tendcf-s1/hw"), ("arch-qualified", "/usr/lib/tendcf-s1/hwm"),
                       ("diverted", "/usr/lib/tendcf-s1/hwd"))


def build_handwritten_db():
    db = TestDb()
    db.add_package("tendcf-s1-hw-a", ["/usr/lib/tendcf-s1/hw"])
    db.add_package("tendcf-s1-hw-b", ["/usr/lib/tendcf-s1/hw"])
    db.add_package("tendcf-s1-hw-m", ["/usr/lib/tendcf-s1/hwm"], multiarch="same")
    db.add_diversion("/usr/lib/tendcf-s1/hwd", "/usr/lib/tendcf-s1/hwd.distrib")
    db.add_package("tendcf-s1-hw-d", ["/usr/lib/tendcf-s1/hwd.distrib"])
    return db


def handwritten_db_items(db):
    """One checked observation per query: all three are owned or diverted paths, so rc 0 is the observation."""
    for label, p in HANDWRITTEN_QUERIES:
        rec("%s (hand-written database)" % label, ["dpkg-query", "--admindir", db.dir, "-S", p])


def real_db_spellings():
    # the /lib spelling misses (rc 1) in the host database: that is the observation
    rec("real database, /lib spelling of one unit file", ["dpkg-query", "-S", "/lib/systemd/system/ssh.service"], ok=OBSERVED_NONZERO)
    rec("real database, /usr/lib spelling of the same file", ["dpkg-query", "-S", "/usr/lib/systemd/system/ssh.service"])
    rec("is /lib a link to usr/lib", ["ls", "-ld", "/lib"])


def baseline_scan():
    out("## Baseline: the classifier on this host with no claims at all\n")
    import json
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"domains": {"supervision": {"coverage": "comprehensive", "entries": {}},
                               "device-trust": {"coverage": "comprehensive",
                                                "entries": {"supervisor": {"host": {"state": "present", "name": "systemd"}}}}}}, f)
    r = sh([sys.executable, CLASSIFIER, "--claims", f.name])
    os.unlink(f.name)
    out("rc=%d\n" % r.returncode)
    if r.returncode != 0:
        FAILURES.append("baseline classifier scan rc=%d" % r.returncode)
    if r.returncode == 0:
        d = json.loads(r.stdout)
        out("summary: `%s`\n" % json.dumps(d["summary"], sort_keys=True))
        out("units judged: %d; by verdict: %s; by rule: %s\n" % (
            len(d["units"]),
            json.dumps({v: sum(1 for u in d["units"] if u["verdict"] == v) for v in sorted({u["verdict"] for u in d["units"]})}),
            json.dumps({str(k): sum(1 for u in d["units"] if u["rule"] == k) for k in sorted({u["rule"] for u in d["units"]})})))
        out("units that are not a plain rule-8 extra (first 40):\n\n```")
        for u in [u for u in d["units"] if u["rule"] != 8][:40]:
            out("%s rule %s %s: %s" % (u["id"], u["rule"], u["verdict"], u["why"][:160]))
        out("```\n")
        out("incomplete reasons (first 40):\n\n```")
        for x in d["incomplete"][:40]:
            out(x)
        out("```\n")
    else:
        out("```\n%s\n```\n" % r.stderr[-3000:])


STEPS = (env_info, baseline_scan, item7_paths, item1, item2_8_masks_alias_transient, link_outside, item3_generated,
         item6_7_dropins, item9_alias_in_dropin, dpkg_items)


def reload_manager():
    r = sh(["systemctl", "daemon-reload"])
    if r.returncode != 0:
        FAILURES.append("daemon-reload rc=%d: %s" % (r.returncode, r.stderr.strip()[:200]))


def main(steps=None, cleanup=None, gate=True):
    """Run every step, collect what went wrong, and exit nonzero afterwards if anything did.
    `steps`, `cleanup` and `gate` exist so a test can inject a failing step off a systemd host."""
    if gate and (os.geteuid() != 0 or os.environ.get("TENDCF_TEST_SYSTEMD") != "1" or not os.path.isdir("/run/systemd/system")):
        print("skip: needs root, TENDCF_TEST_SYSTEMD=1 and a host booted by systemd")
        return 0
    del FAILURES[:]
    cleanup = cleanup or reload_manager
    out("# Spec section 3.5 observations (tests/unit_classifier/s1_probe.py)\n")
    for step in (STEPS if steps is None else steps):
        try:
            step()
        except Exception as e:  # a failing step must not hide the others, and must not pass
            fail("step %s raised %r" % (step.__name__, e))
        finally:
            try:
                cleanup()
            except Exception as e:
                fail("cleanup after %s raised %r" % (step.__name__, e))
    if FAILURES:
        out("## UNEXPECTED FAILURES (%d)\n" % len(FAILURES))
        for f in FAILURES:
            out("- " + f)
        print("s1_probe: %d unexpected failure(s)" % len(FAILURES), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
