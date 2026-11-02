#!/usr/bin/env python3
"""Record what systemd and dpkg actually do, for spec section 3.5 items 1-9.

Root, Linux, booted by systemd, and TENDCF_TEST_SYSTEMD=1 (it writes unit files
under /etc/systemd/system, /run/systemd/system, /usr/lib/systemd/system, plus
/run/systemd/system-generators and /etc/init.d for item 3, all removed again).
Prints a markdown record to stdout; run it in CI and paste the observed rows
into the spec's section 3.5 results. Dpkg behaviour is measured on a private
admindir under /var/tmp with real dpkg, never on the host database.
"""
import os
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


def rec(title, argv, **kw):
    r = sh(argv, **kw) if isinstance(argv, list) else sh(["sh", "-c", argv], **kw)
    shown = argv if isinstance(argv, str) else " ".join(argv)
    out("**%s**\n\n`$ %s`  (rc=%d)\n\n```" % (title, shown, r.returncode))
    out(r.stdout.rstrip())
    if r.stderr.strip():
        out("[stderr] " + r.stderr.rstrip())
    out("```\n")
    return r


def show(unit, *extra):
    return rec("show " + unit, ["systemctl", "show", "--no-pager", "-p", PROPS] + list(extra) + [unit])


def env_info():
    out("## Environment\n")
    rec("systemd", "systemctl --version | head -2")
    rec("dpkg", "dpkg --version | head -1")
    rec("os", "grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release; uname -m; ls -ld /lib /bin /sbin")
    rec("PID 1", "readlink /proc/1/exe; ls -d /run/systemd/system")
    rec("sysv generator present", "ls -l /usr/lib/systemd/system-generators/systemd-sysv-generator")
    rec("real objects the S1 rows name",
        "for f in ssh.service sshd.service kmod.service hwclock.service getty@.service; do "
        "printf '%s: ' $f; ls -l --time-style=+ /usr/lib/systemd/system/$f /etc/systemd/system/$f 2>&1 | tr '\\n' ';'; echo; done; "
        "dpkg-query -S /usr/lib/systemd/system/ssh.service /usr/lib/systemd/system/kmod.service "
        "/usr/lib/systemd/system/hwclock.service /usr/lib/systemd/system/getty@.service")


def item7_paths():
    out("## Item 7: systemd-analyze unit-paths\n")
    rec("default", ["systemd-analyze", "unit-paths"])
    rec("--system", ["systemd-analyze", "--system", "unit-paths"])
    rec("existing vs listed", "for d in $(systemd-analyze unit-paths); do [ -e $d ] && echo \"exists $d\" || echo \"absent $d\"; done")


def item1():
    out("## Item 1: systemctl show on templates and non-loaded units\n")
    show("getty@.service")
    show("tendcf-s1-nonexistent.service")
    rec("show of two names (order, blank-line separation)",
        ["systemctl", "show", "--no-pager", "-p", "Id,LoadState", "getty@.service", "tendcf-s1-nonexistent.service", "systemd-journald.service"])
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
    rec("where the transient fragment lies", "ls -l /run/systemd/transient/ | grep tendcf-s1 || true")
    sh(["systemctl", "stop", "tendcf-s1-trans.service"])
    sh(["systemctl", "reset-failed", "tendcf-s1-trans.service"])


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
        rec("where the generated fragments lie", "ls -l /run/systemd/generator* | grep tendcf-s1 || true")
        rec("survive a second daemon-reload?", "systemctl daemon-reload; ls /run/systemd/generator* | grep tendcf-s1 || true")
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
            rec("dpkg owner of an init script (host database)", "dpkg-query -S /etc/init.d/cron /etc/init.d/tendcf-s1-sysv 2>&1")
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
        rec("probe-side listing for tendcf-s1-p7", "ls -l --time-style=+ /etc/systemd/system/tendcf-s1-p7.service.d /usr/lib/systemd/system/tendcf-s1-p7.service.d")
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
        rec("before enable", "find /etc/systemd/system -name 'tendcfs1p9*' | sort")
        rec("enable", ["systemctl", "enable", "--no-reload", "tendcfs1p9-x.service"])
        rec("after enable (links created)", "find /etc/systemd/system -name 'tendcfs1p9*' -type l -printf '%p -> %l\\n' | sort")
        # unlink what enable made, so the sandbox teardown has nothing to trip on
        rec("disable", ["systemctl", "disable", "--no-reload", "tendcfs1p9-x.service"])
        rec("after disable", "find /etc/systemd/system -name 'tendcfs1p9*' -type l -printf '%p -> %l\\n' | sort")
        for p in sh(["sh", "-c", "find /etc/systemd/system -name 'tendcfs1p9*' -type l"]).stdout.split():
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
    rec("no match", q("/usr/lib/tendcf-s1/nothing"))
    rec("mixed batch: match, no match, match", q("/usr/lib/tendcf-s1/only-a", "/usr/lib/tendcf-s1/nothing", "/usr/lib/tendcf-s1/multi"))
    rec("a directory", q("/usr/lib/tendcf-s1"))
    rec("glob-escaped literal", q("/usr/lib/tendcf-s1/only\\-a"))
    rec("unusable admindir", ["dpkg-query", "--admindir", "/nonexistent/tendcf-s1", "-S", "/usr/bin/ls"])
    out("### Item 4: conffile of a removed (not purged) package, then purged\n")
    rec("status after install", ["dpkg-query", "--admindir", admin, "-W", "-f", "${Package} ${Status}\\n", "tendcf-s1-a"])
    rec("remove a", dp + ["-r", "tendcf-s1-a"])
    rec("status after remove", ["dpkg-query", "--admindir", admin, "-W", "-f", "${Package} ${Status}\\n", "tendcf-s1-a"])
    rec("conffile of the removed package", q("/etc/tendcf-s1/a.conf"))
    rec("program file of the removed package", q("/usr/lib/tendcf-s1/only-a"))
    rec("shared file, one owner removed", q("/usr/lib/tendcf-s1/shared"))
    rec("info/*.list of the removed package", "cat %s/info/tendcf-s1-a.list" % admin)
    rec("purge a", dp + ["-P", "tendcf-s1-a"])
    rec("conffile after purge", q("/etc/tendcf-s1/a.conf"))
    out("### Item 5: diversions\n")
    dv = ["dpkg-divert", "--admindir", admin, "--instdir", root]
    rec("add a package diversion (no rename)", dv + ["--no-rename", "--package", "tendcf-s1-b", "--add", "--divert", "/usr/lib/tendcf-s1/shared.distrib", "/usr/lib/tendcf-s1/shared"])
    rec("query the diverted path", q("/usr/lib/tendcf-s1/shared"))
    rec("query the diversion target", q("/usr/lib/tendcf-s1/shared.distrib"))
    rec("query a diverted path next to an ordinary one", q("/usr/lib/tendcf-s1/multi", "/usr/lib/tendcf-s1/shared"))
    rec("add a local diversion", dv + ["--no-rename", "--local", "--add", "--divert", "/usr/lib/tendcf-s1/multi.local", "/usr/lib/tendcf-s1/multi"])
    rec("query the locally diverted path", q("/usr/lib/tendcf-s1/multi"))
    rec("diversions file", "cat %s/diversions" % admin)
    out("### the hand-written database of s1lib.TestDb, same questions\n")
    db = TestDb()
    try:
        db.add_package("tendcf-s1-hw-a", ["/usr/lib/tendcf-s1/hw"])
        db.add_package("tendcf-s1-hw-b", ["/usr/lib/tendcf-s1/hw"])
        db.add_package("tendcf-s1-hw-m", ["/usr/lib/tendcf-s1/hwm"], multiarch="same")
        db.add_diversion("/usr/lib/tendcf-s1/hwd", "/usr/lib/tendcf-s1/hwd.distrib")
        db.add_package("tendcf-s1-hw-d", ["/usr/lib/tendcf-s1/hwd.distrib"])
        for label, p in (("two owners", "/usr/lib/tendcf-s1/hw"), ("arch-qualified", "/usr/lib/tendcf-s1/hwm"),
                         ("diverted", "/usr/lib/tendcf-s1/hwd")):
            r = db.query(p)
            out("**%s** `%s` rc=%d\n\n```\n%s%s```\n" % (label, p, r.returncode, r.stdout, r.stderr))
        rec("real database, /lib versus /usr/lib spellings of one unit file",
            "dpkg-query -S /lib/systemd/system/ssh.service /usr/lib/systemd/system/ssh.service 2>&1; ls -ld /lib")
    finally:
        db.close()
    import shutil
    shutil.rmtree(root, ignore_errors=True)


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
    if r.returncode == 0:
        d = json.loads(r.stdout)
        out("summary: `%s`\n" % json.dumps(d["summary"], sort_keys=True))
        out("units judged: %d; by verdict: %s; by rule: %s\n" % (
            len(d["units"]),
            json.dumps({v: sum(1 for u in d["units"] if u["verdict"] == v) for v in sorted({u["verdict"] for u in d["units"]})}),
            json.dumps({str(k): sum(1 for u in d["units"] if u["rule"] == k) for k in sorted({u["rule"] for u in d["units"]})})))
        out("incomplete reasons (first 40):\n\n```")
        for x in d["incomplete"][:40]:
            out(x)
        out("```\n")
    else:
        out("```\n%s\n```\n" % r.stderr[-3000:])


def main():
    if os.geteuid() != 0 or os.environ.get("TENDCF_TEST_SYSTEMD") != "1" or not os.path.isdir("/run/systemd/system"):
        print("skip: needs root, TENDCF_TEST_SYSTEMD=1 and a host booted by systemd")
        return 0
    out("# Spec section 3.5 observations (tests/unit_classifier/s1_probe.py)\n")
    for step in (env_info, baseline_scan, item7_paths, item1, item2_8_masks_alias_transient, item3_generated,
                 item6_7_dropins, item9_alias_in_dropin, dpkg_items):
        try:
            step()
        except Exception as e:  # a failing step must not hide the others
            out("**STEP %s FAILED: %r**\n" % (step.__name__, e))
        finally:
            daemon_reload()
    return 0


if __name__ == "__main__":
    sys.exit(main())
