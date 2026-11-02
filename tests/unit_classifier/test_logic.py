"""Pure-logic tests of bin/unit_classifier.py: canned systemctl/dpkg-query output,
no systemd and no root, so they run on the Mac. They prove the section 3.4
verdict table and the parsers; the real behaviour of systemd and dpkg is proven by
test_fixtures.py on the CI VMs.

    python3 -m unittest discover -s tests/unit_classifier -p 'test_logic.py'
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "bin"))
import unit_classifier as uc  # noqa: E402

U = "/usr/lib/systemd/system"
E = "/etc/systemd/system"
R = "/run/systemd/system"
UNIT_PATHS = ["/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
              "/run/systemd/generator.early", E, R, "/run/systemd/generator", "/usr/local/lib/systemd/system",
              U, "/run/systemd/generator.late"]


class FakeSystem(uc.Env):
    """A canned host: a path table, a dpkg table and per-unit `show` properties."""

    def __init__(self):
        self.fs = {"/lib": ("link", "usr/lib")}
        self.owners = {"/usr/bin/dpkg-query": ["dpkg"], "/usr/bin/dpkg": ["dpkg"]}   # literal path -> [raw owners]
        self.diverted = set()
        self.units = {}           # lookup name -> show properties
        self.files = {}           # list-unit-files rows name -> state
        self.install_alias = {}   # unit id -> [Alias=]
        self.manager = True
        self.have_dpkg = True
        self.dpkg_broken = False
        self.commands = []
        self.dpkg_admindir = None
        self.path = ""
        self.merged = True
        self.extra_stdout = ""
        self.unit_paths_out = None   # override of the systemd-analyze unit-paths stdout
        self.files_out = None        # override of the list-unit-files stdout
        self.units_out = None        # override of the list-units stdout

    # ---- uc.Env surface
    def which(self, tool):
        return "/usr/bin/" + tool if (tool != "dpkg-query" or self.have_dpkg) else None

    def manager_up(self):
        return self.manager

    def lstat(self, p):
        p = os.path.normpath(p)
        if p in self.fs:
            return self.fs[p]
        if any(k.startswith(p + "/") for k in self.fs):
            return ("dir",)
        return None

    def listdir(self, p):
        p = os.path.normpath(p)
        return sorted({k[len(p) + 1:].split("/")[0] for k in self.fs if k.startswith(p + "/")})

    def realpath(self, p):
        if p == "/lib" and self.merged:
            return "/usr/lib"
        if p.startswith("/lib/") and self.merged:
            return "/usr/lib/" + p[5:]
        return p

    def run(self, argv):
        self.commands.append(argv)
        tool = os.path.basename(argv[0])
        rest = list(argv[1:])
        if tool == "systemd-analyze":
            return 0, (self.unit_paths_out if self.unit_paths_out is not None else "\n".join(UNIT_PATHS) + "\n"), ""
        if tool == "systemctl":
            return self._systemctl(rest)
        if tool == "dpkg-query":
            return self._dpkg(rest)
        raise AssertionError(argv)

    def _systemctl(self, a):
        if a[0] == "list-unit-files" and self.files_out is not None:
            return 0, self.files_out, ""
        if a[0] == "list-units" and self.units_out is not None:
            return 0, self.units_out, ""
        if a[0] == "list-unit-files":
            return 0, "".join("%-45s %-10s enabled\n" % (n, s) for n, s in sorted(self.files.items())), ""
        if a[0] == "list-units":
            return 0, "".join("%-45s loaded active running x\n" % n for n in sorted(self.units)), ""
        name = a[a.index("--") + 1] if "--" in a else a[-1]
        if a[0] == "show":
            p = self.units.get(name)
            if p is None:
                p = {"Id": name, "Names": name, "LoadState": "not-found", "UnitFileState": "",
                     "FragmentPath": "", "SourcePath": "", "DropInPaths": "", "Transient": "no"}
            return 0, "".join("%s=%s\n" % kv for kv in p.items()), ""
        if a[0] == "cat":
            p = self.units[name]
            uid = p["Id"]
            al = self.install_alias.get(uid, [])
            return 0, "# %s\n[Unit]\nDescription=x\n[Install]\n%s" % (
                p["FragmentPath"], "".join("Alias=%s\n" % x for x in al)), ""
        raise AssertionError(a)

    def _dpkg(self, a):
        if self.dpkg_broken:
            return 2, "", "dpkg-query: error: cannot access archive database\n"
        assert a[0] == "-S"
        out, err, rc = [], [], 0
        for esc in a[1:]:
            p = re.sub(r"\\(.)", r"\1", esc)
            if p in self.diverted:
                out.append("diversion by tendcf from: %s" % p)
                out.append("diversion by tendcf to: %s.distrib" % p)
            elif p in self.owners:
                out.append("%s: %s" % (", ".join(self.owners[p]), p))
            else:
                err.append("dpkg-query: no path found matching pattern %s" % esc)
                rc = 1
        return rc, "\n".join(out) + ("\n" if out else ""), "\n".join(err) + ("\n" if err else "")

    # ---- builders
    def _put(self, path, entry, owners=None):
        self.fs[path] = entry
        if owners is not None:
            self.owners[path] = list(owners)

    def unit(self, uid, frag="", names=None, dropins=(), ufs="static", load="loaded", source="", transient="no", lookup=True):
        self.units[uid] = {"Id": uid, "Names": " ".join(names or [uid]), "LoadState": load, "UnitFileState": ufs,
                           "FragmentPath": frag, "SourcePath": source, "DropInPaths": " ".join(dropins),
                           "Transient": transient}
        if lookup:
            self.files[uid] = ufs

    def vendor(self, name, pkg, d=U, aliases=(), **kw):
        path = "%s/%s" % (d, name)
        self._put(path, ("file",), [pkg] if pkg else None)
        self.unit(name, frag=path, **kw)
        if aliases:
            self.install_alias[name] = list(aliases)
        return path

    def local(self, name, d=E, **kw):
        path = "%s/%s" % (d, name)
        self._put(path, ("file",))
        self.unit(name, frag=path, **kw)
        return path

    def dropin(self, unit, d=E, fname="x.conf", pkg=None, sub=None):
        path = "%s/%s.d/%s" % (d, sub or unit, fname)
        self._put(path, ("file",), [pkg] if pkg else None)
        if unit in self.units:
            cur = self.units[unit]["DropInPaths"]
            self.units[unit]["DropInPaths"] = (cur + " " + path).strip()
        return path

    def dropin_link(self, unit, target, fname="x.conf", d=E, final=None, pkg=None):
        """A drop-in that is a link, with its (optional) final target file and owner of the link."""
        path = "%s/%s.d/%s" % (d, unit, fname)
        self._put(path, ("link", target), [pkg] if pkg else None)
        cur = self.units[unit]["DropInPaths"]
        self.units[unit]["DropInPaths"] = (cur + " " + path).strip()
        return path

    def mask(self, name, d=E):
        self._put("%s/%s" % (d, name), ("link", "/dev/null"))

    def alias(self, name, target, d=E, pkg=None):
        self._put("%s/%s" % (d, name), ("link", target if "/" in target else "/usr/lib/systemd/system/" + target),
                  [pkg] if pkg else None)
        tid = os.path.basename(target)
        self.files[name] = "alias"
        t = self.units[tid]
        self.units[name] = dict(t, Names=(t["Names"] + " " + name))
        self.units[tid] = dict(t, Names=(t["Names"] + " " + name))


def claims(pkgs=(), writers=None, services=None, extra_domains=None, coverage="comprehensive", supervisor="systemd"):
    ents = {}
    if writers:
        ents["unit-writer"] = {k: {"state": "present", "writer": w} for k, w in writers.items()}
    if pkgs:
        ents["unit-package"] = {p: {"state": "present", "writer": "dpkg"} for p in pkgs}
    if services:
        ents["service"] = {k: {"state": s} for k, s in services.items()}
    doc = {"domains": {"supervision": {"coverage": coverage, "entries": ents},
                       "device-trust": {"coverage": "comprehensive",
                                        "entries": {"supervisor": {"host": {"state": "present", "name": supervisor}}}}}}
    doc["domains"].update(extra_domains or {})
    return uc.load_claims(doc)


def verdict(system, cl, unit):
    out = uc.classify(system, cl)
    hit = [u for u in out["units"] if unit in u["names"]]
    return (hit[0]["verdict"] if hit else None), out


class VerdictTable(unittest.TestCase):
    def v(self, s, cl, unit):
        got, out = verdict(s, cl, unit)
        return got

    def test_rogue_etc_unit_no_claim_is_extra(self):
        s = FakeSystem()
        s.local("systemd-rogue.service")
        self.assertEqual(self.v(s, claims(), "systemd-rogue.service"), "extra")

    def test_unowned_file_in_vendor_dir_no_claim_is_extra(self):
        s = FakeSystem()
        s.local("stray.service", d=U)
        self.assertEqual(self.v(s, claims(), "stray.service"), "extra")

    def test_name_claim_makes_local_clean(self):
        s = FakeSystem()
        s.local("mine.service")
        self.assertEqual(self.v(s, claims(writers={"mine.service": "third-party"}), "mine.service"), "clean")

    def test_undeclared_package_and_undeclared_coowner_are_extra(self):
        s = FakeSystem()
        s.vendor("a.service", "pkg-a")
        s.vendor("b.service", None)
        s.owners[U + "/b.service"] = ["pkg-b", "pkg-c"]
        self.assertEqual(self.v(s, claims(), "a.service"), "extra")
        self.assertEqual(self.v(s, claims(pkgs=["pkg-b"]), "b.service"), "extra")
        self.assertEqual(self.v(s, claims(pkgs=["pkg-b", "pkg-c"]), "b.service"), "clean")

    def test_declared_package_fragment_only_is_clean(self):
        s = FakeSystem()
        s.vendor("ssh.service", "openssh-server")
        self.assertEqual(self.v(s, claims(pkgs=["openssh-server"]), "ssh.service"), "clean")

    def ssh_with_alias(self, s, authorized=True):
        s.vendor("ssh.service", "openssh-server", aliases=["sshd.service"] if authorized else [])
        s.alias("sshd.service", "ssh.service")

    def test_enable_created_alias_clean_and_counted_once(self):
        s = FakeSystem()
        self.ssh_with_alias(s)
        got, out = verdict(s, claims(pkgs=["openssh-server"]), "sshd.service")
        self.assertEqual(got, "clean")
        self.assertEqual([u["id"] for u in out["units"]], ["ssh.service"])
        self.assertEqual(out["summary"], {"row_type": "domain_coverage", "domain": "supervision", "extra_scan": "complete",
                                          "extra_entries": 0, "two_writers": 0, "unmet_absence": 0})

    def test_unauthorized_alias_is_extra_even_under_exact_claim(self):
        s = FakeSystem()
        s.vendor("ssh.service", "openssh-server")
        s.alias("evil.service", "ssh.service")
        pk = ["openssh-server"]
        self.assertEqual(self.v(s, claims(pkgs=pk), "evil.service"), "extra")
        self.assertEqual(self.v(s, claims(pkgs=pk, writers={"evil.service": "third-party"}), "evil.service"), "extra")

    def test_alias_authorized_by_a_dropin_is_clean(self):
        s = FakeSystem()
        s.vendor("t.service", "tpkg")
        s.dropin("t.service")
        s.install_alias["t.service"] = ["t-link.service"]
        s.alias("t-link.service", "t.service")
        self.assertEqual(self.v(s, claims(pkgs=["tpkg"], writers={"t.service": "third-party"}), "t.service"), "clean")

    def test_cfengine_claim_on_alias_name_over_vendor_is_two_writers(self):
        s = FakeSystem()
        self.ssh_with_alias(s)
        self.assertEqual(self.v(s, claims(pkgs=["openssh-server"], writers={"sshd.service": "cfengine"},
                                         services={"sshd.service": "present"}), "ssh.service"), "two-writers")

    def test_shipped_alias_and_mask_with_declared_package_are_clean(self):
        s = FakeSystem()
        s.vendor("systemd-modules-load.service", "systemd")
        s.alias("kmod.service", "systemd-modules-load.service", d=U, pkg="kmod")
        s.vendor("hwclock.service", "systemd")
        s.mask("hwclock.service", d=U)
        s.owners[U + "/hwclock.service"] = ["systemd"]
        s.units["hwclock.service"]["LoadState"] = "masked"
        cl = claims(pkgs=["systemd", "kmod"])
        self.assertEqual(self.v(s, cl, "kmod.service"), "clean")
        self.assertEqual(self.v(s, cl, "hwclock.service"), "clean")

    def test_local_dropin_on_vendor_unit(self):
        s = FakeSystem()
        s.vendor("ssh.service", "openssh-server")
        s.dropin("ssh.service")
        self.assertEqual(self.v(s, claims(pkgs=["openssh-server"]), "ssh.service"), "two-writers")
        self.assertEqual(self.v(s, claims(pkgs=["openssh-server"], writers={"ssh.service": "third-party"}), "ssh.service"), "clean")

    def test_dash_truncated_dropin(self):
        s = FakeSystem()
        s.vendor("foo-bar.service", "foo")
        s.dropin("foo-bar.service", sub="foo-.service")
        self.assertEqual(self.v(s, claims(pkgs=["foo"]), "foo-bar.service"), "two-writers")
        self.assertEqual(self.v(s, claims(pkgs=["foo"], writers={"foo-bar.service": "third-party"}), "foo-bar.service"), "clean")

    def test_generated_unit_with_dropin(self):
        s = FakeSystem()
        s._put("/etc/init.d/zhm", ("file",), ["zephyr-clients"])
        s.unit("zhm.service", frag="/run/systemd/generator.late/zhm.service", ufs="generated", source="/etc/init.d/zhm")
        s._put("/run/systemd/generator.late/zhm.service", ("file",))
        s.dropin("zhm.service")
        pk = ["zephyr-clients"]
        self.assertEqual(self.v(s, claims(pkgs=pk), "zhm.service"), "two-writers")
        self.assertEqual(self.v(s, claims(pkgs=pk, writers={"zhm.service": "third-party"}), "zhm.service"), "clean")

    def test_masks_persistent_and_runtime(self):
        for d in (E, R):
            s = FakeSystem()
            s.vendor("ssh.service", "openssh-server")
            s.mask("ssh.service", d=d)
            s.units["ssh.service"]["LoadState"] = "masked"
            s.units["ssh.service"]["FragmentPath"] = ""
            pk = ["openssh-server"]
            self.assertEqual(self.v(s, claims(pkgs=pk), "ssh.service"), "two-writers", d)
            self.assertEqual(self.v(s, claims(pkgs=pk, writers={"ssh.service": "third-party"}), "ssh.service"), "clean", d)
            self.assertEqual(self.v(s, claims(pkgs=pk, writers={"ssh.service": "cfengine"}, services={"ssh.service": "present"}),
                                    "ssh.service"), "two-writers", d)

    def test_package_shipped_dropin_under_etc_is_clean(self):
        s = FakeSystem()
        s.vendor("a.service", "apkg")
        s.dropin("a.service", pkg="apkg")
        self.assertEqual(self.v(s, claims(pkgs=["apkg"]), "a.service"), "clean")

    def test_template_key_covers_instance_dropin(self):
        s = FakeSystem()
        s.vendor("getty@.service", "systemd", lookup=True)
        s.unit("getty@tty1.service", frag=U + "/getty@.service", dropins=[], ufs="enabled")
        s.dropin("getty@tty1.service")
        pk = ["systemd"]
        self.assertEqual(self.v(s, claims(pkgs=pk), "getty@tty1.service"), "two-writers")
        self.assertEqual(self.v(s, claims(pkgs=pk, writers={"getty@.service": "third-party"}), "getty@tty1.service"), "clean")

    def test_local_copy_of_vendor_fragment_is_two_writers_under_any_claim(self):
        s = FakeSystem()
        s.vendor("ssh.service", "openssh-server")
        s._put(E + "/ssh.service", ("file",))
        s.units["ssh.service"]["FragmentPath"] = E + "/ssh.service"
        cl = claims(pkgs=["openssh-server"], writers={"ssh.service": "third-party"})
        self.assertEqual(self.v(s, cl, "ssh.service"), "two-writers")

    def test_local_instance_fragment_hides_template(self):
        s = FakeSystem()
        s.vendor("getty@.service", "systemd")
        s.local("getty@tty1.service", ufs="enabled")
        cl = claims(pkgs=["systemd"], writers={"getty@.service": "third-party"})
        self.assertEqual(self.v(s, cl, "getty@tty1.service"), "two-writers")

    def test_instance_mask_with_template_claims(self):
        s = FakeSystem()
        s.vendor("getty@.service", "systemd")
        s.unit("getty@tty1.service", frag="", load="masked", ufs="masked")
        s.mask("getty@tty1.service")
        pk = ["systemd"]
        self.assertEqual(self.v(s, claims(pkgs=pk), "getty@tty1.service"), "two-writers")
        self.assertEqual(self.v(s, claims(pkgs=pk, writers={"getty@.service": "third-party"}), "getty@tty1.service"), "clean")
        self.assertEqual(self.v(s, claims(pkgs=pk, writers={"getty@*": "cfengine"}, services={"getty@tty1.service": "present"}),
                                "getty@tty1.service"), "two-writers")

    def test_cfengine_claim_and_service_on_vendor_unit_no_local_file(self):
        s = FakeSystem()
        s.vendor("ssh.service", "openssh-server")
        cl = claims(pkgs=["openssh-server"], writers={"ssh.service": "cfengine"}, services={"ssh.service": "present"})
        self.assertEqual(self.v(s, cl, "ssh.service"), "two-writers")

    def test_tombstone_with_surviving_file_is_unmet_absence(self):
        s = FakeSystem()
        s.local("tendcf.canary.service")
        cl = claims(writers={"tendcf.canary.*": "cfengine"}, services={"tendcf.canary.service": "absent"})
        got, out = verdict(s, cl, "tendcf.canary.service")
        self.assertEqual(got, "unmet-absence")
        self.assertEqual(out["summary"]["unmet_absence"], 1)

    def test_cfengine_local_fragment_with_present_service_clean_without_service_extra(self):
        s = FakeSystem()
        s.local("tendcf.canary.service")
        self.assertEqual(self.v(s, claims(writers={"tendcf.canary.*": "cfengine"}, services={"tendcf.canary.service": "present"}),
                                "tendcf.canary.service"), "clean")
        self.assertEqual(self.v(s, claims(writers={"tendcf.canary.*": "cfengine"}), "tendcf.canary.service"), "extra")

    def test_claim_in_a_not_yet_migrated_domain_counts(self):
        s = FakeSystem()
        s.local("mine.service")
        other = {"other": {"coverage": "not-yet-migrated",
                           "entries": {"unit-writer": {"mine.service": {"state": "present", "writer": "third-party"}}}}}
        self.assertEqual(self.v(s, claims(extra_domains=other), "mine.service"), "clean")

    def test_contradictory_service_states_are_incomplete_naming_both(self):
        s = FakeSystem()
        s.local("mine.service")
        other = {"other": {"coverage": "not-yet-migrated",
                           "entries": {"service": {"mine.service": {"state": "absent"}}}}}
        cl = claims(writers={"mine.service": "cfengine"}, services={"mine.service": "present"}, extra_domains=other)
        out = uc.classify(s, cl)
        self.assertEqual(out["summary"]["extra_scan"], "incomplete")
        self.assertNotIn("extra_entries", out["summary"])
        self.assertEqual(out["conflicts"][0]["addresses"],
                         ["other/service/mine.service=absent", "supervision/service/mine.service=present"])

    def test_generated_owned_source_declared_and_undeclared(self):
        s = FakeSystem()
        s._put("/etc/init.d/zhm", ("file",), ["zephyr-clients"])
        s._put("/run/systemd/generator.late/zhm.service", ("file",))
        s.unit("zhm.service", frag="/run/systemd/generator.late/zhm.service", ufs="generated", source="/etc/init.d/zhm")
        self.assertEqual(self.v(s, claims(pkgs=["zephyr-clients"]), "zhm.service"), "clean")
        self.assertEqual(self.v(s, claims(), "zhm.service"), "extra")

    def test_generated_empty_sourcepath_is_incomplete(self):
        s = FakeSystem()
        s._put("/run/systemd/generator.late/g.service", ("file",))
        s.unit("g.service", frag="/run/systemd/generator.late/g.service", ufs="generated", source="")
        out = uc.classify(s, claims())
        self.assertEqual(out["summary"]["extra_scan"], "incomplete")
        self.assertEqual(out["units"][0]["verdict"], "incomplete")

    def test_generated_empty_sourcepath_exact_noncfengine_claim_is_clean_else_incomplete(self):
        """R9 (K5): an empty-SourcePath generated unit is clean under an exact
        non-cfengine claim on it; incomplete without one, under a cfengine claim,
        under a prefix, or under a claim on another unit."""
        def build():
            s = FakeSystem()
            s._put("/run/systemd/generator.late/g.service", ("file",))
            s.unit("g.service", frag="/run/systemd/generator.late/g.service", ufs="generated", source="")
            return s
        out = uc.classify(build(), claims(writers={"g.service": "third-party"}))
        self.assertEqual(out["summary"]["extra_scan"], "complete")
        self.assertEqual((out["units"][0]["verdict"], out["summary"]["extra_entries"], out["summary"]["two_writers"]),
                         ("clean", 0, 0))
        for label, cl in (("no claim", claims()),
                          ("cfengine claim", claims(writers={"g.service": "cfengine"})),
                          ("prefix claim", claims(writers={"g-*": "third-party"})),
                          ("another unit's claim", claims(writers={"other.service": "third-party"}))):
            out = uc.classify(build(), cl)
            self.assertEqual(out["summary"]["extra_scan"], "incomplete", label)
            self.assertEqual(out["units"][0]["verdict"], "incomplete", label)

    def test_generated_empty_sourcepath_instance_under_template_claim_is_clean(self):
        s = FakeSystem()
        s._put("/run/systemd/generator.late/g@1.service", ("file",))
        s.unit("g@1.service", frag="/run/systemd/generator.late/g@1.service", ufs="generated", source="")
        out = uc.classify(s, claims(writers={"g@.service": "third-party"}))
        self.assertEqual((out["summary"]["extra_scan"], out["units"][0]["verdict"]), ("complete", "clean"))

    def test_generator_dropin_on_declared_vendor_unit_is_two_writers_without_a_claim_clean_with_one(self):
        """R9 (K13): a drop-in a generator wrote under /run/systemd/generator* is
        a local drop-in. The generator's package is not consulted, declared or not."""
        for gen_dir in ("/run/systemd/generator", "/run/systemd/generator.early", "/run/systemd/generator.late"):
            s = FakeSystem()
            s.vendor("zram.service", "vendorpkg")
            s.dropin("zram.service", d=gen_dir, fname="bindings.conf")
            for pk in (["vendorpkg"], ["vendorpkg", "generator-pkg"]):
                self.assertEqual(self.v(s, claims(pkgs=pk), "zram.service"), "two-writers", (gen_dir, pk))
                self.assertEqual(self.v(s, claims(pkgs=pk, writers={"zram.service": "third-party"}), "zram.service"),
                                 "clean", (gen_dir, pk))
            self.assertEqual(self.v(s, claims(pkgs=["vendorpkg"], writers={"zram.service": "cfengine"}), "zram.service"),
                             "two-writers", gen_dir)

    def test_transient_unit_is_not_judged(self):
        s = FakeSystem()
        s._put("/run/systemd/transient/run-1.service", ("file",))
        s.unit("run-1.service", frag="/run/systemd/transient/run-1.service", transient="yes")
        out = uc.classify(s, claims())
        self.assertEqual(out["units"], [])
        self.assertEqual(out["summary"]["extra_entries"], 0)

    def test_owner_under_lib_only_is_package_tier(self):
        s = FakeSystem()
        s._put(U + "/tailscaled.service", ("file",))
        s.owners["/lib/systemd/system/tailscaled.service"] = ["tailscale"]
        s.unit("tailscaled.service", frag=U + "/tailscaled.service")
        self.assertEqual(self.v(s, claims(pkgs=["tailscale"]), "tailscaled.service"), "clean")
        self.assertEqual(self.v(s, claims(), "tailscaled.service"), "extra")
        s.merged = False
        s.fs.pop("/lib")
        self.assertEqual(self.v(s, claims(pkgs=["tailscale"]), "tailscaled.service"), "extra")

    def test_arch_qualified_owner_maps_to_the_package(self):
        s = FakeSystem()
        s.vendor("a.service", None)
        s.owners[U + "/a.service"] = ["pkg:amd64"]
        self.assertEqual(self.v(s, claims(pkgs=["pkg"]), "a.service"), "clean")

    def test_vendor_symlink_to_unowned_target_outside_the_tree(self):
        s = FakeSystem()
        s._put(U + "/ext.service", ("link", "/opt/x/ext.service"), ["pkg"])
        s._put("/opt/x/ext.service", ("file",))
        s.unit("ext.service", frag="/opt/x/ext.service")
        self.assertEqual(self.v(s, claims(pkgs=["pkg"]), "ext.service"), "extra")
        self.assertEqual(self.v(s, claims(pkgs=["pkg"], writers={"ext.service": "third-party"}), "ext.service"), "clean")

    def test_diversion_makes_scan_incomplete(self):
        s = FakeSystem()
        s.vendor("a.service", "pkg")
        s.diverted.add(U + "/a.service")
        out = uc.classify(s, claims(pkgs=["pkg"]))
        self.assertEqual(out["summary"]["extra_scan"], "incomplete")

    def test_no_dpkg_and_no_manager_are_incomplete_without_counts(self):
        s = FakeSystem()
        s.vendor("a.service", "pkg")
        s.have_dpkg = False
        out = uc.classify(s, claims())
        self.assertEqual(out["summary"], {"row_type": "domain_coverage", "domain": "supervision", "extra_scan": "incomplete"})
        s = FakeSystem()
        s.manager = False
        self.assertEqual(uc.classify(s, claims())["summary"]["extra_scan"], "incomplete")

    def test_empty_database_is_incomplete_because_no_match_proves_nothing(self):
        s = FakeSystem()
        s.vendor("a.service", "pkg")
        s.owners.clear()      # dpkg-query answers "no path found" for everything, rc 1
        out = uc.classify(s, claims())
        self.assertEqual(out["summary"]["extra_scan"], "incomplete")
        self.assertEqual(out["units"], [])

    def test_gate_not_run(self):
        s = FakeSystem()
        s.local("x.service")
        for kw in ({"coverage": "not-yet-migrated"}, {"supervisor": "launchd"}):
            out = uc.classify(s, claims(**kw))
            self.assertEqual(out["summary"]["extra_scan"], "not-run")
            self.assertEqual(s.commands, [])

    def test_dropin_not_in_dropinpaths_and_fragment_disagreement_are_incomplete(self):
        s = FakeSystem()
        s.vendor("a.service", "pkg")
        s.units["a.service"]["DropInPaths"] = E + "/a.service.d/ghost.conf"
        out = uc.classify(s, claims(pkgs=["pkg"]))
        self.assertEqual(out["units"][0]["verdict"], "incomplete")
        s = FakeSystem()
        s.vendor("b.service", "pkg")
        s.units["b.service"]["FragmentPath"] = "/somewhere/else/b.service"
        self.assertEqual(uc.classify(s, claims(pkgs=["pkg"]))["units"][0]["verdict"], "incomplete")


def one_unit(out, name):
    hit = [u for u in out["units"] if name in u["names"]]
    assert len(hit) == 1, hit
    return hit[0]


class DropinLinkTargets(unittest.TestCase):
    """Review finding 2: a drop-in's link target is part of the layer, never a fragment."""

    def system(self, vendor_pkg="apkg", target_owner=None, link_owner=None):
        s = FakeSystem()
        s.vendor("a.service", vendor_pkg)
        s._put("/opt/conf/x.conf", ("file",), [target_owner] if target_owner else None)
        s.dropin_link("a.service", "/opt/conf/x.conf", pkg=link_owner)
        return s

    def judged(self, s, cl):
        out = uc.classify(s, cl)
        return one_unit(out, "a.service"), out

    def test_local_target_under_exact_claim_is_clean_not_rule_3(self):
        u, out = self.judged(self.system(), claims(pkgs=["apkg"], writers={"a.service": "third-party"}))
        self.assertEqual((u["verdict"], u["rule"]), ("clean", 11), u["why"])
        self.assertEqual(out["summary"]["two_writers"], 0)

    def test_local_target_without_a_claim_is_rule_4_two_writers(self):
        u, _ = self.judged(self.system(), claims(pkgs=["apkg"]))
        self.assertEqual((u["verdict"], u["rule"]), ("two-writers", 4))

    def test_the_target_artifact_keeps_the_dropin_role(self):
        u, _ = self.judged(self.system(), claims(pkgs=["apkg"], writers={"a.service": "third-party"}))
        roles = {a["path"]: a["role"] for a in u["artifacts"] if a["kind"] == "target"}
        self.assertEqual(roles, {"/opt/conf/x.conf": "dropin"})

    def test_owned_target_of_a_local_link_is_not_a_vendor_fragment(self):
        """A unit whose only fragment is local, under an exact claim, with a local drop-in link to a
        package-owned file: no vendor fragment exists, so rule 3 must not fire."""
        s = FakeSystem()
        s.local("b.service")
        s._put("/opt/conf/x.conf", ("file",), ["cpkg"])
        s.dropin_link("b.service", "/opt/conf/x.conf")
        out = uc.classify(s, claims(pkgs=["cpkg"], writers={"b.service": "third-party"}))
        u = one_unit(out, "b.service")
        self.assertEqual((u["verdict"], u["rule"]), ("clean", 11), u["why"])

    def test_shipped_link_and_owned_target_both_declared_is_clean(self):
        s = self.system(target_owner="apkg", link_owner="apkg")
        u, _ = self.judged(s, claims(pkgs=["apkg"]))
        self.assertEqual((u["verdict"], u["rule"]), ("clean", 11), u["why"])

    def test_owned_target_of_an_undeclared_package_is_extra(self):
        s = self.system(target_owner="zpkg", link_owner="apkg")
        u, _ = self.judged(s, claims(pkgs=["apkg"]))
        self.assertEqual((u["verdict"], u["rule"]), ("extra", 8))

    def test_k10_fragment_chain_unchanged(self):
        s = FakeSystem()
        s._put(U + "/ext.service", ("link", "/opt/x/ext.service"), ["pkg"])
        s._put("/opt/x/ext.service", ("file",))
        s.unit("ext.service", frag="/opt/x/ext.service")
        self.assertEqual(one_unit(uc.classify(s, claims(pkgs=["pkg"])), "ext.service")["rule"], 10)

    def test_dropin_link_to_dev_null_is_still_exempt(self):
        s = FakeSystem()
        s.vendor("a.service", "apkg")
        s._put(E + "/a.service.d/x.conf", ("link", "/dev/null"))
        s.units["a.service"]["DropInPaths"] = E + "/a.service.d/x.conf"
        out = uc.classify(s, claims(pkgs=["apkg"], writers={"a.service": "third-party"}))
        self.assertEqual(out["summary"]["extra_scan"], "complete")
        self.assertEqual(one_unit(out, "a.service")["verdict"], "clean")


class SharedPathRoles(unittest.TestCase):
    """Review 4 finding 1: one file reached as a drop-in's target and as a fragment keeps both roles,
    whichever load-path directory is scanned first."""

    ORDERS = {"etc-first": UNIT_PATHS, "usr-first": [U] + [p for p in UNIT_PATHS if p != U]}

    def system(self, order, link_dir):
        s = FakeSystem()
        s.vendor("a.service", "apkg")
        s._put(E + "/a.service", ("file",))                       # an unowned override of the vendor fragment
        s.units["a.service"]["FragmentPath"] = E + "/a.service"
        s.dropin_link("a.service", U + "/a.service", d=link_dir)  # a drop-in link that ends at the vendor file
        s.unit_paths_out = "\n".join(self.ORDERS[order]) + "\n"
        return s

    def test_local_override_plus_vendor_file_as_dropin_target_is_rule_3_in_every_order(self):
        for order in self.ORDERS:
            for link_dir in (E, U):
                for cl in (claims(pkgs=["apkg"]), claims(pkgs=["apkg"], writers={"a.service": "third-party"})):
                    with self.subTest(order=order, link_dir=link_dir, exact=bool(cl.writers)):
                        out = uc.classify(self.system(order, link_dir), cl)
                        u = one_unit(out, "a.service")
                        self.assertEqual((u["verdict"], u["rule"]), ("two-writers", 3), u["why"])

    def test_both_chains_are_recorded_for_the_shared_path(self):
        for order in self.ORDERS:
            out = uc.classify(self.system(order, E), claims(pkgs=["apkg"]))
            roles = sorted((a["kind"], a["role"]) for a in one_unit(out, "a.service")["artifacts"] if a["path"] == U + "/a.service")
            self.assertEqual(roles, [("fragment", "fragment"), ("target", "dropin")], order)

    def test_dropin_only_cases_are_unchanged_in_both_orders(self):
        for order in self.ORDERS:
            s = FakeSystem()
            s.vendor("a.service", "apkg")
            s._put("/opt/conf/x.conf", ("file",))
            s.dropin_link("a.service", "/opt/conf/x.conf")
            s.unit_paths_out = "\n".join(self.ORDERS[order]) + "\n"
            out = uc.classify(s, claims(pkgs=["apkg"], writers={"a.service": "third-party"}))
            self.assertEqual(one_unit(out, "a.service")["verdict"], "clean", order)


class FragmentChainLinkInAnyOrder(unittest.TestCase):
    """Review 5 finding 1: an owned link to an unowned fragment (K10) is one chain in either scan order."""

    ORDERS = SharedPathRoles.ORDERS

    def system(self, order):
        s = FakeSystem()
        s._put(U + "/a.service", ("link", E + "/a.service"), ["apkg"])     # the package's link
        s._put(E + "/a.service", ("file",))                                # ... to an unowned file
        s.unit("a.service", frag=E + "/a.service")
        s.unit_paths_out = "\n".join(self.ORDERS[order]) + "\n"
        return s

    def test_owned_link_to_an_unowned_fragment_is_not_a_second_fragment(self):
        for order in self.ORDERS:
            for writers, rule, verdict in ((None, 10, "extra"), ({"a.service": "third-party"}, 11, "clean")):
                with self.subTest(order=order, exact=bool(writers)):
                    out = uc.classify(self.system(order), claims(pkgs=["apkg"], writers=writers))
                    u = one_unit(out, "a.service")
                    self.assertEqual((u["verdict"], u["rule"]), (verdict, rule), u["why"])

    def test_the_record_for_the_shared_path_carries_the_link_that_leads_to_it(self):
        for order in self.ORDERS:
            out = uc.classify(self.system(order), claims(pkgs=["apkg"]))
            vias = [a["via"] for a in one_unit(out, "a.service")["artifacts"] if a["path"] == E + "/a.service"]
            self.assertEqual(vias, [U + "/a.service"], order)


class RecordShape(unittest.TestCase):
    """Review 5 finding 4: the JSON records say which chain each belongs to, so a consumer need not guess."""

    def test_dropin_records_say_dropin_and_target_records_say_via(self):
        s = FakeSystem()
        s.vendor("a.service", "apkg")
        s._put("/opt/conf/x.conf", ("file",))
        s.dropin_link("a.service", "/opt/conf/x.conf")
        s.dropin("a.service", fname="y.conf")
        out = uc.classify(s, claims(pkgs=["apkg"], writers={"a.service": "third-party"}))
        arts = {a["path"]: a for a in one_unit(out, "a.service")["artifacts"]}
        self.assertEqual(arts[E + "/a.service.d/x.conf"]["role"], "dropin")
        self.assertEqual(arts[E + "/a.service.d/y.conf"]["role"], "dropin")
        self.assertEqual(arts["/opt/conf/x.conf"]["role"], "dropin")
        self.assertEqual(arts["/opt/conf/x.conf"]["via"], E + "/a.service.d/x.conf")
        self.assertEqual(arts[U + "/a.service"]["role"], "fragment")


class UnresolvedLinks(unittest.TestCase):
    """Review finding 3: a link chain with no final target makes the unit unverifiable."""

    def check(self, s):
        out = uc.classify(s, claims(pkgs=["apkg"], writers={"a.service": "third-party"}))
        self.assertEqual(out["summary"], {"row_type": "domain_coverage", "domain": "supervision", "extra_scan": "incomplete"})
        u = one_unit(out, "a.service")
        self.assertEqual(u["verdict"], "incomplete")
        return u

    def base(self):
        s = FakeSystem()
        s.vendor("a.service", "apkg")
        return s

    def test_dangling_dropin_link(self):
        s = self.base()
        s.dropin_link("a.service", "/nonexistent/x.conf")
        self.assertIn("dangling", self.check(s)["why"])

    def test_dangling_shadowed_fragment_link(self):
        s = self.base()
        s._put(R + "/a.service", ("link", "/nonexistent/a.service"))
        self.assertIn("dangling", self.check(s)["why"])

    def test_dropin_link_cycle(self):
        s = self.base()
        s._put("/opt/c/one", ("link", "/opt/c/two"))
        s._put("/opt/c/two", ("link", "/opt/c/one"))
        s.dropin_link("a.service", "/opt/c/one")
        self.assertIn("cycle", self.check(s)["why"])

    def test_dropin_link_chain_over_the_limit(self):
        s = self.base()
        for i in range(12):
            s._put("/opt/c/l%d" % i, ("link", "/opt/c/l%d" % (i + 1)))
        s._put("/opt/c/l12", ("file",))
        s.dropin_link("a.service", "/opt/c/l0")
        self.assertIn("longer than", self.check(s)["why"])

    def test_chain_at_the_limit_resolves(self):
        s = self.base()
        for i in range(9):      # the drop-in link plus nine more: ten hops, the limit
            s._put("/opt/c/l%d" % i, ("link", "/opt/c/l%d" % (i + 1)))
        s._put("/opt/c/l9", ("file",))
        s.dropin_link("a.service", "/opt/c/l0")
        out = uc.classify(s, claims(pkgs=["apkg"], writers={"a.service": "third-party"}))
        self.assertEqual(out["summary"]["extra_scan"], "complete")

    def test_link_final_distinguishes_the_three_failures(self):
        s = FakeSystem()
        s._put("/p/dangling", ("link", "/nowhere"))
        s._put("/p/a", ("link", "/p/b"))
        s._put("/p/b", ("link", "/p/a"))
        self.assertEqual(uc.link_final(s, "/p/dangling")[:2], (None, False))
        self.assertIn("dangling", uc.link_final(s, "/p/dangling")[2])
        self.assertIn("cycle", uc.link_final(s, "/p/a")[2])
        s._put("/p/null", ("link", "/dev/null"))
        self.assertEqual(uc.link_final(s, "/p/null"), ("/dev/null", True, None))


class FailClosedRecords(unittest.TestCase):
    """Review finding 4: malformed manager output never yields complete with zero counts."""

    def incomplete(self, s, **kw):
        out = uc.classify(s, claims(**kw))
        self.assertEqual(out["summary"], {"row_type": "domain_coverage", "domain": "supervision", "extra_scan": "incomplete"})
        return out

    def test_unit_paths_with_no_absolute_path(self):
        s = FakeSystem()
        s.local("x.service")
        s.unit_paths_out = "garbage\nnot a path\n"
        out = self.incomplete(s)
        self.assertTrue(any("malformed record" in r for r in out["incomplete"]), out["incomplete"])
        self.assertTrue(any("load path is unknown" in r for r in out["incomplete"]), out["incomplete"])

    def test_unit_paths_empty_or_blank(self):
        for blank in ("", "\n  \n"):
            s = FakeSystem()
            s.unit_paths_out = blank
            self.incomplete(s)

    def test_unit_paths_one_malformed_line_among_valid_ones(self):
        s = FakeSystem()
        s.local("x.service")
        s.unit_paths_out = "\n".join(UNIT_PATHS) + "\nrelative/dir\n"
        out = self.incomplete(s)
        self.assertEqual(out["units"], [])

    def test_malformed_list_unit_files_record(self):
        s = FakeSystem()
        s.local("x.service")
        s.files_out = "x.service static enabled\nthis is not a unit record\n"
        out = self.incomplete(s)
        self.assertTrue(any("list-unit-files: malformed" in r for r in out["incomplete"]))

    def test_short_list_units_record(self):
        s = FakeSystem()
        s.local("x.service")
        s.units_out = "x.service loaded\n"
        self.incomplete(s)

    def test_a_record_naming_another_unit_type_is_malformed(self):
        s = FakeSystem()
        s.files_out = "multi-user.target static -\n"
        self.incomplete(s)

    def test_empty_unit_lists_stay_legitimate(self):
        s = FakeSystem()
        s.files_out = ""
        s.units_out = ""
        out = uc.classify(s, claims())
        self.assertEqual(out["summary"], {"row_type": "domain_coverage", "domain": "supervision", "extra_scan": "complete",
                                          "extra_entries": 0, "two_writers": 0, "unmet_absence": 0})


class Bounded(unittest.TestCase):
    def test_a_hung_command_times_out_as_a_failed_command(self):
        import stat
        import tempfile
        import time
        with tempfile.TemporaryDirectory() as d:
            exe = os.path.join(d, "systemctl")
            with open(exe, "w") as f:
                f.write("#!/bin/sh\nexec /bin/sleep 30\n")
            os.chmod(exe, os.stat(exe).st_mode | stat.S_IXUSR)
            t = time.time()
            rc, out, err = uc.Env(path=d, timeout=1).run(["systemctl", "show"])
            self.assertEqual(rc, 124)
            self.assertIn("timed out", err)
            self.assertLess(time.time() - t, 10)

    def test_a_scan_with_a_timing_out_manager_is_incomplete(self):
        class Hung(FakeSystem):
            def _systemctl(self, a):
                return 124, "", "systemctl: timed out after 1s"
        s = Hung()
        s.vendor("a.service", "pkg")
        out = uc.classify(s, claims())
        self.assertEqual(out["summary"]["extra_scan"], "incomplete")
        self.assertNotIn("extra_entries", out["summary"])


class ReadOnly(unittest.TestCase):
    def test_only_allowed_commands_run(self):
        env = uc.Env()
        for bad in (["systemctl", "daemon-reload"], ["systemctl", "start", "x"], ["systemctl", "enable", "x"],
                    ["systemctl", "stop", "x"], ["rm", "-rf", "/"], ["dpkg", "-i", "x.deb"], ["dpkg-query", "-W"]):
            with self.assertRaises(PermissionError):
                env.run(bad)

    def test_whole_scan_only_issues_allowed_commands(self):
        s = FakeSystem()
        s.vendor("ssh.service", "openssh-server", aliases=["sshd.service"])
        s.alias("sshd.service", "ssh.service")
        s.local("x.service")
        uc.classify(s, claims(pkgs=["openssh-server"]))
        for argv in s.commands:
            tool, rest = os.path.basename(argv[0]), tuple(argv[1:])
            self.assertTrue(any(rest[:len(p)] == p for p in uc.ALLOWED_COMMANDS[tool]) or rest[:1] == ("-S",), argv)


class Parsers(unittest.TestCase):
    def test_covers_and_template(self):
        self.assertTrue(uc.covers("getty@.service", "getty@tty1.service"))
        self.assertFalse(uc.covers("getty@.service", "getty@.service.d"))
        self.assertTrue(uc.covers("foo-*", "foo-w@1.service"))
        self.assertFalse(uc.covers("foo.service", "foo.service.x"))
        self.assertEqual(uc.template_of("getty@tty1.service"), "getty@.service")
        self.assertIsNone(uc.template_of("getty@.service"))

    def test_dash_dirs(self):
        self.assertEqual(uc.dir_variants("foo-bar-baz.service"),
                         ["foo-bar-baz.service.d", "foo-bar-.service.d", "foo-.service.d"])

    def test_alias_from_cat_includes_dropins_and_reset(self):
        txt = "# /a\n[Install]\nAlias=a.service b.service\n# /d\n[Install]\nAlias=c.service\n"
        self.assertEqual(uc.alias_names_from_cat(txt), ["a.service", "b.service", "c.service"])
        self.assertEqual(uc.alias_names_from_cat(txt + "[Install]\nAlias=\nAlias=z.service\n"), ["z.service"])
        self.assertEqual(uc.alias_names_from_cat("[Service]\nAlias=nope.service\n"), [])

    def test_alias_only_from_dropin_dirs_enable_acts_on(self):
        txt = ("# /usr/lib/systemd/system/x-y.service\n[Install]\nAlias=frag.service\n"
               "# /etc/systemd/system/x-y.service.d/a.conf\n[Install]\nAlias=own.service\n"
               "# /etc/systemd/system/x-.service.d/b.conf\n[Install]\nAlias=dash.service\n"
               "# /etc/systemd/system/service.d/c.conf\n[Install]\nAlias=type.service\n"
               "# /etc/systemd/system/x@.service.d/d.conf\n[Install]\nAlias=tpl.service\n")
        self.assertEqual(uc.alias_names_from_cat(txt, {"x-y.service.d", "x@.service.d"}),
                         ["frag.service", "own.service", "tpl.service"])
        self.assertEqual(len(uc.alias_names_from_cat(txt)), 5)

    def test_glob_escape(self):
        self.assertEqual(uc.glob_escape("/a/b\\x2d[1]*?"), "/a/b\\\\x2d\\[1]\\*\\?")


if __name__ == "__main__":
    unittest.main()
