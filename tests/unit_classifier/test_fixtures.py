"""Every row of the "S1 fixtures" table (schema-v5-dpkg-reconciliation-2026-11-02.md
section 6) against a real systemd manager and real dpkg-query, one independent
test per row (or per variant of a row). Each test builds its own files and its own
dpkg database, and tears both down, whatever the outcome.

Gated like policy check 6: Linux booted by systemd, root, TENDCF_TEST_SYSTEMD=1.

    sudo -E env TENDCF_TEST_SYSTEMD=1 python3 -m unittest discover -s tests/unit_classifier -p test_fixtures.py -v

What is real here: the manager (list-unit-files, show, cat, unit-paths, drop-in
resolution, aliases, masks, generators, transient units) and dpkg-query's output
forms. What is arranged: ownership. Synthetic packages are added to a private copy
of the host's dpkg database (s1lib.TestDb), never the host database; the real
ssh.service (openssh-server) and the real kmod.service / hwclock.service are
used where the row names them. Where a row says getty@ the fixtures use a
synthetic template, tendcf-s1-getty@.service: it is the template semantics that
matter, and the real getty@.service has no instance a fixture can hold loaded
without starting an agetty.

Files are written only under /etc/systemd/system, /run/systemd/system and
/usr/lib/systemd/system, plus /run/systemd/system-generators (a tmpfs directory
beside them) for the rows that need a generated unit. The private dpkg database
lives under /var/tmp.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from s1lib import CLASSIFIER, Sandbox, TestDb, daemon_reload, sh  # noqa: E402

U = "/usr/lib/systemd/system"
E = "/etc/systemd/system"
R = "/run/systemd/system"
GEN = "/run/systemd/system-generators"
SVC = "[Unit]\nDescription=tendcf s1 fixture\n[Service]\nExecStart=/bin/true\n"
TPL = "[Unit]\nDescription=tendcf s1 template\n[Service]\nExecStart=/bin/sleep 600\n"

GATE = (sys.platform.startswith("linux") and os.geteuid() == 0 and os.environ.get("TENDCF_TEST_SYSTEMD") == "1"
        and os.path.isdir("/run/systemd/system"))
SKIP = "skip systemd fixtures: Linux booted by systemd, root and TENDCF_TEST_SYSTEMD=1 required (they write /etc/systemd/system)"


def claims_doc(pkgs=(), writers=None, services=None, others=None, coverage="comprehensive", supervisor="systemd"):
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
    doc["domains"].update(others or {})
    return doc


@unittest.skipUnless(GATE, SKIP)
class Fixture(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox(extra_roots=(GEN,))
        self.sb.__enter__()
        self.db = TestDb()
        self.tmp = tempfile.mkdtemp(prefix="tendcf-s1-run-", dir="/var/tmp")
        self.addCleanup(self._teardown)
        self.cleanups = []

    def _teardown(self):
        for fn in reversed(self.cleanups):
            fn()
        self.sb.__exit__(None, None, None)
        self.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- arranging
    def reload(self):
        daemon_reload()

    def vendor(self, name, pkg, d=U, content=SVC, files=(), multiarch=None, record_as=None):
        """A packaged fragment: the file, plus a synthetic package owning it."""
        path = "%s/%s" % (d, name)
        self.sb.write(path, content)
        self.db.add_package(pkg, [record_as or path] + list(files), multiarch=multiarch)
        return path

    def local(self, name, d=E, content=SVC):
        return self.sb.write("%s/%s" % (d, name), content)

    def dropin(self, unit, fname="tendcf-s1.conf", d=E, sub=None, content="[Service]\nEnvironment=TENDCF_S1=1\n"):
        return self.sb.write("%s/%s.d/%s" % (d, sub or unit, fname), content)

    def real_owner(self, path):
        """The package the host database names for a path that must exist."""
        self.assertTrue(os.path.lexists(path), "%s missing on this runner (the CI step installs openssh-server)" % path)
        r = self.db.query(path)
        self.assertEqual(r.returncode, 0, "%s unowned in the host database: %s" % (path, r.stderr))
        return r.stdout.split(": ")[0].split(", ")[0].split(":")[0]

    def generate(self, units, tag="gen"):
        """Units from a generator of our own; units: {name: SourcePath or None}.
        daemon-reload re-runs generators, so the units survive it."""
        body = "#!/bin/sh\n"
        for name, src in units.items():
            body += "cat > \"$1/%s\" <<'EOF'\n[Unit]\nDescription=tendcf s1 generated\n%s[Service]\nExecStart=/bin/true\nEOF\n" % (
                name, ("SourcePath=%s\n" % src) if src else "")
        self.sb.write("%s/tendcf-s1-%s-%s" % (GEN, tag, self.id().rsplit(".", 1)[-1][-24:].replace("_", "-")), body, mode=0o755)

    # ---- running
    def classify(self, doc, admindir=True, env=None, argv_prefix=()):
        path = os.path.join(self.tmp, "claims.json")
        with open(path, "w") as f:
            json.dump(doc, f)
        argv = list(argv_prefix) + [sys.executable, CLASSIFIER, "--claims", path]
        if admindir:
            argv += ["--dpkg-admindir", self.db.dir]
        r = subprocess.run(argv, capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, "classifier failed: %s" % r.stderr[-2000:])
        return json.loads(r.stdout)

    def unit(self, res, name):
        hit = [u for u in res["units"] if name in u["names"]]
        self.assertEqual(len(hit), 1, "%s: expected exactly one unit record, got %d (counted once). incomplete=%s"
                         % (name, len(hit), res["incomplete"][:5]))
        return hit[0]

    def expect(self, doc, name, verdict, **kw):
        res = self.classify(doc, **kw)
        u = self.unit(res, name)
        self.assertEqual(u["verdict"], verdict, "%s: %s\nrule %s: %s\nartifacts: %s\nscan: %s %s" % (
            name, u["verdict"], u["rule"], u["why"], json.dumps(u["artifacts"], indent=1), res["summary"], res["incomplete"][:5]))
        return res

    def alias_link(self, link, target, d=E):
        return self.sb.symlink("%s/%s" % (d, link), target)

    def wants(self, instance, template):
        """Reach an instance through a .wants link of a loaded target, so the manager
        keeps it loaded without starting it (list-units --all lists it)."""
        return self.sb.symlink("%s/multi-user.target.wants/%s" % (E, instance), "%s/%s" % (U, template))


class Baseline(Fixture):
    def test_clean_host_scan_is_complete_with_no_claims(self):
        """No fixture, no claims: the scan completes, or is incomplete only for the stock
        generated units below. Anything else would silently weaken the assertions that follow."""
        res = self.classify(claims_doc())
        # Observed (S1): ubuntu 26.04 ships generators (netplan, sshd-socket) whose units carry no
        # SourcePath, which the contract makes unverifiable; any other reason is a runner anomaly.
        stock = [r for r in res["incomplete"] if "generated unit with empty SourcePath" in r]
        self.assertEqual(res["incomplete"], stock, "unexpected incomplete reasons")
        if not res["incomplete"]:
            self.assertEqual(res["summary"]["extra_scan"], "complete")
            self.assertEqual(res["summary"]["unmet_absence"], 0)
        else:
            self.assertEqual(res["summary"], {"row_type": "domain_coverage", "domain": "supervision", "extra_scan": "incomplete"})


class Ownership(Fixture):
    def test_rogue_etc_unit_no_claim_is_extra(self):
        self.local("systemd-rogue.service")
        self.reload()
        self.expect(claims_doc(), "systemd-rogue.service", "extra")

    def test_unowned_file_in_vendor_dir_no_claim_is_extra(self):
        self.local("tendcf-s1-stray.service", d=U)
        self.reload()
        self.expect(claims_doc(), "tendcf-s1-stray.service", "extra")

    def test_unit_of_undeclared_package_is_extra(self):
        self.vendor("tendcf-s1-und.service", "tendcf-s1-undeclared")
        self.reload()
        self.expect(claims_doc(), "tendcf-s1-und.service", "extra")

    def test_undeclared_coowner_is_extra_and_both_declared_is_clean(self):
        p = self.vendor("tendcf-s1-co.service", "tendcf-s1-co-a")
        self.db.add_package("tendcf-s1-co-b", [p])
        self.reload()
        self.expect(claims_doc(pkgs=["tendcf-s1-co-a"]), "tendcf-s1-co.service", "extra")
        self.expect(claims_doc(pkgs=["tendcf-s1-co-a", "tendcf-s1-co-b"]), "tendcf-s1-co.service", "clean")

    def test_declared_package_fragment_only_is_clean(self):
        self.vendor("tendcf-s1-ok.service", "tendcf-s1-ok")
        self.reload()
        self.expect(claims_doc(pkgs=["tendcf-s1-ok"]), "tendcf-s1-ok.service", "clean")

    def test_real_ssh_service_declared_is_clean(self):
        pkg = self.real_owner(U + "/ssh.service")
        self.expect(claims_doc(pkgs=[pkg]), "ssh.service", "clean")

    def test_owner_recorded_under_lib_only_is_package_tier(self):
        self.vendor("tendcf-s1-libonly.service", "tendcf-s1-libonly", record_as="/lib/systemd/system/tendcf-s1-libonly.service")
        self.reload()
        self.assertEqual(os.path.realpath("/lib"), "/usr/lib", "this runner has no /lib -> usr/lib merge")
        self.assertEqual(self.db.query(U + "/tendcf-s1-libonly.service").returncode, 1, "precondition: the /usr/lib spelling alone misses")
        self.expect(claims_doc(pkgs=["tendcf-s1-libonly"]), "tendcf-s1-libonly.service", "clean")
        self.expect(claims_doc(), "tendcf-s1-libonly.service", "extra")

    def test_successful_lookup_with_no_owner_is_name_tier_not_a_failure(self):
        self.local("tendcf-s1-noowner.service", d=U)
        self.reload()
        self.expect(claims_doc(writers={"tendcf-s1-noowner.service": "third-party"}), "tendcf-s1-noowner.service", "clean")

    def test_architecture_qualified_owner_maps_to_the_package(self):
        p = self.vendor("tendcf-s1-arch.service", "tendcf-s1-arch", multiarch="same")
        self.reload()
        raw = self.db.query(p).stdout
        self.assertIn("tendcf-s1-arch:%s:" % self.db.arch, raw, "precondition: dpkg-query prints the qualifier")
        res = self.expect(claims_doc(pkgs=["tendcf-s1-arch"]), "tendcf-s1-arch.service", "clean")
        owners = [a["owners_raw"] for a in self.unit(res, "tendcf-s1-arch.service")["artifacts"]]
        self.assertIn(["tendcf-s1-arch:%s" % self.db.arch], owners)

    def test_vendor_symlink_to_target_outside_the_tree(self):
        tgt = self.sb.write("%s/tendcf-s1-ext/tendcf-s1-ext.service" % R, SVC)
        link = self.sb.symlink(U + "/tendcf-s1-ext.service", tgt)
        self.db.add_package("tendcf-s1-ext", [link])
        self.reload()
        self.expect(claims_doc(pkgs=["tendcf-s1-ext"]), "tendcf-s1-ext.service", "extra")
        self.expect(claims_doc(pkgs=["tendcf-s1-ext"], writers={"tendcf-s1-ext.service": "third-party"}),
                    "tendcf-s1-ext.service", "clean")

    def test_a_diversion_on_the_path_is_incomplete(self):
        p = self.vendor("tendcf-s1-div.service", "tendcf-s1-div")
        self.db.add_diversion(p, p + ".distrib")
        self.reload()
        res = self.expect(claims_doc(pkgs=["tendcf-s1-div"]), "tendcf-s1-div.service", "incomplete")
        self.assertEqual(res["summary"], {"row_type": "domain_coverage", "domain": "supervision", "extra_scan": "incomplete"})


class Aliases(Fixture):
    def ssh_alias(self):
        pkg = self.real_owner(U + "/ssh.service")
        self.alias_link("sshd.service", U + "/ssh.service")
        self.reload()
        return pkg

    def test_enable_created_alias_authorized_by_target_alias_clean_counted_once(self):
        pkg = self.ssh_alias()
        res = self.expect(claims_doc(pkgs=[pkg]), "sshd.service", "clean")
        self.assertEqual(len([u for u in res["units"] if "ssh.service" in u["names"]]), 1)
        self.assertEqual(self.unit(res, "ssh.service")["id"], "ssh.service")

    def test_alias_authorized_by_dropin_on_the_target_is_clean(self):
        self.vendor("tendcf-s1-adrop.service", "tendcf-s1-adrop")
        self.dropin("tendcf-s1-adrop.service", content="[Install]\nAlias=tendcf-s1-adrop-link.service\n")
        self.alias_link("tendcf-s1-adrop-link.service", U + "/tendcf-s1-adrop.service")
        self.reload()
        self.expect(claims_doc(pkgs=["tendcf-s1-adrop"], writers={"tendcf-s1-adrop.service": "third-party"}),
                    "tendcf-s1-adrop-link.service", "clean")

    def test_alias_named_only_by_a_dash_truncated_dropin_is_not_authorized(self):
        """S1 observation (spec 3.5 item 9): `systemctl cat` prints that Alias=, `systemctl enable`
        does not act on it, so the link is hand-made and extra."""
        self.vendor("tendcfs1dash-x.service", "tendcfs1dash")
        self.dropin("tendcfs1dash-x.service", fname="a.conf", sub="tendcfs1dash-.service", content="[Install]\nAlias=tendcfs1dash-link.service\n")
        self.alias_link("tendcfs1dash-link.service", U + "/tendcfs1dash-x.service")
        self.reload()
        cat = sh(["systemctl", "cat", "tendcfs1dash-x.service"]).stdout
        self.assertIn("Alias=tendcfs1dash-link.service", cat, "precondition: cat prints it")
        # the exact claim licenses the local drop-in, so the alias link is the only finding
        self.expect(claims_doc(pkgs=["tendcfs1dash"], writers={"tendcfs1dash-x.service": "third-party"}),
                    "tendcfs1dash-link.service", "extra")

    def test_cfengine_claim_on_the_alias_name_over_a_vendor_fragment_is_two_writers(self):
        pkg = self.ssh_alias()
        self.expect(claims_doc(pkgs=[pkg], writers={"sshd.service": "cfengine"}, services={"sshd.service": "present"}),
                    "ssh.service", "two-writers")

    def test_shipped_alias_and_shipped_mask_real_kmod_and_hwclock_are_clean(self):
        pkgs = set()
        for n in ("kmod.service", "hwclock.service"):
            self.assertTrue(os.path.islink(U + "/" + n), "%s is not a shipped link on this runner" % n)
            pkgs.add(self.real_owner(U + "/" + n))
        tgt = os.readlink(U + "/kmod.service")
        pkgs.add(self.real_owner(os.path.join(U, tgt)))
        self.assertEqual(os.readlink(U + "/hwclock.service"), "/dev/null")
        doc = claims_doc(pkgs=sorted(pkgs))
        self.expect(doc, "kmod.service", "clean")
        self.expect(doc, "hwclock.service", "clean")

    def test_shipped_alias_and_shipped_mask_synthetic_are_clean(self):
        self.vendor("tendcf-s1-shiptarget.service", "tendcf-s1-ship")
        link = self.sb.symlink(U + "/tendcf-s1-shipalias.service", "tendcf-s1-shiptarget.service")
        mask = self.sb.symlink(U + "/tendcf-s1-shipmask.service", "/dev/null")
        self.db.add_package("tendcf-s1-shiplinks", [link, mask])
        self.reload()
        doc = claims_doc(pkgs=["tendcf-s1-ship", "tendcf-s1-shiplinks"])
        self.expect(doc, "tendcf-s1-shipalias.service", "clean")
        self.expect(doc, "tendcf-s1-shipmask.service", "clean")
        self.expect(claims_doc(pkgs=["tendcf-s1-ship"]), "tendcf-s1-shipmask.service", "extra")

    def _evil(self, writers):
        pkg = self.real_owner(U + "/ssh.service")
        self.alias_link("tendcf-s1-evil.service", U + "/ssh.service")
        self.reload()
        self.expect(claims_doc(pkgs=[pkg], writers=writers), "tendcf-s1-evil.service", "extra")

    def test_hand_made_alias_to_ssh_no_claim_is_extra(self):
        self._evil(None)

    def test_hand_made_alias_to_ssh_exact_third_party_is_still_extra(self):
        self._evil({"tendcf-s1-evil.service": "third-party"})


class Layers(Fixture):
    def test_local_dropin_on_ssh_no_claim_is_two_writers(self):
        pkg = self.real_owner(U + "/ssh.service")
        self.dropin("ssh.service")
        self.reload()
        self.expect(claims_doc(pkgs=[pkg]), "ssh.service", "two-writers")

    def test_local_dropin_on_ssh_exact_third_party_is_clean(self):
        pkg = self.real_owner(U + "/ssh.service")
        self.dropin("ssh.service")
        self.reload()
        self.expect(claims_doc(pkgs=[pkg], writers={"ssh.service": "third-party"}), "ssh.service", "clean")

    def _dash(self, writers, verdict):
        self.vendor("tendcf-s1-dash-bar.service", "tendcf-s1-dash")
        self.dropin("tendcf-s1-dash-bar.service", sub="tendcf-s1-dash-.service")
        self.reload()
        self.expect(claims_doc(pkgs=["tendcf-s1-dash"], writers=writers), "tendcf-s1-dash-bar.service", verdict)

    def test_dash_truncated_dropin_no_claim_is_two_writers(self):
        self._dash(None, "two-writers")

    def test_dash_truncated_dropin_exact_third_party_is_clean(self):
        self._dash({"tendcf-s1-dash-bar.service": "third-party"}, "clean")

    def _zhm(self, writers, verdict):
        self.db.add_package("tendcf-s1-zhm", ["/etc/init.d/tendcf-s1-zhm"])
        self.generate({"tendcf-s1-zhm.service": "/etc/init.d/tendcf-s1-zhm"})
        self.dropin("tendcf-s1-zhm.service")
        self.reload()
        self.expect(claims_doc(pkgs=["tendcf-s1-zhm"], writers=writers), "tendcf-s1-zhm.service", verdict)

    def test_dropin_on_generated_unit_from_owned_source_no_claim_is_two_writers(self):
        self._zhm(None, "two-writers")

    def test_dropin_on_generated_unit_from_owned_source_exact_third_party_is_clean(self):
        self._zhm({"tendcf-s1-zhm.service": "third-party"}, "clean")

    def _mask(self, d, writers, services, verdict):
        pkg = self.real_owner(U + "/ssh.service")
        self.sb.symlink("%s/ssh.service" % d, "/dev/null")
        self.reload()
        self.assertEqual(sh(["systemctl", "show", "-p", "LoadState", "--value", "ssh.service"]).stdout.strip(), "masked")
        self.expect(claims_doc(pkgs=[pkg], writers=writers, services=services), "ssh.service", verdict)

    def test_persistent_mask_no_claim_is_two_writers(self):
        self._mask(E, None, None, "two-writers")

    def test_persistent_mask_exact_third_party_is_clean(self):
        self._mask(E, {"ssh.service": "third-party"}, None, "clean")

    def test_persistent_mask_cfengine_claim_is_two_writers(self):
        self._mask(E, {"ssh.service": "cfengine"}, {"ssh.service": "present"}, "two-writers")

    def test_runtime_mask_no_claim_is_two_writers(self):
        self._mask(R, None, None, "two-writers")

    def test_runtime_mask_exact_third_party_is_clean(self):
        self._mask(R, {"ssh.service": "third-party"}, None, "clean")

    def test_runtime_mask_cfengine_claim_is_two_writers(self):
        self._mask(R, {"ssh.service": "cfengine"}, {"ssh.service": "present"}, "two-writers")

    def test_package_shipped_dropin_under_etc_declared_is_clean(self):
        d = E + "/tendcf-s1-shipdrop.service.d/shipped.conf"
        self.vendor("tendcf-s1-shipdrop.service", "tendcf-s1-shipdrop", files=[d])
        self.dropin("tendcf-s1-shipdrop.service", fname="shipped.conf")
        self.reload()
        self.expect(claims_doc(pkgs=["tendcf-s1-shipdrop"]), "tendcf-s1-shipdrop.service", "clean")

    def test_local_copy_of_ssh_in_etc_exact_third_party_is_two_writers(self):
        pkg = self.real_owner(U + "/ssh.service")
        self.local("ssh.service", content=open(U + "/ssh.service").read())
        self.reload()
        self.expect(claims_doc(pkgs=[pkg], writers={"ssh.service": "third-party"}), "ssh.service", "two-writers")

    def test_type_wide_dropin_lands_on_every_unit_item_6(self):
        pkg = self.real_owner(U + "/ssh.service")
        self.sb.write(E + "/service.d/tendcf-s1-typewide.conf", "[Service]\nEnvironment=TENDCF_S1_TYPEWIDE=1\n")
        self.reload()
        res = self.expect(claims_doc(pkgs=[pkg]), "ssh.service", "two-writers")
        loud = [u["id"] for u in res["units"] if u["verdict"] == "two-writers"]
        self.assertGreater(len(loud), 5, "a type-wide drop-in must be loud on many units, got %s" % loud)


class Instances(Fixture):
    """Template semantics with a synthetic tendcf-s1-getty@.service (see module docstring)."""

    def template(self):
        self.vendor("tendcf-s1-getty@.service", "tendcf-s1-getty", content=TPL)

    def instance_dropin(self, writers, verdict):
        self.template()
        self.wants("tendcf-s1-getty@tty1.service", "tendcf-s1-getty@.service")
        self.dropin("tendcf-s1-getty@tty1.service")
        self.reload()
        self.expect(claims_doc(pkgs=["tendcf-s1-getty"], writers=writers), "tendcf-s1-getty@tty1.service", verdict)

    def test_instance_dropin_no_claim_is_two_writers(self):
        self.instance_dropin(None, "two-writers")

    def test_instance_dropin_exact_template_third_party_is_clean(self):
        self.instance_dropin({"tendcf-s1-getty@.service": "third-party"}, "clean")

    def test_local_instance_fragment_under_template_third_party_is_two_writers(self):
        self.template()
        self.local("tendcf-s1-getty@tty1.service", content=TPL)
        self.reload()
        self.expect(claims_doc(pkgs=["tendcf-s1-getty"], writers={"tendcf-s1-getty@.service": "third-party"}),
                    "tendcf-s1-getty@tty1.service", "two-writers")

    def _imask(self, d, writers, services, verdict):
        self.template()
        self.sb.symlink("%s/tendcf-s1-getty@tty1.service" % d, "/dev/null")
        self.reload()
        self.expect(claims_doc(pkgs=["tendcf-s1-getty"], writers=writers, services=services),
                    "tendcf-s1-getty@tty1.service", verdict)

    def test_persistent_instance_mask_no_claim_is_two_writers(self):
        self._imask(E, None, None, "two-writers")

    def test_persistent_instance_mask_template_third_party_is_clean(self):
        self._imask(E, {"tendcf-s1-getty@.service": "third-party"}, None, "clean")

    def test_persistent_instance_mask_covering_cfengine_claim_is_two_writers(self):
        self._imask(E, {"tendcf-s1-*": "cfengine"}, {"tendcf-s1-getty@tty1.service": "present"}, "two-writers")

    def test_runtime_instance_mask_no_claim_is_two_writers(self):
        self._imask(R, None, None, "two-writers")

    def test_runtime_instance_mask_template_third_party_is_clean(self):
        self._imask(R, {"tendcf-s1-getty@.service": "third-party"}, None, "clean")

    def test_runtime_instance_mask_covering_cfengine_claim_is_two_writers(self):
        self._imask(R, {"tendcf-s1-*": "cfengine"}, {"tendcf-s1-getty@tty1.service": "present"}, "two-writers")


class Claims(Fixture):
    def test_cfengine_claim_and_present_service_on_ssh_no_local_file_is_two_writers(self):
        pkg = self.real_owner(U + "/ssh.service")
        self.expect(claims_doc(pkgs=[pkg], writers={"ssh.service": "cfengine"}, services={"ssh.service": "present"}),
                    "ssh.service", "two-writers")

    def test_tombstone_with_surviving_regular_file_is_unmet_absence(self):
        self.local("tendcf-s1-tomb.service")
        self.reload()
        res = self.expect(claims_doc(writers={"tendcf-s1-tomb.service": "cfengine"}, services={"tendcf-s1-tomb.service": "absent"}),
                          "tendcf-s1-tomb.service", "unmet-absence")
        if res["summary"]["extra_scan"] == "complete":
            self.assertEqual(res["summary"]["unmet_absence"], 1)

    def test_claim_only_in_a_not_yet_migrated_domain_is_clean(self):
        self.local("tendcf-s1-nym.service")
        self.reload()
        other = {"other": {"coverage": "not-yet-migrated",
                           "entries": {"unit-writer": {"tendcf-s1-nym.service": {"state": "present", "writer": "third-party"}}}}}
        self.expect(claims_doc(others=other), "tendcf-s1-nym.service", "clean")

    def test_present_in_supervision_and_tombstone_in_another_domain_is_incomplete_naming_both(self):
        self.local("tendcf-s1-conflict.service")
        self.reload()
        other = {"other": {"coverage": "not-yet-migrated", "entries": {"service": {"tendcf-s1-conflict.service": {"state": "absent"}}}}}
        res = self.expect(claims_doc(writers={"tendcf-s1-conflict.service": "cfengine"}, services={"tendcf-s1-conflict.service": "present"},
                                     others=other), "tendcf-s1-conflict.service", "incomplete")
        self.assertEqual(res["summary"], {"row_type": "domain_coverage", "domain": "supervision", "extra_scan": "incomplete"})
        self.assertEqual(res["conflicts"], [{"id": "tendcf-s1-conflict.service", "addresses": [
            "other/service/tendcf-s1-conflict.service=absent", "supervision/service/tendcf-s1-conflict.service=present"]}])
        joined = " ".join(res["incomplete"])
        self.assertIn("other/service/tendcf-s1-conflict.service=absent", joined)
        self.assertIn("supervision/service/tendcf-s1-conflict.service=present", joined)

    def test_supervision_not_comprehensive_is_not_run(self):
        self.local("tendcf-s1-nr.service")
        self.reload()
        res = self.classify(claims_doc(coverage="not-yet-migrated"))
        self.assertEqual(res["summary"], {"row_type": "domain_coverage", "domain": "supervision", "extra_scan": "not-run"})
        self.assertEqual(res["units"], [])


class Generated(Fixture):
    def test_generated_unit_from_owned_source_declared_is_clean(self):
        self.db.add_package("tendcf-s1-genpkg", ["/etc/init.d/tendcf-s1-gen"])
        self.generate({"tendcf-s1-gen.service": "/etc/init.d/tendcf-s1-gen"})
        self.reload()
        self.expect(claims_doc(pkgs=["tendcf-s1-genpkg"]), "tendcf-s1-gen.service", "clean")

    def test_generated_unit_from_owned_source_undeclared_is_extra(self):
        self.db.add_package("tendcf-s1-genpkg", ["/etc/init.d/tendcf-s1-gen"])
        self.generate({"tendcf-s1-gen.service": "/etc/init.d/tendcf-s1-gen"})
        self.reload()
        self.expect(claims_doc(), "tendcf-s1-gen.service", "extra")

    def test_generated_unit_with_empty_sourcepath_is_incomplete(self):
        self.generate({"tendcf-s1-gen-nosrc.service": None})
        self.reload()
        res = self.expect(claims_doc(), "tendcf-s1-gen-nosrc.service", "incomplete")
        self.assertEqual(res["summary"], {"row_type": "domain_coverage", "domain": "supervision", "extra_scan": "incomplete"})


class Transient(Fixture):
    def test_systemd_run_transient_unit_is_not_judged(self):
        self.cleanups.append(lambda: (sh(["systemctl", "stop", "tendcf-s1-trans.service"]),
                                      sh(["systemctl", "reset-failed", "tendcf-s1-trans.service"])))
        r = sh(["systemd-run", "--unit=tendcf-s1-trans", "--remain-after-exit", "--collect", "/bin/true"])
        self.assertEqual(r.returncode, 0, r.stderr)
        show = sh(["systemctl", "show", "-p", "Transient", "--value", "tendcf-s1-trans.service"]).stdout.strip()
        self.assertEqual(show, "yes", "precondition")
        listed = sh(["systemctl", "list-unit-files", "--no-legend", "tendcf-s1-trans*"]).stdout
        self.assertIn("tendcf-s1-trans.service", listed, "observed: list-unit-files does list a transient unit")
        res = self.classify(claims_doc())
        self.assertFalse([u for u in res["units"] if "tendcf-s1-trans.service" in u["names"]])


class Gates(Fixture):
    def test_dpkg_query_removed_from_path_is_incomplete_without_counts(self):
        self.local("tendcf-s1-nopath.service")
        self.reload()
        bindir = os.path.join(self.tmp, "bin")
        os.mkdir(bindir)
        for t in ("systemctl", "systemd-analyze"):
            os.symlink(shutil.which(t), os.path.join(bindir, t))
        self.assertIsNone(shutil.which("dpkg-query", path=bindir))
        res = self.classify(claims_doc(), admindir=False, env={"PATH": bindir})
        self.assertEqual(res["summary"], {"row_type": "domain_coverage", "domain": "supervision", "extra_scan": "incomplete"})
        self.assertTrue(any("dpkg" in r for r in res["incomplete"]), res["incomplete"])

    def test_unusable_dpkg_database_is_incomplete_not_zero_owners(self):
        """Observed: dpkg-query -S on a missing admindir exits 1 'no path found'. Without a
        positive control every unit would look unowned and the scan would report extras."""
        self.local("tendcf-s1-emptydb.service")
        self.reload()
        os.mkdir(os.path.join(self.tmp, "emptydb"))
        path = os.path.join(self.tmp, "claims.json")
        with open(path, "w") as f:
            json.dump(claims_doc(), f)
        for adm in (os.path.join(self.tmp, "does-not-exist"), os.path.join(self.tmp, "emptydb")):
            r = subprocess.run([sys.executable, CLASSIFIER, "--claims", path, "--dpkg-admindir", adm], capture_output=True, text=True)
            res = json.loads(r.stdout)
            self.assertEqual(res["summary"]["extra_scan"], "incomplete", adm)
            self.assertNotIn("extra_entries", res["summary"])

    def test_no_run_systemd_system_is_incomplete_without_counts(self):
        """A private mount namespace with a tmpfs over /run/systemd: /run/systemd/system is absent
        for the classifier only; the real manager is untouched."""
        self.local("tendcf-s1-nomgr.service")
        self.reload()
        path = os.path.join(self.tmp, "claims.json")
        with open(path, "w") as f:
            json.dump(claims_doc(), f)
        cmd = "mount -t tmpfs tendcf-s1 /run/systemd && test ! -e /run/systemd/system && exec %s %s --claims %s --dpkg-admindir %s" % (
            sys.executable, CLASSIFIER, path, self.db.dir)
        r = subprocess.run(["unshare", "-m", "sh", "-c", cmd], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        res = json.loads(r.stdout)
        self.assertEqual(res["summary"], {"row_type": "domain_coverage", "domain": "supervision", "extra_scan": "incomplete"})
        self.assertTrue(os.path.isdir("/run/systemd/system"), "the host's /run/systemd must be untouched")


class ReadOnly(Fixture):
    def test_a_scan_changes_nothing_on_disk_or_in_the_manager(self):
        pkg = self.real_owner(U + "/ssh.service")
        self.alias_link("sshd.service", U + "/ssh.service")
        self.dropin("ssh.service")
        self.reload()

        def state():
            # Every path under the unit directories with type, link target, mtime and size.
            return sh(["sh", "-c", "find /etc/systemd/system /run/systemd/system /usr/lib/systemd/system "
                       "-printf '%p %y %l %T@ %s\\n' | sort"]).stdout

        before = state()
        res = self.classify(claims_doc(pkgs=[pkg]))
        self.assertTrue(res["units"])
        self.assertEqual(state(), before)


if __name__ == "__main__":
    unittest.main()
