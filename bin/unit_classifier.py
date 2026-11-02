#!/usr/bin/env python3
"""Read-only prototype of the v5 unit-namespace classifier (S1).

Implements the detector contract of
docs/architecture/schema-v5-dpkg-reconciliation-2026-11-02.md section 3 so that
section 3.5's behaviours and the section 6 fixtures can be proven on a real
systemd host before slice S2 freezes the schema. It is a prototype of the
detector, not the detector: nothing here is wired into the policy bundle.

Input: a JSON file in the goal-file shape (section 2.1): ``domains.<d>.coverage``
and ``domains.<d>.entries`` carrying ``unit-writer``, ``unit-package``,
``service`` and the host ``supervisor``. No schema is validated; S2 owns that.

Output (stdout): one JSON object: ``summary`` (a section 2.3(2) report-row
fragment: ``extra_scan`` plus the three counters, present only when
``complete``), per-unit ``units`` with verdicts and evidence, and the
``conflicts`` and ``incomplete`` reasons that justify an ``incomplete`` scan.

READ-ONLY, enforced in code: every subprocess goes through ``Env.run``, which
refuses any argv outside ALLOWED_COMMANDS (``systemctl show|cat|list-units|
list-unit-files``, ``systemd-analyze unit-paths``, ``dpkg-query -S``). The
filesystem is only ever ``lstat``ed, ``readlink``ed and listed for the
drop-in directories of a unit's own names (a name lookup, never a walk of a
unit directory). One caveat is inherent in enumerating through the manager:
``systemctl show NAME`` makes the manager load NAME. That is a read for every
purpose of this contract and never starts, stops, enables or reloads anything.

Run on a Debian host without any root:
    bin/unit_classifier.py --claims CLAIMS.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

TYPES = ("service", "socket", "timer", "path")
TYPE_RE = r"(?:service|socket|timer|path)"
TEMPLATE_RE = re.compile(r"^(.+@)\.(" + TYPE_RE + r")$")
INSTANCE_RE = re.compile(r"^(.+@)(.+)\.(" + TYPE_RE + r")$")
UNIT_NAME_RE = re.compile(r"^[^/\s]+\.(?:service|socket|timer|path)$")

SHOW_PROPS = ("Id", "Names", "LoadState", "UnitFileState", "FragmentPath",
              "SourcePath", "DropInPaths", "Transient")

# The only commands this program may run. Prefix match on argv[1:].
ALLOWED_COMMANDS = {
    "systemctl": (("show",), ("cat",), ("list-units",), ("list-unit-files",)),
    "systemd-analyze": (("unit-paths",),),
    "dpkg-query": (("-S",),),
}
GENERATOR_DIR_RE = re.compile(r"^/run/systemd/generator(?:\.early|\.late)?$")
DEV_NULL = "/dev/null"


# --------------------------------------------------------------------------
# Environment: the only door to the host. Tests inject a fake.
# --------------------------------------------------------------------------

class Env:
    """Real host access. Subclass or replace for canned tests."""

    def __init__(self, dpkg_admindir=None, path=None):
        self.dpkg_admindir = dpkg_admindir
        self.path = path if path is not None else os.environ.get("PATH", "")

    # -- commands
    def which(self, tool):
        return shutil.which(tool, path=self.path)

    def run(self, argv):
        tool = os.path.basename(argv[0])
        allowed = ALLOWED_COMMANDS.get(tool)
        if allowed is None:
            raise PermissionError("read-only classifier refuses to run %r" % (argv,))
        rest = tuple(argv[1:])
        if tool == "dpkg-query" and rest[:1] == ("--admindir",):
            rest = rest[2:]
        if not any(rest[:len(p)] == p for p in allowed):
            raise PermissionError("read-only classifier refuses to run %r" % (argv,))
        exe = self.which(tool)
        if exe is None:
            return 127, "", "%s: not found in PATH" % tool
        env = {"LC_ALL": "C", "LANG": "C", "SYSTEMD_COLORS": "0",
               "SYSTEMD_PAGER": "", "PATH": self.path}
        r = subprocess.run([exe] + list(argv[1:]), capture_output=True, text=True,
                           errors="replace", env=env)
        return r.returncode, r.stdout, r.stderr

    # -- filesystem (lstat / readlink / listing only)
    def lstat(self, path):
        """None | ('file',) | ('dir',) | ('link', target) | ('other',)"""
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        except NotADirectoryError:
            return None
        import stat as _s
        if _s.S_ISLNK(st.st_mode):
            return ("link", os.readlink(path))
        if _s.S_ISREG(st.st_mode):
            return ("file",)
        if _s.S_ISDIR(st.st_mode):
            return ("dir",)
        return ("other",)

    def listdir(self, path):
        return sorted(os.listdir(path))

    def realpath(self, path):
        return os.path.realpath(path)

    def manager_up(self):
        return os.path.isdir("/run/systemd/system")


# --------------------------------------------------------------------------
# Claims (section 2.1, 3.1)
# --------------------------------------------------------------------------

def template_of(name):
    m = INSTANCE_RE.match(name)
    if m and not TEMPLATE_RE.match(name):
        return "%s.%s" % (m.group(1), m.group(3))
    return None


def covers(key, name):
    """Section 2.2(1) `covers`, verbatim."""
    if key.endswith("*"):
        return name.startswith(key[:-1])
    if name == key:
        return True
    m = TEMPLATE_RE.match(key)
    if m:
        anchor, suffix = m.group(1), "." + m.group(2)
        return (name.startswith(anchor) and name.endswith(suffix)
                and len(name) > len(anchor) + len(suffix))
    return False


@dataclass
class Claims:
    gate: str                       # "run" | "not-run"
    gate_reason: str = ""
    writers: list = field(default_factory=list)    # (key, writer, domain)
    packages: dict = field(default_factory=dict)   # pkg -> [domain]
    services: list = field(default_factory=list)   # (domain, id, state)

    def covering(self, name):
        return [w for w in self.writers if covers(w[0], name)]

    def conflicts(self):
        """Service ids declared both present and absent (section 3.1)."""
        by_id = {}
        for d, i, s in self.services:
            by_id.setdefault(i, []).append((d, s))
        out = []
        for i, decls in sorted(by_id.items()):
            if len({s for _, s in decls}) > 1:
                out.append({"id": i, "addresses": [
                    "%s/service/%s=%s" % (d, i, s) for d, s in decls]})
        return out


def load_claims(doc):
    domains = doc.get("domains", {}) if isinstance(doc, dict) else {}
    writers, packages, services = [], {}, []
    supervisor = None
    for dname, dom in sorted(domains.items()):
        entries = (dom or {}).get("entries", {})
        for key, ent in (entries.get("unit-writer") or {}).items():
            writers.append((key, (ent or {}).get("writer"), dname))
        for pkg in (entries.get("unit-package") or {}):
            packages.setdefault(pkg, []).append(dname)
        for sid, ent in (entries.get("service") or {}).items():
            services.append((dname, sid, (ent or {}).get("state")))
        sup = (entries.get("supervisor") or {}).get("host")
        if sup:
            supervisor = sup.get("name")
    sv = domains.get("supervision") or {}
    if sv.get("coverage") != "comprehensive":
        return Claims("not-run", "supervision.coverage is not comprehensive",
                      writers, packages, services)
    if supervisor != "systemd":
        return Claims("not-run", "supervisor is not systemd", writers, packages, services)
    return Claims("run", "", writers, packages, services)


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------

@dataclass
class Artifact:
    path: str
    kind: str          # fragment | dropin | mask | alias | target | source
    link_target: str = None
    alias_of: str = None
    authorized: bool = False
    owners: list = None          # [] unowned, None unverifiable
    owners_raw: list = field(default_factory=list)
    problem: str = None
    name: str = None             # lookup name it was found under

    @property
    def unverifiable(self):
        return self.problem is not None

    @property
    def owned(self):
        return bool(self.owners)

    @property
    def local(self):
        return self.owners == [] and self.problem is None


@dataclass
class Unit:
    id: str
    names: set
    lookups: set
    props: dict = field(default_factory=dict)
    template: bool = False
    artifacts: list = field(default_factory=list)
    problems: list = field(default_factory=list)
    verdict: str = None
    rule: int = None
    why: str = ""
    transient: bool = False
    not_found: bool = False


def parse_show(text):
    props = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k] = v
    return props


def parse_unit_list(text):
    """First whitespace token of each non-empty line (list-units / list-unit-files)."""
    out = []
    for line in text.splitlines():
        t = line.split()
        if t:
            out.append((t[0], t[1] if len(t) > 1 else ""))
    return out


def alias_names_from_cat(text):
    """Effective [Install] Alias= (fragment plus drop-ins, as `systemctl cat`
    prints them; an empty assignment resets)."""
    aliases, section = [], None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section == "Install" and "=" in line:
            k, v = line.split("=", 1)
            if k.strip() == "Alias":
                if v.strip() == "":
                    aliases = []
                else:
                    aliases += v.split()
    return aliases


# -- ownership ---------------------------------------------------------------

def glob_escape(path):
    return re.sub(r"([*?\[\\])", r"\\\1", path)


def strip_arch(owner):
    # `pkg:arch` -> pkg. Package names contain no colon (Debian Policy 5.6.1).
    return owner.split(":", 1)[0]


class DpkgUnavailable(Exception):
    pass


def spellings(env, canon_path):
    """Section 3.3: under /usr/lib on a merged host, ask both spellings."""
    out = [canon_path]
    if canon_path.startswith("/usr/lib/") and env.realpath("/lib") == "/usr/lib":
        out.append("/lib/" + canon_path[len("/usr/lib/"):])
    return out


def dpkg_prefix(env):
    argv = ["dpkg-query"]
    if env.dpkg_admindir:
        argv += ["--admindir", env.dpkg_admindir]
    return argv


def dpkg_usable(env):
    if env.which("dpkg-query") is None:
        return False, "dpkg-query not found in PATH"
    rc, out, err = env.run(dpkg_prefix(env) + ["-S", "/nonexistent/tendcf-unit-classifier-probe"])
    if rc == 1 and "no path found matching pattern" in err:
        return True, ""
    return False, "dpkg-query probe rc=%s: %s" % (rc, err.strip()[:200])


NO_MATCH_RE = re.compile(r"^dpkg-query: no path found matching pattern (.+)$")
DIVERSION_RE = re.compile(r"^(?:local diversion|diversion by \S+) (from|to): (/.*)$")


def query_dpkg(env, paths, chunk=200):
    """Return {literal_path: ("owners", [raw owners]) | ("diverted",) | ("unknown", why)}.
    Raises DpkgUnavailable when the database cannot be queried at all."""
    result = {}
    paths = list(dict.fromkeys(paths))
    for i in range(0, len(paths), chunk):
        batch = paths[i:i + chunk]
        esc = {glob_escape(p): p for p in batch}
        rc, out, err = env.run(dpkg_prefix(env) + ["-S"] + list(esc))
        if rc not in (0, 1):
            raise DpkgUnavailable("dpkg-query rc=%s: %s" % (rc, err.strip()[:200]))
        owners, diverted, nomatch = {}, set(), set()
        for line in out.splitlines():
            if not line.strip():
                continue
            m = DIVERSION_RE.match(line)
            if m:
                diverted.add(m.group(2))
                continue
            k = line.find(": /")
            if k < 0:
                raise DpkgUnavailable("unparseable dpkg-query line: %r" % line[:200])
            who = [w.strip() for w in line[:k].split(", ")]
            owners.setdefault(line[k + 2:], []).extend(who)
        for line in err.splitlines():
            m = NO_MATCH_RE.match(line.strip())
            if m:
                nomatch.add(m.group(1))
        for e, p in esc.items():
            if p in diverted or e in diverted:
                result[p] = ("diverted",)
            elif p in owners:
                result[p] = ("owners", owners[p])
            elif e in nomatch or p in nomatch:
                result[p] = ("owners", [])
            else:
                result[p] = ("unknown", "no answer from dpkg-query")
    return result


def resolve_ownership(env, artifacts):
    """Fill owners/problem on each artifact (section 3.3)."""
    canon_to_spell = {a.path: spellings(env, a.path) for a in artifacts}
    lits = [s for sp in canon_to_spell.values() for s in sp]
    res = query_dpkg(env, lits)
    for a in artifacts:
        raw, problem = [], None
        for s in canon_to_spell[a.path]:
            r = res[s]
            if r[0] == "diverted":
                problem = "dpkg diversion on %s" % s
            elif r[0] == "unknown":
                problem = "%s: %s" % (s, r[1])
            else:
                raw += r[1]
        if problem:
            a.problem, a.owners = problem, None
        else:
            a.owners_raw = sorted(set(raw))
            a.owners = sorted({strip_arch(o) for o in raw})


# --------------------------------------------------------------------------
# Enumeration and probe (section 3.2)
# --------------------------------------------------------------------------

def dir_variants(name):
    """Drop-in directory names systemd.unit(5) reads for one unit name."""
    m = re.match(r"^(.*)\.(" + TYPE_RE + r")$", name)
    base, suffix = m.group(1), m.group(2)
    out = [name + ".d"]
    t = template_of(name)
    if t:
        out.append(t + ".d")
    if "@" not in base:
        b = base
        while "-" in b:
            b = b[:b.rindex("-")]
            if b:
                out.append("%s-.%s.d" % (b, suffix))
    return out


def link_final(env, path, limit=10):
    """Follow a link chain by hand. Returns (final_path or None, hits_dev_null)."""
    cur = path
    for _ in range(limit):
        st = env.lstat(cur)
        if st is None:
            return None, False
        if st[0] != "link":
            return cur, cur == DEV_NULL
        tgt = st[1]
        if tgt == DEV_NULL:
            return DEV_NULL, True
        cur = tgt if tgt.startswith("/") else os.path.join(os.path.dirname(cur), tgt)
        cur = os.path.normpath(cur)
        if cur == DEV_NULL:
            return DEV_NULL, True
    return None, False


def canon_path(env, path):
    """Resolve the directory through links, never the last component (3.3)."""
    return os.path.join(env.realpath(os.path.dirname(path)), os.path.basename(path))


class Scan:
    def __init__(self, env, claims):
        self.env, self.claims = env, claims
        self.incomplete = []
        self.units = []
        self.load_path = []

    # ---- manager
    def systemctl(self, *args):
        return self.env.run(["systemctl"] + list(args) + ["--no-pager"])

    def enumerate_names(self):
        types = ",".join(TYPES)
        names = {}
        rc, out, err = self.systemctl("list-unit-files", "--no-legend", "--plain", "--type=" + types)
        if rc != 0:
            self.incomplete.append("list-unit-files failed rc=%s: %s" % (rc, err.strip()[:200]))
        for n, st in parse_unit_list(out):
            if UNIT_NAME_RE.match(n):
                names[n] = st
        rc, out, err = self.systemctl("list-units", "--all", "--no-legend", "--plain", "--type=" + types)
        if rc != 0:
            self.incomplete.append("list-units failed rc=%s: %s" % (rc, err.strip()[:200]))
        for n, _ in parse_unit_list(out):
            if UNIT_NAME_RE.match(n):
                names.setdefault(n, "")
        return names

    def read_load_path(self):
        rc, out, err = self.env.run(["systemd-analyze", "unit-paths"])
        if rc != 0 or not out.strip():
            self.incomplete.append("systemd-analyze unit-paths failed rc=%s: %s" % (rc, err.strip()[:200]))
            return
        seen = set()
        for line in out.splitlines():
            p = line.strip()
            if not p.startswith("/"):
                continue
            real = self.env.realpath(p)
            if real in seen:
                continue
            seen.add(real)
            self.load_path.append(p)

    def show(self, name):
        rc, out, err = self.systemctl("show", "--property=" + ",".join(SHOW_PROPS), "--", name)
        if rc != 0:
            return None, "systemctl show %s rc=%s: %s" % (name, rc, err.strip()[:200])
        return parse_show(out), None

    # ---- build units
    def build_units(self, names):
        groups = {}
        for n in sorted(names):
            if TEMPLATE_RE.match(n):
                u = groups.setdefault(n, Unit(n, {n}, {n}, template=True))
                continue
            props, why = self.show(n)
            if props is None or not props.get("Id"):
                u = groups.setdefault(n, Unit(n, {n}, {n}))
                u.problems.append(why or "show returned no Id")
                continue
            uid = props["Id"]
            u = groups.get(uid)
            if u is None:
                u = groups[uid] = Unit(uid, set(props.get("Names", uid).split()) | {uid}, set(), props)
            else:
                u.names |= set(props.get("Names", "").split())
            u.lookups.add(n)
            if n == uid or not u.props:
                u.props = props
        for u in groups.values():
            u.transient = u.props.get("Transient") == "yes"
            u.not_found = u.props.get("LoadState") == "not-found"
        return [u for u in groups.values() if not u.transient]

    # ---- probe
    def probe(self, u):
        env = self.env
        found = {}  # canonical path -> Artifact

        def add(art):
            c = canon_path(env, art.path)
            art.path = c
            old = found.get(c)
            if old is None or (art.kind in ("alias", "mask") and old.kind == "fragment"):
                found[c] = art
            return found[c]

        look = set(u.names) | set(u.lookups)
        t = template_of(u.id)
        if t:
            look.add(t)
        for d in self.load_path:
            for n in sorted(look):
                p = os.path.join(d, n)
                st = env.lstat(p)
                if st is None or st[0] == "dir":
                    continue
                if st[0] == "file":
                    add(Artifact(p, "fragment", name=n))
                elif st[0] == "link":
                    final, devnull = link_final(env, p)
                    if devnull:
                        add(Artifact(p, "mask", link_target=DEV_NULL, name=n))
                    else:
                        tb = os.path.basename(st[1])
                        if tb != n and UNIT_NAME_RE.match(tb):
                            add(Artifact(p, "alias", link_target=st[1], alias_of=tb, name=n))
                        else:
                            add(Artifact(p, "fragment", link_target=st[1], name=n))
                        if final is not None:
                            add(Artifact(final, "target", name=n))
                else:
                    u.problems.append("unsupported file type at %s" % p)
            dnames = []
            for n in sorted(look):
                dnames += dir_variants(n)
            for suffix in sorted({n.rsplit(".", 1)[1] for n in look}):
                dnames.append(suffix + ".d")
            for dn in dict.fromkeys(dnames):
                dp = os.path.join(d, dn)
                st = env.lstat(dp)
                if st is None or st[0] != "dir":
                    continue
                try:
                    entries = env.listdir(dp)
                except OSError as e:
                    u.problems.append("cannot list %s: %s" % (dp, e))
                    continue
                for e in entries:
                    if not e.endswith(".conf"):
                        continue
                    fp = os.path.join(dp, e)
                    fst = env.lstat(fp)
                    if fst is None or fst[0] == "dir":
                        continue
                    if fst[0] == "link":
                        final, devnull = link_final(env, fp)
                        add(Artifact(fp, "dropin", link_target=fst[1]))
                        if final is not None and not devnull:
                            add(Artifact(final, "target", name=e))
                    else:
                        add(Artifact(fp, "dropin"))
        return found

    def cross_check(self, u, found):
        """FragmentPath and DropInPaths against the probe (section 3.2(4))."""
        env = self.env
        paths_known = {}
        for c, a in found.items():
            paths_known[c] = a
            if a.link_target:
                final, _ = link_final(env, c)
                if final:
                    paths_known[canon_path(env, final)] = a
        fp = u.props.get("FragmentPath", "")
        if fp and fp != DEV_NULL:
            if canon_path(env, fp) not in paths_known:
                u.problems.append("FragmentPath %s not found by the probe" % fp)
        elif not fp and u.props.get("LoadState") not in (None, "not-found", "masked", "error"):
            if u.props.get("UnitFileState") != "generated":
                u.problems.append("loaded unit with empty FragmentPath")
        for dp in u.props.get("DropInPaths", "").split():
            if canon_path(env, dp) not in paths_known:
                u.problems.append("DropInPaths entry %s not found by the probe" % dp)

    def finish_artifacts(self, u, found):
        """Generated units are judged via their SourcePath (R2)."""
        arts = list(found.values())
        generated = (u.props.get("UnitFileState") == "generated"
                     or any(GENERATOR_DIR_RE.match(os.path.dirname(a.path)) for a in arts
                            if a.kind == "fragment"))
        if generated:
            arts = [a for a in arts if not (a.kind == "fragment"
                                            and GENERATOR_DIR_RE.match(os.path.dirname(a.path)))]
            src = u.props.get("SourcePath", "")
            if not src:
                u.problems.append("generated unit with empty SourcePath (unverifiable)")
            else:
                arts.append(Artifact(canon_path(self.env, src), "source"))
        return arts

    # ---- alias authorization
    def authorize_aliases(self, u):
        links = [a for a in u.artifacts if a.kind == "alias" and a.owners == []]
        if not links:
            return
        rc, out, err = self.systemctl("cat", "--", u.id)
        if rc != 0:
            u.problems.append("systemctl cat %s rc=%s: %s" % (u.id, rc, err.strip()[:200]))
            return
        wanted = set(alias_names_from_cat(out))
        for a in links:
            a.authorized = os.path.basename(a.path) in wanted

    # ---- driver
    def run(self):
        env = self.env
        if not env.manager_up():
            self.incomplete.append("manager unreachable (/run/systemd/system absent)")
            return
        ok, why = dpkg_usable(env)
        if not ok:
            self.incomplete.append("dpkg database cannot be queried: " + why)
            return
        self.read_load_path()
        if not self.load_path:
            return
        names = self.enumerate_names()
        units = self.build_units(names)
        probes = {}
        # A unit the manager reports not-found has no fragment to judge; a drop-in
        # directory beside it is an orphan the manager ignores (section 7 item 14).
        units = [u for u in units if not u.not_found]
        for u in units:
            found = self.probe(u)
            if not u.template:
                self.cross_check(u, found)
            probes[u.id] = found
            u.artifacts = self.finish_artifacts(u, found)
        every = [a for u in units for a in u.artifacts]
        try:
            resolve_ownership(env, every)
        except DpkgUnavailable as e:
            self.incomplete.append("dpkg database cannot be queried: %s" % e)
            return
        for u in units:
            for a in u.artifacts:
                if a.problem:
                    u.problems.append("%s: %s" % (a.path, a.problem))
            self.authorize_aliases(u)
        self.units = units


# --------------------------------------------------------------------------
# Verdicts (section 3.4)
# --------------------------------------------------------------------------

def exact_noncf(claims, u):
    """An exact (or template) non-cfengine claim on the unit name. A template
    key counts as exact for its instances (R7)."""
    names = {u.id}
    t = template_of(u.id)
    if t:
        names.add(t)
    for key, writer, dom in claims.writers:
        if writer == "cfengine" or key.endswith("*"):
            continue
        if any(covers(key, n) for n in names):
            return True
    return False


def judge(claims, u, conflict_ids):
    packages = set(claims.packages)
    arts = list(u.artifacts)
    names = set(u.names) | set(u.lookups)
    cf = [w for n in names for w in claims.covering(n) if w[1] == "cfengine"]
    any_claim = [w for n in names for w in claims.covering(n)]
    owned = [a for a in arts if a.owned]
    vendor_frag = [a for a in owned if a.kind in ("fragment", "target", "source")]
    local = [a for a in arts if a.local]
    local_frag = [a for a in local if a.kind in ("fragment", "target", "source")]
    local_layer = [a for a in local if a.kind in ("dropin", "mask")]
    svc = [(d, s) for d, i, s in claims.services if i in names]
    tomb = any(s == "absent" for _, s in svc)

    if u.problems:
        return 1, "incomplete", "; ".join(u.problems)[:300]
    if names & conflict_ids:
        return 1, "incomplete", "contradictory service declarations"
    if cf and vendor_frag:
        return 2, "two-writers", "cfengine claim %s over a vendor fragment" % cf[0][0]
    if local_frag and vendor_frag:
        return 3, "two-writers", "local fragment %s hides a vendor fragment" % local_frag[0].path
    if local_layer and vendor_frag and not exact_noncf(claims, u):
        return 4, "two-writers", "local %s %s on a vendor unit without an exact non-cfengine claim" % (
            local_layer[0].kind, local_layer[0].path)
    if local_layer and cf and not vendor_frag:
        return 5, "two-writers", "local %s under a cfengine claim, no vendor fragment" % local_layer[0].kind
    if cf and local_frag and tomb:
        return 6, "unmet-absence", "tombstone but %s survives" % local_frag[0].path
    if cf and local_frag and not svc:
        return 7, "extra", "cfengine-claimed fragment with no service entry"
    for a in owned:
        if not set(a.owners) <= packages:
            return 8, "extra", "%s owned by undeclared package(s) %s" % (
                a.path, sorted(set(a.owners) - packages))
    for a in local:
        if a.kind == "alias" and not a.authorized:
            return 9, "extra", "alias link %s not authorized by the target's Alias=" % a.path
    for a in local:
        if a.kind == "alias" and a.authorized:
            continue
        if not any_claim:
            return 10, "extra", "%s %s covered by no claim" % (a.kind, a.path)
    return 11, "clean", ""


def classify(env, claims):
    summary = {"row_type": "domain_coverage", "domain": "supervision"}
    out = {"summary": summary, "units": [], "conflicts": [], "incomplete": []}
    if claims.gate == "not-run":
        summary["extra_scan"] = "not-run"
        out["incomplete"] = [claims.gate_reason]
        return out
    scan = Scan(env, claims)
    scan.run()
    out["conflicts"] = claims.conflicts()
    conflict_ids = {c["id"] for c in out["conflicts"]}
    counts = {"extra": 0, "two-writers": 0, "unmet-absence": 0}
    for u in scan.units:
        u.rule, u.verdict, u.why = judge(claims, u, conflict_ids)
        if u.verdict in counts:
            counts[u.verdict] += 1
        out["units"].append({
            "id": u.id, "names": sorted(u.names | u.lookups), "verdict": u.verdict,
            "rule": u.rule, "why": u.why,
            "state": u.props.get("UnitFileState", ""),
            "artifacts": [{"path": a.path, "kind": a.kind, "owners": a.owners,
                           "owners_raw": a.owners_raw, "authorized": a.authorized,
                           "link_target": a.link_target, "problem": a.problem}
                          for a in u.artifacts],
        })
    reasons = list(scan.incomplete)
    reasons += ["%s: %s" % (x["id"], x["why"]) for x in out["units"] if x["verdict"] == "incomplete"]
    reasons += ["contradictory service declarations for %s: %s" % (c["id"], ", ".join(c["addresses"]))
                for c in out["conflicts"]]
    out["incomplete"] = reasons
    if reasons:
        summary["extra_scan"] = "incomplete"
    else:
        summary["extra_scan"] = "complete"
        summary["extra_entries"] = counts["extra"]
        summary["two_writers"] = counts["two-writers"]
        summary["unmet_absence"] = counts["unmet-absence"]
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only unit-namespace classifier (schema v5, S1)")
    ap.add_argument("--claims", required=True, help="goal-file-shaped JSON with unit-writer/unit-package/service claims")
    ap.add_argument("--dpkg-admindir", help="dpkg database directory (test databases; default: the host's)")
    ap.add_argument("--quiet", action="store_true", help="print only the summary row")
    a = ap.parse_args(argv)
    with open(a.claims) as f:
        claims = load_claims(json.load(f))
    out = classify(Env(dpkg_admindir=a.dpkg_admindir), claims)
    json.dump(out["summary"] if a.quiet else out, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    for r in out["incomplete"]:
        print("incomplete: " + r, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
