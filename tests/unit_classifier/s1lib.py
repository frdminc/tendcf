"""Shared helpers for the S1 probe and the S1 fixtures (root, Linux, systemd).

Sandbox   writes unit files only under a short allow-list and restores every
          path to exactly what it was, however the test ends.
TestDb    a hardlink-cheap copy of the host's dpkg database plus synthetic
          packages, so ownership can be arranged without touching the real
          database (`dpkg-query --admindir`).
"""
import os
import shutil
import subprocess
import tempfile

ALLOWED_ROOTS = ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system")
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CLASSIFIER = os.path.join(REPO, "bin", "unit_classifier.py")


def sh(argv, check=False, input=None, env=None):
    r = subprocess.run(argv, capture_output=True, text=True, input=input, env=env,
                       errors="replace")
    if check and r.returncode != 0:
        raise RuntimeError("%r rc=%s: %s" % (argv, r.returncode, r.stderr.strip()))
    return r


def daemon_reload():
    sh(["systemctl", "daemon-reload"], check=True)


class CleanupError(RuntimeError):
    """A fixture could not put the host back. Never swallowed: a suite that cannot restore
    its files must not report green (it would poison later fixtures and later CI steps)."""


class Sandbox:
    """Context manager. Every path it touches is recorded first and put back.

    roots     the directories it may write under (default: the unit directories plus extra_roots)
    run       how it runs systemctl (default `sh`); None skips the manager, for tests of the
              sandbox itself on a host with no systemd

    Restoration never opens a pathname through a link: a regular file or a link is rebuilt
    as a fresh sibling and moved over the path with os.replace, so a replacement symlink
    (a mask to /dev/null, a link to some other file) is replaced, never written through.
    Failures of any restoration, stop or reload are collected and raised together as
    CleanupError after every step has been attempted.
    """

    def __init__(self, extra_roots=(), roots=None, run=sh):
        self.roots = tuple(roots) if roots is not None else ALLOWED_ROOTS + tuple(extra_roots)
        self.run = run
        self.undo = []          # callables, run in reverse
        self.started = []
        self.failures = []
        self._tmp_n = 0

    def _check(self, path):
        p = os.path.normpath(path)
        if not any(p == r or p.startswith(r + "/") for r in self.roots):
            raise AssertionError("fixture may not write %s" % path)
        return p

    def _sibling(self, p):
        self._tmp_n += 1
        return os.path.join(os.path.dirname(p), ".tendcf-s1-restore-%d-%d" % (os.getpid(), self._tmp_n))

    def _snapshot(self, p):
        if os.path.islink(p):
            tgt = os.readlink(p)

            def restore_link():
                tmp = self._sibling(p)
                os.symlink(tgt, tmp)
                try:
                    os.replace(tmp, p)
                except BaseException:
                    _unlink_quiet(tmp)
                    raise
            return restore_link
        if os.path.isfile(p):
            st = os.stat(p)
            with open(p, "rb") as f:
                data = f.read()

            def restore_file():
                tmp = self._sibling(p)
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(data)
                        f.flush()
                        # Order matters on Linux: a chown clears setuid/setgid, so the owner is
                        # restored first and the mode (special bits included) last.
                        if os.geteuid() == 0:
                            os.fchown(f.fileno(), st.st_uid, st.st_gid)
                        os.fchmod(f.fileno(), st.st_mode & 0o7777)
                    os.utime(tmp, ns=(st.st_atime_ns, st.st_mtime_ns))
                    os.replace(tmp, p)
                except BaseException:
                    _unlink_quiet(tmp)
                    raise
            return restore_file
        if os.path.isdir(p):
            raise AssertionError("refusing to replace directory %s" % p)
        return lambda: _rm(p)

    def _parents(self, p):
        d = os.path.dirname(p)
        todo = []
        while d and not os.path.isdir(d):
            todo.append(d)
            d = os.path.dirname(d)
        for t in reversed(todo):
            os.mkdir(t)
            self.undo.append(lambda t=t: os.rmdir(t))

    def write(self, path, text, mode=0o644):
        p = self._check(path)
        self._parents(p)
        self.undo.append(self._snapshot(p))
        if os.path.lexists(p):
            os.unlink(p)
        with open(p, "w") as f:
            f.write(text)
        os.chmod(p, mode)
        return p

    def symlink(self, path, target):
        p = self._check(path)
        self._parents(p)
        self.undo.append(self._snapshot(p))
        if os.path.lexists(p):
            os.unlink(p)
        os.symlink(target, p)
        return p

    def remove(self, path):
        """Remove a pre-existing path for the duration (restored on exit)."""
        p = self._check(path)
        if os.path.lexists(p):
            self.undo.append(self._snapshot(p))
            os.unlink(p)

    def start(self, unit):
        if self.run is None:
            raise RuntimeError("a Sandbox without a manager runner cannot start %s" % unit)
        self.started.append(unit)      # registered first: __exit__ stops it even if the start half-failed
        r = self.run(["systemctl", "start", unit])
        if r is None or r.returncode != 0:
            raise RuntimeError("systemctl start %s failed: %s" % (unit, r and r.stderr.strip()))

    def __enter__(self):
        return self

    def _guard(self, what, fn):
        """Run one cleanup operation; an exception is a collected failure, never an abort.
        Returns _FAILED (not None) for an exception, so a runner that returns None is not mistaken for it."""
        try:
            return fn()
        except Exception as e:
            self.failures.append("%s: %r" % (what, e))
            return _FAILED

    def _manager(self, what, argv, ok=(0,)):
        if self.run is None:
            return
        r = self._guard(what, lambda: self.run(argv))
        if r is _FAILED:
            return
        if r is None:
            self.failures.append("%s: the runner returned no result" % what)
        elif r.returncode not in ok:
            self.failures.append("%s: rc=%s %s" % (what, r.returncode, r.stderr.strip()[:200]))

    def __exit__(self, *exc):
        # Every stop, reset, restoration and reload is attempted, whatever any of them does.
        for u in reversed(self.started):
            self._manager("stop " + u, ["systemctl", "stop", u])
            # reset-failed exits 1 for a unit that is not failed: only an exception counts
            self._manager("reset-failed " + u, ["systemctl", "reset-failed", u], ok=(0, 1))
        for i, fn in reversed(list(enumerate(self.undo))):
            self._guard("restore step %d" % i, fn)
        self._manager("daemon-reload", ["systemctl", "daemon-reload"])
        if self.failures:
            raise CleanupError("sandbox could not restore the host: " + "; ".join(self.failures))
        return False


_FAILED = object()


def _unlink_quiet(p):
    try:
        os.unlink(p)
    except OSError:
        pass


def _rm(p):
    if os.path.lexists(p):
        os.unlink(p)


class TestDb:
    """A private dpkg admindir: the host's database, hardlinked, plus synthetic
    packages. Never writes in place to a linked file (status and diversions are
    replaced by a fresh file)."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="tendcf-s1-dpkg-", dir="/var/tmp")
        src = "/var/lib/dpkg"
        os.mkdir(os.path.join(self.dir, "info"))
        for name in os.listdir(os.path.join(src, "info")):
            s, d = os.path.join(src, "info", name), os.path.join(self.dir, "info", name)
            try:
                os.link(s, d)
            except OSError:
                shutil.copy2(s, d)
        for f in ("status", "diversions", "statoverride", "arch", "available"):
            if os.path.exists(os.path.join(src, f)):
                shutil.copy2(os.path.join(src, f), os.path.join(self.dir, f))
        for d in ("updates", "triggers"):
            os.makedirs(os.path.join(self.dir, d), exist_ok=True)
        self.arch = sh(["dpkg", "--print-architecture"], check=True).stdout.strip()

    def add_package(self, name, files, multiarch=None, status="install ok installed"):
        arch = self.arch if multiarch == "same" else "all"
        stanza = ("Package: %s\nStatus: %s\nPriority: optional\nSection: misc\n"
                  "Maintainer: tendcf test <test@invalid>\nArchitecture: %s\n"
                  "Version: 1\nDescription: tendcf S1 test package\n" % (name, status, arch))
        if multiarch:
            stanza += "Multi-Arch: %s\n" % multiarch
        st = os.path.join(self.dir, "status")
        with open(st) as f:
            body = f.read()
        if not body.endswith("\n\n"):
            body = body.rstrip("\n") + "\n\n"
        tmp = st + ".new"
        with open(tmp, "w") as f:
            f.write(body + stanza + "\n")
        os.replace(tmp, st)
        lst = "%s:%s.list" % (name, arch) if multiarch == "same" else name + ".list"
        with open(os.path.join(self.dir, "info", lst), "w") as f:
            f.write("".join(p + "\n" for p in files))

    def add_diversion(self, path, to, package="tendcf-s1-diverter"):
        """diversions file: three lines per entry (from, to, package; ':' = local)."""
        p = os.path.join(self.dir, "diversions")
        with open(p) as f:
            body = f.read()
        tmp = p + ".new"
        with open(tmp, "w") as f:
            f.write(body + "%s\n%s\n%s\n" % (path, to, package))
        os.replace(tmp, p)

    def query(self, *paths):
        return sh(["dpkg-query", "--admindir", self.dir, "-S"] + list(paths))

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)
