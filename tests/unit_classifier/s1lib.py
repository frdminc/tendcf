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


class Sandbox:
    """Context manager. Every path it touches is recorded first and put back."""

    def __init__(self, extra_roots=()):
        self.roots = ALLOWED_ROOTS + tuple(extra_roots)
        self.undo = []          # callables, run in reverse
        self.started = []

    def _check(self, path):
        p = os.path.normpath(path)
        if not any(p == r or p.startswith(r + "/") for r in self.roots):
            raise AssertionError("fixture may not write %s" % path)
        return p

    def _snapshot(self, p):
        if os.path.islink(p):
            tgt = os.readlink(p)
            return lambda: (_rm(p), os.symlink(tgt, p))
        if os.path.isfile(p):
            data, mode = open(p, "rb").read(), os.stat(p).st_mode & 0o7777

            def restore():
                with open(p, "wb") as f:
                    f.write(data)
                os.chmod(p, mode)
            return restore
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
            self.undo.append(lambda t=t: _rmdir(t))

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
        self.started.append(unit)
        sh(["systemctl", "start", unit], check=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        for u in reversed(self.started):
            sh(["systemctl", "stop", u])
            sh(["systemctl", "reset-failed", u])
        for fn in reversed(self.undo):
            try:
                fn()
            except OSError:
                pass
        sh(["systemctl", "daemon-reload"])
        return False


def _rm(p):
    if os.path.lexists(p):
        os.unlink(p)


def _rmdir(p):
    try:
        os.rmdir(p)
    except OSError:
        pass


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
