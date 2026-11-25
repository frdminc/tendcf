#!/usr/bin/env python3
"""State 1 macOS VM: image prep and check harness (issue 70, slice A).

Host-side driver for bigmac (Apple Silicon, tart). Four subcommands, each safe to
re-run after an interruption; every tart and ssh call is an argv list.

    state1_vm.py resolve                      tag -> digest from the registry (no tart, no pull)
    state1_vm.py pull                         pull the pinned image (the heavy ~30 GB job)
    state1_vm.py golden                       build the local VM `state1-golden` from the cached image
    state1_vm.py check                        clone, check, reboot, delete: JSON summary on stdout

Both run with no operator input: `golden` mints a fresh ed25519 key for each golden build
(private half 0600 under <state-dir>/keys/<key id>/, public half baked into the image) and
`check` reads it back through `golden.json`. djbclark's own keys are never used or read. The
guest's console password is randomised in prep.sh and never leaves the guest.

`golden` and `check` never pull: `golden` refuses when the pinned image is not in
tart's OCI cache, so the heavy pull is admitted as its own job. At most one driver
runs at a time (flock), and no VM starts while two are already running.

Exit status: 0 ok, 1 a step failed, 2 refused or bad usage, 130 interrupted.
Logs go to stderr; stdout carries the JSON summary unless --summary FILE is given.
See README.md for what each step proves and what waits for the renderer slice.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import errno
import fcntl
import hashlib
import io
import ipaddress
import json
import os
import pwd
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vmssh

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
DEFAULT_IMAGE_JSON = HERE / "image.json"
DARWIN_INSTALLER = REPO_ROOT / "deploy" / "darwin" / "tendcf-install.sh"
POLICY_DIR = REPO_ROOT / "policy"
DARWIN_CANARY_DIR = REPO_ROOT / "deploy" / "darwin" / "canary"
FORK_PIN_JSON = REPO_ROOT / "overlay" / "fork.json"
CANARY_LABEL = "com.tendcf.canary.main"
EXECD_LABEL = "org.tendcf.execd"
CANARY_GOLDEN = (
    REPO_ROOT
    / "tests"
    / "policy"
    / "golden"
    / "launchd"
    / "system"
    / f"{CANARY_LABEL}.plist"
)
CANARY_PLIST = f"/Library/LaunchDaemons/{CANARY_LABEL}.plist"
EXECD_PLIST = f"/Library/LaunchDaemons/{EXECD_LABEL}.plist"
TENDCF_PREFIX = "/opt/tendcf"
CANARY_PROG = "/bin/sleep"
CANARY_ARG = "86400"
CANARY_DRIFT_ARG = "99999"
EXECD_PROG = "/opt/tendcf/bin/cf-execd"
GH_REPO = "frdminc/tendcf"
RUN_ID_RE = re.compile(r"^[0-9]{1,20}\Z")
SHA256_LINE_RE = re.compile(r"^([0-9A-Fa-f]{64})[ \t]+\*?([^\s]+)\Z")
GUEST_STAGE_RE = re.compile(r"^/var/tmp/tendcf-stage\.[A-Za-z0-9._-]+\Z")
STAGE_UPLOAD_SH = (
    "set -eu; umask 077; d=$(mktemp -d /var/tmp/tendcf-stage.XXXXXX); "
    'tar -xzf - -C "$d"; printf "%s\\n" "$d"'
)
# The account's home from the passwd entry, never $HOME: tart itself (Foundation) ignores
# $HOME, so a second $HOME of the same user must not mean a second lock (or marker).


def account_home(environ: dict[str, str] | None = None) -> str:
    """The account's home from the passwd entry, never $HOME, like Foundation; $HOME (else
    "/") only when this uid has no passwd entry (a container or a sandbox), where Foundation
    also falls back to it. A relative $HOME is rejected (falls back to "/")."""
    try:
        return pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        home = (os.environ if environ is None else environ).get("HOME") or ""
        return home if os.path.isabs(home) else "/"


DEFAULT_STATE_DIR = (
    Path(os.path.realpath(account_home())) / ".local" / "state" / "tendcf-state1-vm"
)
# One lock per account (DEFAULT_STATE_DIR/driver.lock, the name master uses) whatever
# --state-dir and the tart home say: the VM names (state1-golden-build, state1-check-*) are
# global to a tart home and the state dirs are shared across tart homes, so one driver at a
# time per account. Only the owner marker is keyed by tart home.
LOCK_NAME = "driver.lock"
SCHEMA = "tendcf-state1-vm-summary/1"
FRAMEWORK_ROOT = "/Library/Frameworks/Python.framework"
VM_CAP = 2  # Apple's licence: two macOS VMs at once per host
EVIDENCE_MAX = 2000
CHECK_PREFIX = "state1-check-"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
REPO_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*\Z")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}\Z")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}\Z")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
CONSOLE_PW_LINE_RE = re.compile(r"^PREP-CONSOLE-PW rotated\s*$", re.MULTILINE)
# prep.sh logs the Secure Token status after the password rotation (issue 78); the driver
# carries that one line into g6's evidence, which is cut short for a long prep output.
SECURE_TOKEN_AFTER_RE = re.compile(
    r"^prep: secure token status \(after\): .*$", re.MULTILINE
)
# `mdutil -a -s` says kMDConfigSearchLevelTransitioning while a volume is still changing state
# after an earlier command (seen right after a reboot, issue 70 run 2): poll, bounded.
MDUTIL_TRANSITIONING = "kMDConfigSearchLevelTransitioning"
MDUTIL_SETTLE_TIMEOUT = 120.0
MDUTIL_SETTLE_INTERVAL = 2.0
# the keys prep.sh writes with `defaults`; check 2h reads them all. AutomaticCheckEnabled is not
# read: a written one was gone between 30 and 90 s in one run (issue 70 addendum 4, PR 90).
# SplatEnabled is believed to be the Background Security Improvements switch (inferred, not
# documented by Apple; operator ruling 2026-11-21).
UPDATES_KEYS = (
    "AutomaticDownload",
    "AutomaticallyInstallMacOSUpdates",
    "ConfigDataInstall",
    "CriticalUpdateInstall",
    "SplatEnabled",
)
HOSTKEY_LINE_RE = re.compile(
    r"^PREP-HOSTKEY (ssh-ed25519) ([A-Za-z0-9+/]+={0,2})\s*$", re.MULTILINE
)
CLONE_ENV = {
    "TART_NO_AUTO_PRUNE": "1"
}  # a clone must not prune the 30 GB OCI cache entry
GUEST_SHUTDOWN_WAIT = 180
VM_RESTARTS_MAX = 3

# One fixed script, nothing interpolated: reads the public key from stdin.
INSTALL_KEY_SH = (
    'set -eu; umask 077; mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"; '
    'IFS= read -r key; touch "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"; '
    'grep -qxF -- "$key" "$HOME/.ssh/authorized_keys" || printf "%s\\n" "$key" >> "$HOME/.ssh/authorized_keys"'
)
# Run a guest script as root in ONE ssh session: the script arrives on stdin, is stored at
# an unpredictable mktemp path, run with sudo -n, and removed by the trap in that same
# session. Nothing is left behind and nothing depends on a second connection.
RUN_SCRIPT_SH = (
    "umask 077; f=$(mktemp /var/tmp/tendcf-state1.XXXXXX) || exit 1; "
    "trap 'rm -f \"$f\"' EXIT; trap 'exit 129' HUP INT TERM; "
    'cat > "$f" || exit 1; sudo -n /bin/sh "$f" "$@"'
)
# Is the root-owned tree a real directory (not a symlink), root:wheel, and free of group/world
# write, SUID/SGID, and ACLs (including dotfiles and hidden subdirectories)? Prints offenders only.
TREE_CHECK_SH = (
    'test ! -L "$1" && test -d "$1" || exit 1; '
    'find "$1" \\( ! -user root -o ! -group wheel \\) -print | head -n 5; '
    'find "$1" ! -type l \\( -perm -020 -o -perm -002 -o -perm -4000 -o -perm -2000 \\) -print | head -n 5; '
    'out=$(find "$1" -exec /bin/ls -lde {} +) || exit 1; '
    'printf "%s\\n" "$out" | awk \'/^ [0-9]+: / || /^[^[:space:]]+\\+[[:space:]]/ { print "ACL:" $0; exit }\''
)
# Same as TREE_CHECK_SH plus rejects any non-regular/non-directory entry (e.g. symlinks under inputs/).
TREE_CHECK_NO_LINKS_SH = (
    TREE_CHECK_SH + '; find "$1" ! -type f ! -type d -print | head -n 5'
)
WORKDIR_RE = re.compile(r"^/opt/tendcf/[A-Za-z0-9._/-]+\Z")


class Refusal(Exception):
    """A precondition failed before anything was changed: exit 2."""


class ToolError(Exception):
    """A tart or ssh call did not behave: the step fails."""


class StepFail(Exception):
    pass


class Abort(Exception):
    """A fatal step failed and has been recorded; unwind to cleanup."""


class Interrupted(BaseException):
    pass


@dataclass
class Result:
    rc: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


class RealProc:
    def __init__(self, popen: subprocess.Popen[bytes]):
        self._p = popen

    def poll(self) -> int | None:
        return self._p.poll()

    def wait(self, timeout: float) -> int | None:
        try:
            return self._p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def kill(self) -> None:
        with contextlib.suppress(ProcessLookupError):
            self._p.kill()


class RealRunner:
    def run(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
        input_bytes: bytes | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        log_path: Path | None = None,
        no_tty: bool = False,
        raw_newlines: bool = False,
    ) -> Result:
        """raw_newlines: no text mode, so no universal-newline translation (it turns a lone
        CR or CRLF into "\\n"): bytes in, stdout/stderr decoded as UTF-8 with errors="replace".
        Opt-in; cannot be combined with log_path. Default text mode also uses UTF-8 with
        errors="replace" so invalid UTF-8 from a guest command never raises UnicodeDecodeError."""
        if input_text is not None and input_bytes is not None:
            raise ValueError("pass either input_text or input_bytes, not both")
        if raw_newlines and log_path is not None:
            raise ValueError("raw_newlines=True cannot be combined with log_path")
        out = open(log_path, "ab") if log_path else None  # noqa: SIM115
        raw = raw_newlines or input_bytes is not None
        payload: bytes | str | None
        if input_bytes is not None:
            payload = input_bytes
        elif raw and input_text is not None:
            payload = input_text.encode("utf-8")
        else:
            payload = input_text
        use_text = (payload is not None or out is None) and not raw
        try:
            cp = subprocess.run(
                argv,
                input=payload,
                stdin=None if payload is not None else subprocess.DEVNULL,
                stdout=out if out else subprocess.PIPE,
                stderr=subprocess.STDOUT if out else subprocess.PIPE,
                text=use_text,
                encoding="utf-8" if use_text else None,
                errors="replace" if use_text else None,
                env=env,
                timeout=timeout,
                check=False,
                # a new session has no controlling terminal: a tool that would prompt on
                # /dev/tty (ssh-keygen on a passphrase-protected key) cannot
                start_new_session=no_tty,
            )
        except FileNotFoundError as e:
            return Result(127, "", f"{argv[0]}: {e}")
        except subprocess.TimeoutExpired:
            return Result(124, "", f"timeout after {timeout}s", timed_out=True)
        finally:
            if out:
                out.close()
        if out and log_path:
            return Result(cp.returncode, tail_file(log_path), "")
        if raw:
            return Result(
                cp.returncode,
                (cp.stdout or b"").decode("utf-8", "replace"),
                (cp.stderr or b"").decode("utf-8", "replace"),
            )
        return Result(cp.returncode, cp.stdout or "", cp.stderr or "")

    def start(
        self, argv: list[str], *, log_path: Path, env: dict[str, str] | None = None
    ) -> RealProc:
        log = open(log_path, "ab")  # noqa: SIM115
        try:
            p = subprocess.Popen(
                argv,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        finally:
            log.close()
        return RealProc(p)


def tail_file(path: Path, limit: int = EVIDENCE_MAX) -> str:
    try:
        data = path.read_bytes()[-limit:]
    except OSError:
        return ""
    return data.decode("utf-8", "replace")


F_GETPATH = getattr(fcntl, "F_GETPATH", None) if sys.platform == "darwin" else None


def canonical_dir_path(path: str) -> str:
    """Canonical path for a directory (folding symlinks, APFS case, and macOS
    /System/Volumes/Data firmlinks via F_GETPATH on an O_DIRECTORY fd). When the directory
    does not yet exist, canonicalizes its nearest existing ancestor directory and appends the
    remaining components; falls back to os.path.realpath on non-macOS."""
    rp = os.path.realpath(path)
    if F_GETPATH is None:
        return rp
    cur = Path(rp)
    tail: list[str] = []
    while True:
        try:
            fd = os.open(cur, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            parent = cur.parent
            if parent == cur:
                return rp
            tail.append(cur.name)
            cur = parent
            continue
        try:
            buf = fcntl.fcntl(fd, F_GETPATH, b"\0" * 1024)
            canon = os.fsdecode(buf.split(b"\0", 1)[0])
        except OSError:
            return rp
        finally:
            os.close(fd)
        if tail:
            return os.path.join(canon, *reversed(tail))
        return canon


def resolve_tart_home(environ: dict[str, str] | None = None) -> str:
    """The tart home `tart` itself uses, canonicalized (tart's Config.swift): $TART_HOME
    whenever it is set, even to the empty string (realpath("") is the cwd, as in tart); else
    the account's home (CFFIXED_USER_HOME if set, even empty, else the passwd entry: never
    $HOME) plus /.tart. Computed once per run (Ctx) and exported as TART_HOME to every tart
    call, so tart and this driver cannot disagree."""
    env = os.environ if environ is None else environ
    raw = env.get("TART_HOME")
    if raw is not None:
        return canonical_dir_path(raw)
    base = env.get("CFFIXED_USER_HOME")  # set but empty is the cwd, as in Foundation
    if base is None:
        base = account_home(env)
    return canonical_dir_path(os.path.join(base, ".tart"))


def tart_key(tart_home: str) -> str:
    """A short stable name part for one tart home: its lock and its owner markers."""
    return hashlib.sha256(os.fsencode(tart_home)).hexdigest()[:8]


def _symlink_owner_refusal(path: Path, uid: int, euid: int, *, is_final: bool) -> str:
    if is_final:
        if uid != euid:
            if uid == 0:
                return (
                    f"the state dir {str(path)!r} is a root-owned symlink (uid 0), not "
                    "owned by you: refusing to follow it (pass the real directory)"
                )
            return (
                f"the state dir {str(path)!r} is a symlink owned by uid {uid}, not you: "
                "refusing to follow it (pass the real directory)"
            )
    elif uid not in (0, euid):
        return (
            f"ancestor {str(path)!r} of the state dir is a symlink owned by uid "
            f"{uid}, not you or root: refusing to follow it (pass the real directory)"
        )
    return ""


def _walk_state_dir_links(
    base: Path,
    parts: list[str],
    *,
    is_final_leaf: bool,
    in_symlink: bool,
    origin_link: Path | None,
    euid: int,
    hops: int,
) -> tuple[Path | None, int, str]:
    """Walk `parts` from `base` component-by-component without lexical `..` collapse,
    following symlinks hop-by-hop with `os.readlink` and verifying `lstat` ownership at
    every hop (up to 40 hops)."""
    cur = base
    for i, part in enumerate(parts):
        if part in ("", "."):
            continue
        if part == "..":
            cur = cur.parent
            continue
        cand = cur / part
        leaf_here = is_final_leaf and (i == len(parts) - 1)
        try:
            st = os.lstat(cand)
        except FileNotFoundError:
            if in_symlink:
                link_ref = origin_link or cand
                which = "the state dir" if is_final_leaf else "ancestor"
                extra = "" if is_final_leaf else " of the state dir"
                return (
                    None,
                    hops,
                    f"{which} {str(link_ref)!r}{extra} is a symlink that points nowhere: "
                    "refusing to create its target (make the directory or pass a real path)",
                )
            if ".." in parts[i + 1 :]:
                return (
                    None,
                    hops,
                    f"the state dir path uses '..' after missing component {str(cand)!r}: "
                    "refusing to collapse '..' past a missing component (pass a real path)",
                )
            return cand, hops, ""  # missing tail of a real path (made later)
        except NotADirectoryError:
            if in_symlink:
                link_ref = origin_link or cand
                return (
                    None,
                    hops,
                    f"cannot resolve symlink {str(link_ref)!r} for the state dir: "
                    "Not a directory (make the directory or pass a real path)",
                )
            return (
                None,
                hops,
                f"ancestor {str(cur)!r} of the state dir is not a directory "
                "(pass a real directory)",
            )
        except OSError as e:
            if in_symlink:
                link_ref = origin_link or cand
                return (
                    None,
                    hops,
                    f"cannot resolve symlink {str(link_ref)!r} for the state dir: "
                    f"{e.strerror or e} (make the directory or pass a real path)",
                )
            return (
                None,
                hops,
                f"cannot inspect {'the state dir' if leaf_here else 'ancestor'} {str(cand)!r}: "
                f"{e.strerror or e}",
            )
        if not stat.S_ISLNK(st.st_mode):
            if not stat.S_ISDIR(st.st_mode) and i < len(parts) - 1:
                return (
                    None,
                    hops,
                    f"ancestor {str(cand)!r} of the state dir is not a directory "
                    "(pass a real directory)",
                )
            cur = cand
            continue
        err = _symlink_owner_refusal(cand, st.st_uid, euid, is_final=leaf_here)
        if err:
            return None, hops, err
        hops += 1
        if hops > 40:
            link_ref = origin_link or cand
            return (
                None,
                hops,
                f"cannot resolve symlink {str(link_ref)!r} for the state dir: "
                "Too many levels of symbolic links (make the directory or pass a real path)",
            )
        try:
            raw_target = os.readlink(cand)
        except OSError as e:
            return (
                None,
                hops,
                f"cannot resolve symlink {str(cand)!r} for the state dir: "
                f"{e.strerror or e} (make the directory or pass a real path)",
            )
        t_path = Path(raw_target)
        if t_path.is_absolute():
            t_base = Path("/")
            t_parts = list(t_path.parts[1:])
        else:
            t_base = cur
            t_parts = list(t_path.parts)
        resolved, hops, err = _walk_state_dir_links(
            t_base,
            t_parts,
            is_final_leaf=leaf_here,
            in_symlink=True,
            origin_link=origin_link or cand,
            euid=euid,
            hops=hops,
        )
        if err or resolved is None:
            return None, hops, err
        cur = resolved
    return cur, hops, ""


def state_dir_link_problem(given: Path) -> str:
    """Why a --state-dir or any of its symlinked ancestors must not be followed ("" when fine):
    walks `given` component-by-component without lexical `..` collapse and follows symlinks
    hop-by-hop with `lstat` ownership checks at every hop (issue 82 + PR 112 R1). A dangling
    symlink (at the leaf or in an ancestor, e.g. /tmp/link/sub) or a foreign-owned symlink at
    any hop is refused; root-owned system ancestor symlinks (such as /var -> private/var and
    /tmp -> private/tmp on macOS) pointing to existing directories are accepted."""
    euid = os.geteuid()
    # Direct check on the given leaf spelling itself (catches foreign/root leaf symlinks
    # before ancestor symlink canonicalization changes the path spelling).
    try:
        st_given = os.lstat(given)
    except OSError:
        st_given = None
    if st_given is not None and stat.S_ISLNK(st_given.st_mode):
        err = _symlink_owner_refusal(given, st_given.st_uid, euid, is_final=True)
        if err:
            return err
    raw = Path(given)
    if raw.is_absolute():
        parts = list(raw.parts[1:])
    else:
        cwd_parts = list(Path(os.getcwd()).parts)
        parts = cwd_parts[1:] + list(raw.parts)
    _, _, err = _walk_state_dir_links(
        Path("/"),
        parts,
        is_final_leaf=True,
        in_symlink=False,
        origin_link=None,
        euid=euid,
        hops=0,
    )
    return err


@dataclass
class Ctx:
    state_dir: Path
    runner: object = field(default_factory=RealRunner)
    sleep: Callable[[float], None] = time.sleep
    monotonic: Callable[[], float] = time.monotonic
    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    err: Callable[[str], None] = lambda s: print(s, file=sys.stderr, flush=True)
    fetch: Callable[[str, dict[str, str], str], tuple[int, dict[str, str]]] | None = (
        None
    )
    run_id: str = ""
    lock_path: Path | None = None
    tart_home: str = ""
    state_dir_refusal: str = ""

    def __post_init__(self) -> None:
        # resolved once, at startup: a later retarget of a symlink or a chdir cannot move it
        given = Path(self.state_dir)
        self.state_dir = Path(os.path.realpath(given))
        # a symlink given as the state dir that dangles, or is not ours, is refused (by
        # check_state_dir, before anything is created) rather than followed. Judged after
        # the realpath: a link planted before it is seen here, one planted after it is a
        # name the resolved path no longer is (check_state_dir uses lstat)
        self.state_dir_refusal = state_dir_link_problem(given)
        if not self.tart_home:
            self.tart_home = resolve_tart_home()
        else:
            self.tart_home = canonical_dir_path(self.tart_home)
        if self.lock_path is None:
            self.lock_path = DEFAULT_STATE_DIR / LOCK_NAME
        else:
            lp = Path(self.lock_path)
            self.lock_path = Path(os.path.realpath(lp.parent)) / lp.name
        if not self.run_id:
            self.run_id = (
                self.now().strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(2)
            )

    def tart_env(self, env: dict[str, str] | None = None) -> dict[str, str]:
        """The environment of a tart call: the given one (else ours) with TART_HOME pinned to
        the home this run resolved."""
        return {**(os.environ if env is None else env), "TART_HOME": self.tart_home}

    def run(self, argv: list[str], **kw) -> Result:
        self.err(
            "$ " + shlex.join(argv)
        )  # argv only: environments and stdin are never logged
        if argv and argv[0] == "tart":
            kw["env"] = self.tart_env(kw.get("env"))
        return self.runner.run(argv, **kw)  # type: ignore[attr-defined]

    def logs(self) -> Path:
        d = self.state_dir / "logs"
        d.mkdir(parents=True, exist_ok=True)
        return d


def clip(text: str, limit: int = EVIDENCE_MAX) -> str:
    text = text.strip()
    return (
        text
        if len(text) <= limit
        else text[:limit] + f"...[+{len(text) - limit} chars]"
    )


class Summary:
    def __init__(self, command: str, run_id: str):
        self.command = command
        self.run_id = run_id
        self.started = datetime.now(UTC).isoformat(timespec="seconds")
        self.steps: list[dict[str, str]] = []
        self.extra: dict[str, object] = {}

    def add(self, sid: str, name: str, status: str, evidence: str = "") -> None:
        assert status in ("pass", "fail", "skip")
        self.steps.append(
            {"step": sid, "name": name, "status": status, "evidence": clip(evidence)}
        )

    @property
    def ok(self) -> bool:
        return not any(s["status"] == "fail" for s in self.steps)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": SCHEMA,
            "command": self.command,
            "run_id": self.run_id,
            "started": self.started,
            "finished": datetime.now(UTC).isoformat(timespec="seconds"),
            "ok": self.ok,
            **self.extra,
            "steps": self.steps,
        }


def run_step(
    summary: Summary,
    sid: str,
    name: str,
    fn: Callable[[], str | None],
    *,
    fatal: bool = True,
) -> bool:
    try:
        evidence = fn()
    except (StepFail, ToolError, ValueError) as e:
        summary.add(sid, name, "fail", str(e))
        if fatal:
            raise Abort(sid) from e
        return False
    summary.add(sid, name, "pass", evidence or "")
    return True


# ---------------------------------------------------------------- image pin


def read_image_json(path: Path) -> dict:
    """Read and validate image.json (everything but the digest); Refusal, never a traceback."""
    try:
        image = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise Refusal(f"{path}: cannot read the image pin: {e}") from e
    try:
        checks = [
            ("repository", REPO_RE, image["repository"]),
            ("tag", TAG_RE, image["tag"]),
            ("golden_name", NAME_RE, image["golden_name"]),
            ("golden_name + -build", NAME_RE, image["golden_name"] + "-build"),
            (
                "python.version",
                re.compile(r"^\d+\.\d+\.\d+\Z"),
                image["python"]["version"],
            ),
            ("python.sha256", re.compile(r"^[0-9a-f]{64}\Z"), image["python"]["sha256"]),
            ("python.url", re.compile(r"^https://\S+\Z"), image["python"]["url"]),
            (
                "python.signer",
                re.compile(r"^[^\n]+ \([A-Z0-9]{10}\)\Z"),
                image["python"]["signer"],
            ),
        ]
    except (KeyError, TypeError) as e:
        raise Refusal(f"{path}: missing or malformed field: {e!r}") from e
    for name, rx, value in checks:
        if not isinstance(value, str) or not rx.fullmatch(
            value
        ):  # fullmatch: `$` alone allows a trailing newline
            raise Refusal(f"{path}: bad {name}: {value!r}")
    vanilla = image.get("vanilla_host_key")
    if vanilla is not None and not (
        isinstance(vanilla, str)
        and re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}", vanilla)
    ):
        raise Refusal(
            f"{path}: vanilla_host_key must be one 'ssh-ed25519 <base64>' line"
        )
    return image


def load_image(path: Path) -> dict:
    image = read_image_json(path)
    if not DIGEST_RE.match(str(image.get("digest", ""))):
        raise Refusal(f"{path}: no pinned digest (run `resolve`, then commit it)")
    return image


def image_ref(image: dict) -> str:
    return f"{image['repository']}@{image['digest']}"


def resolve_digest(ctx: Ctx, image: dict) -> str:
    """Manifest digest of repository:tag from the registry: a HEAD request, no image data."""
    host, _, repo = image["repository"].partition("/")
    raw_fetch = ctx.fetch or _http_fetch

    def fetch(url: str, headers: dict[str, str], method: str):
        try:
            return raw_fetch(url, headers, method)
        except (
            OSError,
            ValueError,
            urllib.error.URLError,
        ) as e:  # HTTPError is a URLError
            raise ToolError(f"registry request failed ({method} {url}): {e}") from e

    status, hdrs = fetch(
        f"https://{host}/token?service={host}&scope=repository:{repo}:pull",
        {},
        "GET-JSON",
    )
    token = hdrs.get("token", "")
    if status != 200 or not token:
        raise ToolError(f"no registry token from {host} (status {status})")
    accept = (
        "application/vnd.oci.image.manifest.v1+json,"
        "application/vnd.oci.image.index.v1+json,"
        "application/vnd.docker.distribution.manifest.v2+json"
    )
    status, hdrs = fetch(
        f"https://{host}/v2/{repo}/manifests/{image['tag']}",
        {"Authorization": f"Bearer {token}", "Accept": accept},
        "HEAD",
    )
    digest = {k.lower(): v for k, v in hdrs.items()}.get("docker-content-digest", "")
    if status != 200 or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ToolError(
            f"registry did not return a digest for {image['tag']} (status {status})"
        )
    return digest


def _http_fetch(
    url: str, headers: dict[str, str], method: str
) -> tuple[int, dict[str, str]]:
    req = urllib.request.Request(
        url, headers=headers, method="GET" if method == "GET-JSON" else method
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        if method == "GET-JSON":
            return r.status, json.loads(r.read())
        return r.status, {k.lower(): v for k, v in r.headers.items()}


# ---------------------------------------------------------------- tart


def tart_list(ctx: Ctx, source: str) -> list[dict]:
    r = ctx.run(["tart", "list", "--source", source, "--format", "json"], timeout=60)
    if r.rc != 0:
        raise ToolError(
            f"tart list failed (rc {r.rc}): {clip(r.stderr or r.stdout, 300)}"
        )
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        raise ToolError(f"tart list returned non-JSON: {e}") from e
    if not isinstance(data, list):
        raise ToolError("tart list did not return a JSON array")
    return data


def local_vms(ctx: Ctx) -> dict[str, dict]:
    return {v["Name"]: v for v in tart_list(ctx, "local")}


def oci_names(ctx: Ctx) -> set[str]:
    return {v["Name"] for v in tart_list(ctx, "oci")}


def assert_vm_cap(ctx: Ctx, *, limit: int = VM_CAP) -> list[str]:
    """Refuse when `limit` VMs are already running. Counts every running local VM (conservative).

    The default is Apple's licence cap. golden passes limit=1: it needs the vmnet to itself
    (no other guest on it while the host key is pinned), so any running VM refuses it.
    """
    running = sorted(n for n, v in local_vms(ctx).items() if v.get("Running"))
    if len(running) >= limit:
        why = (
            f"Apple's licence allows {VM_CAP} macOS VMs at once. Not starting another."
            if limit >= VM_CAP
            else "golden needs the host network to itself (no other guest may share the vmnet "
            "while the host key is pinned). Stop them first."
        )
        raise Refusal(
            f"{len(running)} VMs already running ({', '.join(running)}); {why}"
        )
    return running


def assert_no_other_vm(ctx: Ctx, allowed: str | None = None) -> None:
    """Fail the current step if any local VM other than `allowed` is running (issue 78:
    re-checked in golden's boot() and at the start of pin() so a VM started mid-build fails it)."""
    others = sorted(
        n for n, v in local_vms(ctx).items() if v.get("Running") and n != allowed
    )
    if others:
        raise StepFail(
            f"another VM is running ({', '.join(others)}); golden needs the host network "
            "to itself while the host key is pinned"
        )


def wait_until(
    ctx: Ctx, pred: Callable[[], bool], timeout: float, interval: float = 2.0
) -> bool:
    deadline = ctx.monotonic() + timeout
    while True:
        if pred():
            return True
        if ctx.monotonic() >= deadline:
            return False
        ctx.sleep(interval)


def remove_vm(ctx: Ctx, name: str, proc: RealProc | None = None) -> str:
    """Stop (if running) and delete a local VM; verify it is gone. Returns what was done."""
    if not NAME_RE.match(name):
        raise ToolError(f"unsafe VM name {name!r}")
    vm = local_vms(ctx).get(name)
    if vm is None:
        return f"{name}: absent"
    done = []
    if vm.get("Running"):
        ctx.run(
            ["tart", "stop", name], timeout=180
        )  # a VM that stopped meanwhile makes this fail; the poll decides
        if not wait_until(
            ctx, lambda: not (local_vms(ctx).get(name) or {}).get("Running"), 90
        ):
            raise ToolError(f"{name} still running after tart stop")
        done.append("stopped")
    if proc is not None and proc.wait(30) is None:
        proc.kill()
    r = ctx.run(["tart", "delete", name], timeout=120)
    if r.rc != 0 and name in local_vms(ctx):
        raise ToolError(
            f"tart delete {name} failed (rc {r.rc}): {clip(r.stderr or r.stdout, 300)}"
        )
    if name in local_vms(ctx):
        raise ToolError(f"{name} still listed after delete")
    done.append("deleted")
    return f"{name}: {', '.join(done)}"


def sweep(ctx: Ctx, prefix: str) -> list[str]:
    """Remove leftovers of an interrupted run. Safe: the caller holds the driver lock."""
    return [remove_vm(ctx, n) for n in sorted(local_vms(ctx)) if n.startswith(prefix)]


class Vm:
    def __init__(self, ctx: Ctx, name: str):
        self.ctx, self.name, self.proc = ctx, name, None

    def start(self) -> None:
        assert_vm_cap(self.ctx)
        log = self.ctx.logs() / f"{self.name}-run.log"
        argv = ["tart", "run", "--no-graphics", self.name]
        self.ctx.err("$ " + shlex.join(argv) + f"   (log {log})")
        self.proc = self.ctx.runner.start(  # type: ignore[attr-defined]
            argv, log_path=log, env=self.ctx.tart_env()
        )

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def ip(self, wait: int = 120) -> str:
        r = self.ctx.run(
            ["tart", "ip", "--wait", str(wait), self.name], timeout=wait + 30
        )
        ip = r.stdout.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError as e:
            raise ToolError(
                f"tart ip gave no address (rc {r.rc}): {clip(r.stderr or r.stdout, 300)}"
            ) from e
        return ip


# ---------------------------------------------------------------- ssh helpers


def rssh(
    ctx: Ctx,
    t: vmssh.Target,
    argv: list[str],
    *,
    input_text: str | None = None,
    input_bytes: bytes | None = None,
    timeout: float = 120,
    raw_newlines: bool = False,
) -> Result:
    kw: dict[str, object] = {}
    if raw_newlines:
        kw["raw_newlines"] = True
    if input_bytes is not None:
        kw["input_bytes"] = input_bytes
    return ctx.run(
        vmssh.ssh_argv(t, argv),
        input_text=input_text,
        env=vmssh.ssh_env(t),
        timeout=timeout,
        **kw,
    )


SSHD_REQUIRED_EXACT: dict[str, frozenset[str]] = {
    "passwordauthentication": frozenset({"passwordauthentication no"}),
    "kbdinteractiveauthentication": frozenset({"kbdinteractiveauthentication no"}),
    "pubkeyauthentication": frozenset({"pubkeyauthentication yes"}),
    "permitrootlogin": frozenset({"permitrootlogin no"}),
    "gssapiauthentication": frozenset({"gssapiauthentication no"}),
    "hostbasedauthentication": frozenset({"hostbasedauthentication no"}),
    # macOS OpenSSH prints `AuthenticationMethods any` by default when unset, or
    # `AuthenticationMethods publickey` when explicitly set by prep.sh; reject any other value.
    "authenticationmethods": frozenset(
        {"authenticationmethods publickey", "authenticationmethods any"}
    ),
}
# Inspect sshd_config and all recursive Include targets (cycle-safe, max depth 16) for any
# uncommented Match directive. Arguments: $1 = main sshd_config path, $2 = base dir (/etc/ssh).
SSHD_MATCH_CHECK_SH = r'''set -eu
cfg=$1; base=$2
[ -f "$cfg" ] || { echo "missing sshd config: $cfg" >&2; exit 1; }
canon() {
    _p=$1; _hops=0
    while [ -L "$_p" ]; do
        _hops=$((_hops + 1))
        [ "$_hops" -le 16 ] || { echo "symlink loop: $1" >&2; exit 1; }
        _t=$(readlink "$_p") || { echo "readlink failed: $_p" >&2; exit 1; }
        case $_t in /*) _p=$_t ;; *) _p=$(dirname "$_p")/$_t ;; esac
    done
    _d=$(CDPATH='' cd -P -- "$(dirname "$_p")" 2>/dev/null && pwd -P) || { echo "cannot resolve dir: $_p" >&2; exit 1; }
    printf '%s/%s\n' "${_d%/}" "$(basename "$_p")"
}
visited=""
queue="0	$cfg"
while [ -n "$queue" ]; do
    entry=${queue%%"
"*}
    case $queue in *"
"*) queue=${queue#*"
"} ;; *) queue="" ;; esac
    [ -n "$entry" ] || continue
    depth=${entry%%"	"*}
    f=${entry#*"	"}
    [ "$depth" -le 16 ] || { echo "Include nesting exceeds 16 levels at $f" >&2; exit 1; }
    if [ -L "$f" ] && [ ! -e "$f" ]; then echo "dangling symlink: $f" >&2; exit 1; fi
    if [ -d "$f" ]; then continue; fi
    if [ ! -f "$f" ]; then echo "non-regular sshd config target: $f" >&2; exit 1; fi
    [ -r "$f" ] || { echo "unreadable config: $f" >&2; exit 1; }
    c=$(canon "$f")
    case $c in *"
"*) echo "config path contains newline: $c" >&2; exit 1 ;; esac
    if [ -n "$visited" ] && printf '%s\n' "$visited" | LC_ALL=C grep -qxF -- "$c"; then
        continue
    fi
    if [ -n "$visited" ]; then
        visited="$visited
$c"
    else
        visited="$c"
    fi
    raw_len=$(wc -c <"$f")
    clean_len=$(LC_ALL=C tr -d '\000' <"$f" | wc -c)
    [ "$raw_len" -eq "$clean_len" ] || { echo "config contains NUL byte: $f" >&2; exit 1; }
    awk_rc=0
    incs=$(LC_ALL=C awk '
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
        }' "$f") || awk_rc=$?
    if [ "$awk_rc" -eq 2 ]; then printf '%s\n' "$incs"; exit 2; fi
    if [ "$awk_rc" -ne 0 ]; then printf '%s\n' "$incs" >&2; exit 1; fi
    next_depth=$((depth + 1))
    set -f
    while [ -n "$incs" ]; do
        pat=${incs%%"
"*}
        case $incs in *"
"*) incs=${incs#*"
"} ;; *) incs="" ;; esac
        [ -n "$pat" ] || continue
        case $pat in /*) full=$pat ;; *) full="$base/$pat" ;; esac
        old_ifs=$IFS
        IFS=''
        set +f
        for matched in $full; do
            set -f
            IFS=$old_ifs
            case $matched in *"
"*) echo "config path contains newline: $matched" >&2; exit 1 ;; esac
            if [ ! -e "$matched" ] && [ ! -L "$matched" ]; then continue; fi
            if [ -L "$matched" ] && [ ! -e "$matched" ]; then echo "dangling symlink: $matched" >&2; exit 1; fi
            if [ -d "$matched" ]; then continue; fi
            if [ ! -f "$matched" ]; then echo "non-regular sshd config target: $matched" >&2; exit 1; fi
            if [ -n "$queue" ]; then
                queue="$queue
$next_depth	$matched"
            else
                queue="$next_depth	$matched"
            fi
        done
        set -f
        IFS=$old_ifs
    done
    set +f
done
'''


def sshd_connection_specs(user: str, ip: str) -> list[str]:
    """Connection specs for `sshd -T -C`: loopback + host-facing guest/client addresses, for
    both the login user and root."""
    users = [user] if user == "root" else [user, "root"]
    specs: list[str] = [f"user={u},host=localhost,addr=127.0.0.1" for u in users]
    extra_addrs: list[str] = []
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        addr = None
    if addr is not None and not addr.is_loopback:
        extra_addrs.append(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            gw = str(ipaddress.IPv4Address((int(addr) & 0xFFFFFF00) | 1))
            if gw != ip:
                extra_addrs.append(gw)
    for client_ip in extra_addrs:
        for u in users:
            specs.append(f"user={u},host={ip},addr={client_ip}")
    return specs


def sshd_key_only(r: Result) -> tuple[bool, str]:
    """Check 2e: does `sshd -T` show key-only login? (ok, evidence).

    macOS 27.2's sshd prints "PasswordAuthentication no", stock OpenSSH lowercase. Accept
    whole lines split on "\\n" only (never splitlines(): it also splits on \\x0b, \\x0c,
    \\x1c-\\x1e, U+0085, U+2028 and U+2029, which a quoted sshd value such as Banner can carry,
    so one printed line could fake a wanted one), no stripping, ASCII-only case folding, and
    require each checked key to appear exactly once (A7). Duplicate checked keys are counted
    before filtering non-ASCII values so a non-ASCII duplicate still fails closed (matching
    prep.sh). The caller must run ssh with raw_newlines=True: in text mode Python turns a lone
    CR into a newline before this sees it. A CR or NUL byte anywhere in the output fails closed."""
    key_counts: dict[str, int] = {k: 0 for k in SSHD_REQUIRED_EXACT}
    exact_counts: dict[str, int] = {k: 0 for k in SSHD_REQUIRED_EXACT}
    for ln in r.stdout.split("\n"):
        stripped_raw = ln.lstrip(" \t")
        if not stripped_raw:
            continue
        raw_key = re.split(r"[ \t=]", stripped_raw, maxsplit=1)[0]
        if raw_key.isascii():
            key = raw_key.lower()
            if key in SSHD_REQUIRED_EXACT:
                key_counts[key] += 1
                if ln.isascii() and ln.lower() in SSHD_REQUIRED_EXACT[key]:
                    exact_counts[key] += 1
    duplicates = sorted(k for k, c in key_counts.items() if c > 1)
    missing = []
    for k, allowed in sorted(SSHD_REQUIRED_EXACT.items()):
        if exact_counts[k] != 1:
            if len(allowed) == 1:
                missing.append(next(iter(allowed)))
            else:
                vals = "|".join(sorted(v.split(" ", 1)[1] for v in allowed))
                missing.append(f"{k} ({vals})")
    cr = "\r" in r.stdout
    nul = "\x00" in r.stdout
    ev = f"rc {r.rc}; missing {missing}"
    if duplicates:
        ev += f"; duplicate keys {duplicates}"
    if cr:
        ev += "; output contains a carriage return (read untranslated; it could fake or hide a line)"
    if nul:
        ev += "; output contains a NUL byte"
    return r.rc == 0 and not cr and not nul and not missing and not duplicates, ev


def check_sshd_key_only(ctx: Ctx, t: vmssh.Target) -> tuple[bool, str]:
    """Reject uncommented Match blocks and unsafe Include targets before running `sshd -T -C`
    across all required connection specs (so a FIFO or malicious Include target cannot hang sshd)."""
    mr = rssh(
        ctx,
        t,
        [
            "sudo",
            "-n",
            "/bin/sh",
            "-c",
            SSHD_MATCH_CHECK_SH,
            "sh",
            "/etc/ssh/sshd_config",
            "/etc/ssh",
        ],
        raw_newlines=True,
    )
    if mr.rc != 0 or mr.stdout.strip():
        detail = clip((mr.stdout + " " + mr.stderr).strip(), 300)
        return False, f"Match/Include check failed (rc {mr.rc}): {detail}"
    specs = sshd_connection_specs(t.user, t.ip)
    failures: list[str] = []
    for spec in specs:
        r = rssh(
            ctx,
            t,
            ["sudo", "-n", "/usr/sbin/sshd", "-T", "-C", spec],
            raw_newlines=True,  # sshd's bytes untranslated: see sshd_key_only
        )
        ok_s, ev_s = sshd_key_only(r)
        if not ok_s:
            failures.append(f"[{spec}] {ev_s}")
    if failures:
        return False, "; ".join(failures)
    return True, f"{len(specs)} specs ok (missing []); no uncommented Match blocks"


def wait_for_ssh(ctx: Ctx, vm: Vm, t: vmssh.Target, timeout: float = 300) -> float:
    start = ctx.monotonic()
    last = Result(255)

    def ready() -> bool:
        nonlocal last
        if not vm.alive():
            raise ToolError("tart run exited before ssh came up (see the run log)")
        last = rssh(ctx, t, ["true"], timeout=45)
        if last.rc != 0 and re.search(
            r"host key verification failed|identification has changed",
            last.stderr,
            re.IGNORECASE,
        ):
            raise ToolError("host key mismatch: " + clip(last.stderr, 300))
        return last.rc == 0

    if not wait_until(ctx, ready, timeout, 5):
        raise ToolError(f"ssh not ready after {timeout:.0f}s: {clip(last.stderr, 300)}")
    return ctx.monotonic() - start


def run_guest_script(
    ctx: Ctx, t: vmssh.Target, script: Path, args: list[str], tag: str
) -> str:
    """Stream one script into the guest and run it as root: one ssh session, no leftover file.

    `tag` only names the step in errors. Returns the script's stdout.
    """
    r = rssh(
        ctx,
        t,
        ["/bin/sh", "-c", RUN_SCRIPT_SH, "sh", *args],
        input_text=script.read_text(),
        timeout=1800,
    )
    if r.rc != 0:
        raise StepFail(
            f"{script.name} ({tag}) rc {r.rc}: {clip(r.stderr + r.stdout, 800)}"
        )
    return r.stdout


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ---------------------------------------------------------------- keys


def read_pubkey(path: Path) -> str:
    try:
        text = path.read_text()
    except OSError as e:
        raise Refusal(f"{path}: cannot read the public key: {e}") from e
    lines = [
        ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")
    ]
    if len(lines) != 1:
        raise Refusal(
            f"{path}: expected exactly one public key line, found {len(lines)}"
        )
    line = lines[0]
    if "PRIVATE KEY" in line or not re.match(
        r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-\S+|sk-\S+) [A-Za-z0-9+/=]+( .*)?$", line
    ):
        raise Refusal(f"{path}: not a single OpenSSH public key line")
    try:
        fingerprint(line)
    except ValueError as e:  # binascii.Error is a ValueError
        raise Refusal(f"{path}: key blob is not valid base64") from e
    return line


def fingerprint(pubkey_line: str) -> str:
    blob = base64.b64decode(pubkey_line.split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip(
        "="
    )


def parse_prep_hostkey(out: str) -> tuple[str, str]:
    """The key prep.sh printed inside the authenticated ssh session: ('ssh-ed25519', blob)."""
    found = HOSTKEY_LINE_RE.findall(out)
    if len(found) != 1:
        raise StepFail(
            f"prep.sh printed {len(found)} PREP-HOSTKEY lines, expected exactly one: {clip(out, 300)}"
        )
    kind, blob = found[0]
    try:
        fingerprint(f"{kind} {blob}")
    except ValueError as e:
        raise StepFail("PREP-HOSTKEY blob is not valid base64") from e
    return kind, blob


def keyscan_ed25519(ctx: Ctx, ip: str) -> str:
    r = ctx.run(["ssh-keyscan", "-t", "ed25519", "-T", "10", ip], timeout=60)
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "ssh-ed25519" and not line.startswith("#"):
            return parts[2]
    raise ToolError(
        f"ssh-keyscan returned no ed25519 key (rc {r.rc}): {clip(r.stderr, 300)}"
    )


def pin_host_key(ctx: Ctx, ip: str, dest: Path, authenticated: tuple[str, str]) -> str:
    """Pin the key prep.sh printed (authenticated); ssh-keyscan must agree, or nothing is pinned."""
    kind, blob = authenticated
    scanned = keyscan_ed25519(ctx, ip)
    if scanned != blob:
        raise StepFail(
            "ssh-keyscan answered with a different ed25519 key than prep.sh printed inside "
            f"the authenticated session ({fingerprint(f'{kind} {scanned}')} vs "
            f"{fingerprint(f'{kind} {blob}')}); nothing was pinned"
        )
    write_landed(dest, f"{vmssh.HOST_ALIAS} {kind} {blob}\n")
    return f"{kind} " + fingerprint(f"{kind} {blob}")


def kh_key_line_of(text: str) -> str | None:
    """The 'ssh-ed25519 <base64>' line of the first entry for our alias in known_hosts text."""
    for line in text.splitlines():
        parts = line.split()
        if (
            len(parts) >= 3
            and parts[0] == vmssh.HOST_ALIAS
            and parts[1] == "ssh-ed25519"
        ):
            return f"{parts[1]} {parts[2]}"
    return None


def kh_key_line(path: Path) -> str | None:
    """The 'ssh-ed25519 <base64>' line of the entry in a known_hosts file for our alias, if any."""
    try:
        return kh_key_line_of(path.read_text())
    except (OSError, ValueError):
        return None


def kh_fingerprint(path: Path) -> str | None:
    """Fingerprint of the ed25519 entry in a known_hosts file written for our alias, if any."""
    line = kh_key_line(path)
    try:
        return fingerprint(line) if line else None
    except ValueError:
        return None


class LandedNotDurable(OSError):
    """The write replaced its destination, but the directory could not be synced: the new text
    is in place and nothing says it will survive a power loss. Never "the write failed"."""


# macOS: fsync only reaches the drive's cache; F_FULLFSYNC makes the drive flush (APFS orders
# writes either way, but the intent marker must be on disk before anything is destroyed).
F_FULLFSYNC = getattr(fcntl, "F_FULLFSYNC", None) if sys.platform == "darwin" else None


def full_fsync(fd: int) -> None:
    if F_FULLFSYNC is not None:
        try:
            fcntl.fcntl(fd, F_FULLFSYNC)
            return
        except OSError as e:
            if e.errno not in (
                errno.ENOTSUP,
                errno.EOPNOTSUPP,
                errno.EINVAL,
                errno.ENOTTY,
            ):
                raise  # a real I/O error is not "unsupported": fsync could report success
    os.fsync(fd)


def atomic_write(dest: Path, text: str, mode: int = 0o600) -> None:
    """Write via a fresh mkstemp file in the same directory (fsync), then os.replace (no
    symlink follow), then fsync the directory. A failure before the replace leaves the
    destination as it was (OSError); one after it raises LandedNotDurable: the text is in
    place."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=dest.name + ".")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
            fh.flush()
            full_fsync(fh.fileno())  # the data is on disk before the rename can be
        os.chmod(tmp, mode)
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    try:
        dfd = os.open(dest.parent, os.O_RDONLY)
        try:
            full_fsync(dfd)  # and the rename is durable
        finally:
            os.close(dfd)
    except OSError as e:
        raise LandedNotDurable(
            f"{dest} was replaced but its directory could not be synced ({e})"
        ) from e


def write_landed(dest: Path, text: str, mode: int = 0o600) -> None:
    """atomic_write for files whose durability nobody depends on (scratch files, the summary,
    parked copies): a write that landed with its directory unsynced is a write that landed."""
    with contextlib.suppress(LandedNotDurable):
        atomic_write(dest, text, mode)


# ---------------------------------------------------------------- lock, signals


def _check_dir_ancestor(
    anc: Path, target_dir: Path, euid: int, *, label: str = "the state dir"
) -> None:
    """Verify one ancestor of a resolved directory via O_DIRECTORY|O_NOFOLLOW + fstat:
    must be a real directory owned by root or us, and not group/world writable unless sticky."""
    try:
        fd = os.open(anc, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EMLINK):
            raise Refusal(
                f"ancestor {anc} of {label} {target_dir} is a symlink "
                "(planted after resolution): refusing to follow it"
            ) from e
        if e.errno == errno.ENOTDIR:
            prefix = (
                f"cannot create the lock directory {target_dir}: "
                if label == "the lock directory"
                else ""
            )
            raise Refusal(
                f"{prefix}ancestor {anc} of {label} {target_dir} is not a directory"
            ) from e
        raise Refusal(
            f"cannot inspect ancestor {anc} of {label} {target_dir}: {e}"
        ) from e
    try:
        st = os.fstat(fd)
    finally:
        os.close(fd)
    if not stat.S_ISDIR(st.st_mode):
        raise Refusal(f"ancestor {anc} of {label} {target_dir} is not a directory")
    if st.st_uid not in (0, euid):
        raise Refusal(
            f"ancestor {anc} of {label} {target_dir} must be owned by root or you "
            f"(is uid {st.st_uid})"
        )
    if (st.st_mode & 0o022) and not (st.st_mode & stat.S_ISVTX):
        raise Refusal(
            f"ancestor {anc} of {label} {target_dir} must not be group or world "
            f"writable unless sticky (is uid {st.st_uid}, mode {st.st_mode & 0o777:o})"
        )


def _check_lock_dir(lock_dir: Path) -> None:
    """Ensure the lock/owner-marker directory and every ancestor up to `/` pass the same
    O_DIRECTORY|O_NOFOLLOW ownership/write checks as check_state_dir (using os.geteuid())."""
    if not lock_dir.is_absolute():
        raise Refusal(f"the lock directory {lock_dir} must be an absolute path")
    euid = os.geteuid()
    old = os.umask(0o077)
    try:
        for anc in reversed(lock_dir.parents):
            if not os.path.lexists(anc):
                try:
                    os.mkdir(anc, 0o700)
                except FileExistsError:
                    pass
                except OSError as e:
                    raise Refusal(
                        f"cannot create the lock directory {lock_dir}: {e}"
                    ) from e
            _check_dir_ancestor(anc, lock_dir, euid, label="the lock directory")
        if not os.path.lexists(lock_dir):
            try:
                os.mkdir(lock_dir, 0o700)
            except FileExistsError:
                pass
            except OSError as e:
                raise Refusal(
                    f"cannot create the lock directory {lock_dir}: {e}"
                ) from e
    finally:
        os.umask(old)
    try:
        fd = os.open(lock_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EMLINK, errno.ENOTDIR):
            raise Refusal(
                f"{lock_dir} (the driver lock and owner markers) must be a real directory"
            ) from e
        raise Refusal(f"cannot inspect {lock_dir}: {e}") from e
    try:
        st = os.fstat(fd)
    finally:
        os.close(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != euid or st.st_mode & 0o022:
        raise Refusal(
            f"{lock_dir} (the driver lock and owner markers) must be a real "
            f"directory owned by you and not group or world writable (is uid {st.st_uid}, "
            f"mode {st.st_mode & 0o777:o})"
        )


@contextlib.contextmanager
def driver_lock(ctx: Ctx):
    """One driver per account (one lock file under the account's passwd home, whatever
    --state-dir and the tart home say); never follows a symlink at the path."""
    # the owner marker beside the lock gates an unattended rebuild: nobody else may plant,
    # replace or delete it, so the directory (and every ancestor) is checked with O_NOFOLLOW.
    lock_dir = (
        ctx.lock_path.parent
        if ctx.lock_path.parent.is_symlink()
        else Path(os.path.realpath(ctx.lock_path.parent))
    )
    _check_lock_dir(lock_dir)
    check_state_dir(ctx)
    try:
        fd = os.open(ctx.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as e:
        raise Refusal(f"cannot open the driver lock {ctx.lock_path}: {e}") from e
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            raise Refusal(
                f"another state1_vm.py run holds the driver lock ({ctx.lock_path})"
            ) from e
        yield
    finally:
        os.close(fd)


def check_state_dir(ctx: Ctx) -> None:
    """The state dir holds the pin (known_hosts) and the record (golden.json) that `check`
    trusts: it must be a real directory of ours that is not group or world writable, and every
    ancestor of the resolved path up to `/` must be a real directory owned by root or us with
    no group/world write unless sticky (issue 82). Ctx resolved it once at startup (symlinks
    and relative paths included, so a later retarget or chdir does not move it); missing
    directories are created one component at a time as 0700 (umask 077) only after all
    existing ancestors are verified with O_DIRECTORY|O_NOFOLLOW."""
    if ctx.state_dir_refusal:
        raise Refusal(ctx.state_dir_refusal)
    if not ctx.state_dir.is_absolute():
        raise Refusal(f"the state dir {ctx.state_dir} must be an absolute path")
    euid = os.geteuid()
    old = os.umask(0o077)
    try:
        for anc in reversed(ctx.state_dir.parents):
            if not os.path.lexists(anc):
                try:
                    os.mkdir(anc, 0o700)
                except FileExistsError:
                    pass
                except OSError as e:
                    raise Refusal(
                        f"cannot create the state dir {ctx.state_dir}: {e}"
                    ) from e
            _check_dir_ancestor(anc, ctx.state_dir, euid, label="the state dir")
        if not os.path.lexists(ctx.state_dir):
            try:
                os.mkdir(ctx.state_dir, 0o700)
            except FileExistsError:
                pass
            except OSError as e:
                raise Refusal(
                    f"cannot create the state dir {ctx.state_dir}: {e}"
                ) from e
    finally:
        os.umask(old)
    try:
        fd = os.open(ctx.state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EMLINK, errno.ENOTDIR):
            raise Refusal(f"the state dir {ctx.state_dir} is not a directory") from e
        raise Refusal(f"cannot inspect the state dir {ctx.state_dir}: {e}") from e
    try:
        st = os.fstat(fd)
    finally:
        os.close(fd)
    if not stat.S_ISDIR(st.st_mode):
        raise Refusal(f"the state dir {ctx.state_dir} is not a directory")
    if st.st_uid != euid or st.st_mode & 0o022:
        raise Refusal(
            f"the state dir {ctx.state_dir} (the pinned known_hosts and golden.json) must be "
            f"a directory owned by you and not group or world writable (is uid "
            f"{st.st_uid}, mode {st.st_mode & 0o777:o})"
        )


SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


@contextlib.contextmanager
def signals_to_exception():
    def handler(signum, _frame):
        # Ignore every further signal first: a second one inside the cleanup must not
        # raise again and skip the summary or the VM removal.
        for s in SIGNALS:
            signal.signal(s, signal.SIG_IGN)
        raise Interrupted(signal.Signals(signum).name)

    old = {s: signal.signal(s, handler) for s in SIGNALS}
    try:
        yield
    finally:
        for s, h in old.items():
            signal.signal(s, h)


@contextlib.contextmanager
def signals_ignored():
    old = {s: signal.signal(s, signal.SIG_IGN) for s in SIGNALS}
    try:
        yield
    finally:
        for s, h in old.items():
            signal.signal(s, h)


# ---------------------------------------------------------------- guest assertions


def perm_ok(owner: str, group: str, mode: str) -> bool:
    """root:wheel and not group/world writable (checklist step 3's rule)."""
    return owner == "root" and group == "wheel" and (int(mode, 8) & 0o022) == 0


def ancestors_of(path: str) -> list[str]:
    """Every parent of an absolute path, nearest first, ending at '/'."""
    parents = [str(p) for p in PurePosixPath(path).parents]
    return parents or ["/"]


def check_root_owned(
    ctx: Ctx,
    t: vmssh.Target,
    path: str,
    *,
    tree: bool = False,
    as_root: bool = False,
    no_symlinks: bool = False,
) -> tuple[bool, str]:
    """Step 3's rule on one path; with tree=True on everything under it as well.

    Every ancestor up to / must also be owned by root and not group/world writable: a
    writable parent lets its owner group rename the checked directory aside and put another
    tree in its place (python.org leaves Python.framework/Versions root:admin 775).
    as_root=True prefixes stat/find with `sudo -n` so trees containing 0700 root-only
    subdirectories (such as /opt/tendcf/var/libntech/{ppkeys,data}) are walked without
    Permission denied errors on stderr.
    """
    pfx = ["sudo", "-n"] if as_root else []
    r = rssh(ctx, t, [*pfx, "stat", "-f", "%Su:%Sg %Lp %Sp", path])
    m = re.fullmatch(r"(\S+):(\S+) ([0-7]+) (\S+)", r.stdout.strip())
    if r.rc != 0 or not m:
        return False, f"stat {path} failed (rc {r.rc}): {clip(r.stderr, 200)}"
    type_ok = not m[4].startswith("l") and (not tree or m[4].startswith("d"))
    ok = perm_ok(m[1], m[2], m[3]) and type_ok
    ev = f"{path} {m[1]}:{m[2]} {m[3]} {m[4]}"
    if not type_ok:
        ev += " (symlink or non-directory refused)"
    parents = ancestors_of(path)
    r = rssh(ctx, t, [*pfx, "stat", "-f", "%N %Su:%Sg %Lp %Sp", *parents])
    rows = [ln.rsplit(" ", 3) for ln in r.stdout.strip().splitlines()]
    seen = {}
    for row in rows:
        if len(row) == 4:
            seen[row[0]] = row
    bad_parents = []
    for par in parents:
        row = seen.get(par)
        pm = re.fullmatch(r"(\S+):(\S+)", row[1]) if row else None
        if (
            r.rc != 0
            or not row
            or not pm
            or not re.fullmatch(r"[0-7]+", row[2])
            or not row[3].startswith("d")
            or pm[1] != "root"
            or int(row[2], 8) & 0o022
        ):
            bad_parents.append(
                f"{par} {row[1] + ' ' + row[2] + ' ' + row[3] if row else '?'}"
            )
    parents_ok = not bad_parents
    ok = ok and parents_ok
    ev += (
        f"; {len(parents)} ancestors root-owned real dirs, no group/world write"
        if parents_ok
        else f"; ancestors not real root-owned dirs or writable (rc {r.rc}): {clip(', '.join(bad_parents) or r.stderr, 300)}"
    )
    # Check macOS ACLs on the target path and every ancestor (issue 78 adversary r3 low 3).
    acl_r = rssh(ctx, t, [*pfx, "/bin/ls", "-lde", path, *parents])
    acl_lines = [
        ln
        for ln in acl_r.stdout.splitlines()
        if re.match(r"^ \d+: ", ln) or re.match(r"^\S+\+\s", ln)
    ]
    acl_ok = acl_r.rc == 0 and not acl_lines
    ok = ok and acl_ok
    if not acl_ok:
        ev += (
            f"; ACL check failed (rc {acl_r.rc}): "
            f"{clip('; '.join(acl_lines) or acl_r.stderr or acl_r.stdout, 300)}"
        )
    if tree:
        tree_sh = TREE_CHECK_NO_LINKS_SH if no_symlinks else TREE_CHECK_SH
        r = rssh(ctx, t, [*pfx, "/bin/sh", "-c", tree_sh, "sh", path])
        offenders = r.stdout.strip()
        tree_ok = r.rc == 0 and not offenders and not r.stderr.strip()
        ok = ok and tree_ok
        ev += (
            "; whole tree root:wheel, no group/world write"
            if tree_ok
            else f"; tree check failed (rc {r.rc}): {clip(offenders or r.stderr, 300)}"
        )
    return ok, ev


def python_paths(image: dict) -> tuple[str, str]:
    """(the whole Python.framework, the interpreter): the root-owned check covers the whole
    framework (Versions/, Versions/Current and the top-level links), not just Versions/X.Y."""
    minor = image["python"]["version"].rsplit(".", 1)[0]
    return FRAMEWORK_ROOT, f"{FRAMEWORK_ROOT}/Versions/{minor}/bin/python{minor}"


class Mdutil(NamedTuple):
    ok: bool
    evidence: str
    polls: int
    waited: float
    listing: str = ""


def mdutil_volumes_problem(text: str) -> str | None:
    """None if `mdutil -a -s` output is only volume headers, each followed by exactly one
    `Indexing disabled.` line, with `/:` and `/System/Volumes/Data:` among the headers; else
    what is wrong.

    A header is a line starting with "/", ending in ":", and containing no tab (so no leading
    blank either); a status line has a leading space or tab. The caller runs ssh with
    raw_newlines=True (no universal-newline translation) and lines are split on "\\n" only; any
    line holding a control character other than tab (CR, FF, VT, NUL, other C0, or DEL) is
    rejected as unexpected before blank, header or status matching. prep.sh applies the same
    rule (including NUL, via a temp file + LC_ALL=C tr before LC_ALL=C awk).
    """
    hdr: str | None = None
    seen = False
    headers: list[str] = []
    for ln in text.split("\n"):
        if any((ord(c) < 0x20 and c != "\t") or ord(c) == 0x7F for c in ln):
            return f"unexpected line {ln!r}"
        if all(c in " \t" for c in ln):
            continue
        if ln[0] in " \t":
            if ln.strip(" \t") != "Indexing disabled.":
                return f"unexpected line {ln!r}"
            if hdr is None:
                return f"status before any volume: {ln!r}"
            if seen:
                return f"two statuses for {hdr}"
            seen = True
        elif ln.startswith("/") and ln.endswith(":") and "\t" not in ln:
            if hdr is not None and not seen:
                return f"no status for {hdr}"
            hdr, seen = ln, False
            headers.append(ln)
        else:
            return f"unexpected line {ln!r}"
    if hdr is not None and not seen:
        return f"no status for {hdr}"
    if not headers:
        return "no volume listed"
    if "/:" not in headers:
        return "no / volume listed"
    if "/System/Volumes/Data:" not in headers:
        return "no /System/Volumes/Data volume listed"
    return None


def _mdutil_done(
    ok: bool, text: str, why: str, note: str, polls: int, waited: float
) -> Mdutil:
    clipped = clip(text, 300)
    return Mdutil(ok, f"{clipped}{why}; {note}", polls, waited, clipped)


def mdutil_off(ctx: Ctx, t: vmssh.Target) -> Mdutil:
    """`mdutil -a -s` says indexing is off on every volume, after a bounded settle.

    Runs ssh with raw_newlines=True so CR and CRLF reach mdutil_volumes_problem untranslated
    and fail as unexpected lines (along with any other control character besides tab). Each
    poll, in this order: "Indexing enabled" anywhere (stdout and stderr together) fails at once;
    kMDConfigSearchLevelTransitioning anywhere is asked again every MDUTIL_SETTLE_INTERVAL
    seconds, whatever mdutil's exit status was (it was never recorded), until
    MDUTIL_SETTLE_TIMEOUT seconds of real time have passed (so about that plus one command);
    then a non-0 exit fails; then mdutil_volumes_problem must find nothing. The evidence carries
    every poll's exit status, and the polls and seconds are returned as values.
    """
    start = ctx.monotonic()
    polls = 0
    rcs: list[int] = []
    while True:
        r = rssh(
            ctx,
            t,
            ["sudo", "-n", "mdutil", "-a", "-s"],
            raw_newlines=True,  # mdutil's bytes untranslated: see mdutil_volumes_problem
        )
        polls += 1
        rcs.append(r.rc)
        waited = ctx.monotonic() - start
        # Stderr is merged into the same volume-list check, so any non-volume stderr text
        # fails 2g on purpose (fail closed; real mdutil on macOS 27.2 printed nothing to
        # stderr on a pass).
        text = r.stdout
        if r.stderr:
            text += ("" if text.endswith("\n") or not text else "\n") + r.stderr
        note = f"rc={r.rc} polls={polls} waited={waited:.0f}s rcs={rcs}"

        if "Indexing enabled" in text:
            return _mdutil_done(False, text, "", note, polls, waited)
        if MDUTIL_TRANSITIONING in text:
            if waited + MDUTIL_SETTLE_INTERVAL > MDUTIL_SETTLE_TIMEOUT:
                return _mdutil_done(
                    False, text, " (still transitioning)", note, polls, waited
                )
            ctx.sleep(MDUTIL_SETTLE_INTERVAL)
            continue
        if r.rc != 0:
            return _mdutil_done(
                False, text, f" (mdutil exited {r.rc})", note, polls, waited
            )
        problem = mdutil_volumes_problem(text)
        return _mdutil_done(
            problem is None,
            text,
            f" ({problem})" if problem else "",
            note,
            polls,
            waited,
        )


def updates_off(ctx: Ctx, t: vmssh.Target) -> tuple[bool, str]:
    """Automatic download and install keys read 0; `softwareupdate` still runs.

    Pass = every key prep.sh writes (UPDATES_KEYS) reads 0 with exit 0, and `sudo -n
    softwareupdate --schedule` exits 0. The keys are preferences that persist; nobody observed
    softwareupdated obeying them. The schedule rc only shows the command still runs. Its text
    (stdout and stderr together) is evidence only and never decides: automatic update checking
    stays on (issue 70 addendum 4, PR 90: four root-script methods did not turn it off, the
    System Settings toggle is untried), so "turned on" is the expected answer. Nothing here
    reads AutomaticCheckEnabled.
    """
    r = rssh(ctx, t, ["sudo", "-n", "softwareupdate", "--schedule"])
    said = (r.stdout + "\n" + r.stderr).strip()
    ok = r.rc == 0
    ev = [f"schedule (info): rc {r.rc}: {clip(said, 200)!r}"]
    plist = "/Library/Preferences/com.apple.SoftwareUpdate"
    for key in UPDATES_KEYS:
        r = rssh(ctx, t, ["defaults", "read", plist, key])
        good = r.rc == 0 and r.stdout.strip() == "0"
        ok &= good
        if good:
            ev.append(f"{key}=0")
        else:
            out, err = r.stdout.strip(), r.stderr.strip()
            src = "stderr " if not out and err else ""
            got = clip(out or err, 80)
            ev.append(
                f"{key}=rc {r.rc} {src}{got!r}" if r.rc else f"{key}={src}{got!r}"
            )
    return ok, " ".join(ev)


def persistent_assertions(
    ctx: Ctx, image: dict, t: vmssh.Target, facts: dict | None = None
) -> list[tuple[str, str, bool, str]]:
    """Checks that must hold on a fresh clone and again after a reboot: (id, name, ok, evidence)."""
    out: list[tuple[str, str, bool, str]] = []

    r = rssh(ctx, t, ["sw_vers", "-productVersion"])
    ver = r.stdout.strip()
    out.append(
        (
            "2a",
            "sw_vers is macOS " + image["expect_macos_major"],
            r.rc == 0 and ver.startswith(image["expect_macos_major"] + "."),
            ver or r.stderr,
        )
    )

    r = rssh(ctx, t, ["csrutil", "status"])
    out.append(
        (
            "2b",
            "csrutil status: SIP enabled",
            r.rc == 0 and re.search(r"status: enabled\.?\s*$", r.stdout) is not None,
            r.stdout or r.stderr,
        )
    )

    r = rssh(ctx, t, ["sudo", "-n", "sh", "-c", "id -u"])
    out.append(
        (
            "2c",
            "sudo -n sh -c 'id -u' is 0",
            r.rc == 0 and r.stdout.strip() == "0",
            f"rc {r.rc} out {r.stdout.strip()!r}",
        )
    )

    r = rssh(ctx, t, ["spctl", "--status"])
    out.append(
        (
            "2d",
            "Gatekeeper enabled",
            r.rc == 0 and "assessments enabled" in r.stdout,
            r.stdout or r.stderr,
        )
    )

    ok_2e, ev_2e = check_sshd_key_only(ctx, t)
    out.append(("2e", "sshd effective config: key login only", ok_2e, ev_2e))

    md = mdutil_off(ctx, t)
    out.append(("2g", "Spotlight indexing off", md.ok, md.evidence))
    if facts is not None:
        facts["mdutil"] = md

    ok_2h, ev_2h = updates_off(ctx, t)
    out.append(("2h", "automatic download and install off", ok_2h, ev_2h))

    fw, py = python_paths(image)
    r = rssh(ctx, t, [py, "-c", "import sys; print('%d.%d.%d' % sys.version_info[:3])"])
    pyver = r.stdout.strip()
    perm_ok_, perm_ev = check_root_owned(ctx, t, fw, tree=True)
    out.append(
        (
            "2i",
            f"python {image['python']['version']} system-wide, root:wheel, not group/world writable",
            pyver == image["python"]["version"] and perm_ok_,
            f"{pyver or r.stderr}; {perm_ev}",
        )
    )

    # Screen Sharing: the vanilla image has it on with the published admin password, a
    # network login that bypasses the pinned ssh key. Off in the launchd database, and
    # nothing listening on 5900.
    r = rssh(ctx, t, ["sudo", "-n", "launchctl", "print-disabled", "system"])
    out.append(
        (
            "2j",
            "Screen Sharing (com.apple.screensharing) disabled",
            r.rc == 0
            and re.search(
                r'"com\.apple\.screensharing"\s*=>\s*(disabled|true)\b', r.stdout
            )
            is not None,
            f"rc {r.rc}; "
            + (
                "disabled entry present"
                if re.search(
                    r'"com\.apple\.screensharing"\s*=>\s*(disabled|true)', r.stdout
                )
                else "no disabled entry for com.apple.screensharing"
            ),
        )
    )
    r = rssh(ctx, t, ["netstat", "-an", "-p", "tcp"])
    listening = [
        ln for ln in r.stdout.splitlines() if re.search(r"[.:]5900\s.*LISTEN", ln)
    ]
    out.append(
        (
            "2k",
            "nothing listening on tcp 5900",
            r.rc == 0 and bool(r.stdout.strip()) and not listening,
            f"rc {r.rc}; " + (listening[0].strip() if listening else "no listener"),
        )
    )
    # The console password is no longer the vanilla image's published "admin". Only the
    # wrong-password result, by code (-14090, eDSAuthFailed), counts as proof: every other
    # dscl result (disabled or expired account, no directory, unparseable output, ssh's own
    # 255) must not read as "the password was changed". A missing user is not another code on
    # macOS 27.2: it also prints -14090 eDSAuthFailed (observed with a nonexistent name), so
    # this step does not prove the account exists; the key login as admin does. No sudo:
    # -authonly only verifies a credential.
    r = rssh(ctx, t, ["dscl", ".", "-authonly", "admin", "admin"])
    refused = r.rc not in (0, 255) and dscl_auth_failed(r.stdout + r.stderr)
    out.append(
        (
            "2l",
            "console password is not the vanilla 'admin' (randomised in prep.sh)",
            bool(refused),
            f"rc {r.rc}; "
            + (
                "dscl -authonly admin admin: -14090 eDSAuthFailed"
                if refused
                else clip((r.stdout + r.stderr).strip() or "no failure reported", 200)
            ),
        )
    )
    return out


# dscl prints a failure as "... failed. (-14090, eDSAuthFailed)" or "<dscl_cmd> DS Error:
# -14090 (eDSAuthFailed)" (forum and vendor threads; not run here).
DSCL_CODE_RES = (
    re.compile(r"\((-?\d+),\s*(eDS\w+)\)"),
    re.compile(r"DS Error:\s*(-?\d+)\s*\((eDS\w+)\)"),
)


def dscl_auth_failed(text: str) -> bool:
    """True only when the output names the wrong-password code and no other code.

    -14090 eDSAuthFailed is "the credential was rejected". Any other code (eDSRecordNotFound,
    eDSAuthAccountDisabled, eDSAuthPasswordExpired, ...) or output with no code is not proof
    that the vanilla password is dead, so it is False."""
    pairs = {m for rx in DSCL_CODE_RES for m in rx.findall(text)}
    names = set(re.findall(r"eDS\w+", text))  # any other name anywhere, as prep.sh does
    return pairs == {("-14090", "eDSAuthFailed")} and names == {"eDSAuthFailed"}


def refused_password_login(ctx: Ctx, ip: str, known_hosts: str) -> str:
    """Password login must be refused by the server, not merely fail.

    A server that still offers `password` or `keyboard-interactive` answers a wrong or
    missing password with "Permission denied (publickey,password,...)": that must fail the
    step, so the result does not depend on whether the bootstrap password is right.
    """
    r = rssh(
        ctx, vmssh.Target(ip, known_hosts, auth="password", no_agent=True), ["true"]
    )
    m = re.search(r"Permission denied \(([^)]*)\)", r.stderr)
    if r.rc == 0 or m is None:
        raise StepFail(
            f"password login was not refused as expected (rc {r.rc}): {clip(r.stderr, 300)}"
        )
    offered = {x.strip() for x in m[1].split(",")}
    if offered & {"password", "keyboard-interactive"}:
        raise StepFail(
            f"the server still offers {sorted(offered & {'password', 'keyboard-interactive'})}: "
            + clip(r.stderr, 300)
        )
    return "password login refused, methods offered: " + ",".join(sorted(offered))


# ---------------------------------------------------------------- renderer / launchd checks


def verify_local_tarball(tarball: Path, sha256_path: Path) -> str:
    """Verify a local PR 95 tarball against its .sha256 file before cloning a VM."""
    if not tarball.is_file():
        raise Refusal(f"tarball not found: {tarball}")
    if not sha256_path.is_file():
        raise Refusal(f"sha256 file not found: {sha256_path}")
    try:
        lines = [ln.strip() for ln in sha256_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except (OSError, UnicodeDecodeError) as e:
        raise Refusal(f"cannot read sha256 file {sha256_path}: {e}") from e
    if len(lines) != 1:
        raise Refusal(
            f"sha256 file {sha256_path} must contain exactly one line (found {len(lines)})"
        )
    m = SHA256_LINE_RE.fullmatch(lines[0])
    if not m:
        raise Refusal(f"sha256 file {sha256_path} is not a valid sha256 line")
    expected = m.group(1).lower()
    named = Path(m.group(2)).name
    if named != tarball.name:
        raise Refusal(
            f"sha256 file {sha256_path} names {named!r}, expected {tarball.name!r}"
        )
    h = hashlib.sha256()
    try:
        with tarball.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError as e:
        raise Refusal(f"cannot read tarball {tarball}: {e}") from e
    actual = h.hexdigest()
    if actual != expected:
        raise Refusal(
            f"tarball sha256 mismatch for {tarball.name}: expected {expected}, got {actual}"
        )
    return actual


def read_fork_core_sha(pin_path: Path = FORK_PIN_JSON) -> str:
    """Read the 40-char core commit SHA from overlay/fork.json."""
    try:
        doc = json.loads(pin_path.read_text(encoding="utf-8"))
        core = doc["core"]["commit"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as e:
        raise Refusal(f"{pin_path}: cannot read fork core sha: {e}") from e
    if not isinstance(core, str) or not re.fullmatch(r"[0-9a-f]{40}", core):
        raise Refusal(f"{pin_path}: bad core sha: {core!r}")
    return core


def verify_artifact_run_provenance(ctx: Ctx, run_id: str) -> None:
    """Confirm the GitHub Actions run belongs to frdminc/tendcf's macOS fork build, not a fork PR."""
    r = ctx.run(
        ["gh", "api", f"repos/{GH_REPO}/actions/runs/{run_id}"],
        timeout=60,
    )
    if r.rc != 0:
        raise ToolError(
            f"gh api run provenance check for {run_id} failed (rc {r.rc}): "
            f"{clip(r.stderr or r.stdout, 300)}"
        )
    try:
        meta = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        raise ToolError(f"gh api run {run_id} returned non-JSON: {e}") from e
    if not isinstance(meta, dict):
        raise ToolError(f"gh api run {run_id} did not return a JSON object")
    head_repo = ((meta.get("head_repository") or {}).get("full_name") or "").strip()
    if head_repo != GH_REPO:
        raise Refusal(
            f"artifact run {run_id} head_repository is {head_repo!r}, expected {GH_REPO!r}"
        )
    event = str(meta.get("event") or "")
    if event in ("pull_request", "pull_request_target") or not event:
        raise Refusal(
            f"artifact run {run_id} has disallowed event {event!r} (refusing PR runs)"
        )
    wf_name = str(meta.get("name") or "")
    wf_path = str(meta.get("path") or "")
    if wf_name != "macOS fork build" and not wf_path.endswith("/macos-fork-build.yml"):
        raise Refusal(
            f"artifact run {run_id} is from unexpected workflow {wf_name!r} ({wf_path!r})"
        )


def download_artifact_run(
    ctx: Ctx, run_id: str, dest: Path
) -> tuple[Path, Path, str]:
    """Verify provenance, download the PR 95 macOS fork tarball + .sha256, and verify sha256."""
    if not RUN_ID_RE.fullmatch(run_id):
        raise Refusal(f"--artifact-run must be a numeric GitHub run id, got {run_id!r}")
    verify_artifact_run_provenance(ctx, run_id)
    core = read_fork_core_sha()
    artifact_name = f"tendcf-fork-macos-arm64-{core}"
    dest.mkdir(parents=True, exist_ok=True)
    r = ctx.run(
        [
            "gh",
            "run",
            "download",
            run_id,
            "-R",
            GH_REPO,
            "-n",
            artifact_name,
            "-D",
            str(dest),
        ],
        timeout=600,
    )
    if r.rc != 0:
        raise ToolError(
            f"gh run download {run_id} ({artifact_name}) failed (rc {r.rc}): "
            f"{clip(r.stderr or r.stdout, 300)}"
        )
    tarball = dest / f"{artifact_name}.tar.gz"
    sha_path = dest / f"{artifact_name}.tar.gz.sha256"
    digest = verify_local_tarball(tarball, sha_path)
    return tarball, sha_path, digest


def build_stage_bundle(tarball: Path, sha_path: Path) -> bytes:
    """Pack installer, policy tree, darwin canary data, tarball and .sha256 into an in-memory tar.gz."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        def add_file(src: Path, arcname: str, mode: int) -> None:
            data = src.read_bytes()
            ti = tarfile.TarInfo(name=arcname)
            ti.size = len(data)
            ti.mode = mode
            ti.uid = 0
            ti.gid = 0
            ti.uname = "root"
            ti.gname = "wheel"
            ti.mtime = 0
            tf.addfile(ti, io.BytesIO(data))

        add_file(DARWIN_INSTALLER, "tendcf-install.sh", 0o755)
        add_file(tarball, f"artifact/{tarball.name}", 0o644)
        add_file(sha_path, f"artifact/{sha_path.name}", 0o644)
        for p in sorted(POLICY_DIR.rglob("*")):
            if p.is_file():
                rel = p.relative_to(POLICY_DIR).as_posix()
                add_file(p, f"policy/{rel}", 0o644)
        add_file(
            DARWIN_CANARY_DIR / "host_specific.json",
            "canary/host_specific.json",
            0o644,
        )
        add_file(
            DARWIN_CANARY_DIR / "host_specific-absent.json",
            "canary/host_specific-absent.json",
            0o644,
        )
    return buf.getvalue()


def stage_renderer_bundle(
    ctx: Ctx, t: vmssh.Target, tarball: Path, sha_path: Path
) -> str:
    """Stream the installer + artifact + policy + canary bundle into a fresh guest temp dir."""
    bundle = build_stage_bundle(tarball, sha_path)
    r = rssh(
        ctx,
        t,
        ["/bin/sh", "-c", STAGE_UPLOAD_SH],
        input_bytes=bundle,
        timeout=300,
    )
    guest_dir = r.stdout.strip()
    if r.rc != 0 or not GUEST_STAGE_RE.fullmatch(guest_dir):
        raise StepFail(
            f"failed to stage installer bundle in guest (rc {r.rc}): "
            f"{clip(r.stderr or r.stdout, 300)}"
        )
    return guest_dir


def parse_launchctl_print(text: str) -> dict[str, object]:
    """Extract state, program, pid, path and arguments from `launchctl print system/<label>`."""
    info: dict[str, object] = {
        "state": None,
        "program": None,
        "pid": None,
        "path": None,
        "arguments": [],
    }
    in_args = False
    args: list[str] = []
    for raw in text.splitlines():
        if in_args:
            if raw == "\t}":
                in_args = False
                continue
            s = raw.strip()
            if s:
                args.append(s)
            continue
        if raw == "\targuments = {":
            in_args = True
            continue
        m = re.match(r"^\t(state|program|path) = (.+)$", raw)
        if m:
            info[m.group(1)] = m.group(2).strip()
            continue
        m_pid = re.match(r"^\tpid = (\d+)$", raw)
        if m_pid:
            info["pid"] = int(m_pid.group(1))
    info["arguments"] = args
    return info


def check_execd_running(ctx: Ctx, t: vmssh.Target) -> tuple[bool, str]:
    """Verify org.tendcf.execd is loaded in system domain, running, and owned by root."""
    r = rssh(ctx, t, ["sudo", "-n", "/bin/launchctl", "print", f"system/{EXECD_LABEL}"])
    if r.rc != 0:
        return (
            False,
            f"launchctl print system/{EXECD_LABEL} failed (rc {r.rc}): {clip(r.stderr or r.stdout, 200)}",
        )
    info = parse_launchctl_print(r.stdout)
    pid = info["pid"]
    if info["program"] != EXECD_PROG:
        return (
            False,
            f"{EXECD_LABEL} program is {info['program']!r}, expected {EXECD_PROG!r}",
        )
    if info["state"] != "running" or not isinstance(pid, int):
        return (
            False,
            f"{EXECD_LABEL} not running (state={info['state']!r}, pid={pid!r})",
        )
    ps = rssh(ctx, t, ["ps", "-o", "user=,comm=", "-p", str(pid)])
    line = ps.stdout.strip()
    parts = line.split(None, 1)
    if ps.rc != 0 or len(parts) != 2:
        return (
            False,
            f"ps -p {pid} failed (rc {ps.rc}): {clip(ps.stderr or ps.stdout, 200)}",
        )
    user, comm = parts[0], parts[1].strip()
    if user != "root" or Path(comm).name != "cf-execd":
        return (
            False,
            f"{EXECD_LABEL} pid {pid} is user={user!r} comm={comm!r}, expected root / cf-execd",
        )
    return True, f"{EXECD_LABEL} loaded, state=running, pid={pid}, user=root, comm={comm}"


def guest_file_sha256(ctx: Ctx, t: vmssh.Target, path: str) -> str:
    r = rssh(ctx, t, ["sudo", "-n", "/usr/bin/shasum", "-a", "256", path])
    parts = r.stdout.strip().split()
    if r.rc != 0 or not parts or not re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
        raise StepFail(
            f"shasum {path} failed (rc {r.rc}): {clip(r.stderr or r.stdout, 200)}"
        )
    return parts[0].lower()


def check_plist_perms_and_lint(
    ctx: Ctx, t: vmssh.Target, path: str, *, check_no_backup: bool = False
) -> str:
    r = rssh(
        ctx,
        t,
        [
            "sudo",
            "-n",
            "/bin/sh",
            "-c",
            'test -f "$1" && ! test -L "$1" && /usr/bin/stat -f "%Su:%Sg %Lp" "$1"',
            "sh",
            path,
        ],
    )
    meta = r.stdout.strip()
    if r.rc != 0 or meta != "root:wheel 644":
        raise StepFail(
            f"{path} must be a regular file root:wheel 644 (rc {r.rc}, got {meta!r}): "
            f"{clip(r.stderr, 200)}"
        )
    lint = rssh(ctx, t, ["sudo", "-n", "/usr/bin/plutil", "-lint", path])
    if lint.rc != 0:
        raise StepFail(
            f"plutil -lint {path} failed (rc {lint.rc}): {clip(lint.stderr or lint.stdout, 200)}"
        )
    if check_no_backup:
        bk = rssh(
            ctx,
            t,
            ["sudo", "-n", "/bin/sh", "-c", '! test -e "$1.cf-before-edit"', "sh", path],
        )
        if bk.rc != 0:
            raise StepFail(f"unexpected backup file {path}.cf-before-edit present")
    return f"{path} {meta}, plutil -lint OK"


# ---------------------------------------------------------------- commands


def emit(summary: Summary, ctx: Ctx, summary_path: Path | None) -> None:
    text = json.dumps(summary.as_dict(), indent=2) + "\n"
    if summary_path:
        write_landed(summary_path, text, 0o644)
        ctx.err(f"summary written to {summary_path}")
    else:
        sys.stdout.write(text)
        sys.stdout.flush()


def refuse(summary: Summary, ctx: Ctx, args, msg: str) -> int:
    ctx.err("refused: " + msg)
    summary.add("refused", "precondition not met", "fail", msg)
    emit(summary, ctx, args.summary)
    return 2


def tart_version(ctx: Ctx) -> str:
    r = ctx.run(["tart", "--version"], timeout=30)
    return (
        r.stdout.strip().splitlines()[0]
        if r.rc == 0 and r.stdout.strip()
        else "unknown"
    )


def cmd_resolve(ctx: Ctx, args) -> int:
    summary = Summary("resolve", ctx.run_id)
    image = read_image_json(args.image)
    try:
        digest = resolve_digest(ctx, image)
    except ToolError as e:
        summary.add("resolve", "tag to digest", "fail", str(e))
    else:
        pinned = image.get("digest", "")
        summary.extra.update(
            repository=image["repository"],
            tag=image["tag"],
            digest=digest,
            pinned=pinned,
        )
        summary.add(
            "resolve",
            "tag to digest",
            "pass",
            f"{image['tag']} -> {digest}"
            + (
                ""
                if digest == pinned
                else f" (pinned: {pinned or 'none'}: the tag has moved or the pin is unset; the pin still decides)"
            ),
        )
    emit(summary, ctx, args.summary)
    return 0 if summary.ok else 1


def cmd_pull(ctx: Ctx, args) -> int:
    summary = Summary("pull", ctx.run_id)
    image = load_image(args.image)
    ref = image_ref(image)
    summary.extra["image"] = ref
    try:
        with driver_lock(ctx), signals_to_exception():
            try:
                if ref in oci_names(ctx):
                    summary.add(
                        "pull",
                        "pinned image in the OCI cache",
                        "pass",
                        f"already cached: {ref}",
                    )
                else:
                    log = ctx.logs() / f"pull-{ctx.run_id}.log"
                    r = ctx.run(
                        ["tart", "pull", ref], log_path=log
                    )  # resumable: re-run after an interruption
                    cached = r.rc == 0 and ref in oci_names(ctx)
                    summary.add(
                        "pull",
                        "pinned image in the OCI cache",
                        "pass" if cached else "fail",
                        f"rc {r.rc}; log {log}; {clip(r.stdout, 600)}",
                    )
            except ToolError as e:
                summary.add("pull", "pinned image in the OCI cache", "fail", str(e))
            except Interrupted as e:
                summary.add(
                    "pull",
                    "pinned image in the OCI cache",
                    "fail",
                    f"interrupted ({e}); re-run pull to resume",
                )
                emit(summary, ctx, args.summary)
                return 130
    except Refusal as e:
        return refuse(summary, ctx, args, str(e))
    emit(summary, ctx, args.summary)
    return 0 if summary.ok else 1


def keys_root(ctx: Ctx) -> Path:
    return ctx.state_dir / "keys"


def key_paths(ctx: Ctx, key_id: str) -> tuple[Path, Path]:
    """(private, public) key paths of one golden. The key id comes from golden.json or the
    run id, and becomes a path component, so it is validated first."""
    if not KEY_ID_RE.fullmatch(key_id) or key_id in (".", ".."):
        raise Refusal(f"unsafe key id {key_id!r}")
    d = keys_root(ctx) / key_id
    return d / "id_ed25519", d / "id_ed25519.pub"


def secure_dir(path: Path, what: str) -> None:
    """A real directory (never a symlink) owned by us with no group or world access.
    lstat, so a symlink to somewhere else (the operator's own ssh directory, say) is refused
    instead of followed."""
    try:
        st = path.lstat()
    except OSError as e:
        raise Refusal(f"{what} {path} is missing: {e}") from e
    if not stat.S_ISDIR(st.st_mode):
        raise Refusal(
            f"{what} {path} must be a real directory, not a symlink or a file"
        )
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise Refusal(
            f"{what} {path} must be owned by you with no group or world access "
            f"(is uid {st.st_uid}, mode {st.st_mode & 0o777:o})"
        )


def mint_keypair(
    ctx: Ctx, key_id: str, created: Callable[[], None] | None = None
) -> tuple[str, str]:
    """A fresh ed25519 key for one golden: private half 0600 in a 0700 directory under the
    state dir, outside the repo and unrelated to anyone's ~/.ssh. Returns (public line, private
    path). Never reuses an existing key: the directory must not exist. `created` is called
    right after this call made the key directory, so the caller removes only what it made."""
    priv, pub = key_paths(ctx, key_id)
    root = keys_root(ctx)
    ctx.state_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(FileExistsError):
        os.mkdir(root, 0o700)
    secure_dir(root, "keys directory")  # never chmod or follow a symlinked root
    try:
        os.mkdir(priv.parent, 0o700)  # exclusive
    except FileExistsError as e:
        raise ToolError(f"key directory {priv.parent} already exists") from e
    if created is not None:
        created()
    r = ctx.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            f"tendcf-state1-vm {key_id}",
            "-f",
            str(priv),
        ],
        timeout=60,
    )
    if r.rc != 0:
        raise ToolError(f"ssh-keygen failed (rc {r.rc}): {clip(r.stderr, 300)}")
    line = read_pubkey(pub)
    if not line.startswith("ssh-ed25519 "):
        raise ToolError(f"{pub}: ssh-keygen did not produce an ed25519 key")
    private_ok(priv)
    return line, str(priv)


def private_ok(priv: Path) -> None:
    """The private key must be a regular file we own, readable by nobody else, in a key
    directory and a keys directory that are real directories we own."""
    secure_dir(priv.parent.parent, "keys directory")
    secure_dir(priv.parent, "key directory")
    try:
        st = priv.lstat()
    except OSError as e:
        raise Refusal(f"private key {priv} is missing: {e}") from e
    if not stat.S_ISREG(st.st_mode):
        raise Refusal(f"private key {priv} is not a regular file")
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise Refusal(
            f"private key {priv} must be owned by you and mode 0600 (is {st.st_mode & 0o777:o})"
        )


def remove_key_dir(ctx: Ctx, key_id: str) -> str:
    d = key_paths(ctx, key_id)[0].parent
    try:
        secure_dir(keys_root(ctx), "keys directory")
        secure_dir(d, "key directory")
    except Refusal as e:
        return f"left in place: {e}"
    shutil.rmtree(d, ignore_errors=True)
    return f"{d}: still present" if os.path.lexists(d) else f"removed {d}"


def sweep_stale_keys(ctx: Ctx, keep: str) -> tuple[list[str], list[str]]:
    """Remove the private keys of every other (deleted or replaced) golden: (removed, failed).
    The keys directory must be a real directory we own (a symlinked root is never followed:
    Refusal). Only real directories are touched: a symlink or a stray file under keys/ is
    left alone. A name counts as removed only if it is really gone afterwards."""
    gone: list[str] = []
    failed: list[str] = []
    root = keys_root(ctx)
    if not os.path.lexists(root):
        return gone, failed
    secure_dir(root, "keys directory")
    for d in sorted(root.iterdir()):
        if d.name == keep or not KEY_ID_RE.fullmatch(d.name):
            continue
        try:
            st = d.lstat()
        except OSError:
            continue
        if not stat.S_ISDIR(
            st.st_mode
        ):  # a symlink or a stray file: not ours to remove
            continue
        try:
            secure_dir(d, "key directory")
        except Refusal as e:
            failed.append(f"{d.name} ({e})")
            continue
        shutil.rmtree(d, ignore_errors=True)
        (failed if os.path.lexists(d) else gone).append(
            f"{d.name} (still present after removal)" if os.path.lexists(d) else d.name
        )
    return gone, failed


def read_golden_record(ctx: Ctx) -> dict:
    """This state dir's golden.json as a dict; Refusal if there is no usable record."""
    rec_path = ctx.state_dir / "golden.json"
    try:
        rec = json.loads(rec_path.read_text())
        key_id, want = rec["key_id"], rec["authorized_key"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise Refusal(f"{rec_path}: no usable golden record ({e!r})") from e
    if not isinstance(key_id, str) or not isinstance(want, str):
        raise Refusal(f"{rec_path}: key_id and authorized_key must be strings")
    return rec


def golden_record(ctx: Ctx) -> tuple[str, str]:
    """(key_id, authorized_key fingerprint) from this state dir's golden.json; Refusal if
    there is no usable record."""
    rec = read_golden_record(ctx)
    return rec["key_id"], rec["authorized_key"]


# The owner marker. The tart golden is global to a tart home and the records are per
# --state-dir, so one file per golden name and tart home lives beside the driver lock (the
# lock directory is the passwd home's, whatever --state-dir says, so every state dir sees it):
# <passwd home>/.local/state/tendcf-state1-vm/golden-owner-<golden name>-<tart key>.json. It
# is a compare-only input: nothing in it ever reaches ssh.
OWNER_FINAL = "final"
OWNER_COMMITTING = "committing"
OWNER_MAX_BYTES = 64 * 1024


def owner_path(ctx: Ctx, golden: str) -> Path:
    if not NAME_RE.fullmatch(golden):
        raise Refusal(f"unsafe golden name {golden!r}")
    return (
        ctx.lock_path.parent / f"golden-owner-{golden}-{tart_key(ctx.tart_home)}.json"
    )  # type: ignore[union-attr]


def owner_state_dir(ctx: Ctx) -> str:
    return os.path.realpath(ctx.state_dir)


def bad_marker_state_dir(recorded: object) -> bool:
    """A marker `state_dir` that is a string but not an absolute, printable path: a torn or
    forged marker. Never stat'ed (a relative path would be the cwd) and never printed except
    with !r (a control character would reach the terminal)."""
    return isinstance(recorded, str) and (
        not os.path.isabs(recorded) or not recorded.isprintable()
    )


def same_state_dir(ctx: Ctx, recorded: object) -> bool:
    """The marker's state dir is this one: equal realpaths, else the same directory by
    os.path.samefile (APFS is case-insensitive: two spellings, one directory). A moved or
    renamed state dir is a different owner."""
    if not isinstance(recorded, str):
        return False
    if recorded == owner_state_dir(ctx):
        return True
    if bad_marker_state_dir(recorded):
        return False  # never stat a relative path out of a file: "." would be the cwd
    try:
        return os.path.samefile(recorded, ctx.state_dir)
    except OSError:
        return False


def read_owner_raw(path: Path) -> str | None:
    """The marker's text, None if there is no file. Refusal, never a hang, for anything but a
    regular file of ours of bounded size: opened with O_NOFOLLOW (a symlink is refused) and
    O_NONBLOCK (a FIFO does not block the open), then fstat'ed."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise Refusal(f"{path} cannot be opened ({e})") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refusal(f"{path} is not a regular file")
        if st.st_uid != os.getuid():
            raise Refusal(f"{path} is not owned by you (uid {st.st_uid})")
        chunks: list[bytes] = []
        size = 0
        while size <= OWNER_MAX_BYTES:
            chunk = os.read(fd, OWNER_MAX_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    if size > OWNER_MAX_BYTES:
        raise Refusal(f"{path} is larger than {OWNER_MAX_BYTES} bytes")
    try:
        return b"".join(chunks).decode()
    except ValueError as e:
        raise Refusal(f"{path} is not UTF-8 text ({e})") from e


def read_owner_file(path: Path) -> dict | None:
    """The marker as a dict, None if there is no file; Refusal for any defect."""
    raw = read_owner_raw(path)
    if raw is None:
        return None
    try:
        owner = json.loads(raw)
    except ValueError as e:
        raise Refusal(f"{path} is not JSON ({e})") from e
    if not isinstance(owner, dict):
        raise Refusal(f"{path} is JSON but not an object")
    return owner


def write_owner(
    ctx: Ctx,
    golden: str,
    key_id: str,
    host_key: str | None,
    state: str = OWNER_FINAL,
    dest: Path | None = None,
) -> None:
    """Write the marker (atomic: temp, fsync, rename, fsync of the directory). `committing`
    is the intent marker a commit writes before its first destructive step; `final` is the
    last write of the commit. `dest` parks a copy (the `.pending` file a hand finish moves)."""
    atomic_write(
        dest or owner_path(ctx, golden),
        json.dumps(
            {
                "golden": golden,
                "state_dir": owner_state_dir(ctx),
                "tart_home": ctx.tart_home,
                "key_id": key_id,
                "host_key": host_key,
                "state": state,
            },
            indent=2,
        )
        + "\n",
    )


def owner_refusal(ctx: Ctx, golden: str, rec: dict | None) -> str:
    """Empty when this state dir may replace the golden unasked, else why not (the text
    `golden` refuses with, and the hint `check` gives). That needs a final marker that names
    this golden, this state dir (same directory) and the key id and host key of this state
    dir's golden.json (`rec`, None if it has none). A commit writes a `committing` marker
    before its first destructive step and the `final` one last, so an agreeing final marker
    means the last commit to touch this golden finished, and it was ours. A missing marker
    (a golden from before markers), another state dir's, a commit that did not finish and
    one that disagrees with the record are all "not ours to replace unasked"."""
    path = owner_path(ctx, golden)
    hint = "pass --rebuild to replace it (this state dir then owns it)"
    try:
        owner = read_owner_file(path)
    except Refusal as e:
        return f"unreadable owner file: {e}; {hint}"
    if owner is None:
        return (
            f"{golden} has no owner file ({path}): it was built before owners were "
            f"recorded; {hint}"
        )
    if owner.get("golden") != golden:
        return f"{path} names golden {owner.get('golden')!r}, not {golden}; {hint}"
    here = owner_state_dir(ctx)
    done = owner.get("state") == OWNER_FINAL
    other = owner.get("state_dir")
    if not isinstance(other, str):
        return f"{path} is an owner file with no state_dir; {hint}"
    if bad_marker_state_dir(other):
        return (
            f"{path} names the state dir {other!r}, which is not an absolute printable "
            f"path: a torn or forged owner file; {hint}"
        )
    if not same_state_dir(ctx, other):
        return (
            f"{golden} is owned by state dir {other!r}, not this one ({here})"
            + ("" if done else " (its commit did not finish)")
            + f"; replacing it from here would break that state dir's logins ({path}); "
            f"{hint}. A moved or renamed state dir is a different owner"
        )
    if not isinstance(owner.get("tart_home"), str):
        return f"{path} has no tart_home (written by an earlier build of this change); {hint}"
    if owner["tart_home"] != ctx.tart_home:
        return (
            f"{path} was written for tart home {owner['tart_home']!r}, this run uses "
            f"{ctx.tart_home!r} (TART_HOME): the golden here is not the one that owner file "
            f"describes; {hint}"
        )
    if not done:
        return (
            f"{path}: a commit of {golden} by this state dir (key "
            f"{owner.get('key_id')!r}) did not finish, so the golden is the old or the "
            f"new build; {hint}"
        )
    if (
        rec is None
        or owner.get("key_id") != rec["key_id"]
        or owner.get("host_key") != rec.get("host_key")
    ):
        return (
            f"{path} names key {owner.get('key_id')!r} and host key "
            f"{owner.get('host_key')!r}, golden.json "
            + (
                f"names {rec['key_id']!r} and {rec.get('host_key')!r}"
                if rec
                else "is missing"
            )
            + f": the commit's writes did not all land; {hint}"
        )
    return ""


def takeover_hint(ctx: Ctx, golden: str) -> str:
    """What to tell an operator whose state dir has no record of an existing golden: never
    `--rebuild` over another state dir's golden without naming it."""
    try:
        owner = read_owner_file(owner_path(ctx, golden))
    except Refusal as e:
        return (
            f"it may belong to another state dir (its owner file is unreadable: {e}); "
            "`golden --rebuild` replaces it for every state dir that uses it"
        )
    other = owner.get("state_dir") if owner else None
    if (
        isinstance(other, str)
        and not bad_marker_state_dir(other)
        and not same_state_dir(ctx, other)
    ):
        return (
            f"it is owned by state dir {other!r} (use `--state-dir {shlex.quote(other)}`); "
            "`golden --rebuild` here would take it over and break that state dir's logins"
        )
    if owner is None:
        return (
            "it may belong to another state dir or predate records (no owner file); "
            "`golden --rebuild` replaces it for every state dir that uses it"
        )
    return "`golden --rebuild` replaces it"


def run_hint(ctx: Ctx, golden: str, rec: dict) -> str:
    """What to run when this state dir has a record but `check` would refuse the golden:
    plain `golden` rebuilds it unattended only for its owner."""
    why = owner_refusal(ctx, golden, rec)
    if not why:
        return "run `golden` (it rebuilds an owner's golden unattended; `golden --rebuild` forces it)"
    return f"`golden` will refuse: {why}"


def check_owner_refusal(ctx: Ctx, golden: str) -> tuple[str, str]:
    """For `check`: (refusal, note). Refuse early when a *final* marker positively says the
    golden is another state dir's, another tart home's or another key's. A commit that did
    not finish (a `committing` marker) proves nothing about whose login works, so the login
    decides and the note says what the marker says. A missing or unreadable marker is
    ignored: login is the proof for a golden from before markers, and this never blesses
    anything."""
    try:
        owner = read_owner_file(owner_path(ctx, golden))
    except Refusal:
        return "", ""
    if not owner:
        return "", ""
    final = owner.get("state") == OWNER_FINAL
    other = owner.get("state_dir")
    if bad_marker_state_dir(other):
        return (
            (
                f"the owner file names the state dir {other!r}, which is not an absolute "
                "printable path: a torn or forged owner file; fix it with `golden --rebuild`"
            ),
            "",
        )
    if isinstance(other, str) and not same_state_dir(ctx, other):
        if final:
            return (
                (
                    f"{golden} is owned by state dir {other!r}, not this one "
                    f"({owner_state_dir(ctx)}): this state dir's pin and key are not its pin "
                    f"and key, so `check` here would fail at ssh. Run "
                    f"`check --state-dir {shlex.quote(other)}`; `golden --rebuild` here would "
                    "take it over and break that state dir's logins"
                ),
                "",
            )
        return "", (
            f"a commit by {other!r} did not finish; the golden is the old or the new build"
        )
    if not final:
        return "", (
            f"a commit by this state dir (key {owner.get('key_id')!r}) did not finish; "
            "the golden is the old or the new build"
        )
    if not isinstance(owner.get("tart_home"), str):
        return (
            (
                "this owner file has no tart_home (written by an earlier build of this "
                "change); run `golden --rebuild`"
            ),
            "",
        )
    if owner["tart_home"] != ctx.tart_home:
        return (
            (
                f"the owner file was written for tart home {owner['tart_home']!r}, this run "
                f"uses {ctx.tart_home!r} (TART_HOME): the golden here is not the one it "
                "describes, so `check` would fail at ssh. Use the TART_HOME of the build, or "
                "`golden --rebuild` here"
            ),
            "",
        )
    try:
        rec = read_golden_record(ctx)
    except Refusal:
        return "", ""
    if owner.get("key_id") != rec["key_id"]:
        return (
            (
                f"the owner file names key {owner.get('key_id')!r}, golden.json names "
                f"{rec['key_id']!r}: this record describes another golden of this state "
                "dir's; `check` would fail at ssh. Run `golden --rebuild`"
            ),
            "",
        )
    return "", ""


def canonical_pin_blob(text: str) -> str | None:
    """The key blob if `text` is exactly the known_hosts text the driver writes, a single
    `<alias> ssh-ed25519 <base64>` line, else None. ssh honours every line of a file, patterns,
    hashed names, @cert-authority and @revoked included, so anything else is not "the pin"."""
    parts = text.split(" ")
    if len(parts) != 3 or parts[0] != vmssh.HOST_ALIAS or parts[1] != "ssh-ed25519":
        return None
    blob = parts[2].removesuffix("\n")
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", blob):
        return None
    try:
        fingerprint(f"ssh-ed25519 {blob}")
    except (ValueError, IndexError):
        return None
    if text != f"{vmssh.HOST_ALIAS} ssh-ed25519 {blob}\n":
        return None
    return blob


def golden_usable(
    ctx: Ctx, golden: str, rec: dict | None = None, hint: str | None = None
) -> str:
    """The one test of "this state dir can check its golden": golden.json parses, the pinned
    known_hosts file is exactly one canonical line holding our alias's ed25519 key, that key
    is the record's `host_key`, and the record's key is usable (golden_identity). Returns the
    private key path; Refusal otherwise. `check` refuses on it and `golden` rebuilds on it,
    so the two never disagree. (Whether this state dir may replace the golden is a separate
    test: owner_refusal.) `hint` replaces the "what to run" text ("" for `golden`, which
    rebuilds by itself and says so)."""
    if rec is None:
        try:
            rec = read_golden_record(ctx)
        except Refusal as e:
            raise Refusal(
                f"{e}; this state dir has no record of the golden: {takeover_hint(ctx, golden)}"
            ) from e
    again = run_hint(ctx, golden, rec) if hint is None else hint
    kh = ctx.state_dir / "known_hosts"
    try:
        kh_text = (
            kh.read_bytes().decode() if kh.is_file() else ""
        )  # no newline translation
    except (OSError, ValueError):
        kh_text = ""
    if kh_key_line_of(kh_text) is None:
        raise Refusal(
            f"{kh} is missing or has no pinned host key (written by golden){then(again)}"
        )
    blob = canonical_pin_blob(kh_text)
    if blob is None:
        raise Refusal(
            f"{kh} is not the single `{vmssh.HOST_ALIAS} ssh-ed25519 <key>` line the driver "
            f"writes (an extra line, pattern, hashed name, @cert-authority or @revoked entry "
            f"would change what ssh trusts){then(again)}"
        )
    pinned = fingerprint(f"ssh-ed25519 {blob}")
    host_key = rec.get("host_key")
    if host_key is None:
        raise Refusal(
            "golden.json has no host_key: a record from before host keys were "
            f"recorded{then(again)}"
        )
    if host_key != f"ssh-ed25519 {pinned}":
        # golden.json and known_hosts are two writes: a kill between them (or a hand-moved
        # .pending file) leaves one of them describing another golden
        raise Refusal(
            f"golden.json host_key {host_key!r} does not match the pin in {kh} "
            f"(ssh-ed25519 {pinned}): the two commit writes did not both land{then(again)}"
        )
    return golden_identity(ctx, rec, again)


def then(again: str) -> str:
    """ "; <hint>" or nothing when there is no hint (golden rebuilds by itself)."""
    return f"; {again}" if again else ""


def golden_identity(
    ctx: Ctx, rec: dict | None = None, again: str = "run `golden`"
) -> str:
    """The private key of the current golden, found through golden.json; Refusal otherwise.
    The private key itself is matched to the recorded fingerprint (its public half is derived
    with `ssh-keygen -y`, not read from the .pub file), so a key from another golden, a
    swapped private key or a hand-edited record is not silently used."""
    if rec is None:
        try:
            rec = read_golden_record(ctx)
        except Refusal as e:
            raise Refusal(f"{e}{then(again)}") from e
    key_id, want = rec["key_id"], rec["authorized_key"]
    priv, pub = key_paths(ctx, key_id)
    try:
        private_ok(priv)
    except Refusal as e:
        raise Refusal(f"{e}{then(again)}") from e
    # -P '' (an empty passphrase, never a prompt) and no controlling tty: a passphrase-
    # protected key (not one this driver minted) is a refusal, not a question on /dev/tty
    r = ctx.run(
        ["ssh-keygen", "-y", "-P", "", "-f", str(priv)], timeout=30, no_tty=True
    )
    derived = r.stdout.strip()
    if r.rc != 0 or not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+( .*)?", derived):
        raise Refusal(
            f"{priv}: ssh-keygen -y could not read the private key without a passphrase "
            f"(rc {r.rc}; a key with a passphrase is refused){then(again)}"
        )
    got = fingerprint(derived)
    pub_got = fingerprint(read_pubkey(pub))
    if got != want or pub_got != want:
        raise Refusal(
            f"{priv} is {got} (its .pub says {pub_got}), golden.json says {want}: "
            f"the key does not belong to this golden{then(again)}"
        )
    return str(priv)


def check_adopt_precondition(ctx: Ctx, golden: str, rec: dict) -> tuple[bool, str]:
    """Validate whether `check --adopt` may adopt `golden` for this state dir (issue 81,
    Ref: ANTIGRAVITY-12j). Returns (need_write, status):
      - (True, "missing") when no owner marker exists yet
      - (False, "already_final") when a final marker already matches this exact state dir
    Raises Refusal (exit 2) on any conflicting final marker, any committing marker, or any
    unreadable/malformed marker."""
    marker = owner_path(ctx, golden)
    try:
        owner = read_owner_file(marker)
    except Refusal as e:
        raise Refusal(
            f"cannot adopt {golden}: unreadable owner file ({e}); run `golden --rebuild`"
        ) from e
    if owner is None:
        return True, "missing"
    if owner.get("golden") != golden:
        raise Refusal(
            f"cannot adopt {golden}: {marker} names golden {owner.get('golden')!r}, not {golden}"
        )
    other = owner.get("state_dir")
    if not isinstance(other, str) or bad_marker_state_dir(other):
        raise Refusal(
            f"cannot adopt {golden}: {marker} has invalid state_dir {other!r}; "
            "run `golden --rebuild`"
        )
    state = owner.get("state")
    if state == OWNER_COMMITTING:
        raise Refusal(
            f"cannot adopt {golden} via `check --adopt`: {marker} has a committing marker "
            f"(a commit by {other!r} did not finish); run `golden --adopt` if this state dir's "
            "commit finished before the final marker, or `golden --rebuild`"
        )
    if state != OWNER_FINAL:
        raise Refusal(
            f"cannot adopt {golden}: {marker} has unexpected state {state!r}; "
            "run `golden --rebuild`"
        )
    if not same_state_dir(ctx, other):
        raise Refusal(
            f"cannot adopt {golden}: owned by state dir {other!r}, not this one "
            f"({owner_state_dir(ctx)}); use `--state-dir {shlex.quote(other)}` or "
            "`golden --rebuild`"
        )
    if not isinstance(owner.get("tart_home"), str) or owner["tart_home"] != ctx.tart_home:
        raise Refusal(
            f"cannot adopt {golden}: {marker} was written for tart home "
            f"{owner.get('tart_home')!r}, not {ctx.tart_home!r}; run `golden --rebuild`"
        )
    if owner.get("key_id") != rec["key_id"] or owner.get("host_key") != rec.get("host_key"):
        raise Refusal(
            f"cannot adopt {golden}: {marker} names key {owner.get('key_id')!r} and host key "
            f"{owner.get('host_key')!r}, disagreeing with golden.json ({rec['key_id']!r} / "
            f"{rec.get('host_key')!r}); run `golden --rebuild`"
        )
    return False, "already_final"


def adopt_committing_golden(
    ctx: Ctx, golden: str, names: set[str], summary: Summary
) -> None:
    """`golden --adopt` (issue 81, Ref: ANTIGRAVITY-12j): under the driver lock, promote an
    existing committing owner marker belonging to this exact state dir to final, after
    verifying the golden exists and its key_id and host_key match golden.json + known_hosts."""
    if golden not in names:
        raise Refusal(f"cannot adopt {golden}: {golden} does not exist in tart list")
    build = golden + "-build"
    if build in names:
        raise Refusal(
            f"cannot adopt {golden}: leftover build VM {build} exists in tart list "
            "(an un-renamed build may be newer than the existing golden); "
            "inspect/rename it or run `golden --rebuild`"
        )
    marker = owner_path(ctx, golden)
    try:
        owner = read_owner_file(marker)
    except Refusal as e:
        raise Refusal(
            f"cannot adopt {golden}: unreadable owner file ({e}); run `golden --rebuild`"
        ) from e
    if owner is None:
        raise Refusal(
            f"cannot adopt {golden} via `golden --adopt`: no owner file ({marker}); "
            "run `check --adopt` to adopt a marker-less golden or `golden --rebuild`"
        )
    if owner.get("golden") != golden:
        raise Refusal(
            f"cannot adopt {golden}: {marker} names golden {owner.get('golden')!r}, not {golden}"
        )
    other = owner.get("state_dir")
    if not isinstance(other, str) or bad_marker_state_dir(other):
        raise Refusal(
            f"cannot adopt {golden}: {marker} has invalid state_dir {other!r}; "
            "run `golden --rebuild`"
        )
    if not same_state_dir(ctx, other):
        raise Refusal(
            f"cannot adopt {golden}: {marker} belongs to state dir {other!r}, not this one "
            f"({owner_state_dir(ctx)}); use `--state-dir {shlex.quote(other)}` or "
            "`golden --rebuild`"
        )
    if not isinstance(owner.get("tart_home"), str) or owner["tart_home"] != ctx.tart_home:
        raise Refusal(
            f"cannot adopt {golden}: {marker} was written for tart home "
            f"{owner.get('tart_home')!r}, not {ctx.tart_home!r}; run `golden --rebuild`"
        )
    state = owner.get("state")
    if state not in (OWNER_COMMITTING, OWNER_FINAL):
        raise Refusal(
            f"cannot adopt {golden}: {marker} has unexpected state {state!r}; "
            "run `golden --rebuild`"
        )
    rec = read_golden_record(ctx)
    golden_usable(ctx, golden, rec, hint="")
    if (
        owner.get("key_id") != rec["key_id"]
        or owner.get("host_key") is None
        or owner.get("host_key") != rec.get("host_key")
    ):
        raise Refusal(
            f"cannot adopt {golden}: {marker} names key {owner.get('key_id')!r} and host key "
            f"{owner.get('host_key')!r}, which does not match golden.json ({rec['key_id']!r} / "
            f"{rec.get('host_key')!r}); run `golden --rebuild`"
        )
    if state == OWNER_FINAL:
        summary.add(
            "adopt",
            f"adopt {golden} owner marker",
            "pass",
            f"already final and owned by this state dir ({marker}); nothing to do",
        )
        return
    with signals_ignored():
        try:
            write_owner(ctx, golden, rec["key_id"], rec["host_key"], OWNER_FINAL)
            note = (
                f"promoted committing owner marker {marker} to final "
                f"(key {rec['key_id']}, host_key {rec['host_key']})"
            )
        except LandedNotDurable as e:
            note = (
                f"promoted committing owner marker {marker} to final "
                f"(landed, durability unconfirmed: {e})"
            )
        except OSError as e:
            raise ToolError(f"failed to write final owner marker {marker}: {e}") from e
        pending_files = [
            ctx.state_dir / "known_hosts.pending",
            ctx.state_dir / "golden.json.pending",
            marker.with_name(marker.name + ".pending"),
        ]
        gone: list[str] = []
        stuck_pending: list[str] = []
        for pf in pending_files:
            try:
                pf.unlink()
                gone.append(str(pf))
            except FileNotFoundError:
                pass
            except OSError as e:
                stuck_pending.append(f"{pf}: {e}")
        if gone or stuck_pending:
            summary.add(
                "pending",
                "remove parked files of an earlier unfinished commit",
                "fail" if stuck_pending else "pass",
                "; ".join(
                    (["removed " + ", ".join(gone)] if gone else [])
                    + (
                        ["NOT removed: " + "; ".join(stuck_pending)]
                        if stuck_pending
                        else []
                    )
                ),
            )
    summary.add(
        "adopt",
        f"promote committing owner marker for {golden} to final",
        "pass",
        note,
    )


def clone_vm(ctx: Ctx, src: str, dst: str, timeout: float) -> Result:
    # TART_NO_AUTO_PRUNE: a clone must not evict the 30 GB pinned image from tart's OCI cache.
    return ctx.run(
        ["tart", "clone", src, dst], env={**os.environ, **CLONE_ENV}, timeout=timeout
    )


def cmd_golden(ctx: Ctx, args) -> int:
    summary = Summary("golden", ctx.run_id)
    image = load_image(args.image)
    ref = image_ref(image)
    golden = image["golden_name"]
    build = golden + "-build"
    summary.extra.update(image=ref, golden=golden)
    scratch = ctx.state_dir / "tmp" / ctx.run_id
    vm = Vm(ctx, build)
    rc = 1
    built = False
    attempted = (
        False  # the clone may exist: set before the call, cleanup handles "absent"
    )
    keep_build = False
    scratch_made = False
    key_made = False
    key_id = ctx.run_id  # one key per golden build: never reused, never shared
    rebuild = args.rebuild
    adopt = bool(getattr(args, "adopt", False))
    if adopt and (rebuild or args.keep_on_failure):
        return refuse(
            summary,
            ctx,
            args,
            "--adopt cannot be combined with --rebuild or --keep-on-failure",
        )

    def key_dir_made() -> None:
        nonlocal key_made
        key_made = True  # only after this run's own exclusive mkdir succeeded

    refusal = ""
    pubkey = ""
    identity = ""
    try:
        key_paths(ctx, key_id)  # the id becomes a path: validate before anything exists
        with driver_lock(ctx), signals_to_exception():
            try:
                summary.extra["tart_version"] = tart_version(ctx)
                names = set(local_vms(ctx))
                if adopt:
                    adopt_committing_golden(ctx, golden, names, summary)
                    emit(summary, ctx, args.summary)
                    return 0 if summary.ok else 1
                if golden in names and not rebuild:
                    try:
                        rec = read_golden_record(ctx)
                    except Refusal as e:
                        # The tart golden is global; the record is per state dir. A golden
                        # this state dir has no record of (another state dir's, or one from
                        # before records) is not ours to replace unasked.
                        raise Refusal(
                            f"{golden} exists but this state dir has no record of it ({e}); "
                            f"{takeover_hint(ctx, golden)}"
                        ) from e
                    # A record is per state dir, the tart golden is global: only the state
                    # dir a finished owner file names may rebuild or bless it unasked.
                    not_owner = owner_refusal(ctx, golden, rec)
                    if not_owner:
                        raise Refusal(not_owner)
                    try:
                        golden_usable(ctx, golden, rec, hint="")
                    except Refusal as e:
                        # This state dir's record describes the golden, but `check` would
                        # refuse it, and nothing here may wait for a human: build it again,
                        # and say so.
                        rebuild = True
                        summary.add(
                            "exists",
                            f"{golden} exists but its pin, record or key is unusable",
                            "pass",
                            f"rebuilding it unattended: {e}",
                        )
                    else:
                        summary.add(
                            "exists",
                            f"{golden} already exists",
                            "pass",
                            "nothing to do; this state dir owns it and its record, pin and key agree; pass --rebuild to build it again",
                        )
                        emit(summary, ctx, args.summary)
                        return 0
                if ref not in oci_names(ctx):
                    raise Refusal(
                        f"pinned image {ref} is not in tart's OCI cache; run `state1_vm.py pull` first (golden never pulls)"
                    )
                swept = sweep(ctx, build)
                assert_vm_cap(ctx, limit=1)  # golden: no other VM running at all
                summary.add(
                    "preflight",
                    "image cached, stale builds swept, no other VM running",
                    "pass",
                    f"swept {swept or 'nothing'}",
                )
                scratch.parent.mkdir(parents=True, exist_ok=True)
                os.chmod(scratch.parent, 0o700)
                try:
                    os.mkdir(
                        scratch, 0o700
                    )  # exclusive: never reuse a directory that exists
                except FileExistsError as e:
                    raise ToolError(
                        f"scratch directory {scratch} already exists"
                    ) from e
                scratch_made = True
                pubkey, identity = mint_keypair(ctx, key_id, created=key_dir_made)
                kh_scratch = str(scratch / "known_hosts")
                kh_pinned = str(scratch / "known_hosts.pinned")
                # Bootstrap leg (before prep rotates the host keys): the image's own key is
                # the same for every puller of the tag. If image.json pins it, check it strictly;
                # otherwise trust on first use into the scratch file and record what was seen.
                vanilla = image.get("vanilla_host_key")
                if vanilla:
                    kh_boot = str(scratch / "known_hosts.vanilla")
                    write_landed(Path(kh_boot), f"{vmssh.HOST_ALIAS} {vanilla}\n")
                else:
                    kh_boot = kh_scratch
                state: dict[str, object] = {}

                def boot_target(**kw) -> vmssh.Target:
                    return vmssh.Target(
                        str(state["ip"]),
                        kh_boot,
                        accept_new=not vanilla,
                        no_agent=True,
                        **kw,
                    )

                def pinned_target() -> vmssh.Target:
                    return vmssh.Target(
                        str(state["ip"]), kh_pinned, identity=identity, no_agent=True
                    )

                def clone() -> str:
                    nonlocal attempted
                    attempted = True
                    r = clone_vm(ctx, ref, build, 1800)
                    if r.rc != 0:
                        raise ToolError(
                            f"tart clone failed (rc {r.rc}): {clip(r.stderr or r.stdout, 400)}"
                        )
                    return f"{ref} -> {build}"

                def boot() -> str:
                    assert_no_other_vm(ctx)
                    vm.start()
                    state["ip"] = vm.ip()
                    return f"ip {state['ip']}"

                def boot_ssh() -> str:
                    t = boot_target(auth="password")
                    how = (
                        "strict against the host key pinned in image.json"
                        if vanilla
                        else "trust on first use into a scratch file"
                    )
                    return f"ssh up after {wait_for_ssh(ctx, vm, t):.0f}s (password, {how})"

                def install_key() -> str:
                    r = rssh(
                        ctx,
                        boot_target(auth="password"),
                        ["/bin/sh", "-c", INSTALL_KEY_SH, "sh"],
                        input_text=pubkey + "\n",
                    )
                    if r.rc != 0:
                        raise StepFail(
                            f"installing the key failed (rc {r.rc}): {clip(r.stderr, 300)}"
                        )
                    return f"installed {fingerprint(pubkey)} (minted for this golden, key id {key_id})"

                def key_sudo() -> str:
                    r = rssh(
                        ctx,
                        boot_target(identity=identity),
                        ["sudo", "-n", "sh", "-c", "id -u"],
                    )
                    if r.rc != 0 or r.stdout.strip() != "0":
                        raise StepFail(
                            f"key login + sudo -n failed (rc {r.rc}): {clip(r.stderr, 300)}"
                        )
                    state["vanilla_fp"] = kh_fingerprint(Path(kh_boot))
                    state["vanilla_key"] = kh_key_line(Path(kh_boot))
                    return f"key login ok; sudo -n is uid 0; vanilla host key {state['vanilla_fp']}"

                def prep() -> str:
                    script = HERE / "guest" / "prep.sh"
                    out = run_guest_script(
                        ctx, boot_target(identity=identity), script, [], "prep"
                    )
                    results = re.findall(r"^PREP-RESULT .*$", out, re.MULTILINE)
                    if not results:
                        raise StepFail(
                            "prep.sh printed no PREP-RESULT line: " + clip(out, 400)
                        )
                    # prep.sh prints its own last; a guest-command line that looks like one
                    # (a lone CR becomes a line break in text mode) comes earlier. Evidence only.
                    result = results[-1] + (
                        f" [{len(results)} PREP-RESULT lines in the prep output; last shown]"
                        if len(results) > 1
                        else ""
                    )
                    state["prep_hostkey"] = parse_prep_hostkey(out)
                    if len(CONSOLE_PW_LINE_RE.findall(out)) != 1:
                        raise StepFail(
                            "prep.sh did not confirm the console password was rotated: "
                            + clip(out, 300)
                        )
                    st = SECURE_TOKEN_AFTER_RE.findall(out)
                    token = (
                        clip(st[0].removeprefix("prep: "), 300)
                        if st
                        else "secure token status (after): not printed by prep.sh"
                    )
                    if len(st) > 1:  # evidence only, never a failure
                        token += (
                            f" [{len(st)} such lines in the prep output; first shown]"
                        )
                    return (
                        f"prep.sh sha256 {sha256_text(script.read_text())[:16]}; {result}; "
                        f"{token}"
                    )

                def pin() -> str:
                    assert_no_other_vm(ctx, allowed=build)
                    key = pin_host_key(
                        ctx,
                        str(state["ip"]),
                        Path(kh_pinned),
                        state["prep_hostkey"],  # type: ignore[arg-type]
                    )
                    r = rssh(ctx, pinned_target(), ["true"])  # strict from here on
                    if r.rc != 0:
                        raise StepFail(
                            f"strict key login against the pinned host key failed (rc {r.rc}): {clip(r.stderr, 300)}"
                        )
                    state["hostkey"] = key
                    return f"pinned {key} (printed by prep.sh in the authenticated session; ssh-keyscan agrees); strict key login ok"

                def python() -> str:
                    py = image["python"]
                    out = run_guest_script(
                        ctx,
                        pinned_target(),
                        HERE / "guest" / "install-python.sh",
                        [py["version"], py["url"], py["sha256"], py["signer"]],
                        "python",
                    )
                    m = re.search(r"^INSTALL-PYTHON-RESULT .*$", out, re.MULTILINE)
                    if not m:
                        raise StepFail(
                            "install-python.sh printed no result line: "
                            + clip(out, 400)
                        )
                    return m[0]

                def no_password() -> str:
                    return refused_password_login(ctx, str(state["ip"]), kh_pinned)

                def save() -> str:
                    nonlocal keep_build
                    # A forced power-off fails this step (stop_vm raises): an image that may
                    # be missing its last writes is never saved.
                    stopped = stop_vm(ctx, build, vm, pinned_target())
                    pinned_text = Path(kh_pinned).read_text()
                    record = json.dumps(
                        {
                            "image": ref,
                            "tag": image["tag"],
                            "built_at": ctx.now().isoformat(timespec="seconds"),
                            "tart_version": summary.extra.get("tart_version"),
                            "prep_sha256": sha256_text(
                                (HERE / "guest" / "prep.sh").read_text()
                            ),
                            "install_python_sha256": sha256_text(
                                (HERE / "guest" / "install-python.sh").read_text()
                            ),
                            "python": image["python"]["version"],
                            "authorized_key": fingerprint(pubkey),
                            "key_id": key_id,
                            "console_password": "random per golden, set in the guest, never stored",
                            "host_key": state.get("hostkey"),
                            # the full public key line (it can go into image.json as
                            # vanilla_host_key), the fingerprint beside it
                            "vanilla_host_key_seen": state.get("vanilla_key"),
                            "vanilla_host_key_seen_fingerprint": state.get(
                                "vanilla_fp"
                            ),
                        },
                        indent=2,
                    )

                    # The commit, all with signals ignored so no interrupt can land between
                    # the steps and leave the old golden gone and the new build deleted:
                    #   0. the intent marker (state "committing": this state dir, the new key
                    #      id and host key), before the first destructive step. From here a
                    #      marker that is not "final" makes every state dir's plain `golden`
                    #      refuse (exit 2, hint --rebuild), whatever stops the commit later;
                    #   1. remove the old golden (--rebuild), 2. rename the build into place,
                    #   3. known_hosts, 4. golden.json, 5. the final marker, last.
                    # keep_build is set first: from here on a failure never deletes the
                    # finished build.
                    marker = owner_path(ctx, golden)
                    landed: list[str] = []
                    pending_files = [
                        ctx.state_dir / "known_hosts.pending",
                        ctx.state_dir / "golden.json.pending",
                        marker.with_name(marker.name + ".pending"),
                    ]

                    def park_record(renamed: bool) -> str:
                        # The new record (it names this build's key) beside the old one, so
                        # finishing by hand does not need a rebuild and the key is not
                        # orphaned: all three files of the commit, the marker last. "" when
                        # parking failed too.
                        kh_p, rec_p, marker_p = pending_files
                        try:
                            write_landed(kh_p, pinned_text)
                            write_landed(rec_p, record + "\n", 0o644)
                            with contextlib.suppress(LandedNotDurable):
                                write_owner(
                                    ctx,
                                    golden,
                                    key_id,
                                    state.get("hostkey"),  # type: ignore[arg-type]
                                    OWNER_FINAL,
                                    marker_p,
                                )
                        except OSError:
                            return ""
                        return (
                            f"the new record is parked as {shlex.quote(str(kh_p))}, "
                            f"{shlex.quote(str(rec_p))} (it names the new key) and "
                            f"{shlex.quote(str(marker_p))}: "
                            + ("" if renamed else "after the rename, ")
                            + "mv them over "
                            f"{shlex.quote(str(ctx.state_dir / 'known_hosts'))}, "
                            f"{shlex.quote(str(ctx.state_dir / 'golden.json'))} and "
                            f"{shlex.quote(str(marker))} (the last one makes this state dir "
                            "the owner)"
                        )

                    def finish_note(renamed: bool) -> str:
                        parked = park_record(renamed)
                        if parked:
                            return f"; to finish by hand: {parked}, or run `golden --rebuild`"
                        return (
                            "; the new record could not be parked either, so only "
                            "`golden --rebuild` finishes it"
                        )

                    def commit_write(label: str, write: Callable[[], None]) -> None:
                        try:
                            write()
                        except LandedNotDurable as e:
                            landed.append(f"{label} (landed, durability unconfirmed)")
                            if label == "the final owner file":
                                # every write of the commit landed: it is complete, only the
                                # directory sync of the last one is unconfirmed. Go on to the
                                # cleanup; the run still exits 0.
                                summary.add(
                                    "owner",
                                    "final owner file written",
                                    "pass",
                                    f"landed, durability unconfirmed ({e}); the commit is "
                                    "complete",
                                )
                                return
                            raise ToolError(
                                f"{label} landed but its directory could not be synced "
                                f"({e}), so it may not survive a power loss; written: "
                                f"{', '.join(landed)}; the commit stops here; {golden} is "
                                "renamed into place and the owner file says its commit did "
                                "not finish, so plain `golden` refuses (exit 2) until "
                                f"`--rebuild`{finish_note(True)}"
                            ) from e
                        except OSError as e:
                            raise ToolError(
                                f"writing {label} failed ({e}); written before it: "
                                f"{', '.join(landed) or 'nothing'}; {golden} is renamed into "
                                "place and the owner file says its commit did not finish, so "
                                f"plain `golden` refuses (exit 2) until `--rebuild`"
                                f"{finish_note(True)}"
                            ) from e
                        landed.append(label)

                    def restore_marker(prev: str | None, readable: bool) -> str:
                        """Put the owner file back as it was before the intent write."""
                        try:
                            if not readable:
                                return (
                                    "the previous owner file was unreadable and the owner "
                                    "file now says a commit did not finish"
                                )
                            if prev is None:
                                marker.unlink(missing_ok=True)
                                return "the owner file is removed again"
                            atomic_write(marker, prev)
                            return "the previous owner file is restored"
                        except LandedNotDurable:
                            return (
                                "the previous owner file is restored (durability "
                                "unconfirmed)"
                            )
                        except OSError as e2:
                            return (
                                f"the owner file could NOT be restored ({e2}): it says a "
                                "commit did not finish, so plain `golden` refuses (exit 2) "
                                "until --rebuild"
                            )

                    with signals_ignored():
                        # Never delete a golden this run did not check: one that appeared
                        # during the build (a hand `tart rename`, a driver under another
                        # TART_HOME) is owner-checked again here, after the lock was taken
                        # and before the intent marker (which would itself refuse).
                        present_at_check = False
                        if not args.rebuild and golden in local_vms(ctx):
                            present_at_check = True
                            try:
                                rec_now = read_golden_record(ctx)
                            except Refusal as e:
                                raise Refusal(
                                    f"{golden} exists but this state dir has no record of "
                                    f"it ({e}); it was not checked before the build, so "
                                    f"nothing was replaced and the finished build is not "
                                    f"installed (the cleanup removes it unless "
                                    f"--keep-on-failure); {takeover_hint(ctx, golden)}"
                                ) from e
                            why = owner_refusal(ctx, golden, rec_now)
                            if why:
                                raise Refusal(
                                    f"{golden} is not this state dir's to replace without "
                                    f"--rebuild; nothing was replaced and the finished "
                                    f"build is not installed (the cleanup removes it unless "
                                    f"--keep-on-failure): {why}"
                                )
                        keep_build = True
                        try:
                            prev_marker: str | None = read_owner_raw(marker)
                            prev_readable = True
                        except Refusal:
                            prev_marker, prev_readable = None, False
                        try:
                            write_owner(
                                ctx,
                                golden,
                                key_id,
                                state.get("hostkey"),  # type: ignore[arg-type]
                                OWNER_COMMITTING,
                            )
                        except OSError as e:
                            if isinstance(e, LandedNotDurable):
                                state_now = (
                                    "the intent owner file landed but could not be made "
                                    f"durable; {restore_marker(prev_marker, prev_readable)}"
                                )
                            else:
                                state_now = "the owner file is as it was"
                            raise ToolError(
                                f"writing the intent owner file failed ({e}); {state_now}; "
                                f"the old {golden}, known_hosts and golden.json are as they "
                                f"were and the finished build is kept as {build} (the next "
                                "golden run sweeps it)"
                            ) from e
                        removed = False
                        try:
                            golden_present = golden in local_vms(ctx)
                        except ToolError as e:
                            raise ToolError(
                                f"checking for an existing {golden} during commit failed: {e}; "
                                f"whether {golden} exists is unknown, so nothing was deleted or "
                                f"renamed; the finished build is kept as {build} and the owner "
                                "file says a commit did not finish, so plain `golden` refuses "
                                "(exit 2) until `--rebuild`"
                            ) from e
                        if golden_present:
                            if not (args.rebuild or present_at_check):
                                # it appeared after the owner re-check: nobody checked
                                # it, so no marker may bless it: the intent (committing)
                                # marker stays, and plain `golden` refuses until --rebuild
                                raise ToolError(
                                    f"{golden} appeared after the owner check, so it was "
                                    f"not replaced; the owner file now says a commit did "
                                    f"not finish, so plain `golden` refuses (exit 2) until "
                                    f"`--rebuild`; the finished build is kept as {build} "
                                    "but no records were parked, so it cannot be finished "
                                    "by hand: `golden --rebuild` sweeps it, replaces "
                                    f"{golden} and builds afresh (this state dir then "
                                    "owns it)"
                                )
                            try:
                                done = remove_vm(ctx, golden)
                            except ToolError as e:
                                # Re-list on a best-effort basis before restoring the old
                                # final marker: local_vms() can raise after `tart delete`
                                # succeeded (issue 82). Only restore the previous marker
                                # when we positively see the old golden still present.
                                try:
                                    still_present: bool | None = golden in local_vms(ctx)
                                    relist_err = ""
                                except ToolError as e2:
                                    still_present = None
                                    relist_err = str(e2)
                                if still_present is True:
                                    back = restore_marker(prev_marker, prev_readable)
                                    raise ToolError(
                                        f"removing the old {golden} failed: {e}; it and the finished "
                                        f"build {build} are both kept; known_hosts and golden.json "
                                        f"are unchanged; {back}{finish_note(False)}"
                                    ) from e
                                if still_present is False:
                                    raise ToolError(
                                        f"removing the old {golden} reported an error ({e}), and a "
                                        f"re-list shows {golden} is now gone (not kept); the owner "
                                        "file remains committing (the old golden is gone, so plain "
                                        "`golden` builds again; rename first to keep this build); "
                                        f"the finished build is kept as {build}{finish_note(False)}"
                                    ) from e
                                raise ToolError(
                                    f"removing the old {golden} failed ({e}) and re-listing "
                                    f"{golden} also failed ({relist_err}), so whether the old "
                                    f"{golden} still exists is unknown; the owner file remains "
                                    "committing (if it still exists, plain `golden` refuses "
                                    "(exit 2) until `--rebuild`); the finished build is kept as "
                                    f"{build}{finish_note(False)}"
                                ) from e
                            removed = True
                            summary.add(
                                "rebuild",
                                f"remove old {golden} (replaced by this build)",
                                "pass",
                                done,
                            )
                        r = ctx.run(["tart", "rename", build, golden], timeout=120)
                        if r.rc != 0:
                            raise ToolError(
                                f"tart rename failed (rc {r.rc}): {clip(r.stderr or r.stdout, 300)}; "
                                f"the finished build is kept as {build}: run `tart rename "
                                f"{build} {golden}` before the next golden run, which sweeps "
                                "it; the owner file says the commit did not finish, so "
                                + (
                                    "the old golden is gone and plain `golden` builds again "
                                    "(rename first to keep this build)"
                                    if removed
                                    else "plain `golden` refuses (exit 2) until --rebuild "
                                    "or the hand finish"
                                )
                                + finish_note(False)
                            )
                        commit_write(
                            "known_hosts",
                            lambda: atomic_write(
                                ctx.state_dir / "known_hosts", pinned_text
                            ),
                        )
                        commit_write(
                            "golden.json",
                            lambda: atomic_write(
                                ctx.state_dir / "golden.json", record + "\n", 0o644
                            ),
                        )
                        # last: a final marker that agrees with the record means every write
                        # of the commit landed
                        commit_write(
                            "the final owner file",
                            lambda: write_owner(
                                ctx,
                                golden,
                                key_id,
                                state.get("hostkey"),  # type: ignore[arg-type]
                            ),
                        )
                        # Parked files of an earlier unfinished commit describe a build that
                        # is gone now: a late hand finish from an old message would install
                        # their record, pin and marker over this one.
                        gone: list[str] = []
                        stuck_pending: list[str] = []
                        for pf in pending_files:
                            try:
                                pf.unlink()
                                gone.append(str(pf))
                            except FileNotFoundError:
                                pass
                            except OSError as e:
                                stuck_pending.append(f"{pf}: {e}")
                        if gone or stuck_pending:
                            summary.add(
                                "pending",
                                "remove parked files of an earlier unfinished commit",
                                "fail" if stuck_pending else "pass",
                                "; ".join(
                                    (["removed " + ", ".join(gone)] if gone else [])
                                    + (
                                        ["NOT removed: " + "; ".join(stuck_pending)]
                                        if stuck_pending
                                        else []
                                    )
                                ),
                            )
                        # The replaced golden's key is of no use now: remove it (and the
                        # private keys of any other deleted golden).
                        try:
                            stale, stuck = sweep_stale_keys(ctx, key_id)
                        except Refusal as e:
                            stale, stuck = [], [str(e)]
                        if stale or stuck:
                            summary.add(
                                "keys",
                                "remove private keys of replaced goldens",
                                "fail" if stuck else "pass",
                                "; ".join(
                                    (["removed " + ", ".join(stale)] if stale else [])
                                    + (
                                        ["NOT removed: " + "; ".join(stuck)]
                                        if stuck
                                        else []
                                    )
                                ),
                            )
                    return f"{stopped}; renamed {build} -> {golden}; record, known_hosts and owner marker written"

                steps: list[tuple[str, str, Callable[[], str | None]]] = [
                    ("g1", f"clone pinned image to {build}", clone),
                    ("g2", "boot --no-graphics, tart ip --wait", boot),
                    ("g3", "ssh reachable (vanilla password, once)", boot_ssh),
                    ("g4", "install this golden's own public key", install_key),
                    ("g5", "key login works; sudo -n is root", key_sudo),
                    (
                        "g6",
                        "prep.sh (spotlight, updates, screen sharing off, launchd, gatekeeper, host keys, sshd)",
                        prep,
                    ),
                    (
                        "g7",
                        "pin the host key prep.sh printed; keyscan agrees; strict key login",
                        pin,
                    ),
                    ("g8", "python.org Python system-wide (strict pinned key)", python),
                    ("g9", "password login refused", no_password),
                    ("g10", f"guest shutdown, save as {golden}", save),
                ]
                for sid, name, fn in steps:
                    run_step(summary, sid, name, fn)
                built = True
                rc = 0
            except Refusal as e:
                refusal = str(e)
            except Abort:
                rc = 1
            except ToolError as e:
                summary.add("error", "tool error", "fail", str(e))
                rc = 1
            except Interrupted as e:
                summary.add(
                    "interrupted",
                    "interrupted",
                    "fail",
                    f"{e}; re-run golden (the half-built {build} is swept)",
                )
                rc = 130
            finally:
                with signals_ignored():
                    if (
                        attempted
                        and not built
                        and not keep_build
                        and not args.keep_on_failure
                    ):
                        try:
                            summary.add(
                                "cleanup",
                                f"remove {build}",
                                "pass",
                                remove_vm(ctx, build, vm.proc),
                            )
                        except ToolError as e:
                            summary.add("cleanup", f"remove {build}", "fail", str(e))
                    if scratch_made:
                        shutil.rmtree(scratch, ignore_errors=True)
                    # A build that is not kept does not keep its private key either.
                    if (
                        key_made
                        and not built
                        and not keep_build
                        and not args.keep_on_failure
                    ):
                        try:
                            left = remove_key_dir(ctx, key_id)
                        except (OSError, Refusal) as e:
                            left = f"left in place: {e}"
                        if not left.startswith("removed "):
                            summary.add(
                                "cleanup-key",
                                "remove this build's private key",
                                "fail",
                                left,
                            )
    except Refusal as e:
        return refuse(summary, ctx, args, str(e))
    if refusal:
        return refuse(summary, ctx, args, refusal)
    emit(summary, ctx, args.summary)
    return 130 if rc == 130 else (0 if summary.ok else 1)


def stop_vm(ctx: Ctx, name: str, vm: Vm, t: vmssh.Target) -> str:
    """Clean guest shutdown of the build VM, without deleting it.

    `shutdown -h now` over ssh lets the guest flush and halt, which ends `tart run`. Only if
    that does not happen in time is `tart stop` used to stop the VM, and that is a power-off
    (tart stop makes tart run call VZVirtualMachine.stop, which does not let the guest shut
    down): the step then FAILS, because the image may be missing its last writes.
    """
    rssh(
        ctx, t, ["sudo", "-n", "shutdown", "-h", "now"], timeout=60
    )  # the connection drops; its status is not evidence

    def halted() -> bool:
        return not vm.alive() and not (local_vms(ctx).get(name) or {}).get("Running")

    if wait_until(ctx, halted, GUEST_SHUTDOWN_WAIT, 5):
        return f"{name}: guest shut down cleanly, tart run exited"
    ctx.run(["tart", "stop", name], timeout=180)
    if not wait_until(
        ctx, lambda: not (local_vms(ctx).get(name) or {}).get("Running"), 120
    ):
        raise ToolError(f"{name} did not stop")
    if vm.proc is not None and vm.proc.wait(60) is None:
        vm.proc.kill()
    raise StepFail(
        f"{name}: guest did not halt within {GUEST_SHUTDOWN_WAIT}s; tart stop powered it off, "
        "so the image may be missing its last writes and is not saved (the build is removed; "
        "--keep-on-failure keeps it for inspection)"
    )


def cmd_check(ctx: Ctx, args) -> int:
    summary = Summary("check", ctx.run_id)
    image = load_image(args.image)
    golden = image["golden_name"]
    clone = f"{CHECK_PREFIX}{ctx.run_id}".lower()
    summary.extra.update(golden=golden, clone=clone)
    vm = Vm(ctx, clone)
    known_hosts = ctx.state_dir / "known_hosts"
    rc = 1
    cloned = False  # the clone may exist: set before the call, cleanup handles "absent"
    refusal = ""

    # Validate renderer artifact CLI arguments before acquiring the lock or cloning a VM.
    tarball_arg: Path | None = getattr(args, "tarball", None)
    sha256_arg: Path | None = getattr(args, "sha256", None)
    artifact_run: str | None = getattr(args, "artifact_run", None)
    golden_plist_path: Path = getattr(args, "golden", CANARY_GOLDEN)
    if tarball_arg is not None and artifact_run is not None:
        return refuse(summary, ctx, args, "pass either --tarball or --artifact-run, not both")
    if sha256_arg is not None and tarball_arg is None:
        return refuse(summary, ctx, args, "--sha256 requires --tarball")
    has_artifact = tarball_arg is not None or artifact_run is not None
    artifact_tmpdir: Path | None = None
    resolved_tarball: Path | None = None
    resolved_sha: Path | None = None
    golden_bytes: bytes = b""
    if has_artifact:
        for req_label, req_path in (
            ("darwin installer", DARWIN_INSTALLER),
            ("policy file", POLICY_DIR / "tendcf_services.cf"),
            ("darwin canary data", DARWIN_CANARY_DIR / "host_specific.json"),
            ("darwin canary tombstone", DARWIN_CANARY_DIR / "host_specific-absent.json"),
            ("committed canary golden", golden_plist_path),
        ):
            if not req_path.is_file():
                return refuse(summary, ctx, args, f"missing {req_label}: {req_path}")
        golden_bytes = golden_plist_path.read_bytes()
        if tarball_arg is not None:
            sha_path = sha256_arg or Path(str(tarball_arg) + ".sha256")
            try:
                digest = verify_local_tarball(tarball_arg, sha_path)
            except Refusal as e:
                return refuse(summary, ctx, args, str(e))
            resolved_tarball, resolved_sha = tarball_arg, sha_path
            summary.extra["artifact_sha256"] = digest
        elif artifact_run is not None and not RUN_ID_RE.fullmatch(artifact_run):
            return refuse(
                summary,
                ctx,
                args,
                f"--artifact-run must be a numeric GitHub run id, got {artifact_run!r}",
            )

    try:
        with driver_lock(ctx), signals_to_exception():
            try:
                summary.extra["tart_version"] = tart_version(ctx)
                swept = sweep(ctx, CHECK_PREFIX)
                vms = local_vms(ctx)
                if golden not in vms:
                    raise Refusal(
                        f"{golden} does not exist; run `state1_vm.py golden` first"
                    )
                if vms[golden].get("Running"):
                    raise Refusal(f"{golden} is running; stop it before `check`")
                # the pin, record and minted key, read under the lock (a concurrent rebuild
                # cannot sweep the key between this and its use): the same test `golden` uses
                not_ours, owner_note = check_owner_refusal(ctx, golden)
                if not_ours:
                    raise Refusal(not_ours)
                if owner_note:
                    summary.add("owner", "owner file", "pass", owner_note)
                identity = golden_usable(ctx, golden)
                adopt = bool(getattr(args, "adopt", False))
                initial_adopt_rec: dict | None = None
                if adopt:
                    initial_adopt_rec = read_golden_record(ctx)
                    check_adopt_precondition(ctx, golden, initial_adopt_rec)
                assert_vm_cap(ctx)
                if artifact_run is not None:
                    artifact_tmpdir = Path(
                        tempfile.mkdtemp(dir=ctx.state_dir, prefix="artifact-")
                    )
                    resolved_tarball, resolved_sha, digest = download_artifact_run(
                        ctx, artifact_run, artifact_tmpdir
                    )
                    summary.extra["artifact_run"] = artifact_run
                    summary.extra["artifact_sha256"] = digest
                summary.add(
                    "preflight",
                    "golden present, host key pinned, stale clones swept, VM cap",
                    "pass",
                    f"swept {swept or 'nothing'}",
                )
                state: dict[str, object] = {}

                def start() -> str:
                    nonlocal cloned
                    cloned = True
                    r = clone_vm(ctx, golden, clone, 600)
                    if r.rc != 0:
                        raise ToolError(
                            f"tart clone failed (rc {r.rc}): {clip(r.stderr or r.stdout, 400)}"
                        )
                    vm.start()
                    state["ip"] = vm.ip()
                    state["t"] = vmssh.Target(
                        str(state["ip"]),
                        str(known_hosts),
                        identity=identity,
                        no_agent=True,
                    )
                    secs = wait_for_ssh(ctx, vm, state["t"])  # type: ignore[arg-type]
                    return f"cloned {golden} -> {clone}; ip {state['ip']}; ssh up after {secs:.0f}s (key, pinned host key)"

                run_step(
                    summary,
                    "1",
                    f"clone {golden}, tart run --no-graphics, tart ip --wait, ssh",
                    start,
                )
                t: vmssh.Target = state["t"]  # type: ignore[assignment]

                for sid, name, ok, ev in persistent_assertions(ctx, image, t):
                    summary.add(sid, name, "pass" if ok else "fail", ev)

                run_step(
                    summary,
                    "2f",
                    "password login refused from the host",
                    lambda: refused_password_login(ctx, t.ip, t.known_hosts),
                    fatal=False,
                )

                guest_stage = ""
                workdir = ""
                installed = False
                if not has_artifact:
                    skip_msg = "no artifact supplied (pass --tarball FILE or --artifact-run RUN_ID)"
                    summary.add(
                        "3",
                        "install tendcf and verify root:wheel ownership on binary tree and policy dir",
                        "skip",
                        skip_msg,
                    )
                    for sid in ("4", "5", "6", "7", "8", "9", "9a"):
                        summary.add(sid, f"checklist step {sid}", "skip", f"SKIP: {skip_msg}")
                else:
                    assert resolved_tarball is not None and resolved_sha is not None
                    tar_name = resolved_tarball.name
                    sha_name = resolved_sha.name
                    golden_sha = hashlib.sha256(golden_bytes).hexdigest()
                    golden_text = golden_bytes.decode("utf-8")

                    def step3_install() -> str:
                        nonlocal guest_stage, workdir
                        guest_stage = stage_renderer_bundle(
                            ctx, t, resolved_tarball, resolved_sha
                        )
                        installer = f"{guest_stage}/tendcf-install.sh"
                        r = rssh(
                            ctx,
                            t,
                            [
                                "sudo",
                                "-n",
                                installer,
                                "install",
                                "--tarball",
                                f"{guest_stage}/artifact/{tar_name}",
                                "--sha256",
                                f"{guest_stage}/artifact/{sha_name}",
                                "--policy-src",
                                f"{guest_stage}/policy",
                                "--data",
                                f"{guest_stage}/canary/host_specific.json",
                            ],
                            timeout=300,
                        )
                        if r.rc != 0:
                            raise StepFail(
                                f"tendcf-install.sh install failed (rc {r.rc}): "
                                f"{clip(r.stderr or r.stdout, 400)}"
                            )
                        wd_r = rssh(ctx, t, ["sudo", "-n", installer, "workdir"])
                        wd = wd_r.stdout.strip()
                        if (
                            wd_r.rc != 0
                            or not WORKDIR_RE.fullmatch(wd)
                            or ".." in wd.split("/")
                        ):
                            raise StepFail(
                                f"bad workdir from installer (rc {wd_r.rc}): {wd!r}"
                            )
                        workdir = wd
                        ok_tree, ev_tree = check_root_owned(
                            ctx, t, TENDCF_PREFIX, tree=True, as_root=True
                        )
                        if not ok_tree:
                            raise StepFail(f"binary tree ownership failed: {ev_tree}")
                        ok_pol, ev_pol = check_root_owned(
                            ctx,
                            t,
                            f"{workdir}/inputs",
                            tree=True,
                            as_root=True,
                            no_symlinks=True,
                        )
                        if not ok_pol:
                            raise StepFail(f"policy dir ownership failed: {ev_pol}")
                        data_st = rssh(
                            ctx,
                            t,
                            [
                                "sudo",
                                "-n",
                                "/usr/bin/stat",
                                "-f",
                                "%Su:%Sg %Lp",
                                f"{workdir}/data/host_specific.json",
                            ],
                        )
                        if data_st.rc != 0 or data_st.stdout.strip() != "root:wheel 600":
                            raise StepFail(
                                f"CMDB data must be root:wheel 600 (rc {data_st.rc}, got {data_st.stdout.strip()!r})"
                            )
                        q = rssh(
                            ctx,
                            t,
                            [
                                "sudo",
                                "-n",
                                "/usr/bin/find",
                                TENDCF_PREFIX,
                                "!",
                                "-type",
                                "s",
                                "-exec",
                                "/usr/bin/xattr",
                                "-s",
                                "{}",
                                "+",
                            ],
                        )
                        if q.rc != 0:
                            raise StepFail(
                                f"xattr check on {TENDCF_PREFIX} failed (rc {q.rc}): {clip(q.stderr or q.stdout, 200)}"
                            )
                        if "com.apple.quarantine" in q.stdout:
                            raise StepFail(
                                f"com.apple.quarantine still present under {TENDCF_PREFIX}"
                            )
                        return f"{ev_tree}; {ev_pol}; data root:wheel 600; no quarantine"

                    installed = run_step(
                        summary,
                        "3",
                        "install tendcf and verify root:wheel ownership on binary tree and policy dir",
                        step3_install,
                        fatal=False,
                    )

                    if not installed:
                        for sid in ("4", "5", "6", "7", "8", "9", "9a"):
                            summary.add(
                                sid,
                                f"checklist step {sid}",
                                "skip",
                                "not run: step 3 failed",
                            )
                    else:
                        installer = f"{guest_stage}/tendcf-install.sh"

                        def step4_render() -> str:
                            r = rssh(
                                ctx, t, ["sudo", "-n", installer, "run-once"], timeout=180
                            )
                            if r.rc != 0:
                                raise StepFail(
                                    f"run-once failed (rc {r.rc}): {clip(r.stderr or r.stdout, 400)}"
                                )
                            ev = check_plist_perms_and_lint(
                                ctx, t, CANARY_PLIST, check_no_backup=True
                            )
                            return f"run-once rc 0; {ev}; no .cf-before-edit backup"

                        def step5_golden() -> str:
                            r = rssh(
                                ctx,
                                t,
                                ["sudo", "-n", "/bin/cat", CANARY_PLIST],
                                raw_newlines=True,
                            )
                            if r.rc != 0:
                                raise StepFail(
                                    f"cannot read {CANARY_PLIST} (rc {r.rc}): {clip(r.stderr, 200)}"
                                )
                            guest_sha = guest_file_sha256(ctx, t, CANARY_PLIST)
                            if r.stdout != golden_text or guest_sha != golden_sha:
                                raise StepFail(
                                    f"rendered {CANARY_PLIST} differs from committed golden "
                                    f"(guest sha256={guest_sha}, golden sha256={golden_sha})"
                                )
                            return (
                                f"byte-identical to {golden_plist_path.name} "
                                f"({len(golden_bytes)} bytes, sha256={golden_sha})"
                            )

                        def step6_launchctl() -> str:
                            p1 = rssh(
                                ctx,
                                t,
                                [
                                    "sudo",
                                    "-n",
                                    "/bin/launchctl",
                                    "print",
                                    f"system/{CANARY_LABEL}",
                                ],
                            )
                            if p1.rc != 0:
                                raise StepFail(
                                    f"launchctl print system/{CANARY_LABEL} failed (rc {p1.rc}): "
                                    f"{clip(p1.stderr or p1.stdout, 300)}"
                                )
                            info1 = parse_launchctl_print(p1.stdout)
                            want_args = [CANARY_PROG, CANARY_ARG]
                            if (
                                info1["program"] != CANARY_PROG
                                or info1["arguments"] != want_args
                                or not isinstance(info1["pid"], int)
                            ):
                                raise StepFail(
                                    f"unexpected launchctl print before kickstart: {info1!r}"
                                )
                            pid_before = info1["pid"]
                            ks = rssh(
                                ctx,
                                t,
                                [
                                    "sudo",
                                    "-n",
                                    "/bin/launchctl",
                                    "kickstart",
                                    "-k",
                                    f"system/{CANARY_LABEL}",
                                ],
                            )
                            if ks.rc != 0:
                                raise StepFail(
                                    f"launchctl kickstart -k failed (rc {ks.rc}): "
                                    f"{clip(ks.stderr or ks.stdout, 300)}"
                                )
                            last_info: dict[str, object] = {}

                            def restarted() -> bool:
                                nonlocal last_info
                                p2 = rssh(
                                    ctx,
                                    t,
                                    [
                                        "sudo",
                                        "-n",
                                        "/bin/launchctl",
                                        "print",
                                        f"system/{CANARY_LABEL}",
                                    ],
                                )
                                if p2.rc != 0:
                                    return False
                                last_info = parse_launchctl_print(p2.stdout)
                                pid2 = last_info["pid"]
                                return (
                                    last_info["state"] == "running"
                                    and isinstance(pid2, int)
                                    and pid2 != pid_before
                                )

                            if not wait_until(ctx, restarted, 10.0, 0.5):
                                raise StepFail(
                                    f"kickstart -k did not replace running process "
                                    f"(before pid={pid_before}, after={last_info!r})"
                                )
                            pid_after = last_info["pid"]
                            assert isinstance(pid_after, int)
                            return (
                                f"program={CANARY_PROG} args={want_args} "
                                f"kickstart -k pid {pid_before} -> {pid_after}"
                            )

                        def step7_idempotency() -> str:
                            sha_before = guest_file_sha256(ctx, t, CANARY_PLIST)
                            p_before = rssh(
                                ctx,
                                t,
                                [
                                    "sudo",
                                    "-n",
                                    "/bin/launchctl",
                                    "print",
                                    f"system/{CANARY_LABEL}",
                                ],
                            )
                            if p_before.rc != 0:
                                raise StepFail(f"launchctl print before re-run failed (rc {p_before.rc})")
                            pid_before = parse_launchctl_print(p_before.stdout)["pid"]

                            r = rssh(
                                ctx, t, ["sudo", "-n", installer, "run-once"], timeout=180
                            )
                            if r.rc != 0:
                                raise StepFail(
                                    f"idempotent run-once failed (rc {r.rc}): {clip(r.stderr or r.stdout, 300)}"
                                )
                            if any(
                                tok in r.stdout
                                for tok in (
                                    "bootout",
                                    "bootstrap",
                                    "Updated rendering",
                                    "Created file",
                                )
                            ):
                                raise StepFail(
                                    f"idempotent run-once reported unexpected repair: {clip(r.stdout, 300)}"
                                )
                            sha_after = guest_file_sha256(ctx, t, CANARY_PLIST)
                            if sha_after != sha_before:
                                raise StepFail(
                                    f"plist sha256 changed on re-run ({sha_before} -> {sha_after})"
                                )
                            p_after = rssh(
                                ctx,
                                t,
                                [
                                    "sudo",
                                    "-n",
                                    "/bin/launchctl",
                                    "print",
                                    f"system/{CANARY_LABEL}",
                                ],
                            )
                            if p_after.rc != 0:
                                raise StepFail(f"launchctl print after re-run failed (rc {p_after.rc})")
                            pid_after = parse_launchctl_print(p_after.stdout)["pid"]
                            if pid_before is None or pid_after != pid_before:
                                raise StepFail(
                                    f"idempotent re-run reloaded daemon (pid {pid_before} -> {pid_after})"
                                )
                            ri = rssh(
                                ctx,
                                t,
                                [
                                    "sudo",
                                    "-n",
                                    installer,
                                    "install",
                                    "--tarball",
                                    f"{guest_stage}/artifact/{tar_name}",
                                    "--sha256",
                                    f"{guest_stage}/artifact/{sha_name}",
                                    "--policy-src",
                                    f"{guest_stage}/policy",
                                    "--data",
                                    f"{guest_stage}/canary/host_specific.json",
                                ],
                                timeout=300,
                            )
                            if ri.rc != 0 or "tendcf-install: no change" not in ri.stdout:
                                raise StepFail(
                                    f"installer re-run was not a no-op (rc {ri.rc}): "
                                    f"{clip(ri.stdout + ri.stderr, 300)}"
                                )
                            return (
                                f"run-once no change (sha256={sha_after}, pid={pid_after} unchanged); "
                                "installer re-run: no change"
                            )

                        def step8_drift() -> str:
                            p_before = rssh(
                                ctx,
                                t,
                                [
                                    "sudo",
                                    "-n",
                                    "/bin/launchctl",
                                    "print",
                                    f"system/{CANARY_LABEL}",
                                ],
                            )
                            if p_before.rc != 0:
                                raise StepFail(f"launchctl print before drift failed (rc {p_before.rc})")
                            pid_before = parse_launchctl_print(p_before.stdout)["pid"]

                            mut = rssh(
                                ctx,
                                t,
                                [
                                    "sudo",
                                    "-n",
                                    "/usr/bin/plutil",
                                    "-replace",
                                    "ProgramArguments.1",
                                    "-string",
                                    CANARY_DRIFT_ARG,
                                    CANARY_PLIST,
                                ],
                            )
                            if mut.rc != 0:
                                raise StepFail(
                                    f"failed to inject drift (rc {mut.rc}): {clip(mut.stderr or mut.stdout, 200)}"
                                )
                            drifted_sha = guest_file_sha256(ctx, t, CANARY_PLIST)
                            if drifted_sha == golden_sha:
                                raise StepFail("drift injection did not change plist sha256")

                            r = rssh(
                                ctx, t, ["sudo", "-n", installer, "run-once"], timeout=180
                            )
                            if r.rc != 0:
                                raise StepFail(
                                    f"drift repair run-once failed (rc {r.rc}): {clip(r.stderr or r.stdout, 300)}"
                                )
                            repaired = rssh(
                                ctx,
                                t,
                                ["sudo", "-n", "/bin/cat", CANARY_PLIST],
                                raw_newlines=True,
                            )
                            repaired_sha = guest_file_sha256(ctx, t, CANARY_PLIST)
                            if repaired.rc != 0 or repaired.stdout != golden_text or repaired_sha != golden_sha:
                                raise StepFail(
                                    f"drift was not repaired to golden (sha256={repaired_sha}, want={golden_sha})"
                                )
                            check_plist_perms_and_lint(
                                ctx, t, CANARY_PLIST, check_no_backup=True
                            )
                            want_args = [CANARY_PROG, CANARY_ARG]
                            info_after: dict[str, object] = {}

                            def reloaded() -> bool:
                                nonlocal info_after
                                p_after = rssh(
                                    ctx,
                                    t,
                                    [
                                        "sudo",
                                        "-n",
                                        "/bin/launchctl",
                                        "print",
                                        f"system/{CANARY_LABEL}",
                                    ],
                                )
                                if p_after.rc != 0:
                                    return False
                                info_after = parse_launchctl_print(p_after.stdout)
                                pid_a = info_after["pid"]
                                return (
                                    info_after["arguments"] == want_args
                                    and info_after["state"] == "running"
                                    and isinstance(pid_a, int)
                                    and pid_a != pid_before
                                )

                            if not wait_until(ctx, reloaded, 10.0, 0.5):
                                raise StepFail(
                                    f"drift repair did not reload repaired service "
                                    f"(before pid={pid_before}, after={info_after!r})"
                                )
                            pid_after = info_after["pid"]
                            return (
                                f"drifted sha256={drifted_sha[:12]} repaired to golden; "
                                f"reloaded pid {pid_before} -> {pid_after}; args={want_args}"
                            )

                        def step9_nonroot_negatives() -> str:
                            sha_before = guest_file_sha256(ctx, t, CANARY_PLIST)
                            nr_inst = rssh(ctx, t, [installer, "run-once"])
                            if nr_inst.rc == 0:
                                raise StepFail("non-root installer run-once exited 0 (must refuse)")
                            nr_agent = rssh(
                                ctx,
                                t,
                                [
                                    "env",
                                    f"CFENGINE_TEST_OVERRIDE_WORKDIR={workdir}",
                                    f"{TENDCF_PREFIX}/bin/cf-agent",
                                    "-K",
                                    "-f",
                                    f"{workdir}/inputs/promises.cf",
                                ],
                            )
                            sha_after = guest_file_sha256(ctx, t, CANARY_PLIST)
                            if sha_after != sha_before:
                                raise StepFail("non-root cf-agent altered root-owned plist")
                            nr_out = nr_agent.stdout + nr_agent.stderr
                            if nr_agent.rc == 0 and not any(
                                tok in nr_out
                                for tok in (
                                    "Permission denied",
                                    "CMDB cross-check failed",
                                    "refused",
                                    "skipped: belongs to launchd 'system' domain",
                                )
                            ):
                                raise StepFail(
                                    f"non-root cf-agent exited 0 without refusal: {clip(nr_out, 200)}"
                                )
                            nr_boot = rssh(
                                ctx,
                                t,
                                ["/bin/launchctl", "bootstrap", "system", CANARY_PLIST],
                            )
                            if nr_boot.rc == 0:
                                raise StepFail(
                                    "non-root launchctl bootstrap system exited 0 (must fail)"
                                )
                            return (
                                f"non-root installer rc={nr_inst.rc}; "
                                f"non-root cf-agent rc={nr_agent.rc} (plist unchanged); "
                                f"non-root bootstrap system rc={nr_boot.rc}"
                            )

                        def step9a_execd() -> str:
                            e1 = rssh(ctx, t, ["sudo", "-n", installer, "enable"])
                            if e1.rc != 0:
                                raise StepFail(
                                    f"installer enable failed (rc {e1.rc}): {clip(e1.stderr or e1.stdout, 300)}"
                                )
                            e2 = rssh(ctx, t, ["sudo", "-n", installer, "enable"])
                            if e2.rc != 0 or "tendcf-install: no change" not in e2.stdout:
                                raise StepFail(
                                    f"installer enable re-run was not a no-op (rc {e2.rc}): "
                                    f"{clip(e2.stdout + e2.stderr, 300)}"
                                )
                            plist_ev = check_plist_perms_and_lint(ctx, t, EXECD_PLIST)
                            last_ev = ""

                            def execd_up() -> bool:
                                nonlocal last_ev
                                ok_ex, last_ev = check_execd_running(ctx, t)
                                return ok_ex

                            if not wait_until(ctx, execd_up, 15.0, 0.5):
                                raise StepFail(last_ev)
                            return f"{plist_ev}; {last_ev}; enable re-run: no change"

                        run_step(
                            summary,
                            "4",
                            "render as root: plist root:wheel 0644, plutil -lint, no backup",
                            step4_render,
                            fatal=False,
                        )
                        run_step(
                            summary,
                            "5",
                            "rendered plist byte-identical to committed golden",
                            step5_golden,
                            fatal=False,
                        )
                        run_step(
                            summary,
                            "6",
                            "launchctl print shows expected program/args; kickstart -k restarts daemon",
                            step6_launchctl,
                            fatal=False,
                        )
                        run_step(
                            summary,
                            "7",
                            "idempotent re-run: no change, plist hash and pid unchanged",
                            step7_idempotency,
                            fatal=False,
                        )
                        run_step(
                            summary,
                            "8",
                            "drift repair: one-key edit repaired to golden and reloaded",
                            step8_drift,
                            fatal=False,
                        )
                        run_step(
                            summary,
                            "9",
                            "non-root negatives: installer, cf-agent and launchctl bootstrap system fail",
                            step9_nonroot_negatives,
                            fatal=False,
                        )
                        run_step(
                            summary,
                            "9a",
                            "root cf-execd LaunchDaemon (org.tendcf.execd) enabled, loaded, running as root",
                            step9a_execd,
                            fatal=False,
                        )

                def boot_session(target: vmssh.Target, timeout: float) -> str:
                    r = rssh(
                        ctx,
                        target,
                        ["sysctl", "-n", "kern.bootsessionuuid"],
                        timeout=timeout,
                    )
                    return r.stdout.strip() if r.rc == 0 else ""

                def reboot() -> str:
                    before = boot_session(t, 60)
                    if not before:
                        raise StepFail(
                            "could not read kern.bootsessionuuid before the reboot"
                        )
                    rssh(
                        ctx, t, ["sudo", "-n", "shutdown", "-r", "now"], timeout=60
                    )  # the connection drops; the status is not evidence
                    state_t = {"t": t}
                    restarts = 0

                    def back() -> bool:
                        nonlocal restarts
                        if not vm.alive():
                            # A guest restart can end tart run: boot the same VM again,
                            # with the cap re-checked, but not forever.
                            if restarts >= VM_RESTARTS_MAX:
                                raise StepFail(
                                    f"tart run exited {restarts} times after the reboot request; not restarting it again (see the run log)"
                                )
                            restarts += 1
                            try:
                                vm.start()
                            except Refusal as e:
                                raise StepFail(f"restart refused: {e}") from e
                        ip = ctx.run(
                            ["tart", "ip", "--wait", "5", clone], timeout=40
                        ).stdout.strip()
                        try:
                            ipaddress.ip_address(ip)
                        except ValueError:
                            return False
                        state_t["t"] = vmssh.Target(
                            ip, t.known_hosts, identity=t.identity, no_agent=True
                        )
                        now = boot_session(state_t["t"], 45)
                        return bool(now) and now != before

                    if not wait_until(ctx, back, 420, 5):
                        raise StepFail(
                            "ssh did not come back with a new boot session within 420s"
                        )
                    state["t"] = state_t["t"]
                    return (
                        f"kern.bootsessionuuid changed; ssh back at {state_t['t'].ip}"  # type: ignore[attr-defined]
                    )

                reboot_ok = run_step(
                    summary, "10", "reboot; ssh comes back", reboot, fatal=False
                )
                if reboot_ok:
                    t = state["t"]  # type: ignore[assignment]
                    facts: dict = {}
                    after = persistent_assertions(ctx, image, t, facts)
                    bad = [
                        f"{sid} {name}: {ev}" for sid, name, ok, ev in after if not ok
                    ]
                    try:
                        refused_password_login(ctx, t.ip, t.known_hosts)
                    except (StepFail, ToolError) as e:
                        bad.append(f"2f password login refused from the host: {e}")
                    summary.add(
                        "10a",
                        "image properties still hold after the reboot",
                        "fail" if bad else "pass",
                        "; ".join(bad)
                        or "2a-2l re-checked (2g after the reboot: "
                        f"polls={facts['mdutil'].polls} waited={facts['mdutil'].waited:.0f}s; "
                        f"listing: {facts['mdutil'].listing!r})",
                    )
                else:
                    summary.add(
                        "10a",
                        "image properties still hold after the reboot",
                        "skip",
                        "not run: step 10 failed",
                    )

                if not has_artifact:
                    skip_msg = "no artifact supplied (pass --tarball FILE or --artifact-run RUN_ID)"
                    summary.add(
                        "10b",
                        "launchctl print system/<label> loads from disk at boot (canary and org.tendcf.execd)",
                        "skip",
                        f"SKIP: {skip_msg}",
                    )
                    summary.add(
                        "11a",
                        "bootout and remove installed daemons; launchctl print then fails",
                        "skip",
                        f"SKIP: {skip_msg}",
                    )
                elif not installed:
                    summary.add(
                        "10b",
                        "launchctl print system/<label> loads from disk at boot (canary and org.tendcf.execd)",
                        "skip",
                        "not run: step 3 failed",
                    )
                    summary.add(
                        "11a",
                        "bootout and remove installed daemons; launchctl print then fails",
                        "skip",
                        "not run: step 3 failed",
                    )
                elif not reboot_ok:
                    summary.add(
                        "10b",
                        "launchctl print system/<label> loads from disk at boot (canary and org.tendcf.execd)",
                        "skip",
                        "not run: step 10 failed",
                    )
                    summary.add(
                        "11a",
                        "bootout and remove installed daemons; launchctl print then fails",
                        "skip",
                        "not run: step 10 failed",
                    )
                else:
                    def step10b_post_reboot() -> str:
                        want_args = [CANARY_PROG, CANARY_ARG]
                        ic: dict[str, object] = {}
                        last_c_err = ""

                        def canary_up() -> bool:
                            nonlocal ic, last_c_err
                            pc = rssh(
                                ctx,
                                t,
                                [
                                    "sudo",
                                    "-n",
                                    "/bin/launchctl",
                                    "print",
                                    f"system/{CANARY_LABEL}",
                                ],
                            )
                            if pc.rc != 0:
                                last_c_err = (
                                    f"post-reboot launchctl print system/{CANARY_LABEL} failed "
                                    f"(rc {pc.rc}): {clip(pc.stderr or pc.stdout, 300)}"
                                )
                                return False
                            ic = parse_launchctl_print(pc.stdout)
                            if (
                                ic["program"] != CANARY_PROG
                                or ic["arguments"] != want_args
                                or ic["state"] != "running"
                            ):
                                last_c_err = f"post-reboot {CANARY_LABEL} unexpected state: {ic!r}"
                                return False
                            return True

                        if not wait_until(ctx, canary_up, 15.0, 0.5):
                            raise StepFail(last_c_err)

                        last_ex_ev = ""

                        def execd_up() -> bool:
                            nonlocal last_ex_ev
                            ok_ex, last_ex_ev = check_execd_running(ctx, t)
                            return ok_ex

                        if not wait_until(ctx, execd_up, 15.0, 0.5):
                            raise StepFail(f"post-reboot {last_ex_ev}")
                        return (
                            f"{CANARY_LABEL} loaded at boot (state=running, pid={ic['pid']}); "
                            f"{last_ex_ev}"
                        )

                    def step11a_teardown() -> str:
                        installer = f"{guest_stage}/tendcf-install.sh"
                        d_r = rssh(
                            ctx,
                            t,
                            [
                                "sudo",
                                "-n",
                                installer,
                                "data",
                                f"{guest_stage}/canary/host_specific-absent.json",
                            ],
                        )
                        if d_r.rc != 0:
                            raise StepFail(
                                f"tombstone data install failed (rc {d_r.rc}): "
                                f"{clip(d_r.stderr or d_r.stdout, 300)}"
                            )
                        ro = rssh(
                            ctx, t, ["sudo", "-n", installer, "run-once"], timeout=180
                        )
                        if ro.rc != 0:
                            raise StepFail(
                                f"tombstone run-once failed (rc {ro.rc}): "
                                f"{clip(ro.stderr or ro.stdout, 300)}"
                            )
                        gone_c = rssh(
                            ctx,
                            t,
                            ["sudo", "-n", "/bin/sh", "-c", '! test -e "$1"', "sh", CANARY_PLIST],
                        )
                        if gone_c.rc != 0:
                            raise StepFail(f"{CANARY_PLIST} still exists after tombstone")
                        pr_c = rssh(
                            ctx,
                            t,
                            [
                                "sudo",
                                "-n",
                                "/bin/launchctl",
                                "print",
                                f"system/{CANARY_LABEL}",
                            ],
                        )
                        if pr_c.rc == 0:
                            raise StepFail(
                                f"launchctl print system/{CANARY_LABEL} still exits 0 after teardown"
                            )

                        dis = rssh(ctx, t, ["sudo", "-n", installer, "disable"])
                        if dis.rc != 0:
                            raise StepFail(
                                f"installer disable failed (rc {dis.rc}): "
                                f"{clip(dis.stderr or dis.stdout, 300)}"
                            )
                        gone_e = rssh(
                            ctx,
                            t,
                            ["sudo", "-n", "/bin/sh", "-c", '! test -e "$1"', "sh", EXECD_PLIST],
                        )
                        if gone_e.rc != 0:
                            raise StepFail(f"{EXECD_PLIST} still exists after disable")
                        pr_e = rssh(
                            ctx,
                            t,
                            [
                                "sudo",
                                "-n",
                                "/bin/launchctl",
                                "print",
                                f"system/{EXECD_LABEL}",
                            ],
                        )
                        if pr_e.rc == 0:
                            raise StepFail(
                                f"launchctl print system/{EXECD_LABEL} still exits 0 after disable"
                            )
                        rssh(ctx, t, ["/bin/rm", "-rf", guest_stage])
                        return (
                            f"{CANARY_LABEL} torn down (plist removed, print rc={pr_c.rc}); "
                            f"{EXECD_LABEL} disabled (plist removed, print rc={pr_e.rc})"
                        )

                    run_step(
                        summary,
                        "10b",
                        "launchctl print system/<label> loads from disk at boot (canary and org.tendcf.execd)",
                        step10b_post_reboot,
                        fatal=False,
                    )
                    run_step(
                        summary,
                        "11a",
                        "bootout and remove installed daemons; launchctl print then fails",
                        step11a_teardown,
                        fatal=False,
                    )
                if adopt:
                    if not summary.ok:
                        summary.add(
                            "adopt",
                            "adopt golden owner marker",
                            "skip",
                            "not adopted: check failed",
                        )
                    else:
                        golden_usable(ctx, golden)
                        rec_adopt = read_golden_record(ctx)
                        if (
                            initial_adopt_rec is None
                            or rec_adopt["key_id"] != initial_adopt_rec["key_id"]
                            or rec_adopt.get("host_key")
                            != initial_adopt_rec.get("host_key")
                        ):
                            raise Refusal(
                                f"cannot adopt {golden}: golden.json changed during check "
                                f"(was key_id={initial_adopt_rec['key_id'] if initial_adopt_rec else None!r}, "
                                f"host_key={initial_adopt_rec.get('host_key') if initial_adopt_rec else None!r}; "
                                f"now key_id={rec_adopt['key_id']!r}, "
                                f"host_key={rec_adopt.get('host_key')!r})"
                            )
                        need_write, _ = check_adopt_precondition(
                            ctx, golden, rec_adopt
                        )
                        marker = owner_path(ctx, golden)
                        if need_write:
                            with signals_ignored():
                                try:
                                    write_owner(
                                        ctx,
                                        golden,
                                        rec_adopt["key_id"],
                                        rec_adopt.get("host_key"),
                                        OWNER_FINAL,
                                    )
                                    adopt_note = (
                                        f"wrote final owner marker {marker} for key "
                                        f"{rec_adopt['key_id']}"
                                    )
                                except LandedNotDurable as e:
                                    adopt_note = (
                                        f"wrote final owner marker {marker} "
                                        f"(landed, durability unconfirmed: {e})"
                                    )
                                except OSError as e:
                                    raise ToolError(
                                        f"failed to write owner marker {marker}: {e}"
                                    ) from e
                            summary.add(
                                "adopt",
                                "adopt golden owner marker",
                                "pass",
                                adopt_note,
                            )
                        else:
                            summary.add(
                                "adopt",
                                "adopt golden owner marker",
                                "pass",
                                f"already owned by this state dir ({marker}); nothing to change",
                            )
                rc = 0
            except Refusal as e:
                refusal = str(e)
            except Abort:
                summary.add("blocked", "steps 2-10", "skip", "not run: step 1 failed")
                rc = 1
            except ToolError as e:
                summary.add("error", "tool error", "fail", str(e))
            except Interrupted as e:
                summary.add(
                    "interrupted",
                    "interrupted",
                    "fail",
                    f"{e}; the clone is removed now and any leftover is swept next run",
                )
                rc = 130
            finally:
                with signals_ignored():
                    if artifact_tmpdir is not None:
                        shutil.rmtree(artifact_tmpdir, ignore_errors=True)
                    try:
                        if cloned:
                            ev = remove_vm(ctx, clone, vm.proc)
                            gone = clone not in local_vms(ctx)
                            summary.add(
                                "11",
                                "stop and delete the clone (always)",
                                "pass" if gone else "fail",
                                ev,
                            )
                        elif not refusal:
                            summary.add(
                                "11",
                                "stop and delete the clone (always)",
                                "pass",
                                "no clone was made",
                            )
                    except ToolError as e:
                        summary.add(
                            "11", "stop and delete the clone (always)", "fail", str(e)
                        )
    except Refusal as e:
        return refuse(summary, ctx, args, str(e))
    if refusal:
        return refuse(summary, ctx, args, refusal)
    emit(summary, ctx, args.summary)
    return 130 if rc == 130 else (0 if summary.ok else 1)


# ---------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="state1_vm.py", description=__doc__.split("\n\n")[0]
    )
    ap.add_argument(
        "--image",
        type=Path,
        default=DEFAULT_IMAGE_JSON,
        help="image pin file (default: image.json beside this script)",
    )
    ap.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help="locks, logs, pinned known_hosts, golden record",
    )
    ap.add_argument(
        "--summary", type=Path, help="write the JSON summary here instead of stdout"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser(
        "resolve", help="print the registry digest of the pinned tag (no tart, no pull)"
    )
    sub.add_parser(
        "pull", help="pull the pinned image into tart's OCI cache (heavy, separate job)"
    )
    g = sub.add_parser("golden", help="build state1-golden from the cached image")
    g.add_argument(
        "--rebuild",
        action="store_true",
        help="delete an existing state1-golden and build it again",
    )
    g.add_argument(
        "--keep-on-failure",
        action="store_true",
        help="leave the half-built VM for inspection (swept on the next run)",
    )
    g.add_argument(
        "--adopt",
        action="store_true",
        help="promote a matching committing owner marker for this state dir to final",
    )
    c = sub.add_parser(
        "check", help="clone state1-golden, run the checklist, delete the clone"
    )
    c.add_argument(
        "--adopt",
        action="store_true",
        help="after passing strict key login, write a final owner marker if none exists",
    )
    c.add_argument(
        "--tarball",
        type=Path,
        help="local PR 95 macOS fork tarball to install and test (runs steps 3-9, 9a, 10b, 11a live)",
    )
    c.add_argument(
        "--sha256",
        type=Path,
        help="sha256 file for --tarball (default: <tarball>.sha256)",
    )
    c.add_argument(
        "--artifact-run",
        help="GitHub Actions run id of macOS fork build to download via gh and test",
    )
    c.add_argument(
        "--golden",
        type=Path,
        default=CANARY_GOLDEN,
        help="committed per-domain golden plist to byte-compare against in step 5",
    )
    return ap


def main(argv: list[str] | None = None, ctx: Ctx | None = None) -> int:
    args = build_parser().parse_args(argv)
    ctx = ctx or Ctx(state_dir=args.state_dir.expanduser())
    handler = {
        "resolve": cmd_resolve,
        "pull": cmd_pull,
        "golden": cmd_golden,
        "check": cmd_check,
    }[args.cmd]
    try:
        return handler(ctx, args)
    except Refusal as e:  # before any summary exists (bad pin file, bad key file)
        ctx.err("refused: " + str(e))
        return 2


if __name__ == "__main__":
    sys.exit(main())
