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
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vmssh

HERE = Path(__file__).resolve().parent
DEFAULT_IMAGE_JSON = HERE / "image.json"
# The account's home from the passwd entry, never $HOME: tart itself (Foundation) ignores
# $HOME, so a second $HOME of the same user must not mean a second lock (or marker).


def account_home(environ: dict[str, str] | None = None) -> str:
    """The account's home from the passwd entry, never $HOME, like Foundation; $HOME (else
    "/") only when this uid has no passwd entry (a container or a sandbox), where Foundation
    also falls back to it."""
    try:
        return pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        return (os.environ if environ is None else environ).get("HOME") or "/"


DEFAULT_STATE_DIR = Path(account_home()) / ".local" / "state" / "tendcf-state1-vm"
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
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
REPO_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
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
UPDATES_OFF_LINE = "Automatic checking for updates is turned off"
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
# Is the root-owned tree root:wheel and free of group/world write? Prints offenders only.
TREE_CHECK_SH = (
    'test -d "$1" || exit 1; '
    'find "$1" \\( ! -user root -o ! -group wheel \\) -print | head -n 5; '
    'find "$1" ! -type l \\( -perm -020 -o -perm -002 \\) -print | head -n 5'
)


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
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        log_path: Path | None = None,
        no_tty: bool = False,
        raw_newlines: bool = False,
    ) -> Result:
        """raw_newlines: no text mode, so no universal-newline translation (it turns a lone
        CR or CRLF into "\\n"): bytes in, stdout/stderr decoded as UTF-8 with errors="replace".
        Opt-in; the default is unchanged for every other caller."""
        out = open(log_path, "ab") if log_path else None  # noqa: SIM115
        raw = raw_newlines and out is None
        try:
            cp = subprocess.run(
                argv,
                input=input_text.encode("utf-8")
                if raw and input_text is not None
                else input_text,
                stdin=None if input_text is not None else subprocess.DEVNULL,
                stdout=out if out else subprocess.PIPE,
                stderr=subprocess.STDOUT if out else subprocess.PIPE,
                text=(input_text is not None or out is None) and not raw,
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


def resolve_tart_home(environ: dict[str, str] | None = None) -> str:
    """The tart home `tart` itself uses, resolved (tart's Config.swift): $TART_HOME whenever
    it is set, even to the empty string (realpath("") is the cwd, as in tart); else the
    account's home (CFFIXED_USER_HOME if set, even empty, else the passwd entry: never $HOME) plus
    /.tart. Computed once per run (Ctx) and exported as TART_HOME to every tart call, so tart
    and this driver cannot disagree."""
    env = os.environ if environ is None else environ
    raw = env.get("TART_HOME")
    if raw is not None:
        return os.path.realpath(raw)
    base = env.get("CFFIXED_USER_HOME")  # set but empty is the cwd, as in Foundation
    if base is None:
        base = account_home(env)
    return os.path.realpath(os.path.join(base, ".tart"))


def tart_key(tart_home: str) -> str:
    """A short stable name part for one tart home: its lock and its owner markers."""
    return hashlib.sha256(os.fsencode(tart_home)).hexdigest()[:8]


def state_dir_link_problem(given: Path) -> str:
    """Why a --state-dir that is itself a symlink must not be followed ("" when fine): one
    that dangles would make the driver create its target (and missing parents) wherever the
    link points, and one that another user owns lets them choose where the state dir is. A
    symlink of ours to an existing directory is the operator's choice and stays accepted.
    Ancestors of the path are not checked (tracked in issue 82)."""
    try:
        st = os.lstat(given)
    except OSError:
        return ""  # missing (made later) or unreadable (the stat there says so)
    if not stat.S_ISLNK(st.st_mode):
        return ""
    if st.st_uid != os.getuid():
        return (
            f"the state dir {str(given)!r} is a symlink owned by uid {st.st_uid}, not you: "
            "refusing to follow it (pass the real directory)"
        )
    try:
        os.stat(given)
    except OSError:
        return (
            f"the state dir {str(given)!r} is a symlink that points nowhere: refusing to "
            "create its target (make the directory or pass a real path)"
        )
    return ""


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
        if self.lock_path is None:
            self.lock_path = DEFAULT_STATE_DIR / LOCK_NAME
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
                re.compile(r"^\d+\.\d+\.\d+$"),
                image["python"]["version"],
            ),
            ("python.sha256", re.compile(r"^[0-9a-f]{64}$"), image["python"]["sha256"]),
            ("python.url", re.compile(r"^https://\S+$"), image["python"]["url"]),
            (
                "python.signer",
                re.compile(r"^[^\n]+ \([A-Z0-9]{10}\)$"),
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
    timeout: float = 120,
    raw_newlines: bool = False,
) -> Result:
    kw = (
        {"raw_newlines": True} if raw_newlines else {}
    )  # opt-in; other callers unchanged
    return ctx.run(
        vmssh.ssh_argv(t, argv),
        input_text=input_text,
        env=vmssh.ssh_env(t),
        timeout=timeout,
        **kw,
    )


SSHD_WANT = frozenset(
    {
        "passwordauthentication no",
        "kbdinteractiveauthentication no",
        "pubkeyauthentication yes",
        "permitrootlogin no",
    }
)


def sshd_key_only(r: Result) -> tuple[bool, str]:
    """Check 2e: does `sshd -T` show key-only login? (ok, evidence).

    macOS 27.2's sshd prints "PasswordAuthentication no", stock OpenSSH lowercase. Accept
    exactly what prep.sh's `LC_ALL=C grep -qixF` accepts: whole lines split on "\\n" only
    (never splitlines(): it also splits on \\x0b, \\x0c, \\x1c-\\x1e, U+0085, U+2028 and U+2029,
    which a quoted sshd value such as Banner can carry, so one printed line could fake a
    wanted one), no stripping, ASCII-only case folding. The caller must run ssh with
    raw_newlines=True: in text mode Python turns a lone CR into a newline before this sees
    it. A CR anywhere in the output fails closed, as grep would see it as part of a line."""
    cfg = {ln.lower() for ln in r.stdout.split("\n") if ln.isascii()}
    missing = sorted(SSHD_WANT - cfg)
    cr = "\r" in r.stdout
    ev = f"rc {r.rc}; missing {missing}"
    if cr:
        ev += "; output contains a carriage return (read untranslated; it could fake or hide a line)"
    return r.rc == 0 and not cr and not missing, ev


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


@contextlib.contextmanager
def driver_lock(ctx: Ctx):
    """One driver per account (one lock file under the account's passwd home, whatever
    --state-dir and the tart home say); never follows a symlink at the path."""
    try:
        ctx.lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as e:
        raise Refusal(
            f"cannot create the lock directory {ctx.lock_path.parent}: {e}"
        ) from e
    # the owner marker beside the lock gates an unattended rebuild: nobody else may plant,
    # replace or delete it, so the directory is ours and not group or world writable
    try:
        st = ctx.lock_path.parent.lstat()
    except OSError as e:
        raise Refusal(f"cannot inspect {ctx.lock_path.parent}: {e}") from e
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
        raise Refusal(
            f"{ctx.lock_path.parent} (the driver lock and owner markers) must be a real "
            f"directory owned by you and not group or world writable (is uid {st.st_uid}, "
            f"mode {st.st_mode & 0o777:o})"
        )
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
    trusts: it must be a directory of ours that is not group or world writable (the same rule
    as the lock directory). Ctx resolved it once at startup (symlinks and relative paths
    included, so a later retarget or chdir does not move it); a missing one is made 0700 with
    its missing parents (umask 077 around the mkdir). Mode bits only: macOS ACLs are not
    considered, and ancestors of an existing path are not checked."""
    if ctx.state_dir_refusal:
        raise Refusal(ctx.state_dir_refusal)
    old = os.umask(0o077)
    try:
        ctx.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    except FileExistsError:
        pass  # a file: the check below says so
    except OSError as e:
        raise Refusal(f"cannot create the state dir {ctx.state_dir}: {e}") from e
    finally:
        os.umask(old)
    try:
        st = ctx.state_dir.lstat()  # resolved already: a link here was planted since
    except OSError as e:
        raise Refusal(f"cannot inspect the state dir {ctx.state_dir}: {e}") from e
    if not stat.S_ISDIR(st.st_mode):
        raise Refusal(f"the state dir {ctx.state_dir} is not a directory")
    if st.st_uid != os.getuid() or st.st_mode & 0o022:
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
    ctx: Ctx, t: vmssh.Target, path: str, *, tree: bool = False
) -> tuple[bool, str]:
    """Step 3's rule on one path; with tree=True on everything under it as well.

    Every ancestor up to / must also be owned by root and not group/world writable: a
    writable parent lets its owner group rename the checked directory aside and put another
    tree in its place (python.org leaves Python.framework/Versions root:admin 775).
    """
    r = rssh(ctx, t, ["stat", "-f", "%Su:%Sg %Lp", path])
    m = re.fullmatch(r"(\S+):(\S+) ([0-7]+)", r.stdout.strip())
    if r.rc != 0 or not m:
        return False, f"stat {path} failed (rc {r.rc}): {clip(r.stderr, 200)}"
    ok = perm_ok(m[1], m[2], m[3])
    ev = f"{path} {m[1]}:{m[2]} {m[3]}"
    parents = ancestors_of(path)
    r = rssh(ctx, t, ["stat", "-f", "%N %Su:%Sg %Lp", *parents])
    rows = [ln.rsplit(" ", 2) for ln in r.stdout.strip().splitlines()]
    seen = {}
    for row in rows:
        if len(row) == 3:
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
            or pm[1] != "root"
            or int(row[2], 8) & 0o022
        ):
            bad_parents.append(f"{par} {row[1] + ' ' + row[2] if row else '?'}")
    parents_ok = not bad_parents
    ok = ok and parents_ok
    ev += (
        f"; {len(parents)} ancestors root-owned, no group/world write"
        if parents_ok
        else f"; ancestors not root-owned or writable (rc {r.rc}): {clip(', '.join(bad_parents) or r.stderr, 300)}"
    )
    if tree:
        r = rssh(ctx, t, ["/bin/sh", "-c", TREE_CHECK_SH, "sh", path])
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


def mdutil_off(ctx: Ctx, t: vmssh.Target) -> tuple[bool, str]:
    """`mdutil -a -s` says indexing is off on every volume, after a bounded settle.

    While the output contains kMDConfigSearchLevelTransitioning the volume is still changing
    state: ask again every MDUTIL_SETTLE_INTERVAL seconds for at most MDUTIL_SETTLE_TIMEOUT.
    "Indexing enabled", a non-0 exit, or any text other than a volume header, "Indexing
    disabled." and the transitioning error fails at once, never retried into a pass. The
    evidence ends with `polls=N waited=Ns`, so a run measures how long a reboot's settle took.
    """
    start = ctx.monotonic()
    polls = 0
    while True:
        r = rssh(ctx, t, ["sudo", "-n", "mdutil", "-a", "-s"])
        polls += 1
        waited = ctx.monotonic() - start
        note = f"polls={polls} waited={waited:.0f}s"
        text = r.stdout
        if r.rc != 0:
            return False, f"rc {r.rc}: {clip(r.stdout or r.stderr, 300)}; {note}"
        if "Indexing enabled" in text:
            return False, f"{clip(text, 300)}; {note}"
        if MDUTIL_TRANSITIONING in text:
            if waited + MDUTIL_SETTLE_INTERVAL > MDUTIL_SETTLE_TIMEOUT:
                return False, f"still transitioning: {clip(text, 300)}; {note}"
            ctx.sleep(MDUTIL_SETTLE_INTERVAL)
            continue
        odd = [
            ln
            for ln in text.splitlines()
            if ln.strip()
            and not ln.rstrip().endswith(":")
            and ln.strip() != "Indexing disabled."
        ]
        ok = "Indexing disabled" in text and not odd
        why = "" if ok else f" (unexpected text {odd[:2]!r})" if odd else ""
        return ok, f"{clip(text.strip(), 300)}{why}; {note}"


def updates_off(ctx: Ctx, t: vmssh.Target) -> tuple[bool, str]:
    """Automatic update checking, download and install are off.

    The check is `softwareupdate --schedule`, which is what the system itself answers with.
    macOS 27.2 drops a raw `defaults write` of AutomaticCheckEnabled (issue 70 run 2: the key
    was absent from the plist file while the schedule said "turned on"), so that key is not
    read, and its absence is not a failure. AutomaticDownload and
    AutomaticallyInstallMacOSUpdates must still read 0.
    """
    r = rssh(ctx, t, ["sudo", "-n", "softwareupdate", "--schedule"])
    said = (r.stdout or r.stderr).strip()
    ok = r.rc == 0 and UPDATES_OFF_LINE in said and "turned on" not in said
    ev = [f"schedule rc {r.rc}: {clip(said, 200)!r}"]
    for key in ("AutomaticDownload", "AutomaticallyInstallMacOSUpdates"):
        r = rssh(
            ctx,
            t,
            ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", key],
        )
        ok &= r.rc == 0 and r.stdout.strip() == "0"
        ev.append(f"{key}={r.stdout.strip() or r.stderr.strip()}")
    return ok, " ".join(ev)


def persistent_assertions(
    ctx: Ctx, image: dict, t: vmssh.Target
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

    r = rssh(
        ctx,
        t,
        [
            "sudo",
            "-n",
            "/usr/sbin/sshd",
            "-T",
            "-C",
            f"user={t.user},host=localhost,addr=127.0.0.1",
        ],
        raw_newlines=True,  # sshd's bytes untranslated: see sshd_key_only
    )
    ok_2e, ev_2e = sshd_key_only(r)
    out.append(("2e", "sshd effective config: key login only", ok_2e, ev_2e))

    ok_2g, ev_2g = mdutil_off(ctx, t)
    out.append(("2g", "Spotlight indexing off", ok_2g, ev_2g))

    ok_2h, ev_2h = updates_off(ctx, t)
    out.append(("2h", "automatic updates off", ok_2h, ev_2h))

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
                    m = re.search(r"^PREP-RESULT .*$", out, re.MULTILINE)
                    if not m:
                        raise StepFail(
                            "prep.sh printed no PREP-RESULT line: " + clip(out, 400)
                        )
                    state["prep_hostkey"] = parse_prep_hostkey(out)
                    if len(CONSOLE_PW_LINE_RE.findall(out)) != 1:
                        raise StepFail(
                            "prep.sh did not confirm the console password was rotated: "
                            + clip(out, 300)
                        )
                    st = SECURE_TOKEN_AFTER_RE.search(out)
                    token = (
                        clip(st[0].removeprefix("prep: "), 300)
                        if st
                        else "secure token status (after): not printed by prep.sh"
                    )
                    return (
                        f"prep.sh sha256 {sha256_text(script.read_text())[:16]}; {m[0]}; "
                        f"{token}"
                    )

                def pin() -> str:
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
                        if golden in local_vms(ctx):
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
                                # the old golden and its records are unchanged: so is the
                                # owner file, again
                                back = restore_marker(prev_marker, prev_readable)
                                raise ToolError(
                                    f"removing the old {golden} failed: {e}; it and the finished "
                                    f"build {build} are both kept; known_hosts and golden.json "
                                    f"are unchanged; {back}{finish_note(False)}"
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
                assert_vm_cap(ctx)
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

                summary.add(
                    "3",
                    "install path ownership and permissions (root:wheel, not group/world writable)",
                    "skip",
                    "needs the renderer slice: there is no tendcf build or install command yet. The assertion (perm_ok, check_root_owned with tree=True) is live and is applied to the Python framework in 2i.",
                )
                for sid in ("4", "5", "6", "7", "8", "9"):
                    summary.add(
                        sid, f"checklist step {sid}", "skip", "SKIP: renderer slice"
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

                if run_step(
                    summary, "10", "reboot; ssh comes back", reboot, fatal=False
                ):
                    t = state["t"]  # type: ignore[assignment]
                    after = persistent_assertions(ctx, image, t)
                    bad = [
                        f"{sid} {name}: {ev}" for sid, name, ok, ev in after if not ok
                    ]
                    settle = [
                        m[0]
                        for sid, _n, _ok, ev in after
                        if sid == "2g"
                        and (m := re.search(r"polls=\d+ waited=\d+s", ev))
                    ]
                    summary.add(
                        "10a",
                        "image properties still hold after the reboot",
                        "fail" if bad else "pass",
                        "; ".join(bad)
                        or "2a-2e, 2g-2l re-checked"
                        + (f" (2g after the reboot: {settle[0]})" if settle else ""),
                    )
                else:
                    summary.add(
                        "10a",
                        "image properties still hold after the reboot",
                        "skip",
                        "not run: step 10 failed",
                    )
                summary.add(
                    "10b",
                    "launchctl print system/<label> loads from disk at boot",
                    "skip",
                    "SKIP: renderer slice (there is no daemon to print yet)",
                )
                summary.add(
                    "11a",
                    "bootout and remove the installed daemon; launchctl print then fails",
                    "skip",
                    "SKIP: renderer slice (nothing is installed to bootout or remove yet; step 11's stop and delete below is live)",
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
    sub.add_parser(
        "check", help="clone state1-golden, run the checklist, delete the clone"
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
