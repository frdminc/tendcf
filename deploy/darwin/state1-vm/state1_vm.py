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
import fcntl
import hashlib
import ipaddress
import json
import os
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
DEFAULT_STATE_DIR = Path.home() / ".local" / "state" / "tendcf-state1-vm"
# One host-wide lock whatever --state-dir says: the VM names (state1-golden-build,
# state1-check-*) are global in tart, so the lock has to be too.
LOCK_PATH = DEFAULT_STATE_DIR / "driver.lock"
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
    ) -> Result:
        out = open(log_path, "ab") if log_path else None  # noqa: SIM115
        try:
            cp = subprocess.run(
                argv,
                input=input_text,
                stdin=None if input_text is not None else subprocess.DEVNULL,
                stdout=out if out else subprocess.PIPE,
                stderr=subprocess.STDOUT if out else subprocess.PIPE,
                text=input_text is not None or out is None,
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
        return Result(cp.returncode, cp.stdout or "", cp.stderr or "")

    def start(self, argv: list[str], *, log_path: Path) -> RealProc:
        log = open(log_path, "ab")  # noqa: SIM115
        try:
            p = subprocess.Popen(
                argv,
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
    lock_path: Path = LOCK_PATH

    def __post_init__(self) -> None:
        if not self.run_id:
            self.run_id = (
                self.now().strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(2)
            )

    def run(self, argv: list[str], **kw) -> Result:
        self.err(
            "$ " + shlex.join(argv)
        )  # argv only: environments and stdin are never logged
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
        self.proc = self.ctx.runner.start(argv, log_path=log)  # type: ignore[attr-defined]

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
) -> Result:
    return ctx.run(
        vmssh.ssh_argv(t, argv),
        input_text=input_text,
        env=vmssh.ssh_env(t),
        timeout=timeout,
    )


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
    blob = base64.b64decode(pubkey_line.split()[1])
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
    atomic_write(dest, f"{vmssh.HOST_ALIAS} {kind} {blob}\n")
    return f"{kind} " + fingerprint(f"{kind} {blob}")


def kh_key_line(path: Path) -> str | None:
    """The 'ssh-ed25519 <base64>' line of the entry in a known_hosts file for our alias, if any."""
    try:
        for line in path.read_text().splitlines():
            parts = line.split()
            if (
                len(parts) >= 3
                and parts[0] == vmssh.HOST_ALIAS
                and parts[1] == "ssh-ed25519"
            ):
                return f"{parts[1]} {parts[2]}"
    except (OSError, ValueError):
        return None
    return None


def kh_fingerprint(path: Path) -> str | None:
    """Fingerprint of the ed25519 entry in a known_hosts file written for our alias, if any."""
    line = kh_key_line(path)
    try:
        return fingerprint(line) if line else None
    except ValueError:
        return None


def atomic_write(dest: Path, text: str, mode: int = 0o600) -> None:
    """Write via a fresh mkstemp file in the same directory, then os.replace (no symlink follow)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=dest.name + ".")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


# ---------------------------------------------------------------- lock, signals


@contextlib.contextmanager
def driver_lock(ctx: Ctx):
    """One driver per host, whatever --state-dir says; never follows a symlink at the path."""
    ctx.lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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
    )
    cfg = set(r.stdout.split("\n"))
    want = {
        "passwordauthentication no",
        "kbdinteractiveauthentication no",
        "pubkeyauthentication yes",
        "permitrootlogin no",
    }
    out.append(
        (
            "2e",
            "sshd effective config: key login only",
            r.rc == 0 and want <= cfg,
            f"rc {r.rc}; missing {sorted(want - cfg)}",
        )
    )

    r = rssh(ctx, t, ["sudo", "-n", "mdutil", "-a", "-s"])
    out.append(
        (
            "2g",
            "Spotlight indexing off",
            r.rc == 0
            and "Indexing enabled" not in r.stdout
            and "Indexing disabled" in r.stdout,
            r.stdout or r.stderr,
        )
    )

    ev = []
    ok = True
    for key in (
        "AutomaticCheckEnabled",
        "AutomaticDownload",
        "AutomaticallyInstallMacOSUpdates",
    ):
        r = rssh(
            ctx,
            t,
            ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", key],
        )
        ok &= r.rc == 0 and r.stdout.strip() == "0"
        ev.append(f"{key}={r.stdout.strip() or r.stderr.strip()}")
    out.append(("2h", "automatic updates off", ok, " ".join(ev)))

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
    # dscl result (no such user, disabled or expired account, no directory, unparseable
    # output, ssh's own 255) must not read as "the password was changed". No sudo: -authonly
    # only verifies a credential.
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
        atomic_write(summary_path, text, 0o644)
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


def golden_record(ctx: Ctx) -> tuple[str, str]:
    """(key_id, authorized_key fingerprint) from this state dir's golden.json; Refusal if
    there is no usable record."""
    rec_path = ctx.state_dir / "golden.json"
    try:
        rec = json.loads(rec_path.read_text())
        key_id, want = rec["key_id"], rec["authorized_key"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise Refusal(f"{rec_path}: no usable golden record ({e!r})") from e
    if not isinstance(key_id, str) or not isinstance(want, str):
        raise Refusal(f"{rec_path}: key_id and authorized_key must be strings")
    return key_id, want


def golden_usable(ctx: Ctx) -> str:
    """The one test of "this state dir can check its golden": the pinned known_hosts file
    holds our alias's ed25519 key, and the record and key are usable (golden_identity).
    Returns the private key path; Refusal otherwise. `check` refuses on it and `golden`
    rebuilds on it, so the two never disagree."""
    kh = ctx.state_dir / "known_hosts"
    if not kh.is_file() or kh_fingerprint(kh) is None:
        raise Refusal(
            f"{kh} is missing or has no pinned host key (written by golden); run `golden`"
        )
    return golden_identity(ctx)


def golden_identity(ctx: Ctx) -> str:
    """The private key of the current golden, found through golden.json; Refusal otherwise.
    The private key itself is matched to the recorded fingerprint (its public half is derived
    with `ssh-keygen -y`, not read from the .pub file), so a key from another golden, a
    swapped private key or a hand-edited record is not silently used."""
    again = "run `golden`"
    try:
        key_id, want = golden_record(ctx)
    except Refusal as e:
        raise Refusal(f"{e}; {again}") from e
    priv, pub = key_paths(ctx, key_id)
    try:
        private_ok(priv)
    except Refusal as e:
        raise Refusal(f"{e}; {again}") from e
    # -P '' (an empty passphrase, never a prompt) and no controlling tty: a passphrase-
    # protected key (not one this driver minted) is a refusal, not a question on /dev/tty
    r = ctx.run(
        ["ssh-keygen", "-y", "-P", "", "-f", str(priv)], timeout=30, no_tty=True
    )
    derived = r.stdout.strip()
    if r.rc != 0 or not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+( .*)?", derived):
        raise Refusal(
            f"{priv}: ssh-keygen -y could not read the private key without a passphrase "
            f"(rc {r.rc}; a key with a passphrase is refused); {again}"
        )
    got = fingerprint(derived)
    pub_got = fingerprint(read_pubkey(pub))
    if got != want or pub_got != want:
        raise Refusal(
            f"{priv} is {got} (its .pub says {pub_got}), golden.json says {want}: "
            f"the key does not belong to this golden; {again}"
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
                        golden_record(ctx)
                    except Refusal as e:
                        # The tart golden is global; the record is per state dir. A golden
                        # this state dir has no record of (another state dir's, or one from
                        # before records) is not ours to replace unasked.
                        raise Refusal(
                            f"{golden} exists but this state dir has no record of it ({e}); "
                            "it may belong to another state dir or predate records: pass "
                            "--rebuild to replace it"
                        ) from e
                    try:
                        golden_usable(ctx)
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
                            "nothing to do; its record and key are usable; pass --rebuild to build it again",
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
                    atomic_write(Path(kh_boot), f"{vmssh.HOST_ALIAS} {vanilla}\n")
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
                    return (
                        f"prep.sh sha256 {sha256_text(script.read_text())[:16]}; {m[0]}"
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

                    # The commit: remove the old golden (--rebuild), rename, then the two
                    # record files, all with signals ignored so no interrupt can land between
                    # the steps and leave the old golden gone and the new build deleted. The
                    # record files are written only after the rename succeeded. keep_build is
                    # set first: from here on a failure never deletes the finished build.
                    def park_record() -> str:
                        # The new record (it names this build's key) beside the old one, so
                        # finishing by hand does not need a rebuild and the key is not orphaned.
                        try:
                            atomic_write(
                                ctx.state_dir / "known_hosts.pending", pinned_text
                            )
                            atomic_write(
                                ctx.state_dir / "golden.json.pending",
                                record + "\n",
                                0o644,
                            )
                        except OSError:
                            return ""
                        return (
                            "; the new record is in known_hosts.pending and golden.json.pending "
                            "in the state dir (golden.json.pending names its key): after the "
                            "rename, mv them over known_hosts and golden.json"
                        )

                    with signals_ignored():
                        keep_build = True
                        if golden in local_vms(ctx):
                            try:
                                done = remove_vm(ctx, golden)
                            except ToolError as e:
                                raise ToolError(
                                    f"removing the old {golden} failed: {e}; it and the finished "
                                    f"build {build} are both kept; known_hosts and golden.json "
                                    f"are unchanged{park_record()}"
                                ) from e
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
                                f"the finished build is kept as {build}: run `tart rename {build} {golden}` "
                                f"before the next golden run, which sweeps it{park_record()}"
                            )
                        atomic_write(ctx.state_dir / "known_hosts", pinned_text)
                        atomic_write(
                            ctx.state_dir / "golden.json", record + "\n", 0o644
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
                    return f"{stopped}; renamed {build} -> {golden}; record and known_hosts written"

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
                identity = golden_usable(ctx)
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
                    bad = [
                        f"{sid} {name}: {ev}"
                        for sid, name, ok, ev in persistent_assertions(ctx, image, t)
                        if not ok
                    ]
                    summary.add(
                        "10a",
                        "image properties still hold after the reboot",
                        "fail" if bad else "pass",
                        "; ".join(bad) or "2a-2e, 2g-2l re-checked",
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
