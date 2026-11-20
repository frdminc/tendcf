#!/usr/bin/env python3
"""State 1 macOS VM: image prep and check harness (issue 70, slice A).

Host-side driver for bigmac (Apple Silicon, tart). Four subcommands, each safe to
re-run after an interruption; every tart and ssh call is an argv list.

    state1_vm.py resolve                      tag -> digest from the registry (no tart, no pull)
    state1_vm.py pull                         pull the pinned image (the heavy ~30 GB job)
    state1_vm.py golden --pubkey K.pub        build the local VM `state1-golden` from the cached image
    state1_vm.py check  --identity K          clone, check, reboot, delete: JSON summary on stdout

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
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vmssh

HERE = Path(__file__).resolve().parent
DEFAULT_IMAGE_JSON = HERE / "image.json"
DEFAULT_STATE_DIR = Path.home() / ".local" / "state" / "tendcf-state1-vm"
SCHEMA = "tendcf-state1-vm-summary/1"
VM_CAP = 2  # Apple's licence: two macOS VMs at once per host
EVIDENCE_MAX = 2000
CHECK_PREFIX = "state1-check-"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# One fixed script, nothing interpolated: reads the public key from stdin.
INSTALL_KEY_SH = (
    'set -eu; umask 077; mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"; '
    'IFS= read -r key; touch "$HOME/.ssh/authorized_keys"; chmod 600 "$HOME/.ssh/authorized_keys"; '
    'grep -qxF -- "$key" "$HOME/.ssh/authorized_keys" || printf "%s\\n" "$key" >> "$HOME/.ssh/authorized_keys"'
)
PUT_FILE_SH = 'umask 077; cat > "$1"'


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


def load_image(path: Path) -> dict:
    image = json.loads(path.read_text())
    if not image.get("digest", "").startswith("sha256:"):
        raise Refusal(f"{path}: no pinned digest (run `resolve`, then commit it)")
    return image


def image_ref(image: dict) -> str:
    return f"{image['repository']}@{image['digest']}"


def resolve_digest(ctx: Ctx, image: dict) -> str:
    """Manifest digest of repository:tag from the registry: a HEAD request, no image data."""
    host, _, repo = image["repository"].partition("/")
    fetch = ctx.fetch or _http_fetch
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


def assert_vm_cap(ctx: Ctx) -> list[str]:
    """Refuse when VM_CAP VMs are already running. Counts every running local VM (conservative)."""
    running = sorted(n for n, v in local_vms(ctx).items() if v.get("Running"))
    if len(running) >= VM_CAP:
        raise Refusal(
            f"{len(running)} VMs already running ({', '.join(running)}); Apple's licence allows {VM_CAP} macOS VMs at once. Not starting another."
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


def put_file(ctx: Ctx, t: vmssh.Target, text: str, remote_path: str) -> None:
    r = rssh(ctx, t, ["/bin/sh", "-c", PUT_FILE_SH, "sh", remote_path], input_text=text)
    if r.rc != 0:
        raise ToolError(
            f"copy to {remote_path} failed (rc {r.rc}): {clip(r.stderr, 300)}"
        )


def run_guest_script(
    ctx: Ctx, t: vmssh.Target, script: Path, args: list[str], tag: str
) -> str:
    """Copy one script into the guest, run it as root with sudo -n, remove it. Returns stdout."""
    text = script.read_text()
    remote = f"/var/tmp/tendcf-state1-{tag}-{ctx.run_id}.sh"
    put_file(ctx, t, text, remote)
    try:
        r = rssh(ctx, t, ["sudo", "-n", "/bin/sh", remote, *args], timeout=1800)
    finally:
        rssh(ctx, t, ["rm", "-f", remote], timeout=60)
    if r.rc != 0:
        raise StepFail(f"{script.name} rc {r.rc}: {clip(r.stderr + r.stdout, 800)}")
    return r.stdout


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ---------------------------------------------------------------- keys


def read_pubkey(path: Path) -> str:
    lines = [
        ln.strip()
        for ln in path.read_text().splitlines()
        if ln.strip() and not ln.startswith("#")
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


def pin_host_key(ctx: Ctx, ip: str, dest: Path) -> str:
    """ssh-keyscan the ed25519 host key and write a known_hosts line under the alias."""
    r = ctx.run(["ssh-keyscan", "-t", "ed25519", "-T", "10", ip], timeout=60)
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "ssh-ed25519" and not line.startswith("#"):
            atomic_write(dest, f"{vmssh.HOST_ALIAS} {parts[1]} {parts[2]}\n")
            return f"{parts[1]} " + fingerprint(f"{parts[1]} {parts[2]}")
    raise ToolError(
        f"ssh-keyscan returned no ed25519 key (rc {r.rc}): {clip(r.stderr, 300)}"
    )


def atomic_write(dest: Path, text: str, mode: int = 0o600) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + f".tmp{os.getpid()}")
    tmp.write_text(text)
    os.chmod(tmp, mode)
    os.replace(tmp, dest)


# ---------------------------------------------------------------- lock, signals


@contextlib.contextmanager
def driver_lock(ctx: Ctx):
    ctx.state_dir.mkdir(parents=True, exist_ok=True)
    with open(ctx.state_dir / "driver.lock", "w") as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            raise Refusal("another state1_vm.py run holds the driver lock") from e
        yield


@contextlib.contextmanager
def signals_to_exception():
    def handler(signum, _frame):
        raise Interrupted(signal.Signals(signum).name)

    sigs = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    old = {s: signal.signal(s, handler) for s in sigs}
    try:
        yield
    finally:
        for s, h in old.items():
            signal.signal(s, h)


@contextlib.contextmanager
def signals_ignored():
    sigs = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    old = {s: signal.signal(s, signal.SIG_IGN) for s in sigs}
    try:
        yield
    finally:
        for s, h in old.items():
            signal.signal(s, h)


# ---------------------------------------------------------------- guest assertions


def perm_ok(owner: str, mode: str) -> bool:
    """root-owned and not group/world writable (checklist step 3's rule)."""
    return owner == "root" and (int(mode, 8) & 0o022) == 0


def check_root_owned(ctx: Ctx, t: vmssh.Target, path: str) -> tuple[bool, str]:
    r = rssh(ctx, t, ["stat", "-f", "%Su:%Sg %Lp", path])
    m = re.fullmatch(r"(\S+):(\S+) ([0-7]+)", r.stdout.strip())
    if r.rc != 0 or not m:
        return False, f"stat {path} failed (rc {r.rc}): {clip(r.stderr, 200)}"
    return perm_ok(m[1], m[3]), f"{path} {m[1]}:{m[2]} {m[3]}"


def python_paths(image: dict) -> tuple[str, str]:
    minor = image["python"]["version"].rsplit(".", 1)[0]
    fw = f"/Library/Frameworks/Python.framework/Versions/{minor}"
    return fw, f"{fw}/bin/python{minor}"


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
            r.rc == 0 and "status: enabled" in r.stdout,
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
            r.rc == 0 and "Indexing enabled" not in r.stdout,
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
    perm_ok_, perm_ev = check_root_owned(ctx, t, fw)
    out.append(
        (
            "2i",
            f"python {image['python']['version']} system-wide, root-owned",
            pyver == image["python"]["version"] and perm_ok_,
            f"{pyver or r.stderr}; {perm_ev}",
        )
    )
    return out


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
    summary.add("preflight", "preconditions", "fail", msg)
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
    image = json.loads(args.image.read_text())
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
    attempted = False
    refusal = ""
    try:
        pubkey = read_pubkey(args.pubkey)
        identity = args.identity or re.sub(r"\.pub$", "", str(args.pubkey))
        with driver_lock(ctx), signals_to_exception():
            try:
                summary.extra["tart_version"] = tart_version(ctx)
                names = set(local_vms(ctx))
                if golden in names and not args.rebuild:
                    summary.add(
                        "exists",
                        f"{golden} already exists",
                        "pass",
                        "nothing to do; pass --rebuild to build it again",
                    )
                    emit(summary, ctx, args.summary)
                    return 0
                if ref not in oci_names(ctx):
                    raise Refusal(
                        f"pinned image {ref} is not in tart's OCI cache; run `state1_vm.py pull` first (golden never pulls)"
                    )
                swept = sweep(ctx, build)
                assert_vm_cap(ctx)
                summary.add(
                    "preflight",
                    "image cached, stale builds swept, VM cap",
                    "pass",
                    f"swept {swept or 'nothing'}",
                )
                if golden in local_vms(ctx):
                    summary.add(
                        "rebuild",
                        f"remove old {golden} (--rebuild)",
                        "pass",
                        remove_vm(ctx, golden),
                    )
                scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
                kh_scratch = str(scratch / "known_hosts")
                kh_pinned = str(scratch / "known_hosts.pinned")
                state: dict[str, str] = {}

                def clone() -> str:
                    nonlocal attempted
                    attempted = True
                    r = ctx.run(["tart", "clone", ref, build], timeout=1800)
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
                    t = vmssh.Target(
                        state["ip"], kh_scratch, auth="password", accept_new=True
                    )
                    return f"ssh up after {wait_for_ssh(ctx, vm, t):.0f}s (password, trust on first use into a scratch file)"

                def install_key() -> str:
                    t = vmssh.Target(
                        state["ip"], kh_scratch, auth="password", accept_new=True
                    )
                    r = rssh(
                        ctx,
                        t,
                        ["/bin/sh", "-c", INSTALL_KEY_SH, "sh"],
                        input_text=pubkey + "\n",
                    )
                    if r.rc != 0:
                        raise StepFail(
                            f"installing the key failed (rc {r.rc}): {clip(r.stderr, 300)}"
                        )
                    return "installed " + fingerprint(pubkey)

                def key_sudo() -> str:
                    t = vmssh.Target(
                        state["ip"], kh_scratch, identity=identity, accept_new=True
                    )
                    r = rssh(ctx, t, ["sudo", "-n", "sh", "-c", "id -u"])
                    if r.rc != 0 or r.stdout.strip() != "0":
                        raise StepFail(
                            f"key login + sudo -n failed (rc {r.rc}): {clip(r.stderr, 300)}"
                        )
                    return "key login ok; sudo -n is uid 0"

                def prep() -> str:
                    t = vmssh.Target(
                        state["ip"], kh_scratch, identity=identity, accept_new=True
                    )
                    script = HERE / "guest" / "prep.sh"
                    out = run_guest_script(ctx, t, script, [], "prep")
                    m = re.search(r"^PREP-RESULT .*$", out, re.MULTILINE)
                    if not m:
                        raise StepFail(
                            "prep.sh printed no PREP-RESULT line: " + clip(out, 400)
                        )
                    return (
                        f"prep.sh sha256 {sha256_text(script.read_text())[:16]}; {m[0]}"
                    )

                def python() -> str:
                    t = vmssh.Target(
                        state["ip"], kh_scratch, identity=identity, accept_new=True
                    )
                    py = image["python"]
                    out = run_guest_script(
                        ctx,
                        t,
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

                def pin() -> str:
                    key = pin_host_key(ctx, state["ip"], Path(kh_pinned))
                    t = vmssh.Target(
                        state["ip"], kh_pinned, identity=identity
                    )  # strict from here on
                    r = rssh(ctx, t, ["true"])
                    if r.rc != 0:
                        raise StepFail(
                            f"strict key login against the pinned host key failed (rc {r.rc}): {clip(r.stderr, 300)}"
                        )
                    state["hostkey"] = key
                    return f"pinned {key}; strict key login ok"

                def no_password() -> str:
                    t = vmssh.Target(state["ip"], kh_pinned, auth="password")
                    r = rssh(ctx, t, ["true"])
                    if r.rc == 0 or "permission denied" not in r.stderr.lower():
                        raise StepFail(
                            f"password login was not refused as expected (rc {r.rc}): {clip(r.stderr, 300)}"
                        )
                    return "password login refused: " + clip(r.stderr, 200)

                def save() -> str:
                    vm_name_ok = stop_vm(ctx, build, vm)
                    atomic_write(
                        ctx.state_dir / "known_hosts", Path(kh_pinned).read_text()
                    )
                    record = {
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
                        "host_key": state.get("hostkey"),
                    }
                    atomic_write(
                        ctx.state_dir / "golden.json",
                        json.dumps(record, indent=2) + "\n",
                        0o644,
                    )
                    r = ctx.run(["tart", "rename", build, golden], timeout=120)
                    if r.rc != 0:
                        raise ToolError(
                            f"tart rename failed (rc {r.rc}): {clip(r.stderr or r.stdout, 300)}"
                        )
                    return f"{vm_name_ok}; renamed {build} -> {golden}; record and known_hosts written"

                steps: list[tuple[str, str, Callable[[], str | None]]] = [
                    ("g1", f"clone pinned image to {build}", clone),
                    ("g2", "boot --no-graphics, tart ip --wait", boot),
                    ("g3", "ssh reachable (vanilla password, once)", boot_ssh),
                    ("g4", "install the operator's public key", install_key),
                    ("g5", "key login works; sudo -n is root", key_sudo),
                    (
                        "g6",
                        "prep.sh (spotlight, updates, launchd, gatekeeper, host keys, sshd)",
                        prep,
                    ),
                    ("g7", "python.org Python system-wide", python),
                    ("g8", "pin the new host key; strict key login", pin),
                    ("g9", "password login refused", no_password),
                    ("g10", f"stop, save as {golden}", save),
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
                    if attempted and not built and not args.keep_on_failure:
                        try:
                            summary.add(
                                "cleanup",
                                f"remove {build}",
                                "pass",
                                remove_vm(ctx, build, vm.proc),
                            )
                        except ToolError as e:
                            summary.add("cleanup", f"remove {build}", "fail", str(e))
                    shutil.rmtree(scratch, ignore_errors=True)
    except Refusal as e:
        return refuse(summary, ctx, args, str(e))
    if refusal:
        return refuse(summary, ctx, args, refusal)
    emit(summary, ctx, args.summary)
    return 130 if rc == 130 else (0 if summary.ok else 1)


def stop_vm(ctx: Ctx, name: str, vm: Vm) -> str:
    """Graceful stop of the build VM (tart stop signals the tart run process), without deleting it."""
    ctx.run(["tart", "stop", name], timeout=180)
    if not wait_until(
        ctx, lambda: not (local_vms(ctx).get(name) or {}).get("Running"), 120
    ):
        raise ToolError(f"{name} did not stop")
    if vm.proc is not None and vm.proc.wait(60) is None:
        vm.proc.kill()
    return f"{name} stopped"


def cmd_check(ctx: Ctx, args) -> int:
    summary = Summary("check", ctx.run_id)
    image = load_image(args.image)
    golden = image["golden_name"]
    clone = f"{CHECK_PREFIX}{ctx.run_id}".lower()
    summary.extra.update(golden=golden, clone=clone)
    vm = Vm(ctx, clone)
    known_hosts = ctx.state_dir / "known_hosts"
    rc = 1
    cloned = False
    refusal = ""
    try:
        with driver_lock(ctx), signals_to_exception():
            try:
                summary.extra["tart_version"] = tart_version(ctx)
                swept = sweep(ctx, CHECK_PREFIX)
                if golden not in local_vms(ctx):
                    raise Refusal(
                        f"{golden} does not exist; run `state1_vm.py golden` first"
                    )
                if not known_hosts.is_file():
                    raise Refusal(
                        f"{known_hosts} is missing (written by golden); run `golden --rebuild`"
                    )
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
                    r = ctx.run(["tart", "clone", golden, clone], timeout=600)
                    cloned = True
                    if r.rc != 0:
                        raise ToolError(
                            f"tart clone failed (rc {r.rc}): {clip(r.stderr or r.stdout, 400)}"
                        )
                    vm.start()
                    state["ip"] = vm.ip()
                    state["t"] = vmssh.Target(
                        str(state["ip"]), str(known_hosts), identity=args.identity
                    )
                    secs = wait_for_ssh(ctx, vm, state["t"])  # type: ignore[arg-type]
                    return f"cloned {golden} -> {clone}; ip {state['ip']}; ssh up after {secs:.0f}s (key, pinned host key)"

                run_step(
                    summary,
                    "1",
                    "clone state1-golden, tart run --no-graphics, tart ip --wait, ssh",
                    start,
                )
                t: vmssh.Target = state["t"]  # type: ignore[assignment]

                for sid, name, ok, ev in persistent_assertions(ctx, image, t):
                    summary.add(sid, name, "pass" if ok else "fail", ev)

                def no_password() -> str:
                    tp = vmssh.Target(t.ip, t.known_hosts, auth="password")
                    r = rssh(ctx, tp, ["true"])
                    if r.rc == 0 or "permission denied" not in r.stderr.lower():
                        raise StepFail(
                            f"password login was not refused as expected (rc {r.rc}): {clip(r.stderr, 300)}"
                        )
                    return "password login refused: " + clip(r.stderr, 200)

                run_step(
                    summary,
                    "2f",
                    "password login refused from the host",
                    no_password,
                    fatal=False,
                )

                summary.add(
                    "3",
                    "install path ownership and permissions (root:wheel, not group/world writable)",
                    "skip",
                    "needs the renderer slice: there is no tendcf build or install command yet. The assertion (perm_ok, check_root_owned) is live and is applied to the Python framework in 2i.",
                )
                for sid in ("4", "5", "6", "7", "8", "9"):
                    summary.add(
                        sid, f"checklist step {sid}", "skip", "SKIP: renderer slice"
                    )

                def reboot() -> str:
                    r = rssh(ctx, t, ["sysctl", "-n", "kern.boottime"])
                    before = r.stdout.strip()
                    if r.rc != 0 or not before:
                        raise StepFail("could not read kern.boottime before the reboot")
                    rssh(
                        ctx, t, ["sudo", "-n", "shutdown", "-r", "now"], timeout=60
                    )  # the connection drops; the status is not evidence
                    state_t = {"t": t}

                    def back() -> bool:
                        if not vm.alive():
                            vm.start()  # guest restart ended tart run: boot the same VM again (cap re-checked)
                        ip = ctx.run(
                            ["tart", "ip", "--wait", "5", clone], timeout=40
                        ).stdout.strip()
                        try:
                            ipaddress.ip_address(ip)
                        except ValueError:
                            return False
                        state_t["t"] = vmssh.Target(
                            ip, t.known_hosts, identity=t.identity
                        )
                        r2 = rssh(
                            ctx,
                            state_t["t"],
                            ["sysctl", "-n", "kern.boottime"],
                            timeout=45,
                        )
                        return (
                            r2.rc == 0
                            and bool(r2.stdout.strip())
                            and r2.stdout.strip() != before
                        )

                    if not wait_until(ctx, back, 420, 5):
                        raise StepFail(
                            "ssh did not come back with a new boot time within 420s"
                        )
                    state["t"] = state_t["t"]
                    return f"boot time changed; ssh back at {state_t['t'].ip}"  # type: ignore[attr-defined]

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
                        "; ".join(bad) or "2a-2e, 2g-2i re-checked",
                    )
                summary.add(
                    "10b",
                    "launchctl print system/<label> loads from disk at boot",
                    "skip",
                    "SKIP: renderer slice (there is no daemon to print yet)",
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
        "--pubkey",
        type=Path,
        required=True,
        help="operator's public key to install (one line)",
    )
    g.add_argument(
        "--identity",
        help="matching private key (default: --pubkey without .pub; a .pub works when ssh-agent holds the key)",
    )
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
    c = sub.add_parser(
        "check", help="clone state1-golden, run the checklist, delete the clone"
    )
    c.add_argument(
        "--identity",
        required=True,
        help="private key path (or .pub path with ssh-agent) for key login",
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
