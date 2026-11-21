#!/usr/bin/env python3
"""SSH wrapper for the state 1 macOS VM (issue 70, slice A).

argv in, exit status out. The remote command is an argv list, quoted for the
guest's login shell with shlex.join, never a string built from variables. The
exit status of the remote command is the exit status of this wrapper; 255 is
ssh's own (connect, host key or auth failure).

    vmssh.py --ip 192.168.64.5 --known-hosts KH --identity STATE_DIR/keys/ID/id_ed25519 -- sw_vers -productVersion

Host-key choice (the same for every connection the driver makes):

  * `HostKeyAlias=state1-vm`, so the pinned key does not depend on the IP address
    that vmnet DHCP hands a throwaway clone (addresses are reused across clones).
  * `golden` regenerates the guest's SSH host keys once (prep.sh) and pins the new ed25519
    key that prep.sh prints inside its own authenticated ssh session (`PREP-HOSTKEY`);
    ssh-keyscan is only a cross-check that must give the same key. The pin lives in a
    known_hosts file next to the image record. Every clone of `state1-golden` carries that
    key, so every connection after prep, and every `check`, uses StrictHostKeyChecking=yes
    against the pinned file: a changed key is a hard failure, never a prompt, never accepted
    again, never `=no`.
  * The only trust-on-first-use connections are the bootstrap ones inside `golden` before
    prep (`accept_new`, into a scratch file that is deleted afterwards, unless image.json
    pins the vanilla image's host key), to a VM this driver just cloned and booted on the
    host-only vmnet NAT.
  * The user's ~/.ssh/config and the system known_hosts are ignored (-F /dev/null,
    GlobalKnownHostsFile=/dev/null), as are agent forwarding, X11 and ControlMaster.

Secrets: key login passes only a key path. The one password login (the vanilla
image's published admin credential, `golden` only) goes through SSH_ASKPASS in the
environment of that one ssh process; nothing secret is on a command line, and the
driver never logs an environment.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

HOST_ALIAS = "state1-vm"
DEFAULT_USER = "admin"
BOOTSTRAP_PW_ENV = "TENDCF_VM_BOOTSTRAP_PW"
# The vanilla cirruslabs image's published credential. Not a secret; still kept off argv.
DEFAULT_BOOTSTRAP_PW = "admin"
ASKPASS = Path(__file__).resolve().parent / "guest" / "bootstrap-askpass.sh"

_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_BAD_PATH_RE = re.compile(r"[\s%$]")


@dataclass(frozen=True)
class Target:
    ip: str
    known_hosts: str
    identity: str | None = None
    user: str = DEFAULT_USER
    auth: str = (
        "key"  # "key" (BatchMode, publickey only) or "password" (golden bootstrap only)
    )
    accept_new: bool = False  # trust on first use into known_hosts; scratch file only
    # do not talk to the operator's ssh-agent at all, in either mode (the driver's own minted
    # key is the only credential); the standalone CLI keeps agent mode for a `.pub` identity
    no_agent: bool = False
    connect_timeout: int = 10

    def __post_init__(self) -> None:
        ipaddress.ip_address(self.ip)  # raises ValueError; also blocks option injection
        if not _USER_RE.match(self.user):
            raise ValueError(f"bad user name: {self.user!r}")
        if self.auth not in ("key", "password"):
            raise ValueError(f"bad auth mode: {self.auth!r}")
        if self.auth == "key" and not self.identity:
            raise ValueError("key login needs an identity path")
        for p in (self.known_hosts, self.identity):
            if not p:
                continue
            if p.startswith("-"):
                raise ValueError(f"path looks like an option: {p!r}")
            # ssh splits UserKnownHostsFile on spaces and expands %tokens, ${ENV} and a
            # leading ~ in both values: a path using any of them would mean another file.
            if _BAD_PATH_RE.search(p) or p.startswith("~"):
                raise ValueError(
                    f"path has whitespace, % or $ or starts with ~ (ssh would expand it): {p!r}"
                )


def remote_command(argv: list[str]) -> str:
    """Quote an argv list into the one string ssh sends to the remote shell.

    Every word is single-quoted, also the ones shlex.join would leave bare: the guest's
    shell is zsh, where a bare leading `=ls` expands to /bin/ls.
    """
    if not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("remote command must be a non-empty list of strings")
    return " ".join("'" + a.replace("'", "'\"'\"'") + "'" for a in argv)


def ssh_argv(t: Target, remote_argv: list[str], ssh_bin: str = "ssh") -> list[str]:
    argv = [
        ssh_bin, "-T", "-F", "/dev/null",
        "-o", f"HostKeyAlias={HOST_ALIAS}",
        "-o", f"UserKnownHostsFile={t.known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"StrictHostKeyChecking={'accept-new' if t.accept_new else 'yes'}",
        "-o", "VerifyHostKeyDNS=no",
        "-o", f"ConnectTimeout={t.connect_timeout}",
        "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
        "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes",
        "-o", "ControlMaster=no", "-o", "ControlPath=none",
        "-o", "LogLevel=ERROR",
    ]  # fmt: skip
    if t.no_agent:
        # ssh opens the agent socket and lists its keys even with PubkeyAuthentication=no,
        # so the operator's agent is left alone in password mode too
        argv += ["-o", "IdentityAgent=none"]
    if t.auth == "key":
        argv += [
            "-o", "BatchMode=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "IdentitiesOnly=yes",
            "-i", t.identity or "",
        ]  # fmt: skip
    else:
        # BatchMode would disable SSH_ASKPASS, so it is off here and only here.
        argv += [
            "-o", "BatchMode=no",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "PubkeyAuthentication=no",
            "-o", "NumberOfPasswordPrompts=1",
        ]  # fmt: skip
    argv += ["--", f"{t.user}@{t.ip}", remote_command(remote_argv)]
    return argv


def ssh_env(t: Target, base: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for the ssh process: only the password mode adds anything."""
    env = dict(os.environ if base is None else base)
    if t.auth == "password":
        env["SSH_ASKPASS"] = str(ASKPASS)
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env[BOOTSTRAP_PW_ENV] = os.environ.get(BOOTSTRAP_PW_ENV, DEFAULT_BOOTSTRAP_PW)
    return env


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="run an argv list in the state 1 VM over ssh; exit with its status"
    )
    ap.add_argument("--ip", required=True)
    ap.add_argument(
        "--known-hosts", required=True, help="pinned known_hosts file (alias state1-vm)"
    )
    ap.add_argument(
        "--identity",
        help="private key path (or a .pub path when ssh-agent holds the key)",
    )
    ap.add_argument("--user", default=DEFAULT_USER)
    ap.add_argument(
        "--password", action="store_true", help="bootstrap password login (golden only)"
    )
    ap.add_argument(
        "--accept-new",
        action="store_true",
        help="trust on first use (scratch known_hosts only)",
    )
    ap.add_argument("command", nargs="+", help="remote argv, after --")
    args = ap.parse_args(argv)
    t = Target(
        ip=args.ip,
        known_hosts=args.known_hosts,
        identity=args.identity,
        user=args.user,
        auth="password" if args.password else "key",
        accept_new=args.accept_new,
    )
    return subprocess.run(
        ssh_argv(t, args.command), env=ssh_env(t), check=False
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
