#!/usr/bin/env python3
"""Run the documented restricted Nix evaluation against the fixtures.

Every call is an argv list (no shell). NIX_PATH is empty and user config
files are replaced by an empty file, so only the flags below are in play.

Usage: run_nix_eval.py matrix            print every variant, never fail
       run_nix_eval.py check VARIANT     fail unless VARIANT behaves as documented
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

FIX = Path(__file__).resolve().parent / "fixtures"
POSITIVE = FIX / "positive" / "recipe.nix"
POSITIVE_WANT = {"site": "ok", "greeting": "hello\n", "helper": {"n": 3}}

# Flags under test (plugin-layout.md, "Frontend inputs are code", item 3).
BASE = [
    "nix-instantiate", "--eval", "--strict", "--json",
    "--option", "restrict-eval", "true",
    "--option", "allow-import-from-derivation", "false",
    "--option", "allowed-uris", "",
    "--option", "allow-unsafe-native-code-during-evaluation", "false",
]
PURE = ["--option", "pure-eval", "true"]
ALLOW_DIR = ["-I", str(POSITIVE.parent)]
# Permissive control: the same file with the restrictions switched off.
OPEN = [
    "nix-instantiate", "--eval", "--strict", "--json",
    "--option", "restrict-eval", "false",
    "--option", "allow-import-from-derivation", "true",
    "--option", "allow-unsafe-native-code-during-evaluation", "true",
]

VARIANTS = {
    "base": BASE,
    "base+I": BASE + ALLOW_DIR,
    "base+pure": BASE + PURE,
    "base+pure+I": BASE + PURE + ALLOW_DIR,
}

# case file -> substring that must appear in stderr when it is refused.
NEGATIVES = {
    "read-absolute.nix": "forbidden in restricted mode",
    "read-relative.nix": "forbidden in restricted mode",
    "fetchurl.nix": "forbidden in restricted mode",
    "fetchtarball.nix": "forbidden in restricted mode",
    "ifd.nix": "import from derivation",
    "exec.nix": "exec",
    "nixpath-lookup.nix": "search path",
}


def run(argv, env, path):
    p = subprocess.run(argv + [str(path)], env=env, capture_output=True,
                       text=True, timeout=300)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def first_line(text):
    lines = [x for x in text.splitlines() if x.strip()]
    return lines[0][:200] if lines else ""


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "matrix"
    with tempfile.TemporaryDirectory() as td:
        empty = Path(td) / "empty.conf"
        empty.write_text("")
        env = dict(os.environ, NIX_PATH="", NIX_USER_CONF_FILES=str(empty))
        env.pop("NIX_CONFIG", None)
        names = [sys.argv[2]] if mode == "check" else list(VARIANTS)
        bad = []
        for name in names:
            argv = VARIANTS[name]
            print(f"== variant {name}: {' '.join(repr(a) for a in argv)}")
            rc, out, err = run(argv, env, POSITIVE)
            ok = rc == 0 and json.loads(out or "null") == POSITIVE_WANT
            print(f"  positive recipe.nix: rc={rc} {'OK' if ok else 'WRONG'} out={out[:120]!r} err={first_line(err)!r}")
            if not ok:
                bad.append((name, "positive"))
            for case, want in NEGATIVES.items():
                rc, out, err = run(argv, env, FIX / "negative" / case)
                refused = rc != 0 and want in err.lower()
                print(f"  negative {case}: rc={rc} {'REFUSED' if refused else 'NOT-AS-EXPECTED'} err={first_line(err)!r}")
                if not refused:
                    bad.append((name, case))
            if "pure" in name:
                rc, out, err = run(argv, env, FIX / "negative" / "currenttime.nix")
                print(f"  negative currenttime.nix: rc={rc} err={first_line(err)!r}")
        print("== permissive controls (restrictions off; shows the refusals are due to the flags)")
        for case in ["read-absolute.nix", "read-relative.nix", "exec.nix"]:
            rc, out, err = run(OPEN, env, FIX / "negative" / case)
            print(f"  control {case}: rc={rc} out={out[:80]!r} err={first_line(err)!r}")
        rc, out, err = run(OPEN, env, FIX / "negative" / "ifd.nix")
        print(f"  control ifd.nix (IFD allowed): rc={rc} err={first_line(err)!r}")
        print("== bad:", bad)
        if mode == "check" and bad:
            sys.exit(1)


if __name__ == "__main__":
    main()
