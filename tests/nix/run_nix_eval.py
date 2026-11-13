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
    # The recipe file itself is outside the allowed paths until -I allows
    # its directory (first CI run: bare `base` refuses the main file).
    "base": BASE,
    "base+I": BASE + ["-I", "{dir}"],
    "base+pure+I": BASE + PURE + ["-I", "{dir}"],
}
DOCUMENTED = "base+I"

# case file -> substrings (lowercase) that must all appear in stderr when it
# is refused. Each case gets `-I <its own directory>`, so the refusal must
# come from the case itself, not from the main file being outside the
# allowed paths.
NEGATIVES = {
    "read-absolute.nix": ["access to absolute path '/etc/passwd' is forbidden in restricted mode"],
    "read-relative.nix": ["outside/secret.txt' is forbidden in restricted mode"],
    "fetchurl.nix": ["access to uri 'https://example.com/index.html' is forbidden in restricted mode"],
    "fetchtarball.nix": ["access to uri 'https://example.com/a.tar.gz' is forbidden in restricted mode"],
    "ifd.nix": ["allow-import-from-derivation"],
    "exec.nix": ["attribute 'exec' missing"],
    "nixpath-lookup.nix": ["was not found in the nix search path"],
}


def run(argv, env, path):
    p = subprocess.run(argv + [str(path)], env=env, capture_output=True,
                       text=True, timeout=300)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def first_line(text):
    lines = [x for x in text.splitlines() if x.strip()]
    # Nix prints the trace first and the message last: keep the tail.
    return " | ".join(x.strip() for x in lines[-3:])[:400]


def with_dir(argv, d):
    return [a.replace("{dir}", str(d)) for a in argv]


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
            rc, out, err = run(with_dir(argv, POSITIVE.parent), env, POSITIVE)
            ok = rc == 0 and json.loads(out or "null") == POSITIVE_WANT
            print(f"  positive recipe.nix: rc={rc} {'OK' if ok else 'WRONG'} out={out[:120]!r} err={first_line(err)!r}")
            if not ok:
                bad.append((name, "positive"))
            for case, wants in NEGATIVES.items():
                nd = FIX / "negative"
                rc, out, err = run(with_dir(argv, nd), env, nd / case)
                refused = rc != 0 and all(w in err.lower() for w in wants)
                print(f"  negative {case}: rc={rc} {'REFUSED' if refused else 'NOT-AS-EXPECTED'} err={first_line(err)!r}")
                if not refused:
                    bad.append((name, case))
        nd = FIX / "negative"
        print("== single-flag controls (documented flags, one relaxed; shows each flag is what refuses)")
        doc = VARIANTS[DOCUMENTED]
        relax = {
            "allowed-uris=https://example.com/ lets fetchurl past the URI check": (
                "fetchurl.nix", "allowed-uris", "https://example.com/", "forbidden in restricted mode"),
            "allow-import-from-derivation=true lets ifd.nix past the IFD check": (
                "ifd.nix", "allow-import-from-derivation", "true", "allow-import-from-derivation"),
            "allow-unsafe-native-code-during-evaluation=true provides builtins.exec": (
                "exec.nix", "allow-unsafe-native-code-during-evaluation", "true", "attribute 'exec' missing"),
        }
        for label, (case, opt, val, absent) in relax.items():
            av = with_dir(doc, nd)
            i = av.index(opt)
            av[i + 1] = val
            rc, out, err = run(av, env, nd / case)
            passed = absent not in err.lower()
            print(f"  control [{label}]: rc={rc} {'OK' if passed else 'STILL-REFUSED'} out={out[:60]!r} err={first_line(err)!r}")
            if not passed:
                bad.append(("control", label))
        av = with_dir(doc, nd)
        i = av.index("restrict-eval")
        av[i + 1] = "false"
        for case in ["read-absolute.nix", "read-relative.nix"]:
            rc, out, err = run(av, env, nd / case)
            print(f"  control [restrict-eval=false allows {case}]: rc={rc} {'OK' if rc == 0 else 'STILL-REFUSED'} out={out[:60]!r}")
            if rc != 0:
                bad.append(("control", case))
        print("== bad:", bad)
        if mode == "check" and bad:
            sys.exit(1)


if __name__ == "__main__":
    main()
