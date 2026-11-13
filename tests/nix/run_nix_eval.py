#!/usr/bin/env python3
"""Run the documented restricted Nix evaluation against the fixtures.

Every call is an argv list (no shell). NIX_PATH is empty, NIX_CONF_DIR and the
user config files point at empty locations, so only the flags below and Nix's
built-in defaults are in play.

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

VARIANTS = {
    # The recipe file itself is outside the allowed paths until -I allows
    # its directory (first CI run: bare `base` refuses the main file).
    "base": BASE,
    "base+I": BASE + ["-I", "{dir}"],
    "base+pure+I": BASE + PURE + ["-I", "{dir}"],
}
DOCUMENTED = "base+I"

# case file -> alternatives; a case is refused when rc != 0 and, for some
# alternative, every substring of it appears (lowercased) in stderr. Each
# case gets `-I <its own directory>`, so the refusal must come from the case
# itself, not from the main file being outside the allowed paths.
NEGATIVES = {
    "read-absolute.nix": [("access to absolute path '/etc/passwd' is forbidden in restricted mode",)],
    "read-relative.nix": [("outside/secret.txt' is forbidden in restricted mode",)],
    "fetchurl.nix": [("access to uri 'https://example.com/index.html' is forbidden in restricted mode",)],
    "fetchtarball.nix": [("access to uri 'https://example.com/a.tar.gz' is forbidden in restricted mode",)],
    # `--eval` is read-only: while the .drv is absent from the store the
    # fixture stops with "is not valid" (fresh store); once a read-write run
    # has written it, the flag itself refuses. Both are a refusal, and the
    # flag is proven by the read-write control below. The gating step runs on
    # a fresh store and again on a populated one.
    "ifd.nix": [("is not valid",), ("allow-import-from-derivation",)],
    "exec.nix": [("attribute 'exec' missing",)],
    "nixpath-lookup.nix": [("was not found in the nix search path",)],
    "symlink-escape.nix": [("outside/secret.txt' is forbidden in restricted mode",)],
    "readdir-outside.nix": [("is forbidden in restricted mode",)],
    "path-outside.nix": [("is forbidden in restricted mode",)],
}

# case file -> exact JSON output: allowed under the documented invocation.
ALLOWED = {
    "getenv.nix": "",  # restrict-eval returns "" for getEnv
    "currenttime.nix": True,
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


def refused(rc, err, alts):
    low = err.lower()
    return rc != 0 and any(all(w in low for w in alt) for alt in alts)


def sub(argv, **kw):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=120, **kw)
    if p.returncode != 0:
        raise SystemExit(f"setup failed: {argv}: {p.stderr}")
    return p.stdout.strip()


def make_generated(td, env):
    """Cases that need a path made at run time: a local git repository and a
    store path, both outside the allowed directory."""
    gen = Path(td) / "gen"
    gen.mkdir()
    outside = Path(td) / "outside-src"
    outside.mkdir()
    (outside / "f.txt").write_text("outside\n")
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    sub(git + ["init", "-q", "-b", "main", str(outside)])
    sub(git + ["-C", str(outside), "add", "f.txt"])
    sub(git + ["-C", str(outside), "commit", "-q", "-m", "x"])
    store_path = sub(["nix-store", "--add", str(outside / "f.txt")], env=env)
    cases = {
        "fetchgit-local-outside.nix": f'builtins.fetchGit "{outside}"\n',
        "storepath.nix": f'builtins.storePath "{store_path}"\n',
        "readfile-storepath.nix": f'builtins.readFile "{store_path}"\n',
    }
    for name, body in cases.items():
        (gen / name).write_text(body)
    return gen, list(cases), store_path


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "matrix"
    with tempfile.TemporaryDirectory() as td:
        empty = Path(td) / "empty.conf"
        empty.write_text("")
        confdir = Path(td) / "conf"
        confdir.mkdir()
        env = dict(os.environ, NIX_PATH="", NIX_USER_CONF_FILES=str(empty),
                   NIX_CONF_DIR=str(confdir))
        env.pop("NIX_CONFIG", None)
        env.setdefault("HOME", "/home/runner")
        gen, gen_cases, store_path = make_generated(td, env)
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
            nd = FIX / "negative"
            for case, alts in NEGATIVES.items():
                rc, out, err = run(with_dir(argv, nd), env, nd / case)
                good = refused(rc, err, alts)
                print(f"  negative {case}: rc={rc} {'REFUSED' if good else 'NOT-AS-EXPECTED'} err={first_line(err)!r}")
                if not good:
                    bad.append((name, case))
            for case in gen_cases:
                rc, out, err = run(with_dir(argv, gen), env, gen / case)
                # Generated cases (paths made at run time, outside the allowed
                # directory): two refused, and builtins.storePath of an existing
                # store path is allowed (it names the path; reading it is refused).
                if case == "storepath.nix":
                    good = rc == 0 and json.loads(out or "null") == store_path
                else:
                    good = refused(rc, err, [("is forbidden in restricted mode",)])
                print(f"  generated {case}: rc={rc} {'OK' if good else 'UNEXPECTED'} out={out[:80]!r} err={first_line(err)!r}")
                if not good:
                    bad.append((name, case))
            ad = FIX / "allowed"
            for case, want in ALLOWED.items():
                rc, out, err = run(with_dir(argv, ad), env, ad / case)
                good = rc == 0 and json.loads(out or "null") == want
                print(f"  allowed {case}: rc={rc} {'OK' if good else 'UNEXPECTED'} out={out[:60]!r} err={first_line(err)!r}")
                if not good and name == DOCUMENTED:
                    bad.append((name, case))
        nd = FIX / "negative"
        print("== single-flag controls (documented flags, one relaxed; shows each flag is what refuses)")
        doc = VARIANTS[DOCUMENTED]
        relax = {
            "allowed-uris=https://example.com/ lets fetchurl reach the network": (
                "fetchurl.nix", "allowed-uris", "https://example.com/", "unable to download"),
            "allow-unsafe-native-code-during-evaluation=true provides builtins.exec": (
                "exec.nix", "allow-unsafe-native-code-during-evaluation", "true", "attribute 'exec' missing"),
        }
        for label, (case, opt, val, absent) in relax.items():
            av = with_dir(doc, nd)
            i = av.index(opt)
            av[i + 1] = val
            rc, out, err = run(av, env, nd / case)
            # A relaxed flag passes when the refusal text is gone and, for the
            # download control, the fetch was actually attempted.
            passed = absent not in err.lower() if case != "fetchurl.nix" else (rc == 0 or absent in err.lower())
            print(f"  control [{label}]: rc={rc} {'OK' if passed else 'STILL-REFUSED'} out={out[:60]!r} err={first_line(err)!r}")
            if not passed:
                bad.append(("control", label))
        print("== IFD flag, proven with --read-write-mode (--eval alone stops IFD only while the .drv is absent)")
        for val in ["true", "false"]:
            av = with_dir(doc, nd)
            i = av.index("allow-import-from-derivation")
            av[i + 1] = val
            av = av + ["--read-write-mode", "--option", "sandbox", "false"]
            rc, out, err = run(av, env, nd / "ifd.nix")
            blocked = "allow-import-from-derivation" in err.lower()
            good = (rc != 0 and blocked) if val == "false" else (rc == 0 and out == "1")
            print(f"  IFD allow-import-from-derivation={val} (--read-write-mode): rc={rc} {'OK' if good else 'UNEXPECTED'} out={out[:40]!r} err={first_line(err)!r}")
            if not good:
                bad.append(("ifd-flag", val))
        print("== restrict-eval=false controls (each refused case above succeeds without the flag)")
        av = with_dir(doc, nd)
        av[av.index("restrict-eval") + 1] = "false"
        for case in ["read-absolute.nix", "read-relative.nix", "symlink-escape.nix",
                     "readdir-outside.nix", "path-outside.nix"]:
            rc, out, err = run(av, env, nd / case)
            print(f"  control [restrict-eval=false allows {case}]: rc={rc} {'OK' if rc == 0 else 'STILL-REFUSED'} out={out[:60]!r} err={first_line(err)!r}")
            if rc != 0:
                bad.append(("control", case))
        avg = with_dir(doc, gen)
        avg[avg.index("restrict-eval") + 1] = "false"
        for case in gen_cases:
            rc, out, err = run(avg, env, gen / case)
            print(f"  control [restrict-eval=false, generated {case}]: rc={rc} out={out[:60]!r} err={first_line(err)!r}")
        ad = FIX / "allowed"
        ave = with_dir(doc, ad)
        ave[ave.index("restrict-eval") + 1] = "false"
        rc, out, err = run(ave, env, ad / "getenv.nix")
        good = rc == 0 and json.loads(out or '""') != ""
        print(f"  control [restrict-eval=false: getenv.nix is non-empty]: rc={rc} {'OK' if good else 'STILL-EMPTY'} out={out[:40]!r}")
        if not good:
            bad.append(("control", "getenv"))
        print("== bad:", bad)
        if mode == "check" and bad:
            sys.exit(1)


if __name__ == "__main__":
    main()
