"""`nix2cf` command line.

    nix2cf buildfile --host mac --platform macos --supervisor launchd \
        --host-key ed25519:… --device-trust trust.json \
        (--site DIR | --site-name SLUG [--ops-root DIR] | --workspace [--ops-root DIR]) \
        [--override-input NS=PATH ...] [--allow-tainted] [--check-releasable] \
        [--tendcf DIR] [--project] [-o OUT]

Renders exactly what one host would receive — the Bcfg2 `buildfile` shape the
guide (§4) and the paper (§6.2) say to build first — without touching the
host. Output is the canonical goal file; `--project` instead prints the
`host_specific.json` tendcf's reference projector derives from it, which is
the only shape `cf-agent` reads.

    nix2cf workspace [--ops-root DIR] [--site-name SLUG] [--config PATH] \
        [--override-input NS=PATH ...] [--check-releasable] [--json]
    nix2cf workspace --list [--ops-root DIR] [--json]

Resolves or lists the multi-site local ops workspace (`~/tendcf-ops`,
`tendcf-{private,public}-<site>`, issue #98) with deterministic, fail-closed
slug pairing and dev-only override taint tracking.

    nix2cf eval-nix site.nix

Evaluates a Nix expression to the JSON the compiler consumes, via
`nix-instantiate --eval --strict --json` (the stable, flake-free evaluator;
Nix manual 2.26, command-ref/nix-instantiate). The Nix *module* frontend of
D12 (`mkOption`/`mkIf`/`mkDefault`) is not built; this is the hook it would
land behind.

Exit codes mirror tendcf's tooling: 0 clean, 1 compile/release refused, 2 cannot read.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .compile import SUPERVISORS, CompileError, HostSpec, compile_host
from .sitemodel import SITE_FILES, Schemas, SiteModel, SiteModelError, load_document, load_site_model, validate_site_model
from .workspace import (
    WorkspaceError,
    WorkspaceResolution,
    format_overrides_summary,
    list_sites,
    parse_override_inputs,
    refuse_release_if_tainted,
    resolve_site_input_dir,
    resolve_workspace,
)


def _in_tree_tendcf() -> Path | None:
    """The enclosing tendcf checkout: this file is <root>/compiler/nix2cf/cli.py.

    The root is accepted only if the package really sits in a checkout: the
    directory two levels up is named `compiler` and holds the compiler's
    pyproject.toml, and the root beside it has the schema and the projector.
    Anything else (pip --target, PYTHONPATH, a venv's site-packages, ...) gives
    None, because the grandparent of such an install is not ours, and a
    projector found there would be run (--project) and schemas found there
    would be trusted for validation.
    """
    here = Path(__file__).resolve()
    compiler_dir, root = here.parents[1], here.parents[2]
    ok = (
        compiler_dir.name == "compiler"
        and (compiler_dir / "pyproject.toml").is_file()
        and (root / "schema" / "goal-file.schema.json").is_file()
        and (root / "bin" / "projector.py").is_file()
    )
    return root if ok else None


def _tendcf_dir(arg: str | None) -> Path | None:
    """--tendcf, else $TENDCF_DIR, else the enclosing tendcf checkout."""
    if arg is not None:
        return Path(arg).expanduser()
    raw = os.environ.get("TENDCF_DIR")
    return Path(raw).expanduser() if raw else _in_tree_tendcf()


def load_projector(tendcf: Path) -> Any:
    """Import tendcf's reference projector from its checkout (no copy here)."""
    path = tendcf / "bin" / "projector.py"
    spec = importlib.util.spec_from_file_location("tendcf_projector", path)
    if spec is None or spec.loader is None:
        raise SiteModelError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cmd_buildfile(args: argparse.Namespace) -> int:
    for flag, val in (
        ("--site", args.site),
        ("--services", args.services),
        ("--roles", args.roles),
        ("--launchd-writers", args.launchd_writers),
        ("--tendcf", args.tendcf),
        ("--output", args.output),
        ("--device-trust", args.device_trust),
    ):
        if val is not None and not str(val).strip():
            print(f"nix2cf: ERROR: {flag} must not be empty", file=sys.stderr)
            return 2

    has_site_dir = args.site is not None
    has_explicit_files = any(getattr(args, attr) is not None for attr in SITE_FILES)
    has_workspace_flags = (
        args.site_name is not None or args.ops_root is not None or args.workspace
    )
    if has_site_dir and has_workspace_flags:
        print(
            "nix2cf: ERROR: --site cannot be combined with --site-name, --ops-root, or --workspace",
            file=sys.stderr,
        )
        return 2
    if has_explicit_files and has_workspace_flags:
        print(
            "nix2cf: ERROR: explicit --services/--roles/--launchd-writers cannot be combined "
            "with --site-name, --ops-root, or --workspace",
            file=sys.stderr,
        )
        return 2

    try:
        overrides = parse_override_inputs(args.override_input)
    except WorkspaceError as exc:
        print(f"nix2cf: ERROR: {exc}", file=sys.stderr)
        return 2

    if args.check_releasable and overrides:
        try:
            refuse_release_if_tainted(overrides)
        except WorkspaceError as exc:
            print(f"nix2cf: REFUSED: {exc}", file=sys.stderr)
            return 1

    if args.output is not None and overrides and not args.allow_tainted:
        print(
            f"nix2cf: REFUSED: refusing to write artifact {args.output!r} while dev-only "
            f"--override-input is active ({format_overrides_summary(overrides)}); pass "
            "--allow-tainted for dev-only local preview output (never for release signing)",
            file=sys.stderr,
        )
        return 1

    workspace: WorkspaceResolution | None = None
    site: Path | None = Path(args.site) if args.site is not None else None
    use_workspace = (
        not has_site_dir
        and not has_explicit_files
        and (has_workspace_flags or "TENDCF_SITE" in os.environ)
    )
    if use_workspace:
        try:
            workspace = resolve_workspace(
                ops_root=args.ops_root,
                site_name=args.site_name,
                overrides=overrides,
            )
            site = resolve_site_input_dir(workspace.private_dir)
        except WorkspaceError as exc:
            print(f"nix2cf: ERROR: {exc}", file=sys.stderr)
            return 2
        print(
            f"nix2cf: workspace: site={workspace.site_slug} source={workspace.selection_source} "
            f"private={workspace.private_dir} public={workspace.public_dir or 'none'}",
            file=sys.stderr,
        )

    if overrides:
        print(
            f"nix2cf: WARNING: dev-only --override-input active ({format_overrides_summary(overrides)}): "
            "paths validated and build marked TAINTED (not releasable); site.lock foreign-input "
            "substitution is not yet wired into compile_host (Site Model inputs are not substituted "
            "from the override path)",
            file=sys.stderr,
        )

    paths = {}
    for attr, default_name in SITE_FILES.items():
        override = getattr(args, attr)
        if override is not None:
            paths[attr] = Path(override)
        elif site is not None:
            paths[attr] = site / default_name
        else:
            print(
                f"nix2cf: ERROR: --{attr.replace('_', '-')} or --site is required "
                "(or select a workspace site with --site-name / --workspace / TENDCF_SITE)",
                file=sys.stderr,
            )
            return 2

    try:
        model: SiteModel = load_site_model(paths["services"], paths["roles"], paths["launchd_writers"])
        trust_doc = load_document(Path(args.device_trust))
    except SiteModelError as exc:
        print(f"nix2cf: ERROR: {exc}", file=sys.stderr)
        return 2

    schemas: Schemas | None = None
    tendcf = _tendcf_dir(args.tendcf)
    if tendcf is not None:
        try:
            schemas = Schemas(tendcf / "schema")
        except SiteModelError as exc:
            print(f"nix2cf: ERROR: {exc}", file=sys.stderr)
            return 2
        problems = validate_site_model(model, schemas)
        if problems:
            for p in problems:
                print(f"nix2cf: FAIL: {p}", file=sys.stderr)
            print(f"nix2cf: {len(problems)} Site Model schema finding(s); not compiled", file=sys.stderr)
            return 1

    host = HostSpec(
        name=args.host,
        platform=args.platform,
        supervisor=args.supervisor,
        key=args.host_key,
        device_trust=trust_doc.data,
    )
    try:
        result = compile_host(model, host, schemas, overrides=overrides)
    except CompileError as exc:
        for f in exc.findings:
            print(f"nix2cf: REFUSED: {f}", file=sys.stderr)
        print(f"nix2cf: {len(exc.findings)} finding(s); no goal file written", file=sys.stderr)
        return 1
    for d in result.diagnostics:
        if d.startswith("TAINTED (not releasable):"):
            continue
        print(f"nix2cf: note: {d}", file=sys.stderr)

    out = result.canonical
    if args.project:
        if tendcf is None:
            print("nix2cf: ERROR: --project needs a tendcf checkout to find bin/projector.py (not inside one: pass --tendcf or set TENDCF_DIR)", file=sys.stderr)
            return 2
        projector = load_projector(tendcf)
        try:
            out = projector.project(json.loads(result.canonical))
        except projector.ProjectionRefused as exc:
            print(f"nix2cf: REFUSED by tendcf projector: {exc}", file=sys.stderr)
            return 1

    if args.output is not None:
        Path(args.output).write_bytes(out)
    else:
        sys.stdout.buffer.write(out)
    return 0


def cmd_workspace(args: argparse.Namespace) -> int:
    if args.list:
        if (
            args.site_name is not None
            or args.config is not None
            or args.check_releasable
            or args.override_input
        ):
            print(
                "nix2cf: ERROR: --list cannot be combined with --site-name, --config, "
                "--override-input, or --check-releasable",
                file=sys.stderr,
            )
            return 2
        try:
            inventory = list_sites(ops_root=args.ops_root)
        except WorkspaceError as exc:
            print(f"nix2cf: ERROR: {exc}", file=sys.stderr)
            return 2
        if args.json:
            json.dump(inventory.to_dict(), sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            print(f"ops_root: {inventory.ops_root} ({inventory.ops_root_source})")
            print(f"tendcf_dir: {inventory.tendcf_dir or 'none'}")
            print(f"state_dir: {inventory.state_dir}")
            print(f"cache_dir: {inventory.cache_dir}")
            if inventory.sites:
                print("sites:")
                for entry in inventory.sites:
                    print(
                        f"  {entry.slug} [{entry.role}] "
                        f"private={entry.private_dir or 'none'} "
                        f"public={entry.public_dir or 'none'}"
                    )
            else:
                print("sites: (none)")
            for warn in inventory.warnings:
                print(f"warning: {warn}")
        return 0

    if args.config is not None and not args.config.strip():
        print("nix2cf: ERROR: --config must not be empty", file=sys.stderr)
        return 2
    if args.config is not None and args.site_name is not None:
        print("nix2cf: ERROR: --config cannot be combined with --site-name", file=sys.stderr)
        return 2

    try:
        overrides = parse_override_inputs(args.override_input)
        ws = resolve_workspace(
            ops_root=args.ops_root,
            site_name=args.site_name,
            config_path=args.config,
            overrides=overrides,
        )
    except WorkspaceError as exc:
        print(f"nix2cf: ERROR: {exc}", file=sys.stderr)
        return 2

    if ws.tainted:
        print(
            f"nix2cf: WARNING: dev-only local override active ({format_overrides_summary(ws.overrides)}); "
            "release signing/publishing is BLOCKED",
            file=sys.stderr,
        )

    if args.json:
        json.dump(ws.to_dict(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(f"ops_root: {ws.ops_root} ({ws.ops_root_source})")
        print(f"site_slug: {ws.site_slug}")
        print(f"selection_source: {ws.selection_source}")
        print(f"private_dir: {ws.private_dir}")
        print(f"public_dir: {ws.public_dir or 'none'}")
        print(f"tendcf_dir: {ws.tendcf_dir or 'none'}")
        if ws.overrides:
            print("overrides:")
            for ov in ws.overrides:
                print(f"  {ov.namespace}={ov.path}")
        else:
            print("overrides: none")
        print(f"release_blocked: {'true' if ws.release_blocked else 'false'}")
        print(f"state_dir: {ws.state_dir}")
        print(f"cache_dir: {ws.cache_dir}")

    if args.check_releasable:
        try:
            ws.assert_releasable()
        except WorkspaceError as exc:
            print(f"nix2cf: REFUSED: {exc}", file=sys.stderr)
            return 1
    return 0


def cmd_eval_nix(args: argparse.Namespace) -> int:
    exe = shutil.which("nix-instantiate")
    if exe is None:
        print("nix2cf: ERROR: nix-instantiate not found on PATH; the Nix frontend needs a Nix install", file=sys.stderr)
        return 2
    proc = subprocess.run(
        [exe, "--eval", "--strict", "--json", str(args.file)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        return 2
    try:
        value = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        print(f"nix2cf: ERROR: nix-instantiate did not return JSON: {exc}", file=sys.stderr)
        return 2
    json.dump(value, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nix2cf", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"nix2cf {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    b = sub.add_parser("buildfile", help="render what one host would receive")
    b.add_argument("--host", required=True, help="host name as used in the Site Model (hosts:, roles)")
    b.add_argument("--host-key", required=True, help="device public key, ed25519:<64 hex>")
    b.add_argument("--platform", required=True, choices=["macos", "linux"], help="no default; android is not offered until Termux is decided")
    b.add_argument(
        "--supervisor",
        required=True,
        choices=list(SUPERVISORS),
        help="what runs the host's units; no default. Written into device-trust.entries.supervisor",
    )
    b.add_argument(
        "--device-trust",
        required=True,
        help="JSON/YAML file holding the goal file's device-trust domain; its supervisor entry, if any, must match --supervisor",
    )
    b.add_argument(
        "--site",
        help="explicit directory holding services.yml, roles.yml, launchd-writers.yml (mutually exclusive with --site-name/--ops-root/--workspace)",
    )
    b.add_argument(
        "--ops-root",
        dest="ops_root",
        help="ops workspace root holding tendcf-{private,public}-<site> (default $TENDCF_OPS_ROOT or ~/tendcf-ops)",
    )
    b.add_argument(
        "--site-name",
        dest="site_name",
        help="site slug inside the ops workspace (precedence: --site-name > $TENDCF_SITE > XDG active-site)",
    )
    b.add_argument(
        "--workspace",
        action="store_true",
        help="resolve site from the ops workspace via $TENDCF_SITE or XDG active-site (fails closed if unset)",
    )
    b.add_argument(
        "--override-input",
        dest="override_input",
        action="append",
        metavar="NS=PATH",
        help="repeatable dev-only local checkout binding; validates path, marks output TAINTED, blocks -o without --allow-tainted, and fails --check-releasable",
    )
    b.add_argument(
        "--allow-tainted",
        dest="allow_tainted",
        action="store_true",
        help="explicitly allow writing -o/--output when --override-input is active (dev-only preview; never releasable)",
    )
    b.add_argument(
        "--check-releasable",
        dest="check_releasable",
        action="store_true",
        help="refuse with exit 1 if any dev-only --override-input is active",
    )
    b.add_argument("--services")
    b.add_argument("--roles")
    b.add_argument("--launchd-writers", dest="launchd_writers")
    b.add_argument("--tendcf", help="tendcf checkout (schemas + projector); default $TENDCF_DIR, else the enclosing tendcf checkout")
    b.add_argument("--project", action="store_true", help="print the projector's host_specific.json instead of the goal file")
    b.add_argument("-o", "--output")
    b.set_defaults(func=cmd_buildfile)

    w = sub.add_parser("workspace", help="resolve or list the multi-site local ops workspace (~/tendcf-ops)")
    w.add_argument(
        "--ops-root",
        dest="ops_root",
        help="ops workspace root (default $TENDCF_OPS_ROOT or ~/tendcf-ops)",
    )
    w.add_argument(
        "--site-name",
        dest="site_name",
        help="site slug (precedence: --site-name > $TENDCF_SITE > XDG active-site)",
    )
    w.add_argument(
        "--config",
        help="override active-site file path (default $XDG_CONFIG_HOME/tendcf/active-site or ~/.config/tendcf/active-site)",
    )
    w.add_argument(
        "--override-input",
        dest="override_input",
        action="append",
        metavar="NS=PATH",
        help="repeatable dev-only local checkout binding; marks workspace tainted and release_blocked=true",
    )
    w.add_argument(
        "--list",
        action="store_true",
        help="list discovered tendcf-{private,public}-<site> repos in ops root without selecting one",
    )
    w.add_argument(
        "--check-releasable",
        dest="check_releasable",
        action="store_true",
        help="exit 1 if any dev-only --override-input is active",
    )
    w.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    w.set_defaults(func=cmd_workspace)

    e = sub.add_parser("eval-nix", help="evaluate a Nix expression to Site Model JSON")
    e.add_argument("file")
    e.set_defaults(func=cmd_eval_nix)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
