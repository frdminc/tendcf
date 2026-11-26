"""`tendcf` compiler command line (D46 Step 4).

    tendcf compile --host mac --platform macos --supervisor launchd \
        --host-key ed25519:… --device-trust trust.json \
        (--site DIR | --site-name SLUG [--ops-root DIR] | --workspace [--ops-root DIR]) \
        [--override-input NS=PATH ...] [--allow-tainted] [--check-releasable] \
        [--tendcf DIR] [--project] [-o OUT]

Renders exactly what one host would receive (the Bcfg2 `buildfile` lineage,
replaced outright by `tendcf compile` with no alias per D46 §6) without
touching the host. Output is the canonical goal file; `--project` instead
prints the `host_specific.json` tendcf's reference projector (`tools/projector.py`)
derives from it, which is the only shape `cf-agent` reads.

When `--check-releasable` is active, `--override-input`, `--tendcf`, and
`$TENDCF_DIR` overrides are all refused (D46 §4 Activation step 7 / F9): a
release build runs strictly from the verified in-tree tendcf checkout.

    tendcf workspace [--ops-root DIR] [--site-name SLUG] [--config PATH] \
        [--override-input NS=PATH ...] [--check-releasable] [--json]
    tendcf workspace --list [--ops-root DIR] [--json]

Resolves or lists the multi-site local ops workspace (`~/tendcf-ops`,
`tendcf-{private,public}-<site>`, issue #98) with deterministic, fail-closed
slug pairing and dev-only override taint tracking.

    tendcf eval-nix site.nix

Evaluates a Nix expression to Site Model JSON via the in-tree Nix frontend
plugin (`plugins/frontends/nix/eval.py`, named `nix2cf`) under the tested D-b
restricted evaluation limits (`restrict-eval true`, no IFD, empty
`allowed-uris`, no unsafe native code, isolated Nix env, `-I <RECIPE_DIR>`).

Exit codes mirror tendcf's tooling: 0 clean, 1 compile/release refused, 2 cannot read.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .compile import SUPERVISORS, CompileError, HostSpec, compile_host
from .plugins import PluginError, load_plugin
from .sitemodel import SITE_FILES, Schemas, SiteModel, SiteModelError, validate_site_model
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


def _is_real_dir(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode)


def _is_real_file(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode)


def _in_tree_tendcf() -> Path | None:
    """The enclosing tendcf checkout: this file is `<root>/compiler/tendcf/cli.py`.

    The root is accepted only if the package really sits in a checkout: the
    directory two levels up is a real directory named `compiler` holding
    `pyproject.toml`, and `<root>` beside it holds real `schema/goal-file.schema.json`,
    `tools/projector.py`, and `plugins/`. Anything else (pip --target,
    PYTHONPATH, a venv's site-packages, ...) returns None.
    """
    here = Path(__file__).resolve()
    if len(here.parents) < 3:
        return None
    compiler_dir, root = here.parents[1], here.parents[2]
    ok = (
        compiler_dir.name == "compiler"
        and _is_real_dir(compiler_dir)
        and _is_real_file(compiler_dir / "pyproject.toml")
        and _is_real_dir(root / "schema")
        and _is_real_file(root / "schema" / "goal-file.schema.json")
        and _is_real_dir(root / "tools")
        and _is_real_file(root / "tools" / "projector.py")
        and _is_real_dir(root / "plugins")
    )
    return root if ok else None


def _tendcf_dir(arg: str | None) -> Path | None:
    """`--tendcf`, else `$TENDCF_DIR`, else the enclosing tendcf checkout."""
    if arg is not None:
        return Path(arg).expanduser()
    raw = os.environ.get("TENDCF_DIR")
    return Path(raw).expanduser() if raw else _in_tree_tendcf()


def load_projector(tendcf: Path) -> Any:
    """Import tendcf's reference projector (`tools/projector.py`) from its checkout."""
    path = tendcf / "tools" / "projector.py"
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise SiteModelError(f"cannot read projector at {path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise SiteModelError(f"projector must be a regular non-symlink file: {path}")
    resolved = path.resolve(strict=True)
    spec = importlib.util.spec_from_file_location("tendcf_projector", resolved)
    if spec is None or spec.loader is None:
        raise SiteModelError(f"cannot import {resolved}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return module


def cmd_compile(args: argparse.Namespace) -> int:
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
            print(f"tendcf: ERROR: {flag} must not be empty", file=sys.stderr)
            return 2

    has_site_dir = args.site is not None
    has_explicit_files = any(getattr(args, attr) is not None for attr in SITE_FILES)
    has_workspace_flags = (
        args.site_name is not None or args.ops_root is not None or args.workspace
    )
    if has_site_dir and has_workspace_flags:
        print(
            "tendcf: ERROR: --site cannot be combined with --site-name, --ops-root, or --workspace",
            file=sys.stderr,
        )
        return 2
    if has_explicit_files and has_workspace_flags:
        print(
            "tendcf: ERROR: explicit --services/--roles/--launchd-writers cannot be combined "
            "with --site-name, --ops-root, or --workspace",
            file=sys.stderr,
        )
        return 2

    try:
        overrides = parse_override_inputs(args.override_input)
    except WorkspaceError as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    # Release-mode guards (D46 §4 Activation step 7 / F9 + issue #98 taint gate):
    # refuse dev overrides AND any --tendcf / $TENDCF_DIR override.
    plugin_root: Path | None = None
    if args.check_releasable:
        if overrides:
            try:
                refuse_release_if_tainted(overrides)
            except WorkspaceError as exc:
                print(f"tendcf: REFUSED: {exc}", file=sys.stderr)
                return 1
        if args.tendcf is not None:
            print(
                "tendcf: REFUSED: --check-releasable forbids --tendcf override; "
                "release builds must use the verified in-tree tendcf checkout",
                file=sys.stderr,
            )
            return 1
        if "TENDCF_DIR" in os.environ:
            print(
                "tendcf: REFUSED: --check-releasable forbids TENDCF_DIR environment override; "
                "release builds must use the verified in-tree tendcf checkout",
                file=sys.stderr,
            )
            return 1
        tendcf = _in_tree_tendcf()
        if tendcf is None:
            print(
                "tendcf: REFUSED: --check-releasable requires running from a verified "
                "in-tree tendcf checkout (none found)",
                file=sys.stderr,
            )
            return 1
        plugin_root = tendcf
    else:
        tendcf = _tendcf_dir(args.tendcf)

    if args.output is not None and overrides and not args.allow_tainted:
        print(
            f"tendcf: REFUSED: refusing to write artifact {args.output!r} while dev-only "
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
            print(f"tendcf: ERROR: {exc}", file=sys.stderr)
            return 2
        print(
            f"tendcf: workspace: site={workspace.site_slug} source={workspace.selection_source} "
            f"private={workspace.private_dir} public={workspace.public_dir or 'none'}",
            file=sys.stderr,
        )

    if overrides:
        print(
            f"tendcf: WARNING: dev-only --override-input active ({format_overrides_summary(overrides)}): "
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
                f"tendcf: ERROR: --{attr.replace('_', '-')} or --site is required "
                "(or select a workspace site with --site-name / --workspace / TENDCF_SITE)",
                file=sys.stderr,
            )
            return 2

    try:
        yaml_plugin = load_plugin("frontend", "yaml", tendcf_root=plugin_root)
        model: SiteModel = yaml_plugin.load_site_model(
            paths["services"], paths["roles"], paths["launchd_writers"]
        )
        trust_doc = yaml_plugin.load_document(Path(args.device_trust))
    except (SiteModelError, PluginError) as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    schemas: Schemas | None = None
    if tendcf is not None:
        try:
            schemas = Schemas(tendcf / "schema")
        except SiteModelError as exc:
            print(f"tendcf: ERROR: {exc}", file=sys.stderr)
            return 2
        problems = validate_site_model(model, schemas)
        if problems:
            for p in problems:
                print(f"tendcf: FAIL: {p}", file=sys.stderr)
            print(f"tendcf: {len(problems)} Site Model schema finding(s); not compiled", file=sys.stderr)
            return 1

    host = HostSpec(
        name=args.host,
        platform=args.platform,
        supervisor=args.supervisor,
        key=args.host_key,
        device_trust=trust_doc.data,
    )
    try:
        result = compile_host(
            model,
            host,
            schemas,
            overrides=overrides,
            tendcf_root=plugin_root,
        )
    except CompileError as exc:
        for f in exc.findings:
            print(f"tendcf: REFUSED: {f}", file=sys.stderr)
        print(f"tendcf: {len(exc.findings)} finding(s); no goal file written", file=sys.stderr)
        return 1
    for d in result.diagnostics:
        if d.startswith("TAINTED (not releasable):"):
            continue
        print(f"tendcf: note: {d}", file=sys.stderr)

    out = result.canonical
    if args.project:
        if tendcf is None:
            print(
                "tendcf: ERROR: --project needs a tendcf checkout to find tools/projector.py "
                "(not inside one: pass --tendcf or set TENDCF_DIR)",
                file=sys.stderr,
            )
            return 2
        try:
            projector = load_projector(tendcf)
        except SiteModelError as exc:
            print(f"tendcf: ERROR: {exc}", file=sys.stderr)
            return 2
        try:
            out = projector.project(json.loads(result.canonical))
        except projector.ProjectionRefused as exc:
            print(f"tendcf: REFUSED by tendcf projector: {exc}", file=sys.stderr)
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
                "tendcf: ERROR: --list cannot be combined with --site-name, --config, "
                "--override-input, or --check-releasable",
                file=sys.stderr,
            )
            return 2
        try:
            inventory = list_sites(ops_root=args.ops_root)
        except WorkspaceError as exc:
            print(f"tendcf: ERROR: {exc}", file=sys.stderr)
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
        print("tendcf: ERROR: --config must not be empty", file=sys.stderr)
        return 2
    if args.config is not None and args.site_name is not None:
        print("tendcf: ERROR: --config cannot be combined with --site-name", file=sys.stderr)
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
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    if ws.tainted:
        print(
            f"tendcf: WARNING: dev-only local override active ({format_overrides_summary(ws.overrides)}); "
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
            print(f"tendcf: REFUSED: {exc}", file=sys.stderr)
            return 1
    return 0


def cmd_eval_nix(args: argparse.Namespace) -> int:
    try:
        nix_plugin = load_plugin("frontend", "nix")
    except PluginError as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        value = nix_plugin.eval_nix_file(
            Path(args.file),
            recipe_dir=Path(args.recipe_dir) if args.recipe_dir is not None else None,
        )
    except nix_plugin.NixEvalError as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2
    json.dump(value, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tendcf", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"tendcf {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("compile", help="render what one host would receive")
    c.add_argument("--host", required=True, help="host name as used in the Site Model (hosts:, roles)")
    c.add_argument("--host-key", required=True, help="device public key, ed25519:<64 hex>")
    c.add_argument("--platform", required=True, choices=["macos", "linux"], help="no default; android is not offered until Termux is decided")
    c.add_argument(
        "--supervisor",
        required=True,
        choices=list(SUPERVISORS),
        help="what runs the host's units; no default. Written into device-trust.entries.supervisor",
    )
    c.add_argument(
        "--device-trust",
        required=True,
        help="JSON/YAML file holding the goal file's device-trust domain; its supervisor entry, if any, must match --supervisor",
    )
    c.add_argument(
        "--site",
        help="explicit directory holding services.yml, roles.yml, launchd-writers.yml (mutually exclusive with --site-name/--ops-root/--workspace)",
    )
    c.add_argument(
        "--ops-root",
        dest="ops_root",
        help="ops workspace root holding tendcf-{private,public}-<site> (default $TENDCF_OPS_ROOT or ~/tendcf-ops)",
    )
    c.add_argument(
        "--site-name",
        dest="site_name",
        help="site slug inside the ops workspace (precedence: --site-name > $TENDCF_SITE > XDG active-site)",
    )
    c.add_argument(
        "--workspace",
        action="store_true",
        help="resolve site from the ops workspace via $TENDCF_SITE or XDG active-site (fails closed if unset)",
    )
    c.add_argument(
        "--override-input",
        dest="override_input",
        action="append",
        metavar="NS=PATH",
        help="repeatable dev-only local checkout binding; validates path, marks output TAINTED, blocks -o without --allow-tainted, and fails --check-releasable",
    )
    c.add_argument(
        "--allow-tainted",
        dest="allow_tainted",
        action="store_true",
        help="explicitly allow writing -o/--output when --override-input is active (dev-only preview; never releasable)",
    )
    c.add_argument(
        "--check-releasable",
        dest="check_releasable",
        action="store_true",
        help="refuse with exit 1 if any dev-only --override-input, --tendcf, or $TENDCF_DIR override is active",
    )
    c.add_argument("--services")
    c.add_argument("--roles")
    c.add_argument("--launchd-writers", dest="launchd_writers")
    c.add_argument("--tendcf", help="tendcf checkout (schemas + projector); default $TENDCF_DIR, else the enclosing tendcf checkout (forbidden with --check-releasable)")
    c.add_argument("--project", action="store_true", help="print the projector's host_specific.json instead of the goal file")
    c.add_argument("-o", "--output")
    c.set_defaults(func=cmd_compile)

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

    e = sub.add_parser("eval-nix", help="evaluate a Nix expression to Site Model JSON (restricted mode)")
    e.add_argument("file", help="Nix expression file to evaluate")
    e.add_argument(
        "--recipe-dir",
        dest="recipe_dir",
        help="allowed recipe directory passed to nix-instantiate -I (default: parent directory of FILE)",
    )
    e.set_defaults(func=cmd_eval_nix)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
