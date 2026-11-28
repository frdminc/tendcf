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
slug pairing and dev-only override taint tracking. `--check-releasable` also
refuses ambient `$TENDCF_DIR` overrides for parity with `tendcf compile`.

    tendcf eval-nix site.nix [--recipe-dir DIR]

Evaluates a Nix expression to Site Model JSON via the in-tree Nix frontend
plugin (`plugins/frontends/nix/eval.py`, named `nix2cf`) under the tested D-b
restricted evaluation limits (`restrict-eval true`, no IFD, empty
`allowed-uris`, no unsafe native code, isolated Nix env, `-I <RECIPE_DIR>`).

Exit codes mirror tendcf's tooling: 0 clean, 1 compile/release refused, 2 cannot read.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .compile import SUPERVISORS, CompileError, HostSpec, compile_host
from .plugin_cli import register_plugin_subparser
from .plugin_env import PluginEnvError, default_plugin_env_dir
from .plugin_manifest import PluginManifestError, SitePluginsConfig, load_site_plugins_config
from .plugins import (
    STATIC_PLUGIN_TABLE,
    PluginError,
    exec_verified_source_module,
    in_tree_tendcf_for_file,
    load_configured_plugin,
    load_plugin,
    plugin_env_import_context,
)
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
    state_dir,
)


def _in_tree_tendcf() -> Path | None:
    """The enclosing tendcf checkout: this file is `<root>/compiler/tendcf/cli.py`."""
    return in_tree_tendcf_for_file(__file__)


def _tendcf_dir(arg: str | None) -> Path | None:
    """`--tendcf`, else `$TENDCF_DIR`, else the enclosing tendcf checkout."""
    if arg is not None:
        return Path(arg).expanduser()
    raw = os.environ.get("TENDCF_DIR")
    return Path(raw).expanduser() if raw else _in_tree_tendcf()


def _resolve_dev_plugin_root(tendcf: Path | None) -> Path | None:
    """In dev mode, honor an explicit checkout that carries `plugins/`; else fall back to in-tree."""
    if tendcf is not None:
        plugins_entry = tendcf / "plugins"
        if plugins_entry.exists() or plugins_entry.is_symlink():
            return tendcf
    in_tree = _in_tree_tendcf()
    if in_tree is not None:
        return in_tree
    return tendcf


def load_projector(tendcf: Path) -> Any:
    """Import tendcf's reference projector (`tools/projector.py`) with full containment checks.

    Verifies `tendcf`, `tendcf/tools`, and `tendcf/tools/projector.py` are all
    real non-symlink entries staying strictly inside `tendcf/tools/`, then
    loads source directly via `O_NOFOLLOW` (no `__pycache__` trust, no leaf TOCTOU).
    """
    try:
        st_root = os.lstat(tendcf)
    except OSError as exc:
        raise SiteModelError(f"cannot inspect tendcf checkout {tendcf}: {exc}") from exc
    if stat.S_ISLNK(st_root.st_mode) or not stat.S_ISDIR(st_root.st_mode):
        raise SiteModelError(
            f"tendcf checkout must be a real non-symlink directory: {tendcf}"
        )
    try:
        resolved_root = tendcf.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SiteModelError(f"cannot resolve tendcf checkout {tendcf}: {exc}") from exc

    tools_dir = resolved_root / "tools"
    try:
        st_tools = os.lstat(tools_dir)
    except OSError as exc:
        raise SiteModelError(f"cannot inspect tools directory {tools_dir}: {exc}") from exc
    if stat.S_ISLNK(st_tools.st_mode) or not stat.S_ISDIR(st_tools.st_mode):
        raise SiteModelError(
            f"tools directory must be a real non-symlink directory: {tools_dir}"
        )
    try:
        resolved_tools = tools_dir.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SiteModelError(f"cannot resolve tools directory {tools_dir}: {exc}") from exc
    if resolved_tools.parent != resolved_root or resolved_tools.name != "tools":
        raise SiteModelError(
            f"tools directory {tools_dir} resolves outside {resolved_root}: {resolved_tools}"
        )

    path = resolved_tools / "projector.py"
    try:
        st_proj = os.lstat(path)
    except OSError as exc:
        raise SiteModelError(f"cannot read projector at {path}: {exc}") from exc
    if stat.S_ISLNK(st_proj.st_mode) or not stat.S_ISREG(st_proj.st_mode):
        raise SiteModelError(f"projector must be a regular non-symlink file: {path}")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SiteModelError(f"cannot resolve projector at {path}: {exc}") from exc
    if resolved.parent != resolved_tools:
        raise SiteModelError(
            f"projector {path} resolves outside {resolved_tools}: {resolved}"
        )

    try:
        return exec_verified_source_module("tendcf_projector", resolved)
    except PluginError as exc:
        raise SiteModelError(str(exc)) from exc


def cmd_compile(args: argparse.Namespace) -> int:
    for flag, val in (
        ("--site", args.site),
        ("--services", args.services),
        ("--roles", args.roles),
        ("--launchd-writers", args.launchd_writers),
        ("--tendcf", args.tendcf),
        ("--output", args.output),
        ("--device-trust", args.device_trust),
        ("--frontend", args.frontend),
        ("--plugins-config", args.plugins_config),
        ("--plugin-env", args.plugin_env),
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
        plugin_root = _resolve_dev_plugin_root(tendcf)

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

    # Resolve optional site-private plugins.toml (explicit --plugins-config, else workspace/site plugins.toml if present).
    # L9: under --check-releasable, refuse --plugins-config outside the resolved site/workspace private directory.
    plugins_cfg: SitePluginsConfig | None = None
    plugins_site_root: Path | None = None
    try:
        if args.plugins_config is not None:
            cfg_p = Path(args.plugins_config).expanduser()
            if args.check_releasable:
                expected_site_root = workspace.private_dir if workspace is not None else (
                    site.resolve(strict=False) if site is not None else None
                )
                if expected_site_root is None or cfg_p.resolve(strict=False).parent != expected_site_root:
                    print(
                        "tendcf: REFUSED: --check-releasable forbids --plugins-config outside the resolved "
                        "site-private directory",
                        file=sys.stderr,
                    )
                    return 1
            plugins_cfg = load_site_plugins_config(cfg_p, allow_missing=False)
            plugins_site_root = workspace.private_dir if workspace is not None else cfg_p.parent.resolve(strict=False)
        elif workspace is not None and (
            (workspace.private_dir / "plugins.toml").exists()
            or (workspace.private_dir / "plugins.toml").is_symlink()
        ):
            plugins_cfg = load_site_plugins_config(workspace.private_dir / "plugins.toml", allow_missing=False)
            plugins_site_root = workspace.private_dir
        elif site is not None and (
            (site / "plugins.toml").exists() or (site / "plugins.toml").is_symlink()
        ):
            plugins_cfg = load_site_plugins_config(site / "plugins.toml", allow_missing=False)
            plugins_site_root = site.resolve(strict=False)
    except (PluginManifestError, OSError) as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    frontend_name = args.frontend or "yaml"
    resolved_plugin_env: Path | None = None
    if args.plugin_env is not None:
        resolved_plugin_env = Path(args.plugin_env).expanduser()
    elif plugins_cfg is not None and workspace is not None:
        resolved_plugin_env = default_plugin_env_dir(
            workspace.state_dir,
            workspace.site_slug,
            plugins_cfg.plugin_set_digest(site_root=plugins_site_root),
        )

    if frontend_name not in STATIC_PLUGIN_TABLE["frontend"] and plugins_cfg is None:
        print(
            f"tendcf: REFUSED: frontend plugin {frontend_name!r} is not a built-in in-tree plugin "
            "and no site-private plugins.toml was provided (pass --plugins-config or use a workspace with plugins.toml)",
            file=sys.stderr,
        )
        return 1

    try:
        yaml_plugin = load_plugin("frontend", "yaml", tendcf_root=plugin_root)
        trust_doc = yaml_plugin.load_document(Path(args.device_trust))
        if plugins_cfg is not None or frontend_name != "yaml":
            frontend_obj = load_configured_plugin(
                "frontend",
                frontend_name,
                config=plugins_cfg,
                plugin_env=resolved_plugin_env,
                tendcf_root=plugin_root,
                site_root=plugins_site_root,
                check_releasable=args.check_releasable,
            )
            pin_rec = plugins_cfg.get_plugin("frontend", frontend_name) if plugins_cfg is not None else None
            if pin_rec is not None and pin_rec.source == "out-of-tree" and resolved_plugin_env is not None:
                with plugin_env_import_context(resolved_plugin_env.resolve(strict=True)):
                    if not hasattr(frontend_obj, "load_site_model") and callable(frontend_obj):
                        frontend_obj = frontend_obj()
                    if not hasattr(frontend_obj, "load_site_model"):
                        raise PluginError(
                            f"frontend plugin {frontend_name!r} does not expose load_site_model(services, roles, launchd_writers)"
                        )
                    model: SiteModel = frontend_obj.load_site_model(
                        paths["services"], paths["roles"], paths["launchd_writers"]
                    )
            else:
                if not hasattr(frontend_obj, "load_site_model") and callable(frontend_obj):
                    frontend_obj = frontend_obj()
                if not hasattr(frontend_obj, "load_site_model"):
                    raise PluginError(
                        f"frontend plugin {frontend_name!r} does not expose load_site_model(services, roles, launchd_writers)"
                    )
                model = frontend_obj.load_site_model(
                    paths["services"], paths["roles"], paths["launchd_writers"]
                )
        else:
            model = yaml_plugin.load_site_model(
                paths["services"], paths["roles"], paths["launchd_writers"]
            )
    except (SiteModelError, PluginError, PluginEnvError, PluginManifestError, OSError) as exc:
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
        if "TENDCF_DIR" in os.environ:
            print(
                "tendcf: REFUSED: --check-releasable forbids TENDCF_DIR environment override; "
                "release builds must use the verified in-tree tendcf checkout",
                file=sys.stderr,
            )
            return 1
        try:
            ws.assert_releasable()
        except WorkspaceError as exc:
            print(f"tendcf: REFUSED: {exc}", file=sys.stderr)
            return 1
    return 0


def cmd_eval_nix(args: argparse.Namespace) -> int:
    if not args.file.strip() or "\x00" in args.file:
        print("tendcf: ERROR: Nix recipe file path must not be empty or contain NUL bytes", file=sys.stderr)
        return 2
    if args.recipe_dir is not None and (not args.recipe_dir.strip() or "\x00" in args.recipe_dir):
        print("tendcf: ERROR: --recipe-dir must not be empty or contain NUL bytes", file=sys.stderr)
        return 2
    try:
        nix_plugin = load_plugin(
            "frontend",
            "nix",
            tendcf_root=_resolve_dev_plugin_root(_tendcf_dir(None)),
        )
    except PluginError as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        value = nix_plugin.eval_nix_file(
            args.file,
            recipe_dir=args.recipe_dir,
        )
    except nix_plugin.NixEvalError as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2
    json.dump(value, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    """Run a site-named importer plugin (in-tree, contrib, or pinned out-of-tree)."""
    for flag, val in (
        ("--importer", args.importer),
        ("--source", args.source),
        ("--output-dir", args.output_dir),
        ("--site-dir", args.site_dir),
        ("--plugins-config", args.plugins_config),
        ("--plugin-env", args.plugin_env),
        ("--tendcf", args.tendcf),
    ):
        if val is not None and not str(val).strip():
            print(f"tendcf: ERROR: {flag} must not be empty", file=sys.stderr)
            return 2

    if args.check_releasable:
        if args.tendcf is not None:
            print(
                "tendcf: REFUSED: --check-releasable forbids --tendcf override",
                file=sys.stderr,
            )
            return 1
        if "TENDCF_DIR" in os.environ:
            print(
                "tendcf: REFUSED: --check-releasable forbids TENDCF_DIR environment override",
                file=sys.stderr,
            )
            return 1
        tendcf = _in_tree_tendcf()
        if tendcf is None:
            print(
                "tendcf: REFUSED: --check-releasable requires running from a verified in-tree tendcf checkout",
                file=sys.stderr,
            )
            return 1
        plugin_root = tendcf
    else:
        tendcf = _tendcf_dir(args.tendcf)
        plugin_root = _resolve_dev_plugin_root(tendcf)

    # Importers follow the exact same activation rule as frontends (D46 §4 step 4):
    # an importer runs ONLY if site-private plugins.toml explicitly names and pins it.
    # Note: `external_import.without_ai` governs external Nix/Guile recipe imports (§4 item 5,
    # Step 6), distinct from one-shot tool-migration importer plugins (§3).
    try:
        site_root: Path | None = None
        site_slug: str | None = None
        if args.plugins_config is not None:
            cfg_path = Path(args.plugins_config).expanduser()
            if args.check_releasable:
                print(
                    "tendcf: REFUSED: --check-releasable forbids --plugins-config override; "
                    "use --site-dir or --site-name/--workspace so plugins.toml comes from site-private",
                    file=sys.stderr,
                )
                return 1
            site_root = Path(args.site_dir).expanduser() if args.site_dir else cfg_path.parent
            site_slug = site_root.name
        elif args.site_dir is not None:
            site_root = Path(args.site_dir).expanduser().resolve(strict=True)
            cfg_path = site_root / "plugins.toml"
            site_slug = site_root.name
        elif args.site_name is not None or args.ops_root is not None or args.workspace or "TENDCF_SITE" in os.environ:
            ws = resolve_workspace(ops_root=args.ops_root, site_name=args.site_name)
            site_root = ws.private_dir
            cfg_path = ws.private_dir / "plugins.toml"
            site_slug = ws.site_slug
        else:
            print(
                "tendcf: REFUSED: importer execution requires site-private plugins.toml "
                "(--plugins-config, --site-dir, or --site-name/--workspace)",
                file=sys.stderr,
            )
            return 1
        plugins_cfg = load_site_plugins_config(cfg_path, allow_missing=False)
    except (PluginManifestError, WorkspaceError, OSError) as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    resolved_plugin_env: Path | None = None
    if args.plugin_env is not None:
        resolved_plugin_env = Path(args.plugin_env).expanduser()
    elif site_slug is not None:
        resolved_plugin_env = default_plugin_env_dir(
            state_dir(), site_slug, plugins_cfg.plugin_set_digest(site_root=site_root)
        )

    try:
        importer_obj = load_configured_plugin(
            "importer",
            args.importer,
            config=plugins_cfg,
            plugin_env=resolved_plugin_env,
            tendcf_root=plugin_root,
            site_root=site_root,
            check_releasable=args.check_releasable,
        )
        src_path = Path(args.source).expanduser()
        out_dir = Path(args.output_dir).expanduser()
        pin_rec = plugins_cfg.get_plugin("importer", args.importer)
        if pin_rec is not None and pin_rec.source == "out-of-tree" and resolved_plugin_env is not None:
            with plugin_env_import_context(resolved_plugin_env.resolve(strict=True)):
                if hasattr(importer_obj, "import_site"):
                    result = importer_obj.import_site(src_path, out_dir)
                elif callable(importer_obj):
                    result = importer_obj(src_path, out_dir)
                else:
                    raise PluginError(
                        f"importer plugin {args.importer!r} is neither callable nor exposes import_site(source, output_dir)"
                    )
        else:
            if hasattr(importer_obj, "import_site"):
                result = importer_obj.import_site(src_path, out_dir)
            elif callable(importer_obj):
                result = importer_obj(src_path, out_dir)
            else:
                raise PluginError(
                    f"importer plugin {args.importer!r} is neither callable nor exposes import_site(source, output_dir)"
                )
    except (PluginError, PluginEnvError, PluginManifestError, OSError) as exc:
        print(f"tendcf: REFUSED: {exc}", file=sys.stderr)
        return 1

    if args.json:
        json.dump(
            {
                "importer": args.importer,
                "source": str(Path(args.source).expanduser()),
                "output_dir": str(Path(args.output_dir).expanduser()),
                "result": result,
            },
            sys.stdout,
            indent=2,
            sort_keys=True,
            default=str,
        )
        sys.stdout.write("\n")
    else:
        print(f"imported via {args.importer!r} -> {args.output_dir}")
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
    c.add_argument("--frontend", default="yaml", help="frontend plugin name (default: 'yaml'; out-of-tree frontends must be pinned in site-private plugins.toml)")
    c.add_argument("--plugins-config", dest="plugins_config", help="explicit site-private plugins.toml (default: <site-private>/plugins.toml if present)")
    c.add_argument("--plugin-env", dest="plugin_env", help="isolated plugin environment directory for pinned out-of-tree plugins")
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
        help="exit 1 if any dev-only --override-input or $TENDCF_DIR override is active",
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

    imp = sub.add_parser("import", help="run a site-pinned importer plugin (in-tree, contrib, or out-of-tree)")
    imp.add_argument("--importer", required=True, help="importer plugin name (must be named in site-private plugins.toml)")
    imp.add_argument("--source", required=True, help="source configuration path to import")
    imp.add_argument("--output-dir", dest="output_dir", required=True, help="output directory for generated Site Model files")
    imp.add_argument("--site-dir", dest="site_dir", help="explicit site-private directory holding plugins.toml")
    imp.add_argument("--plugins-config", dest="plugins_config", help="explicit site-private plugins.toml path")
    imp.add_argument("--ops-root", dest="ops_root", help="ops workspace root")
    imp.add_argument("--site-name", dest="site_name", help="site slug in ops workspace")
    imp.add_argument("--workspace", action="store_true", help="resolve site-private from ops workspace")
    imp.add_argument("--plugin-env", dest="plugin_env", help="isolated plugin environment directory")
    imp.add_argument("--tendcf", help="tendcf checkout path (forbidden with --check-releasable)")
    imp.add_argument("--check-releasable", dest="check_releasable", action="store_true", help="enforce release-mode isolation checks")
    imp.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    imp.set_defaults(func=cmd_import)

    register_plugin_subparser(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
