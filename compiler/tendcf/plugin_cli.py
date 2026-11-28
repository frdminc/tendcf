"""Paseo-style `tendcf plugin` command family (issue #47).

Subcommands (all support `--json` output and fail closed with exit 1 on policy/trust
refusal, exit 2 on usage/IO error):

  tendcf plugin ls [--kind frontend|importer] [--json]
  tendcf plugin inspect <name> [--kind frontend|importer] [--json]
  tendcf plugin add (--in-tree NAME --kind KIND | --contrib NAME --kind KIND --relpath PATH |
                     --manifest PATH --sig PATH --wheel-dir DIR [--plugin-env DIR] [--no-install]) [--json]
  tendcf plugin update <name> --manifest PATH --sig PATH --wheel-dir DIR [--plugin-env DIR] [--no-install] [--json]
  tendcf plugin remove <name> [--kind frontend|importer] [--plugin-env DIR] [--json]
  tendcf plugin verify [--name NAME] [--wheel-dir DIR] [--plugin-env DIR]
                       [--manifest PATH --sig PATH] [--historical --as-of ISO8601] [--json]
  tendcf plugin trust ls [--json]
  tendcf plugin trust add-anchor --key PATH --label LABEL [--role root|direct] [--filename NAME] [--json]
  tendcf plugin trust remove-anchor <fingerprint> [--json]
  tendcf plugin trust revoke <fingerprint> --mode soft|hard --reason TEXT [--revoked-at ISO8601] [--cert PATH] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from .plugin_env import (
    PluginEnvError,
    default_plugin_env_dir,
    discover_env_entry_points,
    stage_plugin_env,
    verify_release_wheels,
    verify_wheel_artifact,
)
from .plugin_manifest import (
    ALLOWED_ANCHOR_ROLES,
    ALLOWED_REVOCATION_MODES,
    ALLOWED_SITE_PLUGIN_KINDS,
    KeyRevocation,
    PluginManifestError,
    PluginPin,
    SitePluginsConfig,
    TrustAnchor,
    format_rfc3339_utc,
    load_release_manifest,
    load_site_plugins_config,
    parse_rfc3339_utc,
    read_regular_file_bytes,
    utc_now,
    validate_contrib_relpath,
    validate_fingerprint,
    validate_plugin_name,
    validate_safe_filename,
    write_site_plugins_config,
)
from .plugin_wot import (
    MAX_KEY_FILE_BYTES,
    PluginTrustError,
    evaluate_revocation_policy,
    inspect_openpgp_key,
    resolve_keyring_dir,
    verify_detached_manifest_signature,
)
from .plugins import (
    STATIC_PLUGIN_TABLE,
    PluginError,
    in_tree_tendcf_root,
    list_plugins,
    resolve_contrib_plugin_path,
)
from .workspace import WorkspaceError, resolve_workspace, state_dir


def _emit(payload: dict[str, Any], human_lines: list[str], *, as_json: bool) -> None:
    if as_json:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        for line in human_lines:
            print(line)


def _resolve_site_and_config_path(args: argparse.Namespace) -> tuple[Path, Path, str]:
    """Return `(site_root, plugins_toml_path, site_slug)` from CLI flags or workspace."""
    site_dir_arg = getattr(args, "site_dir", None)
    plugins_cfg_arg = getattr(args, "plugins_config", None)
    ops_root_arg = getattr(args, "ops_root", None)
    site_name_arg = getattr(args, "site_name", None)
    workspace_flag = getattr(args, "workspace", False)

    has_ws = ops_root_arg is not None or site_name_arg is not None or workspace_flag
    if site_dir_arg is not None and has_ws:
        raise PluginManifestError(
            "--site-dir cannot be combined with --ops-root, --site-name, or --workspace"
        )
    if plugins_cfg_arg is not None:
        cfg_path = Path(plugins_cfg_arg).expanduser()
        if not str(cfg_path).strip() or "\x00" in str(cfg_path):
            raise PluginManifestError("--plugins-config must not be empty")
        if cfg_path.is_symlink():
            raise PluginManifestError(f"--plugins-config must not be a symlink: {cfg_path}")
        site_root = Path(site_dir_arg).expanduser() if site_dir_arg else cfg_path.parent
        if site_root.is_symlink():
            raise PluginManifestError(f"site directory must not be a symlink: {site_root}")
        return site_root.resolve(strict=False), cfg_path, site_root.name

    if site_dir_arg is not None:
        raw = str(site_dir_arg)
        if not raw.strip() or "\x00" in raw:
            raise PluginManifestError("--site-dir must not be empty")
        sr = Path(raw).expanduser()
        if sr.is_symlink():
            raise PluginManifestError(f"--site-dir must not be a symlink: {sr}")
        if not sr.is_dir():
            raise PluginManifestError(f"--site-dir does not exist or is not a directory: {sr}")
        resolved_sr = sr.resolve(strict=True)
        return resolved_sr, resolved_sr / "plugins.toml", resolved_sr.name

    if has_ws or "TENDCF_SITE" in os.environ:
        ws = resolve_workspace(ops_root=ops_root_arg, site_name=site_name_arg)
        return ws.private_dir, ws.private_dir / "plugins.toml", ws.site_slug

    raise PluginManifestError(
        "specify --site-dir DIR, --plugins-config PATH, or workspace selector (--site-name / --workspace / TENDCF_SITE)"
    )


def _resolve_target_plugin_env(
    args: argparse.Namespace,
    *,
    site_slug: str,
    config: SitePluginsConfig,
) -> Path:
    explicit = getattr(args, "plugin_env", None)
    if explicit is not None:
        if not str(explicit).strip() or "\x00" in str(explicit):
            raise PluginEnvError("--plugin-env must not be empty")
        return Path(explicit).expanduser()
    return default_plugin_env_dir(state_dir(), site_slug, config.plugin_set_digest())


def _copy_file_safely_into_keyring(src: Path, keyring_dir: Path, filename: str) -> Path:
    validate_safe_filename(filename, label="keyring filename")
    data = read_regular_file_bytes(src, max_bytes=MAX_KEY_FILE_BYTES, label=f"key file {src}")
    keyring_dir.mkdir(parents=True, exist_ok=True)
    if keyring_dir.is_symlink():
        raise PluginTrustError(f"keyring directory must not be a symlink: {keyring_dir}")
    dest = keyring_dir / filename
    if dest.is_symlink():
        raise PluginTrustError(f"refusing to write keyring file through symlink: {dest}")
    tmp = keyring_dir / f".{filename}.tmp.{os.getpid()}"
    try:
        tmp.write_bytes(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return dest


def _cmd_plugin_ls(args: argparse.Namespace) -> int:
    try:
        site_root, cfg_path, _ = _resolve_site_and_config_path(args)
        config = load_site_plugins_config(cfg_path, allow_missing=True)
    except (PluginManifestError, WorkspaceError) as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    kind_filter = args.kind
    pinned_by_key = {(p.kind, p.name): p for p in config.plugins}
    rows: list[dict[str, Any]] = []

    # Built-in static in-tree plugins (frontends & importers; supervisors listed as in-tree-only when unfiltered).
    for spec in list_plugins(kind_filter):
        if kind_filter is None and spec.kind == "supervisor":
            rows.append(
                {
                    "name": spec.name,
                    "kind": spec.kind,
                    "source": "in-tree",
                    "pinned": True,
                    "in_tree_only": True,
                    "relpath": spec.relpath,
                    "description": spec.description,
                }
            )
            continue
        pin = pinned_by_key.get((spec.kind, spec.name))
        rows.append(
            {
                "name": spec.name,
                "kind": spec.kind,
                "source": "in-tree",
                "pinned": pin is not None,
                "relpath": spec.relpath,
                "description": spec.description,
            }
        )

    for pin in sorted(config.plugins, key=lambda p: (p.kind, p.name)):
        if kind_filter is not None and pin.kind != kind_filter:
            continue
        if pin.source == "in-tree":
            continue
        row = pin.to_dict()
        row["pinned"] = True
        rows.append(row)

    payload = {
        "site_root": str(site_root),
        "plugins_config": str(cfg_path),
        "plugins_config_exists": cfg_path.exists(),
        "plugin_set_digest": config.plugin_set_digest(),
        "plugins": rows,
    }
    lines = [
        f"site_root: {site_root}",
        f"plugins_config: {cfg_path} ({'present' if cfg_path.exists() else 'not initialized'})",
        f"plugin_set_digest: {config.plugin_set_digest()}",
        "plugins:",
    ]
    for r in rows:
        extra = ""
        if r["source"] == "out-of-tree":
            extra = f" {r['distribution']}=={r['version']} seq={r['release_seq']} exp={r['expires_at']}"
        elif r["source"] == "contrib":
            extra = f" relpath={r['relpath']}"
        status = "pinned" if r["pinned"] else "available"
        lines.append(f"  {r['kind']}/{r['name']} [{r['source']}, {status}]{extra}")
    _emit(payload, lines, as_json=args.json)
    return 0


def _cmd_plugin_inspect(args: argparse.Namespace) -> int:
    try:
        site_root, cfg_path, _ = _resolve_site_and_config_path(args)
        config = load_site_plugins_config(cfg_path, allow_missing=True)
    except (PluginManifestError, WorkspaceError) as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    matches: list[dict[str, Any]] = []
    kinds = (args.kind,) if args.kind else ("frontend", "importer", "supervisor")
    for k in kinds:
        pin = config.get_plugin(k, args.name) if k in ALLOWED_SITE_PLUGIN_KINDS else None
        if pin is not None:
            rec = pin.to_dict()
            rec["pinned"] = True
            matches.append(rec)
        elif args.name in STATIC_PLUGIN_TABLE.get(k, {}):
            spec = STATIC_PLUGIN_TABLE[k][args.name]
            matches.append(
                {
                    "name": spec.name,
                    "kind": spec.kind,
                    "source": "in-tree",
                    "pinned": False,
                    "relpath": spec.relpath,
                    "description": spec.description,
                }
            )

    if not matches:
        print(f"tendcf: ERROR: plugin {args.name!r} not found", file=sys.stderr)
        return 1
    if len(matches) > 1:
        found_kinds = [m["kind"] for m in matches]
        print(
            f"tendcf: ERROR: plugin {args.name!r} exists in multiple kinds {found_kinds}; pass --kind",
            file=sys.stderr,
        )
        return 2

    rec = matches[0]
    payload = {
        "site_root": str(site_root),
        "plugins_config": str(cfg_path),
        "plugin_set_digest": config.plugin_set_digest(),
        "plugin": rec,
    }
    lines = [
        f"name: {rec['name']}",
        f"kind: {rec['kind']}",
        f"source: {rec['source']}",
        f"pinned: {'true' if rec['pinned'] else 'false'}",
    ]
    for key in (
        "relpath",
        "distribution",
        "version",
        "entry_point",
        "wheel_filename",
        "wheel_sha256",
        "release_seq",
        "issued_at",
        "expires_at",
        "manifest_sha256",
        "signer_fingerprint",
        "verified_at",
    ):
        if key in rec:
            lines.append(f"{key}: {rec[key]}")
    if rec.get("dependencies"):
        lines.append(f"dependencies ({len(rec['dependencies'])}):")
        for dep in rec["dependencies"]:
            lines.append(f"  {dep['distribution']}=={dep['version']} sha256={dep['sha256']}")
    lines.append(f"plugin_set_digest: {config.plugin_set_digest()}")
    _emit(payload, lines, as_json=args.json)
    return 0


def _cmd_plugin_add(args: argparse.Namespace) -> int:
    try:
        site_root, cfg_path, site_slug = _resolve_site_and_config_path(args)
        config = load_site_plugins_config(cfg_path, allow_missing=True)
    except (PluginManifestError, WorkspaceError) as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    prev_digest = config.plugin_set_digest()

    # Mode 1: in-tree built-in plugin naming
    if args.in_tree is not None:
        if args.manifest or args.sig or args.wheel_dir or args.contrib:
            print("tendcf: ERROR: --in-tree cannot be combined with --contrib or --manifest/--sig/--wheel-dir", file=sys.stderr)
            return 2
        if not args.kind:
            print("tendcf: ERROR: --kind is required with --in-tree", file=sys.stderr)
            return 2
        try:
            name = validate_plugin_name(args.in_tree, kind=args.kind, source="in-tree")
            if config.get_plugin(args.kind, name) is not None:
                raise PluginManifestError(f"{args.kind} plugin {name!r} is already pinned in {cfg_path}")
            pin = PluginPin(name=name, kind=args.kind, source="in-tree")
            new_cfg = replace(config, plugins=(*config.plugins, pin))
            write_site_plugins_config(cfg_path, new_cfg)
        except PluginManifestError as exc:
            print(f"tendcf: REFUSED: {exc}", file=sys.stderr)
            return 1
        new_digest = new_cfg.plugin_set_digest()
        payload = {
            "action": "add",
            "plugin": pin.to_dict(),
            "previous_plugin_set_digest": prev_digest,
            "plugin_set_digest": new_digest,
            "privileged_change": new_digest != prev_digest,
            "requires_ceremony_marker": new_digest != prev_digest,
        }
        _emit(
            payload,
            [
                f"added in-tree plugin {pin.kind}/{pin.name} to {cfg_path}",
                f"plugin_set_digest: {prev_digest[:12]} -> {new_digest[:12]} (privileged change: gate-5 ceremony marker required)",
            ],
            as_json=args.json,
        )
        return 0

    # Mode 2: contrib/ in-tree plugin naming (inherits tendcf git pin, verified path under contrib/)
    if args.contrib is not None:
        if args.manifest or args.sig or args.wheel_dir:
            print("tendcf: ERROR: --contrib cannot be combined with --manifest/--sig/--wheel-dir", file=sys.stderr)
            return 2
        if not args.kind or not args.relpath:
            print("tendcf: ERROR: --kind and --relpath are required with --contrib", file=sys.stderr)
            return 2
        try:
            name = validate_plugin_name(args.contrib, kind=args.kind, source="contrib")
            relpath = validate_contrib_relpath(args.relpath)
            if config.get_plugin(args.kind, name) is not None:
                raise PluginManifestError(f"{args.kind} plugin {name!r} is already pinned in {cfg_path}")
            tendcf_root = Path(args.tendcf).expanduser() if args.tendcf else in_tree_tendcf_root()
            resolve_contrib_plugin_path(args.kind, name, relpath, tendcf_root=tendcf_root)
            pin = PluginPin(name=name, kind=args.kind, source="contrib", relpath=relpath)
            new_cfg = replace(config, plugins=(*config.plugins, pin))
            write_site_plugins_config(cfg_path, new_cfg)
        except (PluginManifestError, PluginError) as exc:
            print(f"tendcf: REFUSED: {exc}", file=sys.stderr)
            return 1
        new_digest = new_cfg.plugin_set_digest()
        payload = {
            "action": "add",
            "plugin": pin.to_dict(),
            "previous_plugin_set_digest": prev_digest,
            "plugin_set_digest": new_digest,
            "privileged_change": new_digest != prev_digest,
            "requires_ceremony_marker": new_digest != prev_digest,
        }
        _emit(
            payload,
            [
                f"added contrib plugin {pin.kind}/{pin.name} ({relpath}) to {cfg_path}",
                f"plugin_set_digest: {prev_digest[:12]} -> {new_digest[:12]} (privileged change: gate-5 ceremony marker required)",
            ],
            as_json=args.json,
        )
        return 0

    # Mode 3: out-of-tree signed plugin release bundle
    if not (args.manifest and args.sig and args.wheel_dir):
        print(
            "tendcf: ERROR: out-of-tree add requires --manifest PATH --sig PATH --wheel-dir DIR "
            "(or use --in-tree / --contrib)",
            file=sys.stderr,
        )
        return 2

    now = utc_now()
    try:
        manifest = load_release_manifest(Path(args.manifest))
        if config.get_plugin(manifest.kind, manifest.name) is not None:
            raise PluginManifestError(
                f"{manifest.kind} plugin {manifest.name!r} is already pinned; use `tendcf plugin update` to upgrade"
            )
        if now >= manifest.expires_at_dt:
            raise PluginManifestError(
                f"plugin release manifest expired at {manifest.expires_at} (anti-freeze protection)"
            )
        wot = verify_detached_manifest_signature(
            Path(args.manifest),
            Path(args.sig),
            site_root=site_root,
            policy=config.trust,
            historical=False,
            issued_at=manifest.issued_at_dt,
        )
        plugin_whl, dep_wheels = verify_release_wheels(manifest, Path(args.wheel_dir))

        pin = PluginPin(
            name=manifest.name,
            kind=manifest.kind,
            source="out-of-tree",
            distribution=manifest.distribution,
            version=manifest.version,
            entry_point=manifest.entry_point,
            wheel_filename=manifest.wheel_filename,
            wheel_sha256=manifest.wheel_sha256,
            release_seq=manifest.release_seq,
            issued_at=manifest.issued_at,
            expires_at=manifest.expires_at,
            manifest_sha256=manifest.manifest_sha256,
            signer_fingerprint=wot.primary_fingerprint,
            verified_at=format_rfc3339_utc(now),
            dependencies=manifest.dependencies,
        )
        new_cfg = replace(config, plugins=(*config.plugins, pin))
        staged_env: Path | None = None
        if not args.no_install:
            target_env = _resolve_target_plugin_env(args, site_slug=site_slug, config=new_cfg)
            tendcf_root = Path(args.tendcf).expanduser() if args.tendcf else in_tree_tendcf_root()
            staged_env = stage_plugin_env(
                target_env,
                config=new_cfg,
                verified_wheels=[plugin_whl, *dep_wheels],
                tendcf_root=tendcf_root,
                site_root=site_root,
            )
        write_site_plugins_config(cfg_path, new_cfg)
    except (PluginManifestError, PluginTrustError, PluginEnvError) as exc:
        print(f"tendcf: REFUSED: {exc}", file=sys.stderr)
        return 1

    new_digest = new_cfg.plugin_set_digest()
    payload = {
        "action": "add",
        "plugin": pin.to_dict(),
        "wot": wot.to_dict(),
        "staged_plugin_env": str(staged_env) if staged_env is not None else None,
        "previous_plugin_set_digest": prev_digest,
        "plugin_set_digest": new_digest,
        "privileged_change": new_digest != prev_digest,
        "requires_ceremony_marker": new_digest != prev_digest,
    }
    lines = [
        f"added out-of-tree plugin {pin.kind}/{pin.name} ({pin.distribution}=={pin.version}, seq={pin.release_seq})",
        f"signer: {wot.primary_fingerprint} (backend={wot.backend}, trust={wot.trust_level})",
        f"wheel_sha256: {pin.wheel_sha256} (+ {len(pin.dependencies)} transitive dep wheel(s))",
        f"staged_plugin_env: {staged_env or 'none (--no-install)'}",
        f"plugin_set_digest: {prev_digest[:12]} -> {new_digest[:12]} (privileged change: gate-5 ceremony marker required)",
    ]
    _emit(payload, lines, as_json=args.json)
    return 0


def _cmd_plugin_update(args: argparse.Namespace) -> int:
    try:
        site_root, cfg_path, site_slug = _resolve_site_and_config_path(args)
        config = load_site_plugins_config(cfg_path, allow_missing=False)
    except (PluginManifestError, WorkspaceError) as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    prev_digest = config.plugin_set_digest()
    now = utc_now()
    try:
        manifest = load_release_manifest(Path(args.manifest))
        if manifest.name != args.name:
            raise PluginManifestError(
                f"update target {args.name!r} does not match manifest plugin name {manifest.name!r}"
            )
        old_pin = config.get_plugin(manifest.kind, manifest.name)
        if old_pin is None or old_pin.source != "out-of-tree":
            raise PluginManifestError(
                f"out-of-tree {manifest.kind} plugin {manifest.name!r} is not currently pinned; use `tendcf plugin add`"
            )
        assert old_pin.release_seq is not None and old_pin.issued_at is not None

        # Strict anti-rollback & anti-freeze enforcement (#47 comment item 4).
        if manifest.release_seq <= old_pin.release_seq:
            raise PluginManifestError(
                f"rollback/replay refused for {manifest.name!r}: new release_seq {manifest.release_seq} "
                f"must be strictly greater than pinned release_seq {old_pin.release_seq}"
            )
        if manifest.issued_at_dt < parse_rfc3339_utc(old_pin.issued_at, label="pinned issued_at"):
            raise PluginManifestError(
                f"rollback refused for {manifest.name!r}: new issued_at {manifest.issued_at} "
                f"precedes pinned issued_at {old_pin.issued_at}"
            )
        if now >= manifest.expires_at_dt:
            raise PluginManifestError(
                f"plugin release manifest expired at {manifest.expires_at} (anti-freeze protection)"
            )

        wot = verify_detached_manifest_signature(
            Path(args.manifest),
            Path(args.sig),
            site_root=site_root,
            policy=config.trust,
            historical=False,
            issued_at=manifest.issued_at_dt,
        )
        plugin_whl, dep_wheels = verify_release_wheels(manifest, Path(args.wheel_dir))

        new_pin = PluginPin(
            name=manifest.name,
            kind=manifest.kind,
            source="out-of-tree",
            distribution=manifest.distribution,
            version=manifest.version,
            entry_point=manifest.entry_point,
            wheel_filename=manifest.wheel_filename,
            wheel_sha256=manifest.wheel_sha256,
            release_seq=manifest.release_seq,
            issued_at=manifest.issued_at,
            expires_at=manifest.expires_at,
            manifest_sha256=manifest.manifest_sha256,
            signer_fingerprint=wot.primary_fingerprint,
            verified_at=format_rfc3339_utc(now),
            dependencies=manifest.dependencies,
        )
        updated_plugins = tuple(
            new_pin if (p.kind == manifest.kind and p.name == manifest.name) else p
            for p in config.plugins
        )
        new_cfg = replace(config, plugins=updated_plugins)
        staged_env: Path | None = None
        if not args.no_install:
            target_env = _resolve_target_plugin_env(args, site_slug=site_slug, config=new_cfg)
            tendcf_root = Path(args.tendcf).expanduser() if args.tendcf else in_tree_tendcf_root()
            staged_env = stage_plugin_env(
                target_env,
                config=new_cfg,
                verified_wheels=[plugin_whl, *dep_wheels],
                tendcf_root=tendcf_root,
                site_root=site_root,
            )
        write_site_plugins_config(cfg_path, new_cfg)
    except (PluginManifestError, PluginTrustError, PluginEnvError) as exc:
        print(f"tendcf: REFUSED: {exc}", file=sys.stderr)
        return 1

    new_digest = new_cfg.plugin_set_digest()
    payload = {
        "action": "update",
        "previous": old_pin.to_dict(),
        "plugin": new_pin.to_dict(),
        "wot": wot.to_dict(),
        "staged_plugin_env": str(staged_env) if staged_env is not None else None,
        "previous_plugin_set_digest": prev_digest,
        "plugin_set_digest": new_digest,
        "privileged_change": new_digest != prev_digest,
        "requires_ceremony_marker": new_digest != prev_digest,
    }
    lines = [
        f"updated {new_pin.kind}/{new_pin.name}: {old_pin.version} (seq {old_pin.release_seq}) -> "
        f"{new_pin.version} (seq {new_pin.release_seq})",
        f"signer: {wot.primary_fingerprint} (backend={wot.backend}, trust={wot.trust_level})",
        f"staged_plugin_env: {staged_env or 'none (--no-install)'}",
        f"plugin_set_digest: {prev_digest[:12]} -> {new_digest[:12]} (privileged change: gate-5 ceremony marker required)",
    ]
    _emit(payload, lines, as_json=args.json)
    return 0


def _cmd_plugin_remove(args: argparse.Namespace) -> int:
    try:
        site_root, cfg_path, site_slug = _resolve_site_and_config_path(args)
        config = load_site_plugins_config(cfg_path, allow_missing=False)
    except (PluginManifestError, WorkspaceError) as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    matches = [
        p for p in config.plugins if p.name == args.name and (args.kind is None or p.kind == args.kind)
    ]
    if not matches:
        print(f"tendcf: REFUSED: plugin {args.name!r} is not pinned in {cfg_path}", file=sys.stderr)
        return 1
    if len(matches) > 1:
        print(
            f"tendcf: ERROR: plugin {args.name!r} exists in multiple kinds {[m.kind for m in matches]}; pass --kind",
            file=sys.stderr,
        )
        return 2

    target = matches[0]
    prev_digest = config.plugin_set_digest()
    remaining = tuple(p for p in config.plugins if not (p.kind == target.kind and p.name == target.name))
    new_cfg = replace(config, plugins=remaining)

    try:
        staged_env: Path | None = None
        if args.plugin_env is not None:
            env_path = Path(args.plugin_env).expanduser()
            tendcf_root = Path(args.tendcf).expanduser() if args.tendcf else in_tree_tendcf_root()
            if any(p.source == "out-of-tree" for p in new_cfg.plugins):
                staged_env = stage_plugin_env(
                    env_path,
                    config=new_cfg,
                    verified_wheels=[],
                    tendcf_root=tendcf_root,
                    site_root=site_root,
                )
            elif env_path.exists() and not env_path.is_symlink():
                staged_env = stage_plugin_env(
                    env_path,
                    config=new_cfg,
                    verified_wheels=[],
                    tendcf_root=tendcf_root,
                    site_root=site_root,
                )
        write_site_plugins_config(cfg_path, new_cfg)
    except (PluginManifestError, PluginEnvError) as exc:
        print(f"tendcf: REFUSED: {exc}", file=sys.stderr)
        return 1

    new_digest = new_cfg.plugin_set_digest()
    payload = {
        "action": "remove",
        "removed": target.to_dict(),
        "staged_plugin_env": str(staged_env) if staged_env is not None else None,
        "previous_plugin_set_digest": prev_digest,
        "plugin_set_digest": new_digest,
        "privileged_change": new_digest != prev_digest,
        "requires_ceremony_marker": new_digest != prev_digest,
    }
    _emit(
        payload,
        [
            f"removed plugin {target.kind}/{target.name} from {cfg_path}",
            f"plugin_set_digest: {prev_digest[:12]} -> {new_digest[:12]} (privileged change: gate-5 ceremony marker required)",
        ],
        as_json=args.json,
    )
    return 0


def _cmd_plugin_verify(args: argparse.Namespace) -> int:
    try:
        site_root, cfg_path, _ = _resolve_site_and_config_path(args)
        config = load_site_plugins_config(cfg_path, allow_missing=False)
    except (PluginManifestError, WorkspaceError) as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    if args.as_of and not args.historical:
        print("tendcf: ERROR: --as-of requires --historical", file=sys.stderr)
        return 2
    if (args.manifest is None) != (args.sig is None):
        print("tendcf: ERROR: --manifest and --sig must be passed together", file=sys.stderr)
        return 2

    try:
        as_of_dt = parse_rfc3339_utc(args.as_of, label="--as-of") if args.as_of else utc_now()
    except PluginManifestError as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    findings: list[str] = []
    warnings: list[str] = []
    wot_result: dict[str, Any] | None = None

    # 1. Verify keyring directory & anchor/revocation files if any anchors or out-of-tree plugins exist.
    has_oot = any(p.source == "out-of-tree" for p in config.plugins)
    if config.trust.anchors or config.trust.revocations or has_oot or args.manifest:
        try:
            resolve_keyring_dir(site_root, config.trust.keyring_dir)
        except PluginTrustError as exc:
            findings.append(str(exc))

    # 2. Verify each pinned plugin's expiry, revocation status, contrib path, and optional wheel-dir hashes.
    pins_to_check = [p for p in config.plugins if args.name is None or p.name == args.name]
    if args.name is not None and not pins_to_check and not args.manifest:
        findings.append(f"plugin {args.name!r} is not pinned in {cfg_path}")

    tendcf_root = Path(args.tendcf).expanduser() if args.tendcf else in_tree_tendcf_root()
    for pin in pins_to_check:
        if pin.source == "contrib":
            assert pin.relpath is not None
            try:
                resolve_contrib_plugin_path(pin.kind, pin.name, pin.relpath, tendcf_root=tendcf_root)
            except PluginError as exc:
                findings.append(str(exc))
            continue
        if pin.source != "out-of-tree":
            continue
        assert pin.expires_at is not None and pin.issued_at is not None and pin.verified_at is not None
        assert pin.signer_fingerprint is not None
        exp_dt = parse_rfc3339_utc(pin.expires_at, label="pin.expires_at")
        iss_dt = parse_rfc3339_utc(pin.issued_at, label="pin.issued_at")
        ver_dt = parse_rfc3339_utc(pin.verified_at, label="pin.verified_at")

        if as_of_dt >= exp_dt:
            findings.append(
                f"{pin.kind}/{pin.name}: pin expired at {pin.expires_at} (checked at {format_rfc3339_utc(as_of_dt)})"
            )
        try:
            rev_warns = evaluate_revocation_policy(
                pin.signer_fingerprint,
                config.trust,
                historical=args.historical,
                as_of=as_of_dt,
                issued_at=iss_dt,
                verified_at=ver_dt,
            )
            warnings.extend(rev_warns)
        except PluginTrustError as exc:
            findings.append(f"{pin.kind}/{pin.name}: {exc}")

        if args.wheel_dir is not None:
            wdir = Path(args.wheel_dir)
            try:
                assert pin.wheel_filename and pin.wheel_sha256 and pin.distribution and pin.version and pin.entry_point
                verify_wheel_artifact(
                    wdir / pin.wheel_filename,
                    expected_filename=pin.wheel_filename,
                    expected_sha256=pin.wheel_sha256,
                    expected_distribution=pin.distribution,
                    expected_version=pin.version,
                    is_plugin_wheel=True,
                    expected_entry_point_group=pin.entry_point_group,
                    expected_plugin_name=pin.name,
                    expected_entry_point=pin.entry_point,
                )
                for dep in pin.dependencies:
                    verify_wheel_artifact(
                        wdir / dep.filename,
                        expected_filename=dep.filename,
                        expected_sha256=dep.sha256,
                        expected_distribution=dep.distribution,
                        expected_version=dep.version,
                        is_plugin_wheel=False,
                    )
            except (PluginEnvError, PluginManifestError) as exc:
                findings.append(f"{pin.kind}/{pin.name}: {exc}")

    # 3. Optional detached release manifest + signature re-verification (e.g., pre-add or historical rebuild).
    if args.manifest is not None and args.sig is not None:
        try:
            manifest = load_release_manifest(Path(args.manifest))
            if as_of_dt >= manifest.expires_at_dt:
                findings.append(
                    f"manifest {args.manifest} expired at {manifest.expires_at} (as_of={format_rfc3339_utc(as_of_dt)})"
                )
            matched_pin = config.get_plugin(manifest.kind, manifest.name)
            pin_verified_at = (
                parse_rfc3339_utc(matched_pin.verified_at, label="pin.verified_at")
                if matched_pin and matched_pin.verified_at
                else None
            )
            wot = verify_detached_manifest_signature(
                Path(args.manifest),
                Path(args.sig),
                site_root=site_root,
                policy=config.trust,
                historical=args.historical,
                as_of=as_of_dt if args.historical else None,
                issued_at=manifest.issued_at_dt,
                verified_at=pin_verified_at,
            )
            wot_result = wot.to_dict()
            warnings.extend(wot.warnings)
            if args.wheel_dir is not None:
                verify_release_wheels(manifest, Path(args.wheel_dir))
        except (PluginManifestError, PluginTrustError, PluginEnvError) as exc:
            findings.append(str(exc))

    # 4. Optional isolated plugin environment integrity + non-dedup entry-point check.
    discovered_count: int | None = None
    if args.plugin_env is not None:
        try:
            discovered = discover_env_entry_points(
                Path(args.plugin_env).expanduser(),
                config=config,
                tendcf_root=tendcf_root,
                site_root=site_root,
                check_releasable=args.check_releasable,
            )
            discovered_count = sum(len(v) for v in discovered.values())
        except PluginEnvError as exc:
            findings.append(str(exc))

    ok = len(findings) == 0
    payload = {
        "ok": ok,
        "site_root": str(site_root),
        "plugins_config": str(cfg_path),
        "plugin_set_digest": config.plugin_set_digest(),
        "historical": args.historical,
        "as_of": format_rfc3339_utc(as_of_dt),
        "wot": wot_result,
        "discovered_entry_points": discovered_count,
        "warnings": warnings,
        "findings": findings,
    }
    lines = [
        f"verify: {'OK' if ok else 'REFUSED'} (plugin_set_digest={config.plugin_set_digest()})",
    ]
    for w in warnings:
        lines.append(f"warning: {w}")
    for f in findings:
        lines.append(f"finding: {f}")
    _emit(payload, lines, as_json=args.json)
    return 0 if ok else 1


def _cmd_plugin_trust_ls(args: argparse.Namespace) -> int:
    try:
        site_root, cfg_path, _ = _resolve_site_and_config_path(args)
        config = load_site_plugins_config(cfg_path, allow_missing=True)
    except (PluginManifestError, WorkspaceError) as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    payload = {
        "site_root": str(site_root),
        "plugins_config": str(cfg_path),
        "plugin_set_digest": config.plugin_set_digest(),
        "trust": config.trust.to_dict(),
    }
    lines = [
        f"keyring_dir: {config.trust.keyring_dir}",
        f"max_depth: {config.trust.max_depth} (full_threshold={config.trust.full_threshold}, marginal_threshold={config.trust.marginal_threshold})",
        f"backend: {config.trust.backend}",
        f"anchors ({len(config.trust.anchors)}):",
    ]
    for a in config.trust.anchors:
        lines.append(f"  {a.fingerprint} [{a.role}] {a.label} ({a.key_file})")
    lines.append(f"revocations ({len(config.trust.revocations)}):")
    for r in config.trust.revocations:
        lines.append(f"  {r.fingerprint} [{r.mode}] at={r.revoked_at} reason={r.reason!r}")
    _emit(payload, lines, as_json=args.json)
    return 0


def _cmd_plugin_trust_add_anchor(args: argparse.Namespace) -> int:
    try:
        site_root, cfg_path, _ = _resolve_site_and_config_path(args)
        config = load_site_plugins_config(cfg_path, allow_missing=True)
        prev_digest = config.plugin_set_digest()
        key_src = Path(args.key).expanduser()
        info = inspect_openpgp_key(key_src)
        fpr = info["fingerprint"]
        if any(a.fingerprint == fpr for a in config.trust.anchors):
            raise PluginManifestError(f"trust anchor {fpr} is already configured")
        filename = validate_safe_filename(args.filename or f"{fpr[:16].lower()}.asc", label="--filename")
        kr_dir = site_root / config.trust.keyring_dir
        _copy_file_safely_into_keyring(key_src, kr_dir, filename)
        anchor = TrustAnchor(fingerprint=fpr, label=args.label.strip(), role=args.role, key_file=filename)
        new_trust = replace(config.trust, anchors=(*config.trust.anchors, anchor))
        new_cfg = replace(config, trust=new_trust)
        write_site_plugins_config(cfg_path, new_cfg)
    except (PluginManifestError, PluginTrustError, WorkspaceError) as exc:
        print(f"tendcf: REFUSED: {exc}", file=sys.stderr)
        return 1

    new_digest = new_cfg.plugin_set_digest()
    payload = {
        "action": "trust.add-anchor",
        "anchor": anchor.to_dict(),
        "uids": info["uids"],
        "previous_plugin_set_digest": prev_digest,
        "plugin_set_digest": new_digest,
        "privileged_change": new_digest != prev_digest,
        "requires_ceremony_marker": new_digest != prev_digest,
    }
    _emit(
        payload,
        [
            f"added trust anchor {anchor.fingerprint} [{anchor.role}] ({anchor.label}) -> {config.trust.keyring_dir}/{anchor.key_file}",
            f"plugin_set_digest: {prev_digest[:12]} -> {new_digest[:12]} (privileged change: gate-5 ceremony marker required)",
        ],
        as_json=args.json,
    )
    return 0


def _cmd_plugin_trust_remove_anchor(args: argparse.Namespace) -> int:
    try:
        site_root, cfg_path, _ = _resolve_site_and_config_path(args)
        config = load_site_plugins_config(cfg_path, allow_missing=False)
        fpr = validate_fingerprint(args.fingerprint, label="fingerprint")
    except (PluginManifestError, WorkspaceError) as exc:
        print(f"tendcf: ERROR: {exc}", file=sys.stderr)
        return 2

    if not any(a.fingerprint == fpr for a in config.trust.anchors):
        print(f"tendcf: REFUSED: trust anchor {fpr} not found", file=sys.stderr)
        return 1
    prev_digest = config.plugin_set_digest()
    new_trust = replace(config.trust, anchors=tuple(a for a in config.trust.anchors if a.fingerprint != fpr))
    new_cfg = replace(config, trust=new_trust)
    try:
        write_site_plugins_config(cfg_path, new_cfg)
    except PluginManifestError as exc:
        print(f"tendcf: REFUSED: {exc}", file=sys.stderr)
        return 1

    new_digest = new_cfg.plugin_set_digest()
    payload = {
        "action": "trust.remove-anchor",
        "fingerprint": fpr,
        "previous_plugin_set_digest": prev_digest,
        "plugin_set_digest": new_digest,
        "privileged_change": new_digest != prev_digest,
        "requires_ceremony_marker": new_digest != prev_digest,
    }
    _emit(
        payload,
        [
            f"removed trust anchor {fpr} from {cfg_path}",
            f"plugin_set_digest: {prev_digest[:12]} -> {new_digest[:12]} (privileged change: gate-5 ceremony marker required)",
        ],
        as_json=args.json,
    )
    return 0


def _cmd_plugin_trust_revoke(args: argparse.Namespace) -> int:
    try:
        site_root, cfg_path, _ = _resolve_site_and_config_path(args)
        config = load_site_plugins_config(cfg_path, allow_missing=True)
        fpr = validate_fingerprint(args.fingerprint, label="fingerprint")
        rev_dt = parse_rfc3339_utc(args.revoked_at, label="--revoked-at") if args.revoked_at else utc_now()
        prev_digest = config.plugin_set_digest()

        cert_filename: str | None = None
        if args.cert is not None:
            cert_filename = validate_safe_filename(f"{fpr[:16].lower()}.rev.asc", label="revocation cert filename")
            kr_dir = site_root / config.trust.keyring_dir
            _copy_file_safely_into_keyring(Path(args.cert).expanduser(), kr_dir, cert_filename)

        rev = KeyRevocation(
            fingerprint=fpr,
            mode=args.mode,
            revoked_at=format_rfc3339_utc(rev_dt),
            reason=args.reason.strip(),
            cert_file=cert_filename,
        )
        # Replace existing revocation for same fingerprint (e.g., upgrading soft -> hard) without duplicates.
        existing = [r for r in config.trust.revocations if r.fingerprint != fpr]
        new_trust = replace(config.trust, revocations=(*existing, rev))
        new_cfg = replace(config, trust=new_trust)
        write_site_plugins_config(cfg_path, new_cfg)
    except (PluginManifestError, PluginTrustError, WorkspaceError) as exc:
        print(f"tendcf: REFUSED: {exc}", file=sys.stderr)
        return 1

    new_digest = new_cfg.plugin_set_digest()
    payload = {
        "action": "trust.revoke",
        "revocation": rev.to_dict(),
        "previous_plugin_set_digest": prev_digest,
        "plugin_set_digest": new_digest,
        "privileged_change": new_digest != prev_digest,
        "requires_ceremony_marker": new_digest != prev_digest,
    }
    _emit(
        payload,
        [
            f"recorded {rev.mode} revocation for {rev.fingerprint} at {rev.revoked_at} ({rev.reason})",
            f"plugin_set_digest: {prev_digest[:12]} -> {new_digest[:12]} (privileged change: gate-5 ceremony marker required)",
        ],
        as_json=args.json,
    )
    return 0


def _add_site_selector_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--site-dir", dest="site_dir", help="explicit site-private directory holding plugins.toml and plugins/keyring/")
    p.add_argument("--plugins-config", dest="plugins_config", help="explicit path to site-private plugins.toml")
    p.add_argument("--ops-root", dest="ops_root", help="ops workspace root (default $TENDCF_OPS_ROOT or ~/tendcf-ops)")
    p.add_argument("--site-name", dest="site_name", help="site slug inside the ops workspace")
    p.add_argument("--workspace", action="store_true", help="resolve site-private from the ops workspace")
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")


def register_plugin_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Attach the `tendcf plugin` command family to the root CLI parser."""
    p = sub.add_parser("plugin", help="manage site-private plugin pins and OpenPGP Web of Trust (#47)")
    psub = p.add_subparsers(dest="plugin_command", required=True)

    p_ls = psub.add_parser("ls", help="list available in-tree and site-pinned plugins")
    _add_site_selector_args(p_ls)
    p_ls.add_argument("--kind", choices=sorted(ALLOWED_SITE_PLUGIN_KINDS), help="filter by plugin kind")
    p_ls.set_defaults(func=_cmd_plugin_ls)

    p_ins = psub.add_parser("inspect", help="inspect one plugin pin or in-tree plugin")
    p_ins.add_argument("name", help="plugin name")
    _add_site_selector_args(p_ins)
    p_ins.add_argument("--kind", choices=["frontend", "importer", "supervisor"])
    p_ins.set_defaults(func=_cmd_plugin_inspect)

    p_add = psub.add_parser("add", help="verify and pin an in-tree, contrib, or signed out-of-tree plugin")
    _add_site_selector_args(p_add)
    p_add.add_argument("--in-tree", dest="in_tree", help="name of a built-in in-tree plugin to enable")
    p_add.add_argument("--contrib", help="name of an in-tree contrib/ plugin to enable")
    p_add.add_argument("--relpath", help="POSIX relative path under contrib/ (required with --contrib)")
    p_add.add_argument("--kind", choices=sorted(ALLOWED_SITE_PLUGIN_KINDS))
    p_add.add_argument("--manifest", help="path to plugin-release.json (out-of-tree)")
    p_add.add_argument("--sig", help="path to detached OpenPGP signature plugin-release.json.asc")
    p_add.add_argument("--wheel-dir", dest="wheel_dir", help="directory containing verified .whl files")
    p_add.add_argument("--plugin-env", dest="plugin_env", help="isolated plugin environment directory (never gate/signing env)")
    p_add.add_argument("--no-install", dest="no_install", action="store_true", help="pin in plugins.toml without staging plugin env")
    p_add.add_argument("--tendcf", help="tendcf checkout path (for contrib/ and isolation checks)")
    p_add.set_defaults(func=_cmd_plugin_add)

    p_upd = psub.add_parser("update", help="verify and upgrade a pinned out-of-tree plugin (anti-rollback & anti-freeze)")
    p_upd.add_argument("name", help="pinned out-of-tree plugin name to upgrade")
    _add_site_selector_args(p_upd)
    p_upd.add_argument("--manifest", required=True, help="path to new plugin-release.json")
    p_upd.add_argument("--sig", required=True, help="path to detached OpenPGP signature plugin-release.json.asc")
    p_upd.add_argument("--wheel-dir", dest="wheel_dir", required=True, help="directory containing new .whl files")
    p_upd.add_argument("--plugin-env", dest="plugin_env", help="isolated plugin environment directory")
    p_upd.add_argument("--no-install", dest="no_install", action="store_true", help="update plugins.toml without staging env")
    p_upd.add_argument("--tendcf", help="tendcf checkout path")
    p_upd.set_defaults(func=_cmd_plugin_update)

    p_rm = psub.add_parser("remove", help="unpin a plugin from site-private plugins.toml")
    p_rm.add_argument("name", help="plugin name to remove")
    _add_site_selector_args(p_rm)
    p_rm.add_argument("--kind", choices=sorted(ALLOWED_SITE_PLUGIN_KINDS))
    p_rm.add_argument("--plugin-env", dest="plugin_env", help="optional isolated plugin env to re-stage without the removed plugin")
    p_rm.add_argument("--tendcf", help="tendcf checkout path")
    p_rm.set_defaults(func=_cmd_plugin_remove)

    p_ver = psub.add_parser("verify", help="verify plugins.toml, keyring, revocations, wheels, and isolated env")
    _add_site_selector_args(p_ver)
    p_ver.add_argument("--name", help="verify one named plugin only")
    p_ver.add_argument("--manifest", help="optional plugin-release.json to verify against WoT")
    p_ver.add_argument("--sig", help="detached .asc signature for --manifest")
    p_ver.add_argument("--wheel-dir", dest="wheel_dir", help="verify wheel SHA-256/RECORD/closure in this dir")
    p_ver.add_argument("--plugin-env", dest="plugin_env", help="verify staged isolated plugin environment")
    p_ver.add_argument("--check-releasable", dest="check_releasable", action="store_true", help="refuse any unpinned dist in --plugin-env")
    p_ver.add_argument("--historical", action="store_true", help="historical rebuild verification (permits soft-revoked keys before revoked_at)")
    p_ver.add_argument("--as-of", dest="as_of", help="RFC 3339 UTC timestamp for --historical verification")
    p_ver.add_argument("--tendcf", help="tendcf checkout path")
    p_ver.set_defaults(func=_cmd_plugin_verify)

    p_tr = psub.add_parser("trust", help="manage offline OpenPGP Web-of-Trust anchors and revocations in site-private")
    tsub = p_tr.add_subparsers(dest="trust_command", required=True)

    t_ls = tsub.add_parser("ls", help="list trust policy, anchors, and revocations")
    _add_site_selector_args(t_ls)
    t_ls.set_defaults(func=_cmd_plugin_trust_ls)

    t_add = tsub.add_parser("add-anchor", help="import an OpenPGP public key into site-private keyring as a trust anchor")
    _add_site_selector_args(t_add)
    t_add.add_argument("--key", required=True, help="path to armored/binary OpenPGP public key file")
    t_add.add_argument("--label", required=True, help="human label for the trust anchor")
    t_add.add_argument("--role", choices=sorted(ALLOWED_ANCHOR_ROLES), default="root", help="'root' (anchor + introducer) or 'direct' (signer only)")
    t_add.add_argument("--filename", help="optional filename inside keyring_dir")
    t_add.set_defaults(func=_cmd_plugin_trust_add_anchor)

    t_rm = tsub.add_parser("remove-anchor", help="remove a trust anchor fingerprint from plugins.toml")
    t_rm.add_argument("fingerprint", help="40-hex or 64-hex primary fingerprint")
    _add_site_selector_args(t_rm)
    t_rm.set_defaults(func=_cmd_plugin_trust_remove_anchor)

    t_rev = tsub.add_parser("revoke", help="record a soft or hard key revocation in plugins.toml")
    t_rev.add_argument("fingerprint", help="40-hex or 64-hex primary fingerprint to revoke")
    _add_site_selector_args(t_rev)
    t_rev.add_argument("--mode", required=True, choices=sorted(ALLOWED_REVOCATION_MODES), help="'soft' (allows pre-revocation historical rebuilds) or 'hard' (blocks all)")
    t_rev.add_argument("--reason", required=True, help="revocation reason")
    t_rev.add_argument("--revoked-at", dest="revoked_at", help="RFC 3339 UTC timestamp (default: now)")
    t_rev.add_argument("--cert", help="optional OpenPGP revocation certificate file to store in keyring_dir")
    t_rev.set_defaults(func=_cmd_plugin_trust_revoke)
