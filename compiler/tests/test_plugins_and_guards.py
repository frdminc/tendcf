"""Tests for D46 Step 4: static in-tree plugin loader, restricted Nix eval,
--check-releasable TENDCF_DIR/--tendcf guard, tendcf compile CLI, and
current-schema-version-only enforcement.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tendcf import cli, plugins
from tendcf.compile import GOAL_FILE_SCHEMA_VERSION, CompileError, HostSpec, compile_host, render_goal_file
from tendcf.plugins import (
    RESERVED_PLUGIN_NAMES,
    STATIC_PLUGIN_TABLE,
    PluginError,
    get_plugin_spec,
    in_tree_tendcf_root,
    list_plugins,
    load_plugin,
    resolve_plugin_path,
)
from tendcf.sitemodel import load_document, load_site_model

REPO = Path(__file__).resolve().parent.parent
TENDCF_ROOT = REPO.parent
SITE = REPO / "examples" / "site"
HOST_KEY = "ed25519:" + "a1" * 32


def _run_cli(args: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    run_env = {k: v for k, v in (os.environ if env is None else env).items()}
    run_env["PYTHONPATH"] = str(REPO)
    return subprocess.run(
        [sys.executable, "-m", "tendcf.cli", *args],
        capture_output=True,
        env=run_env,
        check=False,
    )


def _compile_args(site: Path, *extra: str) -> list[str]:
    return [
        "compile",
        "--host", "mac",
        "--platform", "macos",
        "--supervisor", "launchd",
        "--host-key", HOST_KEY,
        "--device-trust", str(site / "device-trust.json"),
        "--site", str(site),
        *extra,
    ]


# --- static in-tree plugin table & containment proofs (D-a / Smaller 5) ---


def test_static_plugin_table_resolves_and_loads_all_builtins() -> None:
    root = in_tree_tendcf_root()
    assert root == TENDCF_ROOT
    all_specs = list_plugins()
    assert {(s.kind, s.name) for s in all_specs} == {
        ("frontend", "yaml"),
        ("frontend", "nix"),
        ("supervisor", "launchd"),
        ("supervisor", "systemd"),
        ("supervisor", "runit"),
    }
    assert list_plugins("importer") == ()
    assert "nix2cf" in RESERVED_PLUGIN_NAMES["frontend"]

    for spec in all_specs:
        found_spec, path = resolve_plugin_path(spec.kind, spec.name)
        assert found_spec == spec
        assert path.is_relative_to(TENDCF_ROOT / "plugins")
        assert path.is_file() and not path.is_symlink()
        mod = load_plugin(spec.kind, spec.name)
        assert mod.PLUGIN_KIND == spec.kind

    assert load_plugin("supervisor", "launchd").RENDERED is True
    assert load_plugin("supervisor", "systemd").RENDERED is False
    assert load_plugin("supervisor", "runit").RENDERED is False


def test_static_plugin_table_refuses_unknown_kind_or_name() -> None:
    with pytest.raises(PluginError, match="unknown plugin kind"):
        get_plugin_spec("exporter", "yaml")
    with pytest.raises(PluginError, match="unknown in-tree frontend plugin"):
        get_plugin_spec("frontend", "nonexistent")
    with pytest.raises(PluginError, match="non-empty string"):
        get_plugin_spec("frontend", "")
    with pytest.raises(PluginError, match="unknown in-tree importer plugin"):
        load_plugin("importer", "ansible")


def _plant_plugin_tree(root: Path, *, payload: str = "PLUGIN_KIND = 'frontend'\nSENTINEL = True\n") -> Path:
    for spec in list_plugins():
        p = root / spec.relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(payload, encoding="utf-8")
    return root


def test_plugin_loader_refuses_symlinks_and_outside_tree_before_exec(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("raise AssertionError('ESCAPING_PLUGIN_MUST_NEVER_EXECUTE')\n", encoding="utf-8")

    # 1. Leaf symlink escaping plugins/ -> refused before exec.
    r1 = _plant_plugin_tree(tmp_path / "r1")
    leaf = r1 / STATIC_PLUGIN_TABLE["frontend"]["yaml"].relpath
    leaf.unlink()
    leaf.symlink_to(outside)
    with pytest.raises(PluginError, match="is a symlink"):
        load_plugin("frontend", "yaml", tendcf_root=r1)

    # 2. Internal symlink inside plugins/ -> also refused (must be real in-tree file).
    r2 = _plant_plugin_tree(tmp_path / "r2")
    internal_target = r2 / "plugins" / "frontends" / "yaml" / "real.py"
    internal_target.write_text("raise AssertionError('SYMLINK_MUST_NEVER_EXECUTE')\n", encoding="utf-8")
    leaf2 = r2 / STATIC_PLUGIN_TABLE["frontend"]["yaml"].relpath
    leaf2.unlink()
    leaf2.symlink_to(internal_target)
    with pytest.raises(PluginError, match="is a symlink"):
        load_plugin("frontend", "yaml", tendcf_root=r2)

    # 3. Symlinked intermediate directory (`plugins/frontends`) -> refused.
    r3 = tmp_path / "r3"
    (r3 / "plugins").mkdir(parents=True)
    ext_frontends = tmp_path / "ext-frontends"
    (ext_frontends / "yaml").mkdir(parents=True)
    (ext_frontends / "yaml" / "loader.py").write_text(
        "raise AssertionError('EXT_DIR_MUST_NEVER_EXECUTE')\n", encoding="utf-8"
    )
    (r3 / "plugins" / "frontends").symlink_to(ext_frontends)
    with pytest.raises(PluginError, match="is a symlink"):
        load_plugin("frontend", "yaml", tendcf_root=r3)

    # 4. Symlinked top-level `plugins/` -> refused.
    r4 = tmp_path / "r4"
    r4.mkdir()
    ext_plugins = _plant_plugin_tree(tmp_path / "ext-root") / "plugins"
    (r4 / "plugins").symlink_to(ext_plugins)
    with pytest.raises(PluginError, match="real non-symlink directory"):
        load_plugin("frontend", "yaml", tendcf_root=r4)

    # 5. Symlinked tendcf_root itself -> refused.
    r5_real = _plant_plugin_tree(tmp_path / "r5-real")
    r5_link = tmp_path / "r5-link"
    r5_link.symlink_to(r5_real)
    with pytest.raises(PluginError, match="real non-symlink directory"):
        load_plugin("frontend", "yaml", tendcf_root=r5_link)

    # 6. Directory where leaf .py is expected -> refused.
    r6 = _plant_plugin_tree(tmp_path / "r6")
    leaf6 = r6 / STATIC_PLUGIN_TABLE["frontend"]["yaml"].relpath
    leaf6.unlink()
    leaf6.mkdir()
    with pytest.raises(PluginError, match="not a regular file"):
        load_plugin("frontend", "yaml", tendcf_root=r6)


# --- Nix frontend D-b restricted evaluation (`plugins/frontends/nix/eval.py`) ---


def test_nix_frontend_builds_exact_restricted_argv_and_isolated_env(tmp_path: Path) -> None:
    nix_plugin = load_plugin("frontend", "nix")
    assert nix_plugin.PLUGIN_NAME == "nix2cf"

    recipe_dir = tmp_path / "recipe"
    recipe_dir.mkdir()
    recipe = recipe_dir / "site.nix"
    recipe.write_text("{ ok = true; }\n", encoding="utf-8")

    # Fake nix-instantiate that dumps its argv and Nix env vars as JSON.
    fake_nix = tmp_path / "fake-nix-instantiate"
    fake_nix.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "conf_dir = os.environ.get('NIX_CONF_DIR', '')\n"
        "user_conf = os.environ.get('NIX_USER_CONF_FILES', '')\n"
        "payload = {\n"
        "    'argv': sys.argv[1:],\n"
        "    'nix_path': os.environ.get('NIX_PATH'),\n"
        "    'nix_config_present': 'NIX_CONFIG' in os.environ,\n"
        "    'conf_dir_is_empty_dir': os.path.isdir(conf_dir) and os.listdir(conf_dir) == [],\n"
        "    'user_conf_is_empty_file': os.path.isfile(user_conf) and os.path.getsize(user_conf) == 0,\n"
        "}\n"
        "print(json.dumps(payload))\n",
        encoding="utf-8",
    )
    fake_nix.chmod(stat.S_IRWXU)

    result = nix_plugin.eval_nix_file(
        recipe,
        nix_instantiate=str(fake_nix),
        env={
            "PATH": os.environ.get("PATH", ""),
            "NIX_PATH": "nixpkgs=/should/be/cleared",
            "NIX_CONFIG": "restrict-eval = false",
            "NIX_CONF_DIR": "/etc/nix",
            "NIX_USER_CONF_FILES": "/etc/nix/nix.conf",
        },
    )

    argv = result["argv"]
    assert argv == [
        "--eval",
        "--strict",
        "--json",
        "--option", "restrict-eval", "true",
        "--option", "allow-import-from-derivation", "false",
        "--option", "allowed-uris", "",
        "--option", "allow-unsafe-native-code-during-evaluation", "false",
        "-I", str(recipe_dir.resolve()),
        str(recipe.resolve()),
    ]
    assert "--impure" not in argv
    assert "--read-write-mode" not in argv
    assert result["nix_path"] == ""
    assert result["nix_config_present"] is False
    assert result["conf_dir_is_empty_dir"] is True
    assert result["user_conf_is_empty_file"] is True


def test_nix_frontend_refuses_symlink_escape_and_duplicate_json_keys(tmp_path: Path) -> None:
    nix_plugin = load_plugin("frontend", "nix")

    # 1. Symlink recipe escaping allowed directory is refused before invoking nix-instantiate.
    outside = tmp_path / "outside.nix"
    outside.write_text("{ secret = 1; }\n", encoding="utf-8")
    recipe_dir = tmp_path / "recipe"
    recipe_dir.mkdir()
    escape = recipe_dir / "escape.nix"
    escape.symlink_to(outside)

    never_run = tmp_path / "never-run"
    never_run.write_text("#!/bin/sh\necho SHOULD_NOT_RUN >&2\nexit 99\n", encoding="utf-8")
    never_run.chmod(stat.S_IRWXU)

    with pytest.raises(nix_plugin.NixEvalError, match="outside allowed directory"):
        nix_plugin.eval_nix_file(escape, nix_instantiate=str(never_run))

    # 2. Duplicate JSON key in nix-instantiate output is refused (no last-wins).
    good = recipe_dir / "good.nix"
    good.write_text("{ a = 1; }\n", encoding="utf-8")
    dup_nix = tmp_path / "dup-nix"
    dup_nix.write_text('#!/bin/sh\nprintf \'{"a": 1, "a": 2}\\n\'\n', encoding="utf-8")
    dup_nix.chmod(stat.S_IRWXU)

    with pytest.raises(nix_plugin.NixEvalError, match="duplicate JSON key"):
        nix_plugin.eval_nix_file(good, nix_instantiate=str(dup_nix))


# --- --check-releasable F9 guard (refuses --tendcf and $TENDCF_DIR) ---


def test_check_releasable_refuses_tendcf_flag_and_env_override(tmp_path: Path) -> None:
    clean_env = {k: v for k, v in os.environ.items() if k != "TENDCF_DIR"}

    # Clean in-tree release check succeeds with exit 0.
    ok = _run_cli(_compile_args(SITE, "--check-releasable"), env=clean_env)
    assert ok.returncode == 0, ok.stderr.decode()

    # Passing --tendcf (even pointing at the real checkout) is refused in release mode.
    flag_refused = _run_cli(
        _compile_args(SITE, "--check-releasable", "--tendcf", str(TENDCF_ROOT)),
        env=clean_env,
    )
    assert flag_refused.returncode == 1
    assert b"REFUSED:" in flag_refused.stderr and b"--tendcf" in flag_refused.stderr
    assert flag_refused.stdout == b""

    # Setting TENDCF_DIR (even to the real checkout OR empty string) is refused in release mode.
    for env_val in (str(TENDCF_ROOT), str(tmp_path), ""):
        env_with_var = dict(clean_env, TENDCF_DIR=env_val)
        env_refused = _run_cli(_compile_args(SITE, "--check-releasable"), env=env_with_var)
        assert env_refused.returncode == 1
        assert b"REFUSED:" in env_refused.stderr and b"TENDCF_DIR" in env_refused.stderr
        assert env_refused.stdout == b""


def test_check_releasable_refuses_when_not_in_verified_checkout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("TENDCF_DIR", raising=False)
    monkeypatch.setattr(cli, "_in_tree_tendcf", lambda: None)
    rc = cli.main(_compile_args(SITE, "--check-releasable"))
    err = capsys.readouterr().err
    assert rc == 1
    assert "REFUSED:" in err and "verified in-tree tendcf checkout" in err


# --- CLI rename: tendcf compile replaces buildfile outright (no alias) ---


def test_buildfile_subcommand_removed_without_alias() -> None:
    clean_env = {k: v for k, v in os.environ.items() if k != "TENDCF_DIR"}
    proc = _run_cli(["buildfile", "--host", "mac"], env=clean_env)
    assert proc.returncode == 2
    assert b"invalid choice" in proc.stderr and proc.stdout == b""

    ver = _run_cli(["--version"], env=clean_env)
    assert ver.returncode == 0
    assert ver.stdout.decode().strip().startswith("tendcf ")


# --- Current schema_version only (older-version rendering removed) ---


@pytest.mark.parametrize("bad_version", [1, 2, 3, 4, 5, 6, 7, 8, 10, True])
def test_non_current_schema_versions_refused(bad_version: int) -> None:
    model = load_site_model(SITE / "services.yml", SITE / "roles.yml", SITE / "launchd-writers.yml")
    host = HostSpec(
        name="mac",
        platform="macos",
        supervisor="launchd",
        key=HOST_KEY,
        device_trust=load_document(SITE / "device-trust.json").data,
    )
    with pytest.raises(CompileError, match=f"only current schema_version {GOAL_FILE_SCHEMA_VERSION}"):
        compile_host(model, host, None, schema_version=bad_version)

    doc, errs = render_goal_file(model, host, [], schema_version=bad_version)
    assert doc == {}
    assert any(f"only current schema_version {GOAL_FILE_SCHEMA_VERSION}" in e for e in errs)
