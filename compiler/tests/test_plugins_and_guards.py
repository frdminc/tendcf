"""Tests for D46 Step 4: static in-tree plugin loader, restricted Nix eval,
--check-releasable TENDCF_DIR/--tendcf guard, tendcf compile CLI,
load_projector/Schemas containment, and current-schema-version-only enforcement.
"""

from __future__ import annotations

import json
import os
import shutil
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
    clear_plugin_cache,
    get_plugin_spec,
    in_tree_tendcf_root,
    list_plugins,
    load_plugin,
    resolve_plugin_path,
)
from tendcf.sitemodel import Schemas, SiteModelError, load_document, load_site_model

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


# --- static in-tree plugin table & containment proofs (D-a / Smaller 5 / M1 / L1) ---


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
        assert mod.PLUGIN_NAME == spec.name

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


def _plant_plugin_tree(root: Path) -> Path:
    for spec in list_plugins():
        p = root / spec.relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            f"PLUGIN_KIND = {spec.kind!r}\nPLUGIN_NAME = {spec.name!r}\nSENTINEL = True\n",
            encoding="utf-8",
        )
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


def test_plugin_loader_ignores_pycache_verifies_metadata_and_reraises_base_exceptions(tmp_path: Path) -> None:
    # M1: Poisoned __pycache__/.pyc must NEVER be executed; source is compiled directly from fd.
    root = _plant_plugin_tree(tmp_path / "pyc-root")
    leaf = root / STATIC_PLUGIN_TABLE["frontend"]["yaml"].relpath
    pycache = leaf.parent / "__pycache__"
    pycache.mkdir()
    (pycache / f"loader.{sys.implementation.cache_tag}.pyc").write_bytes(b"NOT_VALID_PYC_POISON")
    mod = load_plugin("frontend", "yaml", tendcf_root=root)
    assert mod.SENTINEL is True

    # L1: Mismatched PLUGIN_KIND / PLUGIN_NAME is refused cleanly.
    bad_meta = _plant_plugin_tree(tmp_path / "bad-meta")
    bad_leaf = bad_meta / STATIC_PLUGIN_TABLE["frontend"]["yaml"].relpath
    bad_leaf.write_text("PLUGIN_KIND = 'frontend'\nPLUGIN_NAME = 'impostor'\n", encoding="utf-8")
    with pytest.raises(PluginError, match="declared PLUGIN_KIND"):
        load_plugin("frontend", "yaml", tendcf_root=bad_meta)

    # M1: SystemExit / KeyboardInterrupt are NOT swallowed into PluginError.
    exit_root = _plant_plugin_tree(tmp_path / "sys-exit")
    exit_leaf = exit_root / STATIC_PLUGIN_TABLE["frontend"]["yaml"].relpath
    exit_leaf.write_text("raise SystemExit(42)\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc_info:
        load_plugin("frontend", "yaml", tendcf_root=exit_root)
    assert exc_info.value.code == 42


# --- H2: Lazy plugin load, non-in-tree CLI survival, and single SiteModelError identity ---


def test_non_in_tree_package_runs_version_and_refuses_check_releasable_cleanly(tmp_path: Path) -> None:
    # Copy compiler/tendcf into an isolated site-packages dir with NO checkout around it.
    site_pkgs = tmp_path / "site-packages"
    shutil.copytree(REPO / "tendcf", site_pkgs / "tendcf")
    env = {k: v for k, v in os.environ.items() if k != "TENDCF_DIR"}
    env["PYTHONPATH"] = str(site_pkgs)

    # --version must work without loading any plugin (run from tmp_path so CWD
    # does not shadow site_pkgs with the editable checkout).
    ver = subprocess.run(
        [sys.executable, "-m", "tendcf.cli", "--version"],
        cwd=tmp_path,
        capture_output=True,
        env=env,
        check=False,
    )
    assert ver.returncode == 0, ver.stderr.decode()
    assert ver.stdout.decode().strip().startswith("tendcf ")

    # --check-releasable outside a verified checkout must exit 1 with REFUSED (not traceback!).
    rel = subprocess.run(
        [sys.executable, "-m", "tendcf.cli", *_compile_args(SITE, "--check-releasable")],
        cwd=tmp_path,
        capture_output=True,
        env=env,
        check=False,
    )
    assert rel.returncode == 1
    assert b"REFUSED:" in rel.stderr and b"Traceback" not in rel.stderr

    # Codex P2: in dev mode outside a checkout, explicit --tendcf or TENDCF_DIR
    # supplies both schemas and verified plugins cleanly!
    dev_flag = subprocess.run(
        [sys.executable, "-m", "tendcf.cli", *_compile_args(SITE, "--tendcf", str(TENDCF_ROOT))],
        cwd=tmp_path,
        capture_output=True,
        env=env,
        check=False,
    )
    assert dev_flag.returncode == 0, dev_flag.stderr.decode()

    dev_env = subprocess.run(
        [sys.executable, "-m", "tendcf.cli", *_compile_args(SITE)],
        cwd=tmp_path,
        capture_output=True,
        env=dict(env, TENDCF_DIR=str(TENDCF_ROOT)),
        check=False,
    )
    assert dev_env.returncode == 0, dev_env.stderr.decode()

    # Symlinked plugins/ inside explicit --tendcf still fails closed!
    bad_checkout = tmp_path / "bad-checkout"
    bad_checkout.mkdir()
    shutil.copytree(TENDCF_ROOT / "schema", bad_checkout / "schema")
    (bad_checkout / "plugins").symlink_to(TENDCF_ROOT / "plugins")
    bad_dev = subprocess.run(
        [sys.executable, "-m", "tendcf.cli", *_compile_args(SITE, "--tendcf", str(bad_checkout))],
        cwd=tmp_path,
        capture_output=True,
        env=env,
        check=False,
    )
    assert bad_dev.returncode == 2
    assert b"real non-symlink directory" in bad_dev.stderr


def test_clear_plugin_cache_preserves_sitemodel_error_identity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # H2: clear_plugin_cache() before cmd_compile on malformed YAML must exit 2 cleanly (no traceback).
    site = tmp_path / "bad-yaml-site"
    shutil.copytree(SITE, site)
    (site / "services.yml").write_text("contract_version: 1\ncontract_version: 2\n", encoding="utf-8")

    clear_plugin_cache()
    rc = cli.main(_compile_args(site))
    err = capsys.readouterr().err
    assert rc == 2
    assert "duplicate key" in err


# --- H3 + M2: load_projector and Schemas containment proofs ---


def test_load_projector_refuses_symlinked_root_tools_and_leaf(tmp_path: Path) -> None:
    outside = tmp_path / "outside-tools"
    outside.mkdir()
    (outside / "projector.py").write_text(
        "raise AssertionError('ESCAPED_PROJECTOR_MUST_NEVER_EXECUTE')\n", encoding="utf-8"
    )

    # 1. Symlinked tools/ directory inside real root -> refused.
    r1 = tmp_path / "sym-tools-root"
    r1.mkdir()
    (r1 / "tools").symlink_to(outside)
    with pytest.raises(SiteModelError, match="tools directory must be a real non-symlink"):
        cli.load_projector(r1)

    # 2. Symlinked root itself -> refused.
    r2_real = tmp_path / "real-root"
    (r2_real / "tools").mkdir(parents=True)
    (r2_real / "tools" / "projector.py").write_text("X = 1\n", encoding="utf-8")
    r2_link = tmp_path / "sym-root"
    r2_link.symlink_to(r2_real)
    with pytest.raises(SiteModelError, match="tendcf checkout must be a real non-symlink"):
        cli.load_projector(r2_link)

    # 3. Symlinked tools/projector.py leaf -> refused.
    r3 = tmp_path / "sym-leaf-root"
    (r3 / "tools").mkdir(parents=True)
    (r3 / "tools" / "projector.py").symlink_to(outside / "projector.py")
    with pytest.raises(SiteModelError, match="regular non-symlink file"):
        cli.load_projector(r3)


def test_schemas_refuses_symlinked_schema_dir_and_schema_files(tmp_path: Path) -> None:
    real_schemas = TENDCF_ROOT / "schema"

    # 1. Symlinked schema directory -> refused.
    sym_dir = tmp_path / "sym-schema"
    sym_dir.symlink_to(real_schemas)
    with pytest.raises(SiteModelError, match="real non-symlink directory"):
        Schemas(sym_dir)

    # 2. Symlinked schema file inside real schema directory -> refused.
    dir_with_link = tmp_path / "schema-with-link"
    shutil.copytree(real_schemas, dir_with_link)
    target_schema = dir_with_link / "services.schema.json"
    target_schema.unlink()
    target_schema.symlink_to(real_schemas / "services.schema.json")
    with pytest.raises(SiteModelError, match="real non-symlink regular file"):
        Schemas(dir_with_link)


# --- Nix frontend D-b restricted evaluation & H1 hardening (`plugins/frontends/nix/eval.py`) ---


def test_nix_frontend_builds_exact_restricted_argv_and_isolated_env(tmp_path: Path) -> None:
    nix_plugin = load_plugin("frontend", "nix")
    assert nix_plugin.PLUGIN_NAME == "nix"
    assert nix_plugin.FRONTEND_DISPLAY_NAME == "nix2cf"

    recipe_dir = tmp_path / "recipe"
    recipe_dir.mkdir()
    recipe = recipe_dir / "site.nix"
    recipe.write_text("{ ok = true; }\n", encoding="utf-8")

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


def test_nix_frontend_h1_hardening_empty_dir_delimiters_symlinks_and_timeout(tmp_path: Path) -> None:
    nix_plugin = load_plugin("frontend", "nix")
    never_run = tmp_path / "never-run"
    never_run.write_text("#!/bin/sh\necho SHOULD_NOT_RUN >&2\nexit 99\n", encoding="utf-8")
    never_run.chmod(stat.S_IRWXU)

    # 1. CLI --recipe-dir "" must exit 2 (never silently become Path(".") / CWD).
    clean_env = {k: v for k, v in os.environ.items() if k != "TENDCF_DIR"}
    empty_dir_cli = _run_cli(["eval-nix", "--recipe-dir", "", str(SITE / "site.nix")], env=clean_env)
    assert empty_dir_cli.returncode == 2
    assert b"--recipe-dir must not be empty" in empty_dir_cli.stderr
    empty_file_cli = _run_cli(["eval-nix", ""], env=clean_env)
    assert empty_file_cli.returncode == 2
    assert b"must not be empty" in empty_file_cli.stderr

    # 2. '=' and ':' in allowed_dir refused before launching nix-instantiate (-I injection).
    for bad_dirname in ("x=y", "a:b"):
        bad_dir = tmp_path / bad_dirname
        bad_dir.mkdir()
        bad_file = bad_dir / "site.nix"
        bad_file.write_text("{ ok = 1; }\n", encoding="utf-8")
        with pytest.raises(nix_plugin.NixEvalError, match="contains '=' or ':'"):
            nix_plugin.eval_nix_file(bad_file, nix_instantiate=str(never_run))

    # 3. Symlinked --recipe-dir refused.
    real_dir = tmp_path / "real-recipe"
    real_dir.mkdir()
    real_file = real_dir / "site.nix"
    real_file.write_text("{ ok = 1; }\n", encoding="utf-8")
    sym_dir = tmp_path / "sym-recipe"
    sym_dir.symlink_to(real_dir)
    with pytest.raises(nix_plugin.NixEvalError, match="real non-symlink directory"):
        nix_plugin.eval_nix_file(real_file, recipe_dir=sym_dir, nix_instantiate=str(never_run))

    # 4. Symlinked parent directory when recipe_dir is omitted refused.
    with pytest.raises(nix_plugin.NixEvalError, match="parent directory must not be a symlink"):
        nix_plugin.eval_nix_file(sym_dir / "site.nix", nix_instantiate=str(never_run))

    # 5. Symlinked intermediate subdirectory under explicit recipe_dir refused.
    outer = tmp_path / "outer-recipe"
    outer.mkdir()
    (outer / "sub_link").symlink_to(real_dir)
    with pytest.raises(nix_plugin.NixEvalError, match="symlinked directory"):
        nix_plugin.eval_nix_file(
            outer / "sub_link" / "site.nix",
            recipe_dir=outer,
            nix_instantiate=str(never_run),
        )

    # 6. Symlinked leaf recipe file refused.
    outside = tmp_path / "outside.nix"
    outside.write_text("{ secret = 1; }\n", encoding="utf-8")
    escape = real_dir / "escape.nix"
    escape.symlink_to(outside)
    with pytest.raises(nix_plugin.NixEvalError, match="regular non-symlink file"):
        nix_plugin.eval_nix_file(escape, nix_instantiate=str(never_run))

    # 7. Duplicate JSON key in nix-instantiate output refused (no last-wins).
    dup_nix = tmp_path / "dup-nix"
    dup_nix.write_text('#!/bin/sh\nprintf \'{"a": 1, "a": 2}\\n\'\n', encoding="utf-8")
    dup_nix.chmod(stat.S_IRWXU)
    with pytest.raises(nix_plugin.NixEvalError, match="duplicate JSON key"):
        nix_plugin.eval_nix_file(real_file, nix_instantiate=str(dup_nix))

    # 8. Timeout converts cleanly to NixEvalError; NaN/bool/non-positive timeouts refused.
    for bad_timeout in (0, -1.0, float("nan"), float("inf"), True):
        with pytest.raises(nix_plugin.NixEvalError, match="positive finite number"):
            nix_plugin.eval_nix_file(real_file, nix_instantiate=str(never_run), timeout=bad_timeout)  # type: ignore[arg-type]

    # 9. '..' traversal segments in recipe path or recipe_dir refused before resolving.
    with pytest.raises(nix_plugin.NixEvalError, match="traversal segments"):
        nix_plugin.eval_nix_file(sym_dir / ".." / "real-recipe" / "site.nix", nix_instantiate=str(never_run))

    slow_nix = tmp_path / "slow-nix"
    slow_nix.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(5)\n", encoding="utf-8")
    slow_nix.chmod(stat.S_IRWXU)
    with pytest.raises(nix_plugin.NixEvalError, match="timed out"):
        nix_plugin.eval_nix_file(real_file, nix_instantiate=str(slow_nix), timeout=0.1)


# --- --check-releasable F9 guard (refuses --tendcf and $TENDCF_DIR on compile & workspace) ---


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

    # M2 parity: `tendcf workspace --check-releasable` also refuses ambient TENDCF_DIR.
    ops = tmp_path / "ops-ws"
    (ops / "tendcf-private-alice").mkdir(parents=True)
    ws_env = dict(clean_env, TENDCF_DIR=str(TENDCF_ROOT))
    ws_refused = _run_cli(
        ["workspace", "--ops-root", str(ops), "--site-name", "alice", "--check-releasable"],
        env=ws_env,
    )
    assert ws_refused.returncode == 1
    assert b"REFUSED:" in ws_refused.stderr and b"TENDCF_DIR" in ws_refused.stderr


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
