"""Tests for multi-site local ops workspace resolution and CLI (issue #98)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tendcf.compile import CompileError, HostSpec, compile_host
from tendcf.sitemodel import Schemas, load_document, load_site_model
from tendcf.workspace import (
    OverrideInput,
    WorkspaceError,
    _expand_path,
    active_site_config_path,
    cache_dir,
    is_tendcf_checkout,
    list_sites,
    parse_override_inputs,
    refuse_release_if_tainted,
    resolve_ops_root,
    resolve_site_input_dir,
    resolve_site_slug,
    resolve_workspace,
    state_dir,
    validate_override_namespace,
    validate_site_slug,
)

REPO = Path(__file__).resolve().parent.parent
SITE = REPO / "examples" / "site"
HOST_KEY = "ed25519:" + "a1" * 32


def _tendcf_root() -> Path:
    raw = os.environ.get("TENDCF_DIR")
    candidates = [Path(raw).expanduser()] if raw else []
    candidates.append(REPO.parent)
    for c in candidates:
        if (c / "schema" / "goal-file.schema.json").exists():
            return c
    pytest.skip("no tendcf checkout available")


def _clean_env(tmp_path: Path, **extra: str) -> dict[str, str]:
    """Hermetic subprocess environment free of the operator's TENDCF_*/XDG_* vars."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"TENDCF_DIR", "TENDCF_OPS_ROOT", "TENDCF_SITE", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"}
    }
    env["HOME"] = str(home)
    env["PYTHONPATH"] = str(REPO)
    env.update(extra)
    return env


def _run_cli(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "tendcf.cli", *args],
        capture_output=True,
        env=env,
        check=False,
    )


def _plant_site(ops_root: Path, slug: str, *, with_public: bool = False, in_subdir: bool = False) -> Path:
    priv = ops_root / f"tendcf-private-{slug}"
    target = priv / "site" if in_subdir else priv
    target.mkdir(parents=True, exist_ok=True)
    for name in ("services.yml", "roles.yml", "launchd-writers.yml", "device-trust.json"):
        shutil.copy2(SITE / name, target / name)
    if with_public:
        (ops_root / f"tendcf-public-{slug}").mkdir(exist_ok=True)
    return priv


def _plant_tendcf_checkout(root: Path) -> Path:
    (root / "schema").mkdir(parents=True, exist_ok=True)
    (root / "schema" / "goal-file.schema.json").write_text("{}", encoding="utf-8")
    (root / "tools").mkdir(parents=True, exist_ok=True)
    (root / "tools" / "projector.py").write_text("", encoding="utf-8")
    return root


# --- slug & namespace grammar ------------------------------------------------


@pytest.mark.parametrize("slug", ["a", "djbclark", "dann", "djbclark-lab", "alice-home", "op1-dev2", "a" * 64])
def test_validate_site_slug_accepts_valid(slug: str) -> None:
    assert validate_site_slug(slug) == slug


@pytest.mark.parametrize(
    "bad",
    [
        "",
        " ",
        "Djbclark",
        "1site",
        "-site",
        "site-",
        "djbclark--lab",
        "djbclark_lab",
        "djbclark.lab",
        "a/b",
        "../escape",
        "djbclark\n",
        "djbclark\x00",
        "a" * 65,
        "djbclark-wt",
        "lab-wt",
    ],
)
def test_validate_site_slug_rejects_invalid(bad: str) -> None:
    with pytest.raises(WorkspaceError):
        validate_site_slug(bad)


@pytest.mark.parametrize("bad_ns", ["", "Alice", "../alice", "a/b", "a.b", "a_b", "a--b", "a\n", "a" * 65])
def test_validate_override_namespace_rejects_invalid(bad_ns: str) -> None:
    with pytest.raises(WorkspaceError):
        validate_override_namespace(bad_ns)


# --- XDG directories ---------------------------------------------------------


def test_xdg_helpers_honor_absolute_and_ignore_relative(tmp_path: Path) -> None:
    home = tmp_path / "home"
    env_abs = {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(tmp_path / "cfg"),
        "XDG_STATE_HOME": str(tmp_path / "st"),
        "XDG_CACHE_HOME": str(tmp_path / "ca"),
    }
    assert active_site_config_path(env_abs) == tmp_path / "cfg" / "tendcf" / "active-site"
    assert state_dir(env_abs) == tmp_path / "st" / "tendcf"
    assert cache_dir(env_abs) == tmp_path / "ca" / "tendcf"

    # Per XDG Base Directory Spec, relative paths must be ignored.
    env_rel = {
        "HOME": str(home),
        "XDG_CONFIG_HOME": "relative/cfg",
        "XDG_STATE_HOME": "relative/st",
        "XDG_CACHE_HOME": "relative/ca",
    }
    assert active_site_config_path(env_rel) == home / ".config" / "tendcf" / "active-site"
    assert state_dir(env_rel) == home / ".local" / "state" / "tendcf"
    assert cache_dir(env_rel) == home / ".cache" / "tendcf"


# --- ops root resolution -----------------------------------------------------


def test_resolve_ops_root_precedence_and_validation(tmp_path: Path) -> None:
    home = tmp_path / "home"
    default_root = home / "tendcf-ops"
    env_root = tmp_path / "env-ops"
    cli_root = tmp_path / "cli-ops"
    for d in (default_root, env_root, cli_root):
        d.mkdir(parents=True)

    env = {"HOME": str(home), "TENDCF_OPS_ROOT": str(env_root)}
    assert resolve_ops_root(str(cli_root), env) == (cli_root.resolve(), "cli")
    assert resolve_ops_root(None, env) == (env_root.resolve(), "env:TENDCF_OPS_ROOT")
    assert resolve_ops_root(None, {"HOME": str(home)}) == (default_root.resolve(), "default")
    assert resolve_ops_root("~/tendcf-ops", {"HOME": str(home)}) == (default_root.resolve(), "cli")

    # Stage 2 bridge symlink at ops_root itself is allowed when pointing to a real dir.
    bridge = tmp_path / "bridge-ops"
    bridge.symlink_to(cli_root)
    assert resolve_ops_root(str(bridge), {"HOME": str(home)}) == (cli_root.resolve(), "cli")

    # Invalid ops roots fail closed.
    with pytest.raises(WorkspaceError, match="must not be empty"):
        resolve_ops_root("", {"HOME": str(home)})
    with pytest.raises(WorkspaceError, match="set but empty"):
        resolve_ops_root(None, {"HOME": str(home), "TENDCF_OPS_ROOT": ""})
    with pytest.raises(WorkspaceError, match="absolute path"):
        resolve_ops_root("relative/ops", {"HOME": str(home)})
    with pytest.raises(WorkspaceError, match="does not exist"):
        resolve_ops_root(str(tmp_path / "missing"), {"HOME": str(home)})
    not_dir = tmp_path / "file"
    not_dir.write_text("x", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="not a directory"):
        resolve_ops_root(str(not_dir), {"HOME": str(home)})
    dangling = tmp_path / "dangling-ops"
    dangling.symlink_to(tmp_path / "nowhere")
    with pytest.raises(WorkspaceError, match="dangling symlink"):
        resolve_ops_root(str(dangling), {"HOME": str(home)})


# --- selector precedence & active-site file safety ---------------------------


def test_resolve_site_slug_precedence_and_fail_closed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    cfg = tmp_path / "xdg" / "tendcf" / "active-site"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("# active site\n  alice-home  \n\n", encoding="utf-8")

    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(tmp_path / "xdg"), "TENDCF_SITE": "bob"}
    assert resolve_site_slug("djbclark", env) == ("djbclark", "cli")
    assert resolve_site_slug(None, env) == ("bob", "env:TENDCF_SITE")

    env_no_site = {"HOME": str(home), "XDG_CONFIG_HOME": str(tmp_path / "xdg")}
    assert resolve_site_slug(None, env_no_site) == ("alice-home", f"config:{cfg}")

    # Empty TENDCF_SITE fails closed rather than silently falling back to active-site.
    with pytest.raises(WorkspaceError, match="TENDCF_SITE is set but empty"):
        resolve_site_slug(None, {**env_no_site, "TENDCF_SITE": ""})

    # Missing config and no CLI/env fails closed (never guesses).
    with pytest.raises(WorkspaceError, match="no site selected"):
        resolve_site_slug(None, {"HOME": str(home), "XDG_CONFIG_HOME": str(tmp_path / "empty-xdg")})


def test_active_site_file_refuses_symlinks_multiline_and_empty(tmp_path: Path) -> None:
    real = tmp_path / "real-site"
    real.write_text("djbclark\n", encoding="utf-8")
    link = tmp_path / "link-site"
    link.symlink_to(real)
    with pytest.raises(WorkspaceError, match="must not be a symlink"):
        resolve_site_slug(None, {"HOME": str(tmp_path)}, config_path=link)

    multi = tmp_path / "multi-site"
    multi.write_text("djbclark\nalice\n", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="ambiguous"):
        resolve_site_slug(None, {"HOME": str(tmp_path)}, config_path=multi)

    empty = tmp_path / "empty-site"
    empty.write_text("# only comments\n\n", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="no site slug"):
        resolve_site_slug(None, {"HOME": str(tmp_path)}, config_path=empty)

    as_dir = tmp_path / "dir-site"
    as_dir.mkdir()
    with pytest.raises(WorkspaceError, match="regular file"):
        resolve_site_slug(None, {"HOME": str(tmp_path)}, config_path=as_dir)


# --- workspace pair resolution & adversarial guards --------------------------


def test_resolve_workspace_fail_closed_even_with_sole_checkout(tmp_path: Path) -> None:
    ops = tmp_path / "tendcf-ops"
    ops.mkdir()
    _plant_site(ops, "djbclark", with_public=True)
    # Also plant legacy names that must NEVER be read.
    (ops / "tendcf-private").mkdir()
    (ops / "site-private").mkdir()
    (ops / ".mysite").write_text("djbclark\n", encoding="utf-8")

    env = {"HOME": str(tmp_path / "home")}
    with pytest.raises(WorkspaceError, match="no site selected"):
        resolve_workspace(ops_root=ops, env=env)


def test_resolve_workspace_pair_bound_and_cross_site_isolation(tmp_path: Path) -> None:
    ops = tmp_path / "tendcf-ops"
    ops.mkdir()
    alice_priv = _plant_site(ops, "alice", with_public=False)
    (ops / "tendcf-public-bob").mkdir()  # another operator's public repo must NEVER pair with alice
    tendcf_dir = _plant_tendcf_checkout(ops / "tendcf")

    env = {"HOME": str(tmp_path / "home")}
    ws = resolve_workspace(ops_root=ops, site_name="alice", env=env)
    assert ws.ops_root == ops.resolve()
    assert ws.site_slug == "alice"
    assert ws.selection_source == "cli"
    assert ws.private_dir == alice_priv.resolve()
    assert ws.public_dir is None
    assert ws.tendcf_dir == tendcf_dir.resolve()
    assert ws.tainted is False
    assert ws.release_blocked is False
    ws.assert_releasable()

    # Selecting bob fails closed because tendcf-private-bob is missing.
    with pytest.raises(WorkspaceError, match="primary site repository for 'bob' not found"):
        resolve_workspace(ops_root=ops, site_name="bob", env=env)


def test_resolve_workspace_with_public_companion_and_rejects_bad_entries(tmp_path: Path) -> None:
    ops = tmp_path / "tendcf-ops"
    ops.mkdir()
    priv = _plant_site(ops, "djbclark", with_public=True)
    ws = resolve_workspace(ops_root=ops, site_name="djbclark", env={"HOME": str(tmp_path)})
    assert ws.private_dir == priv.resolve()
    assert ws.public_dir == (ops / "tendcf-public-djbclark").resolve()
    assert ws.tendcf_dir is None

    # Non-directory at public path fails closed.
    bad_pub = ops / "tendcf-public-filepub"
    _plant_site(ops, "filepub", with_public=False)
    bad_pub.write_text("not a dir", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="not a directory"):
        resolve_workspace(ops_root=ops, site_name="filepub", env={"HOME": str(tmp_path)})

    # Symlink at private or public path fails closed (prevents aliasing & cross-site spoofing).
    outside = tmp_path / "outside"
    outside.mkdir()
    (ops / "tendcf-private-linkpriv").symlink_to(outside)
    with pytest.raises(WorkspaceError, match="is a symlink"):
        resolve_workspace(ops_root=ops, site_name="linkpriv", env={"HOME": str(tmp_path)})

    _plant_site(ops, "linkpub", with_public=False)
    (ops / "tendcf-public-linkpub").symlink_to(ops / "tendcf-public-djbclark")
    with pytest.raises(WorkspaceError, match="is a symlink"):
        resolve_workspace(ops_root=ops, site_name="linkpub", env={"HOME": str(tmp_path)})

    # Dangling symlink at public path fails closed.
    _plant_site(ops, "dangle", with_public=False)
    (ops / "tendcf-public-dangle").symlink_to(tmp_path / "missing-target")
    with pytest.raises(WorkspaceError, match="dangling symlink"):
        resolve_workspace(ops_root=ops, site_name="dangle", env={"HOME": str(tmp_path)})


# --- list_sites & worktree hygiene -------------------------------------------


def test_list_sites_excludes_worktrees_and_flags_stray_wt(tmp_path: Path) -> None:
    ops = tmp_path / "tendcf-ops"
    ops.mkdir()
    _plant_site(ops, "djbclark", with_public=True)
    _plant_site(ops, "djbclark-lab", with_public=False)
    (ops / "tendcf-public-dann").mkdir()  # foreign read-only public clone
    (ops / ".worktrees" / "tendcf-private-hidden").mkdir(parents=True)  # excluded
    (ops / "tendcf-private-djbclark-wt").mkdir()  # stray worktree -> warned & excluded
    (ops / "tendcf-private").mkdir()  # legacy alias -> ignored
    (ops / "site-private").mkdir()  # legacy alias -> ignored
    (ops / "tendcf-private-BadCaps").mkdir()  # invalid slug -> warned & excluded

    inv = list_sites(ops_root=ops, env={"HOME": str(tmp_path)})
    by_slug = {s.slug: s for s in inv.sites}
    assert set(by_slug) == {"dann", "djbclark", "djbclark-lab"}
    assert by_slug["djbclark"].role == "site"
    assert by_slug["djbclark"].public_dir == (ops / "tendcf-public-djbclark").resolve()
    assert by_slug["djbclark-lab"].role == "site"
    assert by_slug["djbclark-lab"].public_dir is None
    assert by_slug["dann"].role == "foreign-public-only"
    assert by_slug["dann"].private_dir is None
    assert any("tendcf-private-djbclark-wt" in w for w in inv.warnings)
    assert any("tendcf-private-BadCaps" in w for w in inv.warnings)
    assert not any("hidden" in w for w in inv.warnings)


# --- site input directory discovery ------------------------------------------


def test_resolve_site_input_dir_root_subdir_and_ambiguity(tmp_path: Path) -> None:
    ops = tmp_path / "ops"
    ops.mkdir()
    root_priv = _plant_site(ops, "rootlayout", in_subdir=False)
    assert resolve_site_input_dir(root_priv) == root_priv

    sub_priv = _plant_site(ops, "sublayout", in_subdir=True)
    assert resolve_site_input_dir(sub_priv) == sub_priv / "site"

    # Ambiguity: files in both root and site/ fails closed.
    shutil.copy2(SITE / "services.yml", sub_priv / "services.yml")
    with pytest.raises(WorkspaceError, match="ambiguous Site Model layout"):
        resolve_site_input_dir(sub_priv)


# --- dev-only --override-input & release taint gate --------------------------


def test_parse_override_inputs_and_release_gate(tmp_path: Path) -> None:
    alice = tmp_path / "tendcf-public-alice"
    bob = tmp_path / "tendcf-public-bob"
    alice.mkdir()
    bob.mkdir()

    parsed = parse_override_inputs([f"alice={alice}", f"bob-lab={bob}"])
    assert parsed == (
        OverrideInput(namespace="alice", path=alice.resolve()),
        OverrideInput(namespace="bob-lab", path=bob.resolve()),
    )

    # Empty overrides pass release gate.
    refuse_release_if_tainted(())
    # Non-empty overrides fail closed naming every active override.
    with pytest.raises(WorkspaceError) as exc:
        refuse_release_if_tainted(parsed)
    msg = str(exc.value)
    assert "alice=" in msg and "bob-lab=" in msg and "refused" in msg

    # Duplicate namespace refused (never last-wins).
    with pytest.raises(WorkspaceError, match="duplicate --override-input"):
        parse_override_inputs([f"alice={alice}", f"alice={bob}"])

    # Malformed, bad namespace, missing path, and file path refused.
    with pytest.raises(WorkspaceError, match="expected <namespace>=<path>"):
        parse_override_inputs(["no-equals"])
    with pytest.raises(WorkspaceError, match="invalid override-input namespace"):
        parse_override_inputs([f"../evil={alice}"])
    with pytest.raises(WorkspaceError, match="does not exist"):
        parse_override_inputs([f"alice={tmp_path / 'missing'}"])
    file_target = tmp_path / "not-a-dir"
    file_target.write_text("x", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="not a directory"):
        parse_override_inputs([f"alice={file_target}"])


def test_compile_result_records_override_taint_without_altering_goal_file(tmp_path: Path) -> None:
    tendcf = _tendcf_root()
    schemas = Schemas(tendcf / "schema")
    model = load_site_model(SITE / "services.yml", SITE / "roles.yml", SITE / "launchd-writers.yml")
    host = HostSpec(
        name="mac",
        platform="macos",
        supervisor="launchd",
        key=HOST_KEY,
        device_trust=load_document(SITE / "device-trust.json").data,
    )
    clean = compile_host(model, host, schemas)
    assert clean.tainted is False
    clean.assert_releasable()

    local_alice = tmp_path / "tendcf-public-alice"
    local_alice.mkdir()
    ov = parse_override_inputs([f"alice={local_alice}"])
    tainted = compile_host(model, host, schemas, overrides=ov)
    assert tainted.tainted is True
    assert tainted.overrides == ov
    assert tainted.canonical == clean.canonical  # goal file stays schema-valid
    assert any("TAINTED" in d and "alice=" in d for d in tainted.diagnostics)
    with pytest.raises(WorkspaceError, match="refused"):
        tainted.assert_releasable()


# --- CLI integration: `tendcf workspace` and `tendcf compile` --------------


def test_cli_workspace_json_human_list_and_check_releasable(tmp_path: Path) -> None:
    ops = tmp_path / "tendcf-ops"
    ops.mkdir()
    priv = _plant_site(ops, "djbclark", with_public=True)
    (ops / "tendcf-public-dann").mkdir()
    (ops / "tendcf-private-djbclark-wt").mkdir()
    override_dir = tmp_path / "local-alice"
    override_dir.mkdir()

    env = _clean_env(tmp_path)

    # JSON output clean
    proc = _run_cli(["workspace", "--ops-root", str(ops), "--site-name", "djbclark", "--json", "--check-releasable"], env)
    assert proc.returncode == 0, proc.stderr.decode()
    data = json.loads(proc.stdout)
    assert data["ops_root"] == str(ops.resolve())
    assert data["site_slug"] == "djbclark"
    assert data["selection_source"] == "cli"
    assert data["private_dir"] == str(priv.resolve())
    assert data["public_dir"] == str((ops / "tendcf-public-djbclark").resolve())
    assert data["tendcf_dir"] is None
    assert data["overrides"] == []
    assert data["tainted"] is False
    assert data["release_blocked"] is False

    # With --override-input and --check-releasable: warns loudly and exits 1 (REFUSED)
    tainted = _run_cli(
        [
            "workspace",
            "--ops-root",
            str(ops),
            "--site-name",
            "djbclark",
            "--override-input",
            f"alice={override_dir}",
            "--check-releasable",
            "--json",
        ],
        env,
    )
    assert tainted.returncode == 1
    assert b"WARNING: dev-only local override active" in tainted.stderr
    assert b"REFUSED:" in tainted.stderr
    tdata = json.loads(tainted.stdout)
    assert tdata["tainted"] is True
    assert tdata["release_blocked"] is True
    assert tdata["overrides"] == [{"namespace": "alice", "path": str(override_dir.resolve())}]

    # Human-readable output
    human = _run_cli(["workspace", "--ops-root", str(ops), "--site-name", "djbclark"], env)
    assert human.returncode == 0, human.stderr.decode()
    out_text = human.stdout.decode()
    assert "site_slug: djbclark" in out_text
    assert "release_blocked: false" in out_text

    # --list mode
    listed = _run_cli(["workspace", "--ops-root", str(ops), "--list", "--json"], env)
    assert listed.returncode == 0, listed.stderr.decode()
    ldata = json.loads(listed.stdout)
    assert [s["slug"] for s in ldata["sites"]] == ["dann", "djbclark"]
    assert any("tendcf-private-djbclark-wt" in w for w in ldata["warnings"])

    # --list combined with --site-name exits 2
    bad_combo = _run_cli(["workspace", "--ops-root", str(ops), "--list", "--site-name", "djbclark"], env)
    assert bad_combo.returncode == 2


def test_cli_workspace_reads_config_file(tmp_path: Path) -> None:
    ops = tmp_path / "tendcf-ops"
    ops.mkdir()
    _plant_site(ops, "alice-lab", with_public=False)
    cfg = tmp_path / "active-site"
    cfg.write_text("alice-lab\n", encoding="utf-8")

    env = _clean_env(tmp_path)
    proc = _run_cli(["workspace", "--ops-root", str(ops), "--config", str(cfg), "--json"], env)
    assert proc.returncode == 0, proc.stderr.decode()
    data = json.loads(proc.stdout)
    assert data["site_slug"] == "alice-lab"
    assert data["selection_source"] == f"config:{cfg}"
    assert data["public_dir"] is None


def test_cli_compile_workspace_end_to_end_and_mutual_exclusion(tmp_path: Path) -> None:
    tendcf = _tendcf_root()
    ops = tmp_path / "tendcf-ops"
    ops.mkdir()
    priv = _plant_site(ops, "djbclark-lab", with_public=True, in_subdir=True)
    override_dir = tmp_path / "foreign-alice"
    override_dir.mkdir()
    trust = priv / "site" / "device-trust.json"

    env = _clean_env(tmp_path, TENDCF_DIR=str(tendcf))

    # Baseline compile via --site
    baseline = _run_cli(
        [
            "compile",
            "--host", "mac",
            "--platform", "macos",
            "--supervisor", "launchd",
            "--host-key", HOST_KEY,
            "--device-trust", str(trust),
            "--site", str(priv / "site"),
        ],
        env,
    )
    assert baseline.returncode == 0, baseline.stderr.decode()

    # Compile via --ops-root + --site-name + --override-input
    ws_proc = _run_cli(
        [
            "compile",
            "--host", "mac",
            "--platform", "macos",
            "--supervisor", "launchd",
            "--host-key", HOST_KEY,
            "--device-trust", str(trust),
            "--ops-root", str(ops),
            "--site-name", "djbclark-lab",
            "--override-input", f"alice={override_dir}",
        ],
        env,
    )
    assert ws_proc.returncode == 0, ws_proc.stderr.decode()
    assert ws_proc.stdout == baseline.stdout
    err = ws_proc.stderr.decode()
    assert "tendcf: workspace: site=djbclark-lab source=cli" in err
    assert "WARNING: dev-only --override-input active" in err
    assert "TAINTED (not releasable)" in err
    assert "not yet wired into compile_host" in err

    # Mutual exclusion: --site with --site-name or --ops-root or --workspace exits 2
    for extra in (["--site-name", "djbclark-lab"], ["--ops-root", str(ops)], ["--workspace"]):
        conflict = _run_cli(
            [
                "compile",
                "--host", "mac",
                "--platform", "macos",
                "--supervisor", "launchd",
                "--host-key", HOST_KEY,
                "--device-trust", str(trust),
                "--site", str(priv / "site"),
                *extra,
            ],
            env,
        )
        assert conflict.returncode == 2
        assert b"cannot be combined" in conflict.stderr

    # TENDCF_SITE in env does NOT break explicit --site DIR
    env_with_site = _clean_env(tmp_path, TENDCF_DIR=str(tendcf), TENDCF_SITE="nonexistent-slug")
    explicit_ok = _run_cli(
        [
            "compile",
            "--host", "mac",
            "--platform", "macos",
            "--supervisor", "launchd",
            "--host-key", HOST_KEY,
            "--device-trust", str(trust),
            "--site", str(priv / "site"),
        ],
        env_with_site,
    )
    assert explicit_ok.returncode == 0, explicit_ok.stderr.decode()

    # TENDCF_SITE + TENDCF_OPS_ROOT resolves cleanly without --site or --site-name
    env_ws = _clean_env(
        tmp_path,
        TENDCF_DIR=str(tendcf),
        TENDCF_OPS_ROOT=str(ops),
        TENDCF_SITE="djbclark-lab",
    )
    from_env = _run_cli(
        [
            "compile",
            "--host", "mac",
            "--platform", "macos",
            "--supervisor", "launchd",
            "--host-key", HOST_KEY,
            "--device-trust", str(trust),
        ],
        env_ws,
    )
    assert from_env.returncode == 0, from_env.stderr.decode()
    assert from_env.stdout == baseline.stdout
    assert b"source=env:TENDCF_SITE" in from_env.stderr

    # Hermetic default: XDG active-site is NOT read unless --workspace/--ops-root is requested
    xdg = tmp_path / "xdg"
    (xdg / "tendcf").mkdir(parents=True)
    (xdg / "tendcf" / "active-site").write_text("djbclark-lab\n", encoding="utf-8")
    env_xdg = _clean_env(
        tmp_path,
        TENDCF_DIR=str(tendcf),
        TENDCF_OPS_ROOT=str(ops),
        XDG_CONFIG_HOME=str(xdg),
    )
    no_flag = _run_cli(
        [
            "compile",
            "--host", "mac",
            "--platform", "macos",
            "--supervisor", "launchd",
            "--host-key", HOST_KEY,
            "--device-trust", str(trust),
        ],
        env_xdg,
    )
    assert no_flag.returncode == 2
    assert b"--services or --site is required" in no_flag.stderr

    # With --workspace, XDG active-site IS read and succeeds
    with_ws_flag = _run_cli(
        [
            "compile",
            "--host", "mac",
            "--platform", "macos",
            "--supervisor", "launchd",
            "--host-key", HOST_KEY,
            "--device-trust", str(trust),
            "--workspace",
        ],
        env_xdg,
    )
    assert with_ws_flag.returncode == 0, with_ws_flag.stderr.decode()
    assert with_ws_flag.stdout == baseline.stdout
    assert b"source=config:" in with_ws_flag.stderr

    # Invalid --override-input exits 2 cleanly without traceback
    bad_ov = _run_cli(
        [
            "compile",
            "--host", "mac",
            "--platform", "macos",
            "--supervisor", "launchd",
            "--host-key", HOST_KEY,
            "--device-trust", str(trust),
            "--site", str(priv / "site"),
            "--override-input", "bad=missing/path",
        ],
        env,
    )
    assert bad_ov.returncode == 2
    assert b"Traceback" not in bad_ov.stderr


def test_extra_edge_cases_symlinks_oversized_and_fallback_tendcf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tendcf import cli

    # Oversized and invalid UTF-8 active-site files fail closed.
    big = tmp_path / "big-site"
    big.write_text("a" * 5000, encoding="utf-8")
    with pytest.raises(WorkspaceError, match="exceeds 4096 bytes"):
        resolve_site_slug(None, {"HOME": str(tmp_path)}, config_path=big)

    # Exact byte-limit check: multi-byte UTF-8 > 4096 bytes even with < 4096 chars fails closed.
    utf8_over = tmp_path / "utf8-over"
    utf8_over.write_bytes(b"#" + ("é".encode("utf-8") * 2048) + b"\ndjbclark\n")  # > 4096 bytes, < 2060 chars
    with pytest.raises(WorkspaceError, match="exceeds 4096 bytes"):
        resolve_site_slug(None, {"HOME": str(tmp_path)}, config_path=utf8_over)

    # Exact 4096-byte file succeeds.
    slug_bytes = b"\ndjbclark\n"
    pad_len = 4096 - 1 - len(slug_bytes)
    utf8_exact = tmp_path / "utf8-exact"
    utf8_exact.write_bytes(b"#" + (b"x" * pad_len) + slug_bytes)
    assert len(utf8_exact.read_bytes()) == 4096
    assert resolve_site_slug(None, {"HOME": str(tmp_path)}, config_path=utf8_exact)[0] == "djbclark"

    # CRLF is accepted; bare CR, NUL byte in comment, and U+2028 line separator are rejected.
    crlf = tmp_path / "crlf-site"
    crlf.write_bytes(b"# comment\r\n  djbclark \t\r\n")
    assert resolve_site_slug(None, {"HOME": str(tmp_path)}, config_path=crlf)[0] == "djbclark"

    bare_cr = tmp_path / "bare-cr"
    bare_cr.write_bytes(b"djbclark\ralice\n")
    with pytest.raises(WorkspaceError, match="bare CR"):
        resolve_site_slug(None, {"HOME": str(tmp_path)}, config_path=bare_cr)

    nul_comment = tmp_path / "nul-comment"
    nul_comment.write_bytes(b"# comment\x00hidden\ndjbclark\n")
    with pytest.raises(WorkspaceError, match="NUL byte"):
        resolve_site_slug(None, {"HOME": str(tmp_path)}, config_path=nul_comment)

    u2028 = tmp_path / "u2028-site"
    u2028.write_text("djbclark\u2028alice\n", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="invalid site slug"):
        resolve_site_slug(None, {"HOME": str(tmp_path)}, config_path=u2028)

    bad_utf8 = tmp_path / "bad-utf8"
    bad_utf8.write_bytes(b"\xff\xfe")
    with pytest.raises(WorkspaceError, match="valid UTF-8"):
        resolve_site_slug(None, {"HOME": str(tmp_path)}, config_path=bad_utf8)

    # Real FIFO active-site file fails closed immediately via O_NONBLOCK + S_ISREG (never hangs).
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "fifo-site"
        os.mkfifo(fifo)
        with pytest.raises(WorkspaceError, match="regular file"):
            resolve_site_slug(None, {"HOME": str(tmp_path)}, config_path=fifo)

    # Relative XDG_CONFIG_HOME is ignored end-to-end by resolve_site_slug, falling back to $HOME/.config.
    home = tmp_path / "rel-home"
    fallback_cfg = home / ".config" / "tendcf" / "active-site"
    fallback_cfg.parent.mkdir(parents=True)
    fallback_cfg.write_text("djbclark\n", encoding="utf-8")
    assert resolve_site_slug(
        None, {"HOME": str(home), "XDG_CONFIG_HOME": "relative/config"}
    ) == ("djbclark", f"config:{fallback_cfg}")

    # _expand_path: `~//etc` stays under $HOME (never drops $HOME to `/etc`), and `~root/foo` is refused.
    assert _expand_path("~//etc", {"HOME": str(home)}) == home / "etc"
    with pytest.raises(WorkspaceError, match="unsupported tilde user expansion"):
        _expand_path("~root/foo", {"HOME": str(home)})

    # Dangling symlink, symlink loop, and empty path in --override-input fail closed as WorkspaceError.
    dangling = tmp_path / "dangling-ov"
    dangling.symlink_to(tmp_path / "does-not-exist")
    with pytest.raises(WorkspaceError, match="does not exist"):
        parse_override_inputs([f"alice={dangling}"])
    loop_a = tmp_path / "loop-a"
    loop_b = tmp_path / "loop-b"
    loop_a.symlink_to(loop_b)
    loop_b.symlink_to(loop_a)
    with pytest.raises(WorkspaceError, match="does not exist or is unreadable"):
        parse_override_inputs([f"alice={loop_a}"])
    with pytest.raises(WorkspaceError, match="must not be empty"):
        parse_override_inputs(["alice="])

    # Unreadable 0o000 ops_root raises WorkspaceError, not raw PermissionError.
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        locked = tmp_path / "locked-ops"
        locked.mkdir()
        locked.chmod(0o000)
        try:
            with pytest.raises(WorkspaceError, match="cannot read"):
                list_sites(ops_root=locked, env={"HOME": str(tmp_path)})
        finally:
            locked.chmod(0o755)

    # Symlinked `site/` inside private_dir fails closed.
    priv = tmp_path / "tendcf-private-sym"
    priv.mkdir()
    outside = tmp_path / "outside-site"
    outside.mkdir()
    (priv / "site").symlink_to(outside)
    with pytest.raises(WorkspaceError, match="is a symlink"):
        resolve_site_input_dir(priv)

    # list_sites flags symlinked and non-directory site entries and symlinked tendcf/.
    ops = tmp_path / "ops-warn"
    ops.mkdir()
    (ops / "tendcf-private-link").symlink_to(outside)
    (ops / "tendcf-public-file").write_text("x", encoding="utf-8")
    _plant_tendcf_checkout(ops / "tendcf")
    inv = list_sites(ops_root=ops, env={"HOME": str(tmp_path)})
    assert inv.sites == ()
    assert inv.tendcf_dir == (ops / "tendcf").resolve()
    assert any("symlink" in w for w in inv.warnings)
    assert any("non-directory" in w for w in inv.warnings)

    # _tendcf_dir has NO workspace fallback: returns None when --tendcf, TENDCF_DIR, and in-tree are absent.
    monkeypatch.delenv("TENDCF_DIR", raising=False)
    monkeypatch.setattr(cli, "_in_tree_tendcf", lambda: None)
    assert cli._tendcf_dir(None) is None


def test_compile_never_falls_back_to_ops_root_tendcf_and_tendcf_hardening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tendcf import cli

    ops = tmp_path / "ops-no-fallback"
    ops.mkdir()
    priv = _plant_site(ops, "alice", with_public=False)
    # Plant a fake <ops_root>/tendcf whose projector.py would raise if ever imported!
    fake_tendcf = _plant_tendcf_checkout(ops / "tendcf")
    (fake_tendcf / "tools" / "projector.py").write_text(
        "raise AssertionError('ops_root/tendcf projector must NEVER be auto-loaded')\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("TENDCF_DIR", raising=False)
    monkeypatch.setattr(cli, "_in_tree_tendcf", lambda: None)
    out_file = tmp_path / "out.json"
    rc = cli.main(
        [
            "compile",
            "--host", "mac",
            "--platform", "macos",
            "--supervisor", "launchd",
            "--host-key", HOST_KEY,
            "--device-trust", str(priv / "device-trust.json"),
            "--ops-root", str(ops),
            "--site-name", "alice",
            "-o", str(out_file),
        ]
    )
    err = capsys.readouterr().err
    assert rc == 0, err
    # Because <ops_root>/tendcf is never auto-loaded, schema validation was NOT run from it.
    assert "NOT validated" in err

    # With --project and no --tendcf / TENDCF_DIR / in-tree checkout, buildfile fails closed (exit 2).
    rc_proj = cli.main(
        [
            "compile",
            "--host", "mac",
            "--platform", "macos",
            "--supervisor", "launchd",
            "--host-key", HOST_KEY,
            "--device-trust", str(priv / "device-trust.json"),
            "--ops-root", str(ops),
            "--site-name", "alice",
            "--project",
        ]
    )
    err_proj = capsys.readouterr().err
    assert rc_proj == 2
    assert "--project needs a tendcf checkout" in err_proj

    # Hardening of <ops_root>/tendcf discovery: symlinks on tendcf/ or tools/projector.py fail closed.
    outside_tendcf = _plant_tendcf_checkout(tmp_path / "outside-tendcf")
    ops_link = tmp_path / "ops-tendcf-link"
    ops_link.mkdir()
    _plant_site(ops_link, "alice", with_public=False)
    (ops_link / "tendcf").symlink_to(outside_tendcf)
    assert is_tendcf_checkout(ops_link / "tendcf") is False
    with pytest.raises(WorkspaceError, match="is a symlink"):
        resolve_workspace(ops_root=ops_link, site_name="alice", env={"HOME": str(tmp_path)})
    inv_link = list_sites(ops_root=ops_link, env={"HOME": str(tmp_path)})
    assert inv_link.tendcf_dir is None
    assert any("local tendcf entry" in w for w in inv_link.warnings)

    # Symlinked tools/projector.py inside real <ops_root>/tendcf fails closed.
    ops_proj_link = tmp_path / "ops-proj-link"
    ops_proj_link.mkdir()
    _plant_site(ops_proj_link, "alice", with_public=False)
    td = _plant_tendcf_checkout(ops_proj_link / "tendcf")
    (td / "tools" / "projector.py").unlink()
    (td / "tools" / "projector.py").symlink_to(outside_tendcf / "tools" / "projector.py")
    assert is_tendcf_checkout(td) is False
    with pytest.raises(WorkspaceError, match="is a symlink"):
        resolve_workspace(ops_root=ops_proj_link, site_name="alice", env={"HOME": str(tmp_path)})
    inv_proj = list_sites(ops_root=ops_proj_link, env={"HOME": str(tmp_path)})
    assert inv_proj.tendcf_dir is None
    assert any("local tendcf entry" in w for w in inv_proj.warnings)


def test_resolve_site_input_dir_refuses_symlinked_and_dangling_model_files(tmp_path: Path) -> None:
    ops = tmp_path / "ops-sitemodel-sym"
    ops.mkdir()
    bob = _plant_site(ops, "bob", with_public=False)

    # 1. Cross-site symlink at private_dir/services.yml -> refused.
    alice = _plant_site(ops, "alice", with_public=False)
    (alice / "services.yml").unlink()
    (alice / "services.yml").symlink_to(bob / "services.yml")
    with pytest.raises(WorkspaceError, match="is a symlink"):
        resolve_site_input_dir(alice)

    # 2. Cross-site symlink inside private_dir/site/services.yml -> refused.
    carol = _plant_site(ops, "carol", with_public=False, in_subdir=True)
    (carol / "site" / "services.yml").unlink()
    (carol / "site" / "services.yml").symlink_to(bob / "services.yml")
    with pytest.raises(WorkspaceError, match="is a symlink"):
        resolve_site_input_dir(carol)

    # 3. Cross-site symlink inside private_dir/site/ EVEN when root files are regular -> refused.
    dave = _plant_site(ops, "dave", with_public=False)
    (dave / "site").mkdir()
    (dave / "site" / "roles.yml").symlink_to(bob / "roles.yml")
    with pytest.raises(WorkspaceError, match="is a symlink"):
        resolve_site_input_dir(dave)

    # 4. Dangling symlink at private_dir/roles.yml and private_dir/site/roles.yml -> refused.
    eve = _plant_site(ops, "eve", with_public=False)
    (eve / "roles.yml").unlink()
    (eve / "roles.yml").symlink_to(tmp_path / "nonexistent.yml")
    with pytest.raises(WorkspaceError, match="is a symlink"):
        resolve_site_input_dir(eve)

    frank = _plant_site(ops, "frank", with_public=False, in_subdir=True)
    (frank / "site" / "roles.yml").unlink()
    (frank / "site" / "roles.yml").symlink_to(tmp_path / "nonexistent.yml")
    with pytest.raises(WorkspaceError, match="is a symlink"):
        resolve_site_input_dir(frank)

    # 5. Non-regular file (directory) at services.yml -> refused.
    grace = _plant_site(ops, "grace", with_public=False)
    (grace / "services.yml").unlink()
    (grace / "services.yml").mkdir()
    with pytest.raises(WorkspaceError, match="not a regular file"):
        resolve_site_input_dir(grace)


def test_apfs_exact_case_site_directory_refusal(tmp_path: Path) -> None:
    ops = tmp_path / "ops-case"
    ops.mkdir()
    (ops / "tendcf-private-Alice").mkdir()
    # Requesting lowercase `alice` must fail closed even on case-insensitive APFS.
    with pytest.raises(WorkspaceError, match="wrong directory casing"):
        resolve_workspace(ops_root=ops, site_name="alice", env={"HOME": str(tmp_path)})

    # Same for public companion with wrong casing.
    _plant_site(ops, "bob", with_public=False)
    (ops / "tendcf-public-Bob").mkdir()
    with pytest.raises(WorkspaceError, match="wrong directory casing"):
        resolve_workspace(ops_root=ops, site_name="bob", env={"HOME": str(tmp_path)})


def test_override_taint_output_gate_check_releasable_and_compile_host_mapping(tmp_path: Path) -> None:
    tendcf = _tendcf_root()
    schemas = Schemas(tendcf / "schema")
    model = load_site_model(SITE / "services.yml", SITE / "roles.yml", SITE / "launchd-writers.yml")
    host = HostSpec(
        name="mac",
        platform="macos",
        supervisor="launchd",
        key=HOST_KEY,
        device_trust=load_document(SITE / "device-trust.json").data,
    )
    ov_dir = tmp_path / "local-alice"
    ov_dir.mkdir()

    # compile_host normalizes Mapping[str, Path] cleanly.
    res_map = compile_host(model, host, schemas, overrides={"alice": ov_dir})
    assert res_map.tainted is True
    assert res_map.overrides == (OverrideInput(namespace="alice", path=ov_dir),)
    assert any("not yet wired" in d for d in res_map.diagnostics)

    # Invalid overrides raise CompileError (never AttributeError).
    with pytest.raises(CompileError):
        compile_host(model, host, schemas, overrides="alice=/tmp")  # type: ignore[arg-type]
    with pytest.raises(CompileError):
        compile_host(model, host, schemas, overrides={"BadCaps": ov_dir})
    with pytest.raises(CompileError):
        compile_host(
            model,
            host,
            schemas,
            overrides=[OverrideInput("alice", ov_dir), OverrideInput("alice", ov_dir)],
        )

    # CLI buildfile -o taint gate and --check-releasable
    env = _clean_env(tmp_path, TENDCF_DIR=str(tendcf))
    out_file = tmp_path / "tainted-goal.json"
    base_cmd = [
        "compile",
        "--host", "mac",
        "--platform", "macos",
        "--supervisor", "launchd",
        "--host-key", HOST_KEY,
        "--device-trust", str(SITE / "device-trust.json"),
        "--site", str(SITE),
    ]

    # -o with --override-input WITHOUT --allow-tainted -> exit 1, file not written!
    refused_out = _run_cli([*base_cmd, "--override-input", f"alice={ov_dir}", "-o", str(out_file)], env)
    assert refused_out.returncode == 1
    assert b"REFUSED:" in refused_out.stderr and b"--allow-tainted" in refused_out.stderr
    assert not out_file.exists()

    # -o with --override-input WITH --allow-tainted -> exit 0, file written, loud honest warning!
    allowed_out = _run_cli(
        [*base_cmd, "--override-input", f"alice={ov_dir}", "-o", str(out_file), "--allow-tainted"],
        env,
    )
    assert allowed_out.returncode == 0, allowed_out.stderr.decode()
    assert out_file.is_file()
    assert b"not yet wired into compile_host" in allowed_out.stderr

    # --check-releasable with --override-input -> exit 1!
    refused_rel = _run_cli([*base_cmd, "--override-input", f"alice={ov_dir}", "--check-releasable"], env)
    assert refused_rel.returncode == 1
    assert b"REFUSED:" in refused_rel.stderr and refused_rel.stdout == b""

    # --check-releasable without overrides and without TENDCF_DIR -> exit 0!
    ok_rel = _run_cli([*base_cmd, "--check-releasable"], _clean_env(tmp_path))
    assert ok_rel.returncode == 0, ok_rel.stderr.decode()


def test_cli_hermetic_flag_checks_config_precedence_and_sole_checkout_workspace(tmp_path: Path) -> None:
    tendcf = _tendcf_root()
    ops = tmp_path / "tendcf-ops"
    ops.mkdir()
    priv = _plant_site(ops, "alice", with_public=False)
    env = _clean_env(tmp_path, TENDCF_DIR=str(tendcf))

    base = [
        "compile",
        "--host", "mac",
        "--platform", "macos",
        "--supervisor", "launchd",
        "--host-key", HOST_KEY,
        "--device-trust", str(SITE / "device-trust.json"),
    ]

    # Empty string flags fail closed with exit 2 (is not None checks).
    for bad_args in (
        [*base, "--site", ""],
        [*base, "--site", "", "--site-name", "alice"],
        [*base, "--site", str(SITE), "--tendcf", ""],
        [*base, "--services", "", "--roles", str(SITE / "roles.yml"), "--launchd-writers", str(SITE / "launchd-writers.yml")],
    ):
        proc = _run_cli(bad_args, env)
        assert proc.returncode == 2, (bad_args, proc.stderr.decode())

    # Ambient TENDCF_SITE + partial explicit file flags MUST NOT pull missing files from workspace.
    env_site = _clean_env(tmp_path, TENDCF_DIR=str(tendcf), TENDCF_OPS_ROOT=str(ops), TENDCF_SITE="alice")
    partial = _run_cli([*base, "--services", str(SITE / "services.yml")], env_site)
    assert partial.returncode == 2
    assert b"--roles or --site is required" in partial.stderr
    assert b"workspace:" not in partial.stderr

    # Explicit file flags + workspace flags are mutually exclusive (exit 2).
    for ws_flag in (["--site-name", "alice"], ["--ops-root", str(ops)], ["--workspace"]):
        mixed = _run_cli([*base, "--services", str(SITE / "services.yml"), *ws_flag], env)
        assert mixed.returncode == 2
        assert b"cannot be combined" in mixed.stderr

    # All three explicit files + ambient TENDCF_SITE succeeds without touching workspace.
    all_explicit = _run_cli(
        [
            *base,
            "--services", str(SITE / "services.yml"),
            "--roles", str(SITE / "roles.yml"),
            "--launchd-writers", str(SITE / "launchd-writers.yml"),
        ],
        _clean_env(tmp_path, TENDCF_DIR=str(tendcf), TENDCF_SITE="nonexistent-site"),
    )
    assert all_explicit.returncode == 0, all_explicit.stderr.decode()
    assert b"workspace:" not in all_explicit.stderr

    # tendcf workspace: explicit --config beats ambient TENDCF_SITE, fails closed if missing,
    # and is mutually exclusive with --site-name.
    cfg = tmp_path / "explicit-active-site"
    cfg.write_text("alice\n", encoding="utf-8")
    env_bob = _clean_env(tmp_path, TENDCF_SITE="nonexistent-bob")
    ws_cfg = _run_cli(["workspace", "--ops-root", str(ops), "--config", str(cfg), "--json"], env_bob)
    assert ws_cfg.returncode == 0, ws_cfg.stderr.decode()
    assert json.loads(ws_cfg.stdout)["site_slug"] == "alice"

    ws_missing_cfg = _run_cli(
        ["workspace", "--ops-root", str(ops), "--config", str(tmp_path / "missing-cfg")],
        env_bob,
    )
    assert ws_missing_cfg.returncode == 2
    assert b"not found" in ws_missing_cfg.stderr

    ws_conflict = _run_cli(
        ["workspace", "--ops-root", str(ops), "--config", str(cfg), "--site-name", "alice"],
        env,
    )
    assert ws_conflict.returncode == 2
    assert b"cannot be combined" in ws_conflict.stderr

    # CLI tendcf workspace with no selector and a sole checkout exits 2 (no sole-dir glob).
    ws_sole = _run_cli(["workspace", "--ops-root", str(ops)], env)
    assert ws_sole.returncode == 2
    assert b"no site selected" in ws_sole.stderr
    assert priv.is_dir()
