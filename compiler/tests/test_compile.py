"""tendcf compiler tests. Every test needs a tendcf checkout for the contract
(schemas, projector, fixtures): by default the enclosing repository (this
directory is <root>/compiler/tests); set TENDCF_DIR to use another (dev mode).

The goldens under tests/golden/ are the compiler's own regression test
(paper §6.2): a compiler change that alters output for a host nobody touched
fails here. Regenerate deliberately with TENDCF_UPDATE_GOLDEN=1 and read the
diff before committing it.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tendcf.cli import load_projector, main
from tendcf.compile import GOAL_FILE_SCHEMA_VERSION, CompileError, HostSpec, compile_host
from tendcf.sitemodel import Schemas, SiteModel, load_document, load_site_model, validate_site_model

REPO = Path(__file__).resolve().parent.parent
SITE = REPO / "examples" / "site"
GOLDEN = REPO / "tests" / "golden"
HOST_KEY = "ed25519:" + "a1" * 32


def _tendcf() -> Path:
    raw = os.environ.get("TENDCF_DIR")
    candidates = [Path(raw).expanduser()] if raw else []
    candidates.append(REPO.parent)  # compiler/ sits directly under the tendcf root
    for c in candidates:
        if (c / "schema" / "goal-file.schema.json").exists():
            return c
    pytest.skip("no tendcf checkout: not inside one; set TENDCF_DIR")


@pytest.fixture(scope="session")
def tendcf() -> Path:
    return _tendcf()


@pytest.fixture(scope="session")
def schemas(tendcf: Path) -> Schemas:
    return Schemas(tendcf / "schema")


@pytest.fixture(scope="session")
def projector(tendcf: Path):
    return load_projector(tendcf)


@pytest.fixture(scope="session")
def lint(tendcf: Path):
    """tendcf's schema_lint, for its goal-file cross-file rules (no copy here)."""
    spec = importlib.util.spec_from_file_location("tendcf_schema_lint", tendcf / "tools" / "schema_lint.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _cross_file_findings(lint, doc: dict) -> list:
    """Run tendcf's own goal cross-file checks over one rendered goal file."""
    with lint.capture_findings() as found:
        lint.check_goal_file_cross_file({"goal-file.json": doc}, "goal-file.json")
    return list(found)


def _model(site: Path) -> SiteModel:
    return load_site_model(site / "services.yml", site / "roles.yml", site / "launchd-writers.yml")


def _trust(site: Path, supervisor: str | None = "launchd") -> dict:
    """The example device-trust domain, with its supervisor entry set, or removed if None."""
    trust = load_document(site / "device-trust.json").data
    if supervisor is None:
        del trust["entries"]["supervisor"]
    else:
        trust["entries"]["supervisor"] = {"host": {"name": supervisor, "state": "present"}}
    return trust


def _host(
    site: Path,
    name: str = "mac",
    platform: str = "macos",
    supervisor: str = "launchd",
    trust: dict | None = None,
) -> HostSpec:
    if trust is None:
        trust = _trust(site, supervisor)
    return HostSpec(name=name, platform=platform, supervisor=supervisor, key=HOST_KEY, device_trust=trust)


def _nixos_host(name: str = "get", trust: dict | None = None) -> HostSpec:
    return _host(SITE, name=name, platform="linux", supervisor="nixos", trust=trust or _trust(SITE, None))


def _check_golden(name: str, raw: bytes) -> None:
    path = GOLDEN / name
    if os.environ.get("TENDCF_UPDATE_GOLDEN"):
        path.write_bytes(raw)
    assert path.exists(), f"missing golden {path}; run with TENDCF_UPDATE_GOLDEN=1"
    assert raw == path.read_bytes(), f"output for {name} changed; diff the golden before updating"


# --- the end-to-end slice ---------------------------------------------------

def test_site_model_inputs_validate(schemas: Schemas) -> None:
    assert validate_site_model(_model(SITE), schemas) == []


def test_example_site_mac_golden(schemas: Schemas) -> None:
    result = compile_host(_model(SITE), _host(SITE), schemas)
    doc = result.goal_file
    assert doc["schema_version"] == GOAL_FILE_SCHEMA_VERSION == 9
    assert doc["host"] == HOST_KEY
    assert doc["domains"]["device-trust"]["entries"]["supervisor"] == {"host": {"name": "launchd", "state": "present"}}
    sup = doc["domains"]["supervision"]
    assert sup["coverage"] == "comprehensive"
    assert set(sup["entries"]["service"]) == {
        "com.djbclark.caddy", "com.djbclark.litellm", "com.tendcf.example.tailscaled"
    }
    for svc in sup["entries"]["service"].values():
        assert svc["unit"]["launchd"]["domain"] == "system"
    # The fleet-vpn interlock renders because tailscaled is on this host, with
    # the common-schema defaults stated rather than implied.
    ilk = sup["entries"]["interlock"]["tailscale-authenticated-before-lockdown"]
    assert ilk == {
        "state": "present",
        "bundle": "fleet-vpn",
        "pre_action": {"command": ["/usr/local/bin/tailscale", "status", "--json"], "expect_exit": 0, "timeout_seconds": 15},
        "defines_class": "tailscale_authenticated",
        "blocks": "enclosing-bundle",
        "report": True,
    }
    assert set(sup["entries"]["unit-writer"]) == {
        "com.djbclark.*", "com.tendcf.example.*", "org.tendcf.execd", "dev.mise.*", "org.nixos.*", "com.apple.*"
    }
    assert sup["entries"]["unit-writer"]["org.tendcf.execd"] == {"state": "present", "writer": "tendcf-install"}
    # env carries secret NAMES only, and only when non-empty.
    assert sup["entries"]["service"]["com.djbclark.litellm"]["env"] == {
        "LITELLM_MASTER_KEY": "LITELLM_MASTER_KEY", "OPENAI_API_KEY": "OPENAI_API_KEY"
    }
    assert "env" not in sup["entries"]["service"]["com.djbclark.caddy"]
    assert not result.canonical.endswith(b"\n")
    _check_golden("example-site_mac.goal-file.json", result.canonical)


def test_tendcf_fixtures_mac_golden(tendcf: Path, schemas: Schemas) -> None:
    """tendcf's own examples compile; tailscaled has no hosts/role so only two render."""
    model = _model(tendcf / "examples")
    result = compile_host(model, _host(SITE), schemas)
    sup = result.goal_file["domains"]["supervision"]
    assert set(sup["entries"]["service"]) == {"com.djbclark.caddy", "com.djbclark.litellm"}
    assert "interlock" not in sup["entries"]  # fleet-vpn unused on this host
    assert any("tailscaled" in d and "neither" in d for d in result.diagnostics)
    _check_golden("tendcf-examples_mac.goal-file.json", result.canonical)


def test_output_validates_and_is_canonical(schemas: Schemas) -> None:
    import rfc8785

    result = compile_host(_model(SITE), _host(SITE), schemas)
    assert schemas.errors("goal-file.schema.json", result.goal_file) == []
    assert rfc8785.dumps(json.loads(result.canonical)) == result.canonical


def test_schema_version_matches_tendcf(tendcf: Path) -> None:
    """The renderer's version is tendcf's schema const (CI checks this too)."""
    raw = json.loads((tendcf / "schema" / "goal-file.schema.json").read_text())
    assert GOAL_FILE_SCHEMA_VERSION == raw["properties"]["schema_version"]["const"]


def test_rendered_files_pass_tendcf_cross_file_checks(tendcf: Path, schemas: Schemas, lint) -> None:
    docs = [
        compile_host(_model(SITE), _host(SITE), schemas).goal_file,
        compile_host(_model(tendcf / "examples"), _host(SITE), schemas).goal_file,
        compile_host(_model(SITE), _nixos_host(), schemas).goal_file,
    ]
    for doc in docs:
        assert _cross_file_findings(lint, doc) == []


def test_projects_through_tendcf_projector(schemas: Schemas, projector) -> None:
    """The device-side projection accepts what the compiler rendered."""
    result = compile_host(_model(SITE), _host(SITE), schemas)
    raw = projector.project(json.loads(result.canonical))
    assert projector.validate_projection(raw) == []
    vars_ = json.loads(raw)["vars"]
    assert set(vars_) == {"tendcf_service", "tendcf_interlock"}
    assert vars_["tendcf_service"]["com.tendcf.example.tailscaled"]["state"] == "present"
    assert vars_["tendcf_service"]["com.tendcf.example.tailscaled"]["unit"]["launchd"]["domain"] == "system"


def test_multi_interlock_argv_passthrough_and_projection(
    schemas: Schemas, projector, lint
) -> None:
    """Issue #56 item 5: multi-interlock argv pass-through (shared + distinct bundles)."""
    model = _model(SITE)
    bundles = model.services.data["bundles"]
    # Add a second interlock on the same bundle (`fleet-vpn`) with distinct argv,
    # non-zero expect_exit, and custom timeout_seconds, plus a third interlock on
    # a distinct active bundle (`edge-http`) using the full interlock_argv alphabet.
    bundles["fleet-vpn"]["interlocks"].append(
        {
            "id": "tailscale-route-probe",
            "description": "Verify route table check returns expected sentinel exit code.",
            "pre_action": {
                "command": ["/usr/local/bin/tailscale", "netcheck", "--format=json", "--verbose=1"],
                "expect_exit": 2,
                "timeout_seconds": 7,
            },
            "defines_class": "tailscale_route_ok",
            "blocks": "enclosing-bundle",
            "report": True,
        }
    )
    bundles["edge-http"]["interlocks"] = [
        {
            "id": "edge-cert-fresh",
            "description": "Verify TLS certificate file is readable before starting edge-http.",
            "pre_action": {
                "command": ["/usr/bin/test", "-r", "/etc/caddy/cert_v1.pem", "a+b:c=d,e@f-g"],
                "expect_exit": 0,
                "timeout_seconds": 5,
            },
            "defines_class": "edge_cert_ready",
            "blocks": "enclosing-bundle",
            "report": True,
        }
    ]
    assert validate_site_model(model, schemas) == []

    result = compile_host(model, _host(SITE), schemas)
    doc = result.goal_file
    assert schemas.errors("goal-file.schema.json", doc) == []
    assert _cross_file_findings(lint, doc) == []

    ilks = doc["domains"]["supervision"]["entries"]["interlock"]
    assert set(ilks) == {
        "tailscale-authenticated-before-lockdown",
        "tailscale-route-probe",
        "edge-cert-fresh",
    }
    assert ilks["tailscale-authenticated-before-lockdown"] == {
        "state": "present",
        "bundle": "fleet-vpn",
        "pre_action": {
            "command": ["/usr/local/bin/tailscale", "status", "--json"],
            "expect_exit": 0,
            "timeout_seconds": 15,
        },
        "defines_class": "tailscale_authenticated",
        "blocks": "enclosing-bundle",
        "report": True,
    }
    assert ilks["tailscale-route-probe"] == {
        "state": "present",
        "bundle": "fleet-vpn",
        "pre_action": {
            "command": ["/usr/local/bin/tailscale", "netcheck", "--format=json", "--verbose=1"],
            "expect_exit": 2,
            "timeout_seconds": 7,
        },
        "defines_class": "tailscale_route_ok",
        "blocks": "enclosing-bundle",
        "report": True,
    }
    assert ilks["edge-cert-fresh"] == {
        "state": "present",
        "bundle": "edge-http",
        "pre_action": {
            "command": ["/usr/bin/test", "-r", "/etc/caddy/cert_v1.pem", "a+b:c=d,e@f-g"],
            "expect_exit": 0,
            "timeout_seconds": 5,
        },
        "defines_class": "edge_cert_ready",
        "blocks": "enclosing-bundle",
        "report": True,
    }

    projected_raw = projector.project(json.loads(result.canonical))
    assert projector.validate_projection(projected_raw) == []
    projected_ilks = json.loads(projected_raw)["vars"]["tendcf_interlock"]
    assert projected_ilks == ilks


def test_pure_and_order_independent(schemas: Schemas) -> None:
    a = compile_host(_model(SITE), _host(SITE), schemas).canonical
    model = _model(SITE)
    model.services.data["services"].reverse()
    b = compile_host(model, _host(SITE), schemas).canonical
    assert a == b


# --- merge rules --------------------------------------------------------------

def test_role_main_receives_backup_does_not(schemas: Schemas) -> None:
    model = _model(SITE)
    vps = _host(SITE, name="vps-1")
    result = compile_host(model, vps, schemas)
    assert "supervision" not in result.goal_file["domains"]  # nothing selected
    assert any("backup/peer of role 'llm-gateway'" in d for d in result.diagnostics)


def test_non_cfengine_service_is_skipped_loudly(schemas: Schemas) -> None:
    model = _model(SITE)
    model.services.data["services"][0]["managed_by"] = "external"
    result = compile_host(model, _host(SITE), schemas)
    assert "com.djbclark.caddy" not in result.goal_file["domains"]["supervision"]["entries"]["service"]
    assert any("managed_by 'external'" in d for d in result.diagnostics)


def test_service_platform_mismatch_refused(schemas: Schemas) -> None:
    with pytest.raises(CompileError) as exc:
        compile_host(_model(SITE), _host(SITE, platform="linux", supervisor="systemd"), schemas)
    assert "platform is 'macos' and the host is 'linux'" in str(exc.value)


def test_bad_host_key_refused(schemas: Schemas) -> None:
    host = HostSpec(
        name="mac", platform="macos", supervisor="launchd", key="ed25519:short", device_trust=_trust(SITE)
    )
    with pytest.raises(CompileError) as exc:
        compile_host(_model(SITE), host, schemas)
    assert "64 lowercase hex" in str(exc.value)


# --- supervisor (schema v4) -----------------------------------------------------------

def test_supervisor_is_written_when_the_document_omits_it(schemas: Schemas) -> None:
    host = _host(SITE, trust=_trust(SITE, None))
    assert "supervisor" not in host.device_trust["entries"]
    doc = compile_host(_model(SITE), host, schemas).goal_file
    assert doc["domains"]["device-trust"]["entries"]["supervisor"] == {"host": {"name": "launchd", "state": "present"}}
    assert "supervisor" not in host.device_trust["entries"]  # the input is not mutated


def test_supplied_supervisor_that_disagrees_is_refused(schemas: Schemas) -> None:
    host = _host(SITE, trust=_trust(SITE, "systemd"))  # document says systemd, host input says launchd
    with pytest.raises(CompileError) as exc:
        compile_host(_model(SITE), host, schemas)
    assert "carries supervisor entry" in str(exc.value) and "'systemd'" in str(exc.value)


def test_supplied_malformed_supervisor_is_refused(schemas: Schemas) -> None:
    trust = _trust(SITE)
    trust["entries"]["supervisor"] = {"main": {"name": "launchd", "state": "present"}}  # id is not `host`
    with pytest.raises(CompileError, match="carries supervisor entry"):
        compile_host(_model(SITE), _host(SITE, trust=trust), schemas)


def test_unknown_supervisor_refused(schemas: Schemas) -> None:
    with pytest.raises(CompileError) as exc:
        compile_host(_model(SITE), _host(SITE, platform="linux", supervisor="openrc"), schemas)
    assert "supervisor 'openrc' is not one of" in str(exc.value)
    assert "there is no default" in str(exc.value)


PAIRING = "Resolution: fix --platform or --supervisor"


@pytest.mark.parametrize(
    ("platform", "supervisor", "expected"),
    [
        ("macos", "systemd", PAIRING),
        ("macos", "nixos", PAIRING),
        ("linux", "launchd", PAIRING),
        ("android", "runit", "no supervisor is decided for that platform"),
    ],
)
def test_platform_supervisor_mismatch_refused(schemas: Schemas, platform: str, supervisor: str, expected: str) -> None:
    host = _host(SITE, platform=platform, supervisor=supervisor, trust=_trust(SITE, None))
    with pytest.raises(CompileError) as exc:
        compile_host(_model(SITE), host, schemas)
    assert expected in str(exc.value)
    assert (PAIRING in str(exc.value)) == (expected == PAIRING)  # the other row's message is not produced


def _declare_on(model: SiteModel, host: str) -> None:
    """Make every service of the example site apply to `host` on any platform."""
    for rec in model.services.data["services"]:
        rec["platform"] = "any"
        rec["hosts"] = [host]
        rec.pop("role", None)


def test_nixos_host_without_services_is_deliberately_unmanaged(tendcf: Path, schemas: Schemas, projector, lint) -> None:
    result = compile_host(_model(SITE), _nixos_host(), schemas)
    # tendcf's own passthrough fixture is the oracle (the cross-file lint is a
    # no-op on a file with no entries): drift in either repo shows up here.
    assert result.canonical == (tendcf / "deploy" / "linux" / "passthrough" / "goal-file.json").read_bytes()
    doc = result.goal_file
    assert doc["schema_version"] == GOAL_FILE_SCHEMA_VERSION == 9
    assert doc["domains"]["supervision"] == {"coverage": "deliberately-unmanaged"}
    assert doc["domains"]["device-trust"]["entries"]["supervisor"] == {"host": {"name": "nixos", "state": "present"}}
    assert set(doc["domains"]) == {"device-trust", "supervision"}  # no unit-writer registry travels
    assert schemas.errors("goal-file.schema.json", doc) == []
    assert _cross_file_findings(lint, doc) == []
    raw = projector.project(doc)
    assert raw == b'{"vars":{}}'
    assert projector.validate_projection(raw) == []
    _check_golden("nixos-get.goal-file.json", result.canonical)


def test_nixos_host_refuses_any_selected_service(schemas: Schemas) -> None:
    model = _model(SITE)
    _declare_on(model, "get")
    with pytest.raises(CompileError) as exc:
        compile_host(model, _nixos_host(), schemas)
    msg = str(exc.value)
    assert "host is nixos-supervised; its units are the Nix configuration's" in msg
    assert "'caddy'" in msg and "services.yml:" in msg


@pytest.mark.parametrize("supervisor", ["systemd", "runit"])
def test_unrendered_supervisor_refuses_selected_services_but_not_none(schemas: Schemas, supervisor: str) -> None:
    host = _host(SITE, name="get", platform="linux", supervisor=supervisor, trust=_trust(SITE, None))
    model = _model(SITE)
    _declare_on(model, "get")
    with pytest.raises(CompileError, match="unit renderer is not built"):
        compile_host(model, host, schemas)
    # With nothing selected it states the supervisor and nothing else.
    doc = compile_host(_model(SITE), host, schemas).goal_file
    assert doc["domains"]["device-trust"]["entries"]["supervisor"]["host"]["name"] == supervisor
    assert "supervision" not in doc["domains"]
    assert schemas.errors("goal-file.schema.json", doc) == []


def test_dpkg_writer_is_refused(schemas: Schemas) -> None:
    """`dpkg` left the unit-writer enum in v5 (a package claim is its only spelling)."""
    model = _model(SITE)
    writer = next(w for w in model.launchd_writers.data["writers"] if w.get("prefix") == "dev.mise.*")
    writer["writer"] = "dpkg"
    assert validate_site_model(model, schemas) != []
    with pytest.raises(CompileError, match="dpkg"):
        compile_host(model, _host(SITE), schemas)


def test_launchd_domain_three_values_and_system_default(schemas: Schemas, lint) -> None:
    model = _model(SITE)
    model.services.data["services"][0]["launchd"]["domain"] = "user-gui"
    model.services.data["services"][1]["launchd"]["domain"] = "user-background"
    # service[2] (tailscaled) leaves domain omitted -> resolves to "system"
    assert validate_site_model(model, schemas) == []
    doc = compile_host(model, _host(SITE), schemas).goal_file
    svcs = doc["domains"]["supervision"]["entries"]["service"]
    assert svcs["com.djbclark.caddy"]["unit"]["launchd"]["domain"] == "user-gui"
    assert svcs["com.djbclark.litellm"]["unit"]["launchd"]["domain"] == "user-background"
    assert svcs["com.tendcf.example.tailscaled"]["unit"]["launchd"]["domain"] == "system"
    assert _cross_file_findings(lint, doc) == []


def test_launchd_stale_v8_user_domain_refused() -> None:
    model = _model(SITE)
    model.services.data["services"][0]["launchd"]["domain"] = "user"
    with pytest.raises(CompileError) as exc:
        compile_host(model, _host(SITE), None)
    msg = str(exc.value)
    assert "stale v8 launchd.domain='user'" in msg
    assert "'user-gui'" in msg and "'user-background'" in msg


def test_launchd_invalid_domain_refused() -> None:
    model = _model(SITE)
    model.services.data["services"][0]["launchd"]["domain"] = "gui"
    with pytest.raises(CompileError, match="invalid launchd.domain='gui'"):
        compile_host(model, _host(SITE), None)


@pytest.mark.parametrize("domain", ["user-gui", "user-background"])
def test_launchd_user_domains_with_root_runs_as_refused(domain: str, schemas: Schemas) -> None:
    from tendcf.compile import render_goal_file, select_services

    model = _model(SITE)
    tailscaled = next(s for s in model.services.data["services"] if s["name"] == "tailscaled")
    tailscaled["launchd"]["domain"] = domain
    host = _host(SITE)
    with pytest.raises(CompileError) as exc:
        compile_host(model, host, None)
    msg = str(exc.value)
    assert f"launchd.domain={domain!r}" in msg
    assert "runs_as='root'" in msg

    with pytest.raises(CompileError, match="runs_as='root'"):
        compile_host(model, host, schemas)

    selected, _, _ = select_services(model, host)
    doc, errs = render_goal_file(model, host, selected)
    assert "com.tendcf.example.tailscaled" not in doc["domains"]["supervision"]["entries"].get("service", {})
    assert any(f"launchd.domain={domain!r}" in e and "runs_as='root'" in e for e in errs)


def test_render_goal_file_alone_refuses_stale_user_domain() -> None:
    from tendcf.compile import render_goal_file, select_services

    host = _host(SITE)
    model = _model(SITE)
    model.services.data["services"][0]["launchd"]["domain"] = "user"
    selected, _, _ = select_services(model, host)
    doc, errs = render_goal_file(model, host, selected)
    assert "com.djbclark.caddy" not in doc["domains"]["supervision"]["entries"].get("service", {})
    assert any("stale v8 launchd.domain='user'" in e for e in errs)


def test_exact_cfengine_label_covers_service(schemas: Schemas, lint) -> None:
    model = _model(SITE)
    model.launchd_writers.data["writers"].append(
        {"label": "org.example.exactsvc", "writer": "cfengine", "note": "Exact label witness."}
    )
    model.services.data["services"][0]["launchd"]["label"] = "org.example.exactsvc"
    assert validate_site_model(model, schemas) == []
    doc = compile_host(model, _host(SITE), schemas).goal_file
    assert doc["domains"]["supervision"]["entries"]["unit-writer"]["org.example.exactsvc"] == {
        "state": "present",
        "writer": "cfengine",
    }
    assert _cross_file_findings(lint, doc) == []


def test_duplicate_launchd_writer_key_refused(schemas: Schemas) -> None:
    model = _model(SITE)
    model.launchd_writers.data["writers"].append(
        {"prefix": "com.djbclark.*", "writer": "third-party", "note": "Duplicate prefix."}
    )
    with pytest.raises(CompileError) as exc:
        compile_host(model, _host(SITE), schemas)
    msg = str(exc.value)
    assert "launchd unit-writer 'com.djbclark.*' is declared twice" in msg
    assert "launchd-writers.yml" in msg
    assert "Resolution:" in msg


def test_overlapping_launchd_writer_prefix_and_label_refused(schemas: Schemas) -> None:
    model = _model(SITE)
    model.launchd_writers.data["writers"].append(
        {"label": "com.djbclark.caddy", "writer": "cfengine", "note": "Overlaps com.djbclark.*"}
    )
    with pytest.raises(CompileError) as exc:
        compile_host(model, _host(SITE), schemas)
    msg = str(exc.value)
    assert "overlaps 'com.djbclark.*'" in msg
    assert "matches 2 launchd unit-writers" in msg


def test_launchd_tendcf_install_wrong_label_refused(schemas: Schemas) -> None:
    model = _model(SITE)
    model.launchd_writers.data["writers"].append(
        {"label": "org.tendcf.other", "writer": "tendcf-install", "note": "Wrong exact label."}
    )
    with pytest.raises(CompileError) as exc:
        compile_host(model, _host(SITE), schemas)
    msg = str(exc.value)
    assert "org.tendcf.other" in msg
    assert "reserved exclusively for exact label 'org.tendcf.execd'" in msg


def _model_without_execd_writer(site: Path) -> SiteModel:
    model = _model(site)
    model.launchd_writers.data["writers"] = [
        w for w in model.launchd_writers.data["writers"]
        if w.get("label") != "org.tendcf.execd"
    ]
    return model


@pytest.mark.parametrize(
    "writer_entry",
    [
        {"prefix": "org.tendcf.*", "writer": "cfengine", "note": "Prefix covers org.tendcf.execd."},
        {"prefix": "Org.Tendcf.*", "writer": "cfengine", "note": "Case-variant prefix."},
        {"prefix": "org.Tendcf.*", "writer": "cfengine", "note": "Mixed-case prefix."},
        {"label": "org.tendcf.execd", "writer": "cfengine", "note": "Exact execd with cfengine."},
        {"label": "org.tendcf.execd", "writer": "third-party", "note": "Exact execd with third-party."},
        {"label": "ORG.TENDCF.EXECD", "writer": "cfengine", "note": "Uppercase exact with cfengine."},
        {"label": "ORG.TENDCF.EXECD", "writer": "tendcf-install", "note": "Uppercase exact with tendcf-install."},
        {"label": "org.tendcf.EXECD", "writer": "tendcf-install", "note": "Mixed-case exact with tendcf-install."},
    ],
)
def test_launchd_writer_covering_reserved_execd_refused(schemas: Schemas, writer_entry: dict[str, str]) -> None:
    model = _model_without_execd_writer(SITE)
    model.launchd_writers.data["writers"].append(writer_entry)
    with pytest.raises(CompileError) as exc:
        compile_host(model, _host(SITE), schemas)
    msg = str(exc.value)
    assert "reserved installer-owned label 'org.tendcf.execd'" in msg
    assert "Resolution:" in msg


@pytest.mark.parametrize(
    "bad_writer",
    [
        {"prefix": "org.tendcf.*", "label": "org.tendcf.execd", "writer": "tendcf-install"},
        {"prefix": "com.other.*", "label": "org.tendcf.execd", "writer": "tendcf-install"},
        {"writer": "cfengine"},
    ],
)
def test_launchd_writer_dual_or_missing_key_refused(bad_writer: dict[str, str]) -> None:
    from tendcf.compile import render_goal_file, select_services

    model = _model_without_execd_writer(SITE)
    model.launchd_writers.data["writers"].append(bad_writer)
    host = _host(SITE)

    with pytest.raises(CompileError) as exc:
        compile_host(model, host, None)
    assert "must declare exactly one of 'prefix' or 'label'" in str(exc.value)

    selected, _, _ = select_services(model, host)
    _, errs = render_goal_file(model, host, selected)
    assert any("must declare exactly one of 'prefix' or 'label'" in e for e in errs)


@pytest.mark.parametrize(
    "bad_label",
    [
        "org.tendcf.execd",
        "ORG.TENDCF.EXECD",
        "org.tendcf.EXECD",
        "tendcf-execd.service",
        "tendcf-execd",
        "tendcf-execd.timer",
        "tendcf-execd.socket",
        "tendcf-execd.path",
    ],
)
def test_service_targeting_reserved_installer_unit_refused(schemas: Schemas, bad_label: str) -> None:
    from tendcf.compile import render_goal_file, select_services

    model = _model(SITE)
    model.services.data["services"][0]["launchd"]["label"] = bad_label
    with pytest.raises(CompileError) as exc:
        compile_host(model, _host(SITE), schemas)
    msg = str(exc.value)
    assert bad_label in msg
    assert "reserved installer-owned unit" in msg
    assert "Resolution:" in msg

    # Direct render_goal_file() also refuses without relying on conflict_check().
    host = _host(SITE)
    selected, _, _ = select_services(model, host)
    doc, errs = render_goal_file(model, host, selected)
    assert doc == {}
    assert any("reserved installer-owned unit" in e and bad_label in e for e in errs)


@pytest.mark.parametrize(
    "bad_unit",
    ["tendcf-execd.service", "tendcf-execd", "tendcf-execd.timer", "tendcf-execd.socket", "tendcf-execd.path"],
)
def test_service_targeting_reserved_systemd_unit_refused_in_conflict_check(bad_unit: str) -> None:
    from tendcf.compile import conflict_check, select_services

    model = _model(SITE)
    model.services.data["services"][0]["systemd"] = {"unit": bad_unit}
    host = _host(SITE)
    selected, _, _ = select_services(model, host)
    errs, _ = conflict_check(model, host, selected)
    assert any(bad_unit in e and "reserved installer-owned unit" in e for e in errs)


def test_launchd_exact_execd_tendcf_install_v8_positive_control(schemas: Schemas, lint) -> None:
    result = compile_host(_model(SITE), _host(SITE), schemas)
    writers = result.goal_file["domains"]["supervision"]["entries"]["unit-writer"]
    assert writers["org.tendcf.execd"] == {"state": "present", "writer": "tendcf-install"}
    assert _cross_file_findings(lint, result.goal_file) == []


def test_render_goal_file_alone_refuses_unrendered_services() -> None:
    from tendcf.compile import render_goal_file, select_services

    model = _model(SITE)
    _declare_on(model, "get")
    host = _nixos_host()
    selected, _, _ = select_services(model, host)
    assert selected
    doc, errors = render_goal_file(model, host, selected)
    assert doc == {} and any("nixos-supervised" in e for e in errors)


def test_cli_platform_is_required_and_android_not_offered(tendcf: Path) -> None:
    base = ["compile", "--host", "mac", "--supervisor", "launchd", "--host-key", HOST_KEY,
            "--device-trust", str(SITE / "device-trust.json"), "--site", str(SITE)]
    missing = _run(base, tendcf)
    assert missing.returncode == 2 and b"--platform" in missing.stderr and missing.stdout == b""
    android = _run([*base, "--platform", "android"], tendcf)
    assert android.returncode == 2 and b"invalid choice" in android.stderr


def test_unsupported_schema_version_refused() -> None:
    with pytest.raises(CompileError, match="not one this compiler renders"):
        compile_host(_model(SITE), _host(SITE), None, schema_version=GOAL_FILE_SCHEMA_VERSION + 1)


# --- conflict check -------------------------------------------------------------

def test_duplicate_entry_id_names_both_writers(schemas: Schemas) -> None:
    model = _model(SITE)
    services = model.services.data["services"]
    services[1]["launchd"]["label"] = services[0]["launchd"]["label"]
    with pytest.raises(CompileError) as exc:
        compile_host(model, _host(SITE), schemas)
    msg = str(exc.value)
    assert "entry id 'com.djbclark.caddy'" in msg
    assert "'caddy'" in msg and "'litellm-proxy'" in msg
    assert "services.yml:" in msg  # source locations, not just names
    assert "Resolution:" in msg


def test_two_providers_of_one_token_refused(schemas: Schemas) -> None:
    model = _model(SITE)
    model.services.data["services"][1]["provides"].append("port:443")
    with pytest.raises(CompileError) as exc:
        compile_host(model, _host(SITE), schemas)
    assert "token 'port:443'" in str(exc.value)
    assert "Resolution:" in str(exc.value)


def test_mixed_domains_refused(schemas: Schemas) -> None:
    model = _model(SITE)
    doc = model.services.data
    doc["domains"]["second"] = {"description": "x"}
    doc["bundles"]["edge-http"]["domain"] = "second"
    doc["services"][0]["domain"] = "second"
    doc["services"][1]["domain"] = "second"
    with pytest.raises(CompileError) as exc:
        compile_host(model, _host(SITE), schemas)
    assert "2 Site Model domains" in str(exc.value)


def test_label_outside_declared_writers_refused(schemas: Schemas) -> None:
    model = _model(SITE)
    model.services.data["services"][0]["launchd"]["label"] = "com.rogue.caddy"
    with pytest.raises(CompileError) as exc:
        compile_host(model, _host(SITE), schemas)
    assert "falls under no prefix" in str(exc.value)


def test_interlock_without_defines_class_refused(schemas: Schemas) -> None:
    model = _model(SITE)
    del model.services.data["bundles"]["fleet-vpn"]["interlocks"][0]["defines_class"]
    with pytest.raises(CompileError) as exc:
        compile_host(model, _host(SITE), schemas)
    assert "no `defines_class`" in str(exc.value)


def test_unmatched_requires_is_a_note_not_a_refusal(schemas: Schemas) -> None:
    model = _model(SITE)
    model.services.data["services"][0]["requires"].append("service:nothing-provides-this")
    result = compile_host(model, _host(SITE), schemas)
    assert any("requires 'service:nothing-provides-this'" in d for d in result.diagnostics)


def test_yaml_duplicate_key_refused(tmp_path: Path) -> None:
    bad = tmp_path / "services.yml"
    bad.write_text("contract_version: 1\ncontract_version: 2\n")
    from tendcf.sitemodel import SiteModelError

    with pytest.raises(SiteModelError, match="duplicate key 'contract_version'"):
        load_document(bad)


def test_non_nfc_input_refused(schemas: Schemas) -> None:
    model = _model(SITE)
    model.services.data["services"][0]["command"].append("café")  # NFD é
    with pytest.raises(CompileError, match="NFC"):
        compile_host(model, _host(SITE), schemas)


# --- the command line -------------------------------------------------------------

def _run(args: list[str], tendcf: Path) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ, TENDCF_DIR=str(tendcf), PYTHONPATH=str(REPO))
    return subprocess.run([sys.executable, "-m", "tendcf.cli", *args], capture_output=True, env=env, check=False)


def test_cli_compile_matches_library(tendcf: Path, schemas: Schemas) -> None:
    proc = _run(
        ["compile", "--host", "mac", "--platform", "macos", "--supervisor", "launchd", "--host-key", HOST_KEY, "--device-trust", str(SITE / "device-trust.json"), "--site", str(SITE)],
        tendcf,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    assert proc.stdout == compile_host(_model(SITE), _host(SITE), schemas).canonical


def test_cli_project_matches_projector(tendcf: Path, schemas: Schemas, projector) -> None:
    proc = _run(
        ["compile", "--host", "mac", "--platform", "macos", "--supervisor", "launchd", "--host-key", HOST_KEY, "--device-trust", str(SITE / "device-trust.json"), "--site", str(SITE), "--project"],
        tendcf,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    expected = projector.project(compile_host(_model(SITE), _host(SITE), schemas).goal_file)
    assert proc.stdout == expected


def test_cli_requires_supervisor(tendcf: Path) -> None:
    proc = _run(
        ["compile", "--host", "mac", "--platform", "macos", "--host-key", HOST_KEY, "--device-trust", str(SITE / "device-trust.json"), "--site", str(SITE)],
        tendcf,
    )
    assert proc.returncode == 2 and b"--supervisor" in proc.stderr and proc.stdout == b""


def test_cli_nixos_host_projects_to_empty_vars(tendcf: Path, schemas: Schemas, projector, tmp_path: Path) -> None:
    trust = tmp_path / "device-trust.json"
    trust.write_text(json.dumps(_trust(SITE, None)))
    args = ["compile", "--host", "get", "--platform", "linux", "--supervisor", "nixos", "--host-key", HOST_KEY,
            "--device-trust", str(trust), "--site", str(SITE)]
    proc = _run(args, tendcf)
    assert proc.returncode == 0, proc.stderr.decode()
    assert proc.stdout == compile_host(_model(SITE), _nixos_host(), schemas).canonical
    projected = _run([*args, "--project"], tendcf)
    assert projected.returncode == 0, projected.stderr.decode()
    assert projected.stdout == projector.project(json.loads(proc.stdout)) == b'{"vars":{}}'


def test_cli_supervisor_disagreeing_with_document_exits_1(tendcf: Path) -> None:
    proc = _run(
        ["compile", "--host", "mac", "--supervisor", "systemd", "--platform", "linux", "--host-key", HOST_KEY,
         "--device-trust", str(SITE / "device-trust.json"), "--site", str(SITE)],
        tendcf,
    )
    assert proc.returncode == 1 and b"carries supervisor entry" in proc.stderr and proc.stdout == b""


def test_cli_refusal_exits_1(tendcf: Path, tmp_path: Path) -> None:
    site = tmp_path / "site"
    shutil.copytree(SITE, site)
    doc = yaml.safe_load((site / "services.yml").read_text())
    doc["services"][1]["launchd"]["label"] = doc["services"][0]["launchd"]["label"]
    (site / "services.yml").write_text(yaml.safe_dump(doc))
    proc = _run(
        ["compile", "--host", "mac", "--platform", "macos", "--supervisor", "launchd", "--host-key", HOST_KEY, "--device-trust", str(site / "device-trust.json"), "--site", str(site)],
        tendcf,
    )
    assert proc.returncode == 1
    assert b"REFUSED" in proc.stderr and proc.stdout == b""


def test_cli_schema_invalid_input_exits_1(tendcf: Path, tmp_path: Path) -> None:
    site = tmp_path / "site"
    shutil.copytree(SITE, site)
    doc = yaml.safe_load((site / "services.yml").read_text())
    doc["domains"]["macos-user-daemons"].pop("opt_out_reason")  # opt-out with no reason
    (site / "services.yml").write_text(yaml.safe_dump(doc))
    proc = _run(
        ["compile", "--host", "mac", "--platform", "macos", "--supervisor", "launchd", "--host-key", HOST_KEY, "--device-trust", str(site / "device-trust.json"), "--site", str(site)],
        tendcf,
    )
    assert proc.returncode == 1
    assert b"opt_out_reason" in proc.stderr


# --- where the CLI finds tendcf: --tendcf, then $TENDCF_DIR, then the enclosing checkout ---
# `_run` always sets TENDCF_DIR, so these use `_run_env` to leave it out or to
# set it to something other than the real checkout.

def _run_env(args: list[str], tendcf_dir: str | None) -> subprocess.CompletedProcess[bytes]:
    env = {k: v for k, v in os.environ.items() if k != "TENDCF_DIR"}
    env["PYTHONPATH"] = str(REPO)
    if tendcf_dir is not None:
        env["TENDCF_DIR"] = tendcf_dir
    return subprocess.run([sys.executable, "-m", "tendcf.cli", *args], capture_output=True, env=env, check=False)


def _compile_args(site: Path, *extra: str) -> list[str]:
    return ["compile", "--host", "mac", "--platform", "macos", "--supervisor", "launchd", "--host-key", HOST_KEY,
            "--device-trust", str(site / "device-trust.json"), "--site", str(site), *extra]


def test_cli_defaults_to_the_enclosing_checkout(schemas: Schemas, projector, tmp_path: Path) -> None:
    # No --tendcf and no TENDCF_DIR: --project works (it needs tools/projector.py) ...
    proc = _run_env(_compile_args(SITE, "--project"), None)
    assert proc.returncode == 0, proc.stderr.decode()
    assert proc.stdout == projector.project(compile_host(_model(SITE), _host(SITE), schemas).goal_file)
    assert b"NOT validated" not in proc.stderr
    # ... and validation is on: a schema-invalid Site Model is refused, not compiled.
    site = tmp_path / "site"
    shutil.copytree(SITE, site)
    doc = yaml.safe_load((site / "services.yml").read_text())
    doc["domains"]["macos-user-daemons"].pop("opt_out_reason")
    (site / "services.yml").write_text(yaml.safe_dump(doc))
    bad = _run_env(_compile_args(site), None)
    assert bad.returncode == 1 and b"opt_out_reason" in bad.stderr and bad.stdout == b""


def test_cli_tendcf_location_precedence(tendcf: Path, tmp_path: Path) -> None:
    empty = tmp_path / "no-schemas"  # a directory with an empty schema/ dir: using it fails loudly
    (empty / "schema").mkdir(parents=True)
    refused = b"no *.schema.json under " + str(empty).encode()
    # --tendcf beats TENDCF_DIR: the real one in the env does not rescue the bad flag ...
    flag = _run_env(_compile_args(SITE, "--tendcf", str(empty)), str(tendcf))
    assert flag.returncode == 2 and refused in flag.stderr and flag.stdout == b""
    # ... and the good flag beats a bad TENDCF_DIR.
    flag_ok = _run_env(_compile_args(SITE, "--tendcf", str(tendcf)), str(empty))
    assert flag_ok.returncode == 0, flag_ok.stderr.decode()
    # TENDCF_DIR beats the in-tree default: the enclosing checkout has schemas, the env's dir does not.
    env = _run_env(_compile_args(SITE), str(empty))
    assert env.returncode == 2 and refused in env.stderr and env.stdout == b""


def _checkout_shape(
    root: Path,
    *,
    projector: bool = True,
    pyproject: bool = True,
    schema: bool = True,
    plugins_dir: bool = True,
) -> Path:
    """Build <root>/compiler/tendcf/cli.py's surroundings; return the fake cli.py path."""
    (root / "compiler" / "tendcf").mkdir(parents=True)
    if pyproject:
        (root / "compiler" / "pyproject.toml").write_text("")
    if schema:
        (root / "schema").mkdir()
        (root / "schema" / "goal-file.schema.json").write_text("{}")
    if projector:
        (root / "tools").mkdir()
        (root / "tools" / "projector.py").write_text("")
    if plugins_dir:
        (root / "plugins").mkdir()
    return root / "compiler" / "tendcf" / "cli.py"


def test_in_tree_tendcf_accepts_only_a_real_checkout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from tendcf import cli

    # In this repository it is the root (compiler/ sits directly under it).
    assert cli._in_tree_tendcf() == REPO.parent
    # A full checkout shape is accepted ...
    good = tmp_path / "good"
    monkeypatch.setattr(cli, "__file__", str(_checkout_shape(good)))
    assert cli._in_tree_tendcf() == good
    # ... and each piece of the rule is needed.
    for name, kwargs in {
        "no-projector": {"projector": False},
        "no-pyproject": {"pyproject": False},
        "no-schema": {"schema": False},
        "no-plugins": {"plugins_dir": False},
    }.items():
        root = tmp_path / name
        monkeypatch.setattr(cli, "__file__", str(_checkout_shape(root, **kwargs)))
        assert cli._in_tree_tendcf() is None, name
    # The directory must be called compiler/.
    other = tmp_path / "other"
    _checkout_shape(other)
    (other / "compiler").rename(other / "elsewhere")
    monkeypatch.setattr(cli, "__file__", str(other / "elsewhere" / "tendcf" / "cli.py"))
    assert cli._in_tree_tendcf() is None
    # With no checkout and no TENDCF_DIR there is nothing to find (no validation, as before the default existed).
    monkeypatch.delenv("TENDCF_DIR", raising=False)
    assert cli._tendcf_dir(None) is None


def _plant_tendcf(root: Path) -> None:
    (root / "schema").mkdir(parents=True)
    (root / "schema" / "goal-file.schema.json").write_text("{}")
    (root / "tools").mkdir()
    (root / "tools" / "projector.py").write_text("")
    (root / "plugins").mkdir()


def test_in_tree_tendcf_none_for_site_packages_layout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from tendcf import cli

    # <tmp>/lib/python3.12/site-packages/tendcf/cli.py: parents[2] is lib/python3.12, which a
    # planted schema/, tools/projector.py, and plugins/ must not turn into a tendcf checkout.
    pyroot = tmp_path / "lib" / "python3.12"
    _plant_tendcf(pyroot)
    pkg = pyroot / "site-packages" / "tendcf"
    pkg.mkdir(parents=True)
    monkeypatch.setattr(cli, "__file__", str(pkg / "cli.py"))
    assert cli._in_tree_tendcf() is None


def test_in_tree_tendcf_none_for_pip_target_layout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from tendcf import cli

    # pip install --target <tmp>/pkgs (or PYTHONPATH=<tmp>/pkgs): parents[2] is <tmp>, which
    # anyone may have written to.
    _plant_tendcf(tmp_path)
    pkg = tmp_path / "pkgs" / "tendcf"
    pkg.mkdir(parents=True)
    monkeypatch.setattr(cli, "__file__", str(pkg / "cli.py"))
    assert cli._in_tree_tendcf() is None


def test_yaml_unhashable_key_refused_cleanly(tmp_path: Path) -> None:
    from tendcf.sitemodel import SiteModelError

    bad = tmp_path / "services.yml"
    bad.write_text("? [a, b]\n: 1\n")
    with pytest.raises(SiteModelError, match="not a scalar"):
        load_document(bad)


def test_cli_unhashable_key_exits_2_without_traceback(tendcf: Path, tmp_path: Path) -> None:
    site = tmp_path / "site"
    shutil.copytree(SITE, site)
    (site / "services.yml").write_text("? [a, b]\n: 1\n")
    proc = _run(_compile_args(site), tendcf)
    assert proc.returncode == 2 and b"not a scalar" in proc.stderr and b"Traceback" not in proc.stderr


# --- the Nix frontend hook ---------------------------------------------------------

@pytest.mark.skipif(shutil.which("nix-instantiate") is None, reason="no Nix install")
def test_nix_expression_equals_yaml(tendcf: Path) -> None:
    proc = _run(["eval-nix", str(SITE / "site.nix")], tendcf)
    assert proc.returncode == 0, proc.stderr.decode()
    assert json.loads(proc.stdout) == yaml.safe_load((SITE / "services.yml").read_text())


def test_eval_nix_without_nix_is_a_clean_error(tendcf: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "")
    proc = _run(["eval-nix", str(SITE / "site.nix")], tendcf)
    assert proc.returncode == 2
    assert b"nix-instantiate not found" in proc.stderr
