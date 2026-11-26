"""In-tree Nix frontend (`nix2cf`, `plugins/frontends/nix/eval.py`).

Loaded exclusively through tendcf's static in-tree plugin table
(`compiler/tendcf/plugins.py`).

Evaluates a Nix expression to Site Model JSON via `nix-instantiate` under the
restricted evaluation limits proven in `tests/nix/run_nix_eval.py` and required
by `docs/architecture/plugin-layout.md` §4 item 3 (decision D-b):

  nix-instantiate --eval --strict --json \
    --option restrict-eval true \
    --option allow-import-from-derivation false \
    --option allowed-uris '' \
    --option allow-unsafe-native-code-during-evaluation false \
    -I <RECIPE_DIR> <RECIPE_FILE>

With isolated Nix environment variables (`NIX_PATH=""`, empty `NIX_CONF_DIR`
and `NIX_USER_CONF_FILES`, `NIX_CONFIG` unset), never `--impure`, and refusing
any target recipe file that resolves outside `<RECIPE_DIR>`.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PLUGIN_KIND = "frontend"
PLUGIN_NAME = "nix2cf"

# Tested D-b Nix evaluation limits (docs/architecture/plugin-layout.md §4 item 3).
NIX_RESTRICTED_OPTIONS: tuple[tuple[str, str], ...] = (
    ("restrict-eval", "true"),
    ("allow-import-from-derivation", "false"),
    ("allowed-uris", ""),
    ("allow-unsafe-native-code-during-evaluation", "false"),
)


class NixEvalError(Exception):
    """Restricted Nix evaluation could not start, failed, or returned invalid JSON."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise NixEvalError(f"nix-instantiate output has duplicate JSON key {key!r}")
        seen.add(key)
    return dict(pairs)


def build_nix_eval_argv(exe: str, allowed_dir: Path, recipe_file: Path) -> list[str]:
    """Return the exact restricted `nix-instantiate` argv (never `--impure`)."""
    argv = [exe, "--eval", "--strict", "--json"]
    for opt_name, opt_val in NIX_RESTRICTED_OPTIONS:
        argv.extend(["--option", opt_name, opt_val])
    argv.extend(["-I", str(allowed_dir), str(recipe_file)])
    return argv


def _resolve_recipe_paths(
    file_path: Path | str,
    *,
    recipe_dir: Path | str | None = None,
) -> tuple[Path, Path]:
    """Resolve and verify `(allowed_dir, resolved_file)` without escaping `allowed_dir`."""
    raw_file = str(file_path)
    if not raw_file.strip() or "\x00" in raw_file:
        raise NixEvalError("Nix recipe path must not be empty or contain NUL bytes")
    candidate = Path(raw_file)

    if recipe_dir is not None:
        raw_dir = str(recipe_dir)
        if not raw_dir.strip() or "\x00" in raw_dir:
            raise NixEvalError("recipe_dir must not be empty or contain NUL bytes")
        try:
            allowed_dir = Path(raw_dir).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise NixEvalError(f"cannot resolve recipe directory {recipe_dir}: {exc}") from exc
    else:
        try:
            allowed_dir = candidate.parent.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise NixEvalError(f"cannot resolve recipe directory for {candidate}: {exc}") from exc

    if not allowed_dir.is_dir():
        raise NixEvalError(f"recipe directory is not a directory: {allowed_dir}")

    try:
        resolved_file = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise NixEvalError(f"cannot resolve Nix recipe {candidate}: {exc}") from exc

    try:
        st = os.stat(resolved_file)
    except OSError as exc:
        raise NixEvalError(f"cannot stat Nix recipe {resolved_file}: {exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise NixEvalError(f"Nix recipe is not a regular file: {resolved_file}")

    if not resolved_file.is_relative_to(allowed_dir) or resolved_file == allowed_dir:
        raise NixEvalError(
            f"Nix recipe {candidate} resolves to {resolved_file}, outside allowed directory {allowed_dir}"
        )

    return allowed_dir, resolved_file


def eval_nix_file(
    file_path: Path | str,
    *,
    recipe_dir: Path | str | None = None,
    nix_instantiate: str | None = None,
    env: Mapping[str, str] | None = None,
) -> Any:
    """Evaluate `file_path` under restricted `nix-instantiate` and return parsed JSON."""
    base_env = dict(os.environ if env is None else env)
    exe = nix_instantiate if nix_instantiate is not None else shutil.which(
        "nix-instantiate", path=base_env.get("PATH")
    )
    if not exe:
        raise NixEvalError(
            "nix-instantiate not found on PATH; the Nix frontend needs a Nix install"
        )

    allowed_dir, resolved_file = _resolve_recipe_paths(file_path, recipe_dir=recipe_dir)

    with tempfile.TemporaryDirectory(prefix="tendcf-nix-conf.") as td:
        empty_dir = Path(td) / "conf.d"
        empty_dir.mkdir()
        empty_conf = Path(td) / "empty.conf"
        empty_conf.write_text("", encoding="utf-8")

        run_env = dict(base_env)
        run_env["NIX_PATH"] = ""
        run_env["NIX_CONF_DIR"] = str(empty_dir)
        run_env["NIX_USER_CONF_FILES"] = str(empty_conf)
        run_env.pop("NIX_CONFIG", None)

        argv = build_nix_eval_argv(exe, allowed_dir, resolved_file)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                env=run_env,
                check=False,
            )
        except OSError as exc:
            raise NixEvalError(f"failed to run nix-instantiate: {exc}") from exc

    if proc.returncode != 0:
        detail = proc.stderr.rstrip("\n")
        raise NixEvalError(detail or f"nix-instantiate exited {proc.returncode}")

    try:
        return json.loads(proc.stdout, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise NixEvalError(f"nix-instantiate did not return JSON: {exc}") from exc
