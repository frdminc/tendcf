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

Hardening enforced before launching `nix-instantiate`:
- Rejects empty/whitespace/NUL paths (never lets `Path("")` silently become CWD).
- Rejects `=` and `:` in `allowed_dir` so Nix `-I` (`<prefix>=<path>` / `:` list
  syntax) can never widen `restrict-eval`'s `allowedPaths`.
- Refuses symlinked `recipe_dir`, symlinked `candidate.parent`, and any symlink
  along the path from `allowed_dir` down to the target recipe file.
- Isolates Nix env (`NIX_PATH=""`, empty `NIX_CONF_DIR` & `NIX_USER_CONF_FILES`,
  unset `NIX_CONFIG`), closes stdin (`DEVNULL`), and bounds execution with a
  finite timeout (default 300 s, matching `tests/nix/run_nix_eval.py`).
"""

from __future__ import annotations

import json
import math
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PLUGIN_KIND = "frontend"
PLUGIN_NAME = "nix"
FRONTEND_DISPLAY_NAME = "nix2cf"

DEFAULT_TIMEOUT_SECONDS = 300.0

# Tested D-b Nix evaluation limits (docs/architecture/plugin-layout.md §4 item 3).
NIX_RESTRICTED_OPTIONS: tuple[tuple[str, str], ...] = (
    ("restrict-eval", "true"),
    ("allow-import-from-derivation", "false"),
    ("allowed-uris", ""),
    ("allow-unsafe-native-code-during-evaluation", "false"),
)


class NixEvalError(Exception):
    """Restricted Nix evaluation could not start, failed, timed out, or returned invalid JSON."""


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


def _reject_symlink_components_within(base_dir: Path, raw_target: Path) -> None:
    """Reject any symlink on the target leaf or any directory between `base_dir` and `raw_target`."""
    try:
        st_leaf = os.lstat(raw_target)
    except OSError as exc:
        raise NixEvalError(f"cannot inspect Nix recipe {raw_target}: {exc}") from exc
    if stat.S_ISLNK(st_leaf.st_mode):
        raise NixEvalError(
            f"Nix recipe must be a regular non-symlink file: {raw_target}"
        )
    if not stat.S_ISREG(st_leaf.st_mode):
        raise NixEvalError(f"Nix recipe is not a regular file: {raw_target}")

    # Walk logical parent directories up to `base_dir` (comparing resolved paths
    # to stop at `base_dir`) and reject any symlinked directory on the way.
    logical_abs = Path(os.path.abspath(str(raw_target)))
    cur = logical_abs.parent
    seen: set[Path] = set()
    while cur not in seen:
        seen.add(cur)
        try:
            st_cur = os.lstat(cur)
        except OSError as exc:
            raise NixEvalError(f"cannot inspect directory {cur}: {exc}") from exc
        if stat.S_ISLNK(st_cur.st_mode):
            raise NixEvalError(
                f"Nix recipe path traverses a symlinked directory (refused): {cur}"
            )
        try:
            if cur.resolve(strict=True) == base_dir:
                return
        except (OSError, RuntimeError) as exc:
            raise NixEvalError(f"cannot resolve directory {cur}: {exc}") from exc
        if cur.parent == cur:
            break
        cur = cur.parent


def _resolve_recipe_paths(
    file_path: Path | str,
    *,
    recipe_dir: Path | str | None = None,
) -> tuple[Path, Path]:
    """Resolve and verify `(allowed_dir, resolved_file)` without escaping or widening `-I`."""
    if isinstance(file_path, str):
        raw_file = file_path
    else:
        raw_file = str(file_path)
    if not raw_file.strip() or "\x00" in raw_file:
        raise NixEvalError("Nix recipe path must not be empty or contain NUL bytes")
    candidate = Path(raw_file)
    if ".." in candidate.parts:
        raise NixEvalError(f"Nix recipe path must not contain '..' traversal segments: {candidate}")

    if recipe_dir is not None:
        raw_dir = recipe_dir if isinstance(recipe_dir, str) else str(recipe_dir)
        if not raw_dir.strip() or "\x00" in raw_dir:
            raise NixEvalError("recipe_dir must not be empty or contain NUL bytes")
        dir_candidate = Path(raw_dir)
        if ".." in dir_candidate.parts:
            raise NixEvalError(f"recipe_dir must not contain '..' traversal segments: {dir_candidate}")
        try:
            st_dir = os.lstat(dir_candidate)
        except OSError as exc:
            raise NixEvalError(f"cannot inspect recipe directory {dir_candidate}: {exc}") from exc
        if stat.S_ISLNK(st_dir.st_mode):
            raise NixEvalError(
                f"recipe_dir must be a real non-symlink directory: {dir_candidate}"
            )
        if not stat.S_ISDIR(st_dir.st_mode):
            raise NixEvalError(f"recipe directory is not a directory: {dir_candidate}")
        try:
            allowed_dir = dir_candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise NixEvalError(f"cannot resolve recipe directory {dir_candidate}: {exc}") from exc
    else:
        parent_candidate = candidate.parent
        try:
            st_parent = os.lstat(parent_candidate)
        except OSError as exc:
            raise NixEvalError(
                f"cannot inspect recipe directory for {candidate}: {exc}"
            ) from exc
        if stat.S_ISLNK(st_parent.st_mode):
            raise NixEvalError(
                f"Nix recipe parent directory must not be a symlink: {parent_candidate}"
            )
        if not stat.S_ISDIR(st_parent.st_mode):
            raise NixEvalError(f"recipe directory is not a directory: {parent_candidate}")
        try:
            allowed_dir = parent_candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise NixEvalError(
                f"cannot resolve recipe directory for {candidate}: {exc}"
            ) from exc

    allowed_str = str(allowed_dir)
    if "=" in allowed_str or ":" in allowed_str:
        raise NixEvalError(
            f"recipe directory {allowed_dir} contains '=' or ':' which is forbidden "
            "in nix-instantiate -I (prefix=path / search-path delimiter injection)"
        )

    _reject_symlink_components_within(allowed_dir, candidate)

    try:
        resolved_file = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise NixEvalError(f"cannot resolve Nix recipe {candidate}: {exc}") from exc

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
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Any:
    """Evaluate `file_path` under restricted `nix-instantiate` and return parsed JSON."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise NixEvalError(f"timeout must be a positive finite number, got {timeout!r}")

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
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                env=run_env,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise NixEvalError(
                f"nix-instantiate timed out after {timeout}s evaluating {resolved_file}"
            ) from exc
        except OSError as exc:
            raise NixEvalError(f"failed to run nix-instantiate: {exc}") from exc

    if proc.returncode != 0:
        detail = proc.stderr.rstrip("\n")
        raise NixEvalError(detail or f"nix-instantiate exited {proc.returncode}")

    try:
        return json.loads(proc.stdout, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise NixEvalError(f"nix-instantiate did not return JSON: {exc}") from exc
