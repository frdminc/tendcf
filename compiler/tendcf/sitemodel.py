"""Site Model data contract, schema validation, and lazy YAML frontend bridge.

`SiteModelError`, `Document`, `SiteModel`, and `SITE_FILES` live directly in
this module so exception and dataclass identity never split across plugin
reloads and importing `tendcf.cli` executes ZERO plugin code until a Site Model
is actually loaded (`load_document` / `load_site_model`).

YAML/JSON parsing (source-line tracking and duplicate-key refusal) lives in
the built-in YAML frontend plugin (`plugins/frontends/yaml/loader.py`), loaded
lazily through `tendcf.plugins.load_plugin("frontend", "yaml")`.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from .plugins import load_plugin


class SiteModelError(Exception):
    """An input could not be read, parsed, or validated."""


@dataclass
class Document:
    """A parsed input file plus the line of every mapping in it."""

    path: Path
    data: Any
    lines: dict[int, int] = field(default_factory=dict)

    def line_of(self, mapping: Any) -> int | None:
        return self.lines.get(id(mapping))

    def where(self, mapping: Any) -> str:
        line = self.line_of(mapping)
        return f"{self.path}:{line}" if line else str(self.path)


@dataclass
class SiteModel:
    services: Document
    roles: Document
    launchd_writers: Document


SITE_FILES: dict[str, str] = {
    "services": "services.yml",
    "roles": "roles.yml",
    "launchd_writers": "launchd-writers.yml",
}
# Site Model file -> the tendcf schema that checks it.
SCHEMA_FOR: dict[str, str] = {
    "services": "services.schema.json",
    "roles": "roles.schema.json",
    "launchd_writers": "launchd-writers.schema.json",
}
GOAL_FILE_SCHEMA = "goal-file.schema.json"


def load_document(path: Path, *, tendcf_root: Path | None = None) -> Document:
    """Parse a `.yml`/`.yaml` or `.json` file via the in-tree YAML frontend plugin."""
    yaml_plugin = load_plugin("frontend", "yaml", tendcf_root=tendcf_root)
    return yaml_plugin.load_document(path)


def load_site_model(
    services: Path,
    roles: Path,
    launchd_writers: Path,
    *,
    tendcf_root: Path | None = None,
) -> SiteModel:
    """Load all three Site Model documents via the in-tree YAML frontend plugin."""
    yaml_plugin = load_plugin("frontend", "yaml", tendcf_root=tendcf_root)
    return yaml_plugin.load_site_model(services, roles, launchd_writers)


class Schemas:
    """tendcf's `schema/` directory, loaded into one `$ref` registry.

    The registry is built the way `tools/schema_lint.py` builds its own,
    from each schema's `$id`, so a `$ref` across files resolves identically
    here and in the lint. Refuses symlinked `schema_dir` or symlinked/escaping
    `*.schema.json` files.
    """

    def __init__(self, schema_dir: Path) -> None:
        try:
            st_dir = os.lstat(schema_dir)
        except OSError as exc:
            raise SiteModelError(f"cannot inspect schema directory {schema_dir}: {exc}") from exc
        if stat.S_ISLNK(st_dir.st_mode) or not stat.S_ISDIR(st_dir.st_mode):
            raise SiteModelError(f"schema directory must be a real non-symlink directory: {schema_dir}")
        try:
            resolved_dir = schema_dir.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise SiteModelError(f"cannot resolve schema directory {schema_dir}: {exc}") from exc

        self.schema_dir = resolved_dir
        self.schemas: dict[str, dict] = {}
        registry: Registry = Registry()
        paths = sorted(resolved_dir.glob("*.schema.json"))
        if not paths:
            raise SiteModelError(f"no *.schema.json under {schema_dir}")
        for path in paths:
            try:
                st_file = os.lstat(path)
            except OSError as exc:
                raise SiteModelError(f"cannot inspect schema {path}: {exc}") from exc
            if stat.S_ISLNK(st_file.st_mode) or not stat.S_ISREG(st_file.st_mode):
                raise SiteModelError(
                    f"schema file must be a real non-symlink regular file: {path}"
                )
            try:
                resolved_file = path.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise SiteModelError(f"cannot resolve schema {path}: {exc}") from exc
            if resolved_file.parent != resolved_dir:
                raise SiteModelError(
                    f"schema file {path} resolves outside {resolved_dir}: {resolved_file}"
                )
            try:
                schema = json.loads(resolved_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise SiteModelError(f"cannot read schema {path}: {exc}") from exc
            if "$id" not in schema:
                raise SiteModelError(f"{path} has no $id — relative $refs cannot resolve")
            self.schemas[path.name] = schema
            registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
        self.registry = registry

    def validator(self, name: str) -> Draft202012Validator:
        if name not in self.schemas:
            raise SiteModelError(f"tendcf has no schema named {name} under {self.schema_dir}")
        return Draft202012Validator(
            self.schemas[name], registry=self.registry, format_checker=FormatChecker()
        )

    def errors(self, name: str, instance: Any) -> list[str]:
        """Every validation error as `pointer: message`, best-first."""
        validator = self.validator(name)
        found = []
        for err in sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path)):
            pointer = "/" + "/".join(str(p) for p in err.absolute_path)
            found.append(f"{pointer}: {err.message}")
        return found


def validate_site_model(model: SiteModel, schemas: Schemas) -> list[str]:
    """Schema-validate every Site Model file; returns findings (empty = OK)."""
    findings: list[str] = []
    for attr, schema_name in SCHEMA_FOR.items():
        doc: Document = getattr(model, attr)
        for err in schemas.errors(schema_name, doc.data):
            findings.append(f"{doc.path}: {err}")
    return findings
