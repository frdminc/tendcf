"""Load and validate Site Model inputs.

YAML/JSON loading (with source-line tracking and duplicate-key refusal) lives
in the built-in YAML frontend plugin (`plugins/frontends/yaml/loader.py`),
loaded exclusively through tendcf's static in-tree plugin table
(`tendcf.plugins.load_plugin`). This module re-exports the YAML frontend's
types/loaders and provides JSON Schema validation against `schema/*.schema.json`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from .plugins import load_plugin

_YAML_FRONTEND = load_plugin("frontend", "yaml")

SiteModelError = _YAML_FRONTEND.SiteModelError
Document = _YAML_FRONTEND.Document
SiteModel = _YAML_FRONTEND.SiteModel
SITE_FILES: dict[str, str] = _YAML_FRONTEND.SITE_FILES
load_document = _YAML_FRONTEND.load_document
load_site_model = _YAML_FRONTEND.load_site_model

# Site Model file -> the tendcf schema that checks it.
SCHEMA_FOR = {
    "services": "services.schema.json",
    "roles": "roles.schema.json",
    "launchd_writers": "launchd-writers.schema.json",
}
GOAL_FILE_SCHEMA = "goal-file.schema.json"


class Schemas:
    """tendcf's `schema/` directory, loaded into one `$ref` registry.

    The registry is built the way `tools/schema_lint.py` builds its own,
    from each schema's `$id`, so a `$ref` across files resolves identically
    here and in the lint.
    """

    def __init__(self, schema_dir: Path) -> None:
        self.schema_dir = schema_dir
        self.schemas: dict[str, dict] = {}
        registry: Registry = Registry()
        paths = sorted(schema_dir.glob("*.schema.json"))
        if not paths:
            raise SiteModelError(f"no *.schema.json under {schema_dir}")
        for path in paths:
            try:
                schema = json.loads(path.read_text(encoding="utf-8"))
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
