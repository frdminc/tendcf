"""Built-in YAML/JSON Site Model frontend (`plugins/frontends/yaml/loader.py`).

Loaded exclusively through tendcf's static in-tree plugin table
(`compiler/tendcf/plugins.py`).

Provides two guarantees plain `yaml.safe_load` / `json.loads` do not:
1. Source locations: records the 1-based line number of every YAML mapping so
   compiler conflict diagnostics cite `file:line`.
2. Duplicate keys refused: both YAML and JSON reject duplicate mapping keys
   at parse time instead of silently resolving last-wins.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PLUGIN_KIND = "frontend"
PLUGIN_NAME = "yaml"


class SiteModelError(Exception):
    """An input could not be read, parsed, or validated."""


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that records the source line of every mapping it builds."""

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        self.lines: dict[int, int] = {}

    def construct_yaml_map(self, node: yaml.MappingNode):  # type: ignore[override]
        data: dict[str, Any] = {}
        self.lines[id(data)] = node.start_mark.line + 1
        yield data
        data.update(self.construct_mapping(node))

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict:  # type: ignore[override]
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
            except TypeError:  # an unhashable key, e.g. `? [a, b]`
                raise SiteModelError(
                    f"mapping key {key!r} at line {key_node.start_mark.line + 1} is not a scalar — refused"
                ) from None
            if duplicate:
                raise SiteModelError(
                    f"duplicate key {key!r} at line {key_node.start_mark.line + 1} "
                    "— refused rather than resolved last-wins"
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


_LineLoader.add_constructor("tag:yaml.org,2002:map", _LineLoader.construct_yaml_map)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise SiteModelError(f"duplicate key {key!r} — refused rather than resolved last-wins")
        seen.add(key)
    return dict(pairs)


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


def load_document(path: Path) -> Document:
    """Parse a `.yml`/`.yaml` or `.json` file, refusing duplicate keys."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SiteModelError(f"cannot read {path}: {exc}") from exc
    if path.suffix == ".json":
        try:
            data = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        except json.JSONDecodeError as exc:
            raise SiteModelError(f"{path} is not JSON: {exc}") from exc
        return Document(path, data)
    loader = _LineLoader(raw)
    try:
        data = loader.get_single_data()
    except yaml.YAMLError as exc:
        raise SiteModelError(f"{path} is not YAML: {exc}") from exc
    finally:
        loader.dispose()
    return Document(path, data, loader.lines)


@dataclass
class SiteModel:
    services: Document
    roles: Document
    launchd_writers: Document


SITE_FILES = {
    "services": "services.yml",
    "roles": "roles.yml",
    "launchd_writers": "launchd-writers.yml",
}


def load_site_model(services: Path, roles: Path, launchd_writers: Path) -> SiteModel:
    return SiteModel(
        services=load_document(services),
        roles=load_document(roles),
        launchd_writers=load_document(launchd_writers),
    )
