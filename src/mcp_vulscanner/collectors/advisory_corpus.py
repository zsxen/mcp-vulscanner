"""Load manually curated advisory descriptors into a normalized corpus."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_vulscanner.models.advisory import NormalizedAdvisory


SUPPORTED_EXTENSIONS = {".json", ".yaml", ".yml"}


@dataclass(frozen=True)
class DatasetSyncSummary:
    """Summary returned after building the advisory corpus."""

    descriptor_count: int
    source_directory: Path
    output_path: Path
    by_vulnerability_class: dict[str, int]
    by_ecosystem: dict[str, int]


def sync_advisory_corpus(project_root: Path) -> DatasetSyncSummary:
    """Validate advisory descriptors and write the normalized corpus JSON."""

    advisories_dir = project_root / "data" / "advisories"
    corpus_dir = project_root / "data" / "corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)

    descriptors = load_advisory_descriptors(advisories_dir)
    output_path = corpus_dir / "advisory-corpus.json"
    output_path.write_text(
        json.dumps([descriptor.to_dict() for descriptor in descriptors], indent=2) + "\n",
        encoding="utf-8",
    )

    vuln_counts = Counter(item.vulnerability_class for item in descriptors)
    ecosystem_counts = Counter(item.ecosystem for item in descriptors)
    return DatasetSyncSummary(
        descriptor_count=len(descriptors),
        source_directory=advisories_dir,
        output_path=output_path,
        by_vulnerability_class=dict(sorted(vuln_counts.items())),
        by_ecosystem=dict(sorted(ecosystem_counts.items())),
    )


def load_advisory_descriptors(advisories_dir: Path) -> list[NormalizedAdvisory]:
    """Load, validate, and normalize all advisory descriptor files."""

    if not advisories_dir.exists():
        raise ValueError(f"Advisory directory does not exist: {advisories_dir}")

    advisory_files = sorted(
        path
        for path in advisories_dir.iterdir()
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS
    )
    if not advisory_files:
        raise ValueError(f"No advisory descriptor files found in {advisories_dir}")

    descriptors: list[NormalizedAdvisory] = []
    for path in advisory_files:
        payload = parse_descriptor_file(path)
        if not isinstance(payload, dict):
            raise ValueError(f"{path} must contain a top-level object.")
        try:
            descriptor = NormalizedAdvisory.from_mapping(payload)
        except ValueError as exc:
            raise ValueError(f"{path}: {exc}") from exc
        descriptors.append(descriptor)

    return sorted(descriptors, key=_descriptor_sort_key)


def parse_descriptor_file(path: Path) -> dict[str, Any]:
    """Parse a descriptor file based on its extension."""

    raw_text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".json":
        return json.loads(raw_text)
    if suffix in {".yaml", ".yml"}:
        return parse_simple_yaml(raw_text)
    raise ValueError(f"Unsupported descriptor format: {path.suffix}")


def parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse a small YAML subset used by curated advisory descriptors."""

    data: dict[str, Any] = {}
    current_list_key: str | None = None

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw_line.startswith("  - "):
            if current_list_key is None:
                raise ValueError(f"Line {line_number}: list item without a preceding key.")
            list_value = data.get(current_list_key)
            if not isinstance(list_value, list):
                raise ValueError(f"Line {line_number}: key '{current_list_key}' is not a list.")
            list_value.append(_parse_scalar(stripped[2:].strip()))
            continue
        if ":" not in raw_line:
            raise ValueError(f"Line {line_number}: expected 'key: value' mapping.")

        key, _, value = raw_line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError(f"Line {line_number}: key cannot be empty.")
        if not value:
            data[key] = []
            current_list_key = key
            continue

        data[key] = _parse_scalar(value)
        current_list_key = None

    return data


def _parse_scalar(value: str) -> Any:
    """Parse a scalar YAML token into a Python value."""

    if value in {"null", "Null", "NULL", "~"}:
        return None
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def _descriptor_sort_key(descriptor: NormalizedAdvisory) -> tuple[str, str, str]:
    """Provide deterministic ordering for the merged corpus."""

    return (
        descriptor.ecosystem.lower(),
        descriptor.package_name.lower(),
        descriptor.advisory_url.lower(),
    )
