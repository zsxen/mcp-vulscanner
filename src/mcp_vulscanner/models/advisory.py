"""Normalized advisory models for the research corpus."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


REQUIRED_STRING_FIELDS = (
    "project_name",
    "repo_url",
    "package_name",
    "ecosystem",
    "advisory_source",
    "advisory_url",
    "vulnerability_class",
    "transport_mode",
    "entrypoint_kind",
    "sink_kind",
)

OPTIONAL_STRING_FIELDS = ("ghsa_id", "cve_id", "notes")
LIST_FIELDS = ("affected_versions", "patched_versions")


@dataclass(frozen=True)
class NormalizedAdvisory:
    """A validated advisory descriptor ready for corpus export."""

    project_name: str
    repo_url: str
    package_name: str
    ecosystem: str
    advisory_source: str
    advisory_url: str
    ghsa_id: str | None
    cve_id: str | None
    vulnerability_class: str
    affected_versions: list[str]
    patched_versions: list[str]
    transport_mode: str
    entrypoint_kind: str
    sink_kind: str
    notes: str | None

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> "NormalizedAdvisory":
        """Validate a raw advisory mapping and build a normalized descriptor."""

        normalized: dict[str, Any] = {}
        for field_name in REQUIRED_STRING_FIELDS:
            normalized[field_name] = cls._require_non_empty_string(payload, field_name)
        for field_name in OPTIONAL_STRING_FIELDS:
            normalized[field_name] = cls._optional_string(payload.get(field_name), field_name)
        for field_name in LIST_FIELDS:
            normalized[field_name] = cls._string_list(payload.get(field_name), field_name)
        return cls(**normalized)

    @staticmethod
    def _require_non_empty_string(payload: dict[str, Any], field_name: str) -> str:
        """Require a non-empty string field."""

        value = payload.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Field '{field_name}' must be a non-empty string.")
        return value.strip()

    @staticmethod
    def _optional_string(value: Any, field_name: str) -> str | None:
        """Normalize optional string fields."""

        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"Field '{field_name}' must be a string or null.")
        stripped = value.strip()
        return stripped or None

    @staticmethod
    def _string_list(value: Any, field_name: str) -> list[str]:
        """Require a list of non-empty strings."""

        if not isinstance(value, list) or not value:
            raise ValueError(f"Field '{field_name}' must be a non-empty list of strings.")
        normalized_items: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"Field '{field_name}' must contain only non-empty strings.")
            normalized_items.append(item.strip())
        return normalized_items

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary."""

        return asdict(self)
