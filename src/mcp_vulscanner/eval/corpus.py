"""Minimal corpus validation for paper-ready evaluation targets."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REQUIRED_FIELDS = (
    "target_id",
    "project_name",
    "repo_url",
    "language",
    "transport_mode",
    "startup_command",
    "vulnerability_class",
    "expected_label",
    "advisory_id",
    "pinned_ref",
    "setup_notes",
)
VALID_LABELS = {"positive", "negative"}


@dataclass(frozen=True)
class CorpusSummary:
    """Compact validation summary for the evaluation corpus."""

    target_count: int
    by_vulnerability_class: dict[str, int]
    by_expected_label: dict[str, int]


def validate_corpus(project_root: Path) -> CorpusSummary:
    """Validate corpus manifests and return grouped counts."""

    targets_path = project_root / "data" / "corpus" / "targets.json"
    ground_truth_path = project_root / "data" / "corpus" / "ground-truth.json"
    targets_payload = json.loads(targets_path.read_text(encoding="utf-8"))
    ground_truth_payload = json.loads(ground_truth_path.read_text(encoding="utf-8"))

    if not isinstance(targets_payload, list) or not targets_payload:
        raise ValueError("data/corpus/targets.json must contain a non-empty list.")
    if not isinstance(ground_truth_payload, list) or not ground_truth_payload:
        raise ValueError("data/corpus/ground-truth.json must contain a non-empty list.")

    seen_ids: set[str] = set()
    targets_by_id: dict[str, dict[str, Any]] = {}
    for item in targets_payload:
        if not isinstance(item, dict):
            raise ValueError("Each target entry must be an object.")
        normalized = _validate_target(item)
        target_id = normalized["target_id"]
        if target_id in seen_ids:
            raise ValueError(f"Duplicate target_id: {target_id}")
        seen_ids.add(target_id)
        targets_by_id[target_id] = normalized

    truth_ids: set[str] = set()
    for item in ground_truth_payload:
        if not isinstance(item, dict):
            raise ValueError("Each ground-truth entry must be an object.")
        target_id = item.get("target_id")
        expected_label = item.get("expected_label")
        if not isinstance(target_id, str) or not target_id.strip():
            raise ValueError("Each ground-truth entry must include a non-empty target_id.")
        if expected_label not in VALID_LABELS:
            raise ValueError("Each ground-truth entry must include a valid expected_label.")
        if target_id not in targets_by_id:
            raise ValueError(f"Ground-truth target_id not found in targets.json: {target_id}")
        if targets_by_id[target_id]["expected_label"] != expected_label:
            raise ValueError(f"Mismatched expected_label for target_id: {target_id}")
        truth_ids.add(target_id)

    if truth_ids != set(targets_by_id):
        missing = sorted(set(targets_by_id) - truth_ids)
        raise ValueError(f"Missing ground-truth entries for: {', '.join(missing)}")

    vuln_counts = Counter(item["vulnerability_class"] for item in targets_by_id.values())
    label_counts = Counter(item["expected_label"] for item in targets_by_id.values())
    return CorpusSummary(
        target_count=len(targets_by_id),
        by_vulnerability_class=dict(sorted(vuln_counts.items())),
        by_expected_label=dict(sorted(label_counts.items())),
    )


def _validate_target(payload: dict[str, Any]) -> dict[str, str]:
    """Validate one compact target manifest entry."""

    normalized: dict[str, str] = {}
    for field_name in REQUIRED_FIELDS:
        value = payload.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Field '{field_name}' must be a non-empty string.")
        normalized[field_name] = value.strip()
    if normalized["expected_label"] not in VALID_LABELS:
        raise ValueError("Field 'expected_label' must be 'positive' or 'negative'.")
    return normalized
