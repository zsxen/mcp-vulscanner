"""Structured finding models for static analysis results."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class EvidenceFeature:
    """A scoring feature that contributed to a finding."""

    name: str
    score: int
    detail: str


@dataclass(frozen=True)
class StaticFinding:
    """A normalized static-analysis finding."""

    rule_id: str
    vulnerability_class: str
    language: str
    severity: str
    confidence: str
    file_path: str
    line: int
    tool_name: str | None
    sink: str
    symbol: str | None
    code_snippet: str
    score: int
    evidence: list[EvidenceFeature]
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the finding."""

        return asdict(self)


@dataclass(frozen=True)
class ScanReport:
    """A JSON-friendly report for a static scan."""

    target: str
    mode: str
    findings: list[StaticFinding]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the report."""

        return {
            "target": self.target,
            "mode": self.mode,
            "finding_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
        }
