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
    reachable: bool = True
    suppression_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the finding."""

        return asdict(self)


@dataclass(frozen=True)
class ScanReport:
    """A JSON-friendly report for a static scan."""

    target: str
    mode: str
    findings: list[StaticFinding]
    raw_findings: int = 0
    scope_excluded_findings: int = 0
    suppression_reasons: dict[str, int] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the report."""

        return {
            "target": self.target,
            "mode": self.mode,
            "raw_findings": self.raw_findings or len(self.findings),
            "scope_excluded_findings": self.scope_excluded_findings,
            "scoped_findings": len(self.findings),
            "finding_count": len(self.findings),
            "suppression_reasons": self.suppression_reasons or {},
            "findings": [finding.to_dict() for finding in self.findings],
        }
