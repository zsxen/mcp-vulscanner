"""Common interfaces and helpers for rule-based static analyzers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol

from mcp_vulscanner.models.finding import EvidenceFeature, StaticFinding


RISKY_SCHEMA_FIELDS = ("cmd", "command", "url", "path", "download_path", "base_url")
RISKY_DESCRIPTION_TERMS = ("shell", "network", "download", "fetch", "http", "url")


@dataclass(frozen=True)
class SourceFile:
    """A source file selected for static analysis."""

    path: Path
    language: str
    content: str


@dataclass(frozen=True)
class RuleMatch:
    """A low-level match produced by a language-specific rule."""

    rule_id: str
    vulnerability_class: str
    line: int
    tool_name: str | None
    sink: str
    symbol: str | None
    snippet: str
    evidence: list[EvidenceFeature]
    message: str


class StaticAnalyzer(Protocol):
    """A common interface for language-specific analyzers."""

    language: str

    def supports(self, path: Path) -> bool:
        """Return whether this analyzer can process the file."""

    def analyze(self, source_file: SourceFile) -> list[RuleMatch]:
        """Analyze a source file and return low-level rule matches."""


def collect_source_files(target: Path, analyzers: Iterable[StaticAnalyzer]) -> list[SourceFile]:
    """Collect source files for all registered analyzers under a target."""

    paths: list[Path]
    if target.is_file():
        paths = [target]
    else:
        paths = sorted(path for path in target.rglob("*") if path.is_file())

    source_files: list[SourceFile] = []
    analyzers_list = list(analyzers)
    for path in paths:
        analyzer = next((item for item in analyzers_list if item.supports(path)), None)
        if analyzer is None:
            continue
        source_files.append(
            SourceFile(
                path=path,
                language=analyzer.language,
                content=path.read_text(encoding="utf-8"),
            )
        )
    return source_files


def finalize_finding(source_file: SourceFile, match: RuleMatch) -> StaticFinding:
    """Convert a low-level rule match into a structured finding."""

    score = sum(feature.score for feature in match.evidence)
    if score >= 6:
        severity = "high"
        confidence = "high"
    elif score >= 4:
        severity = "medium"
        confidence = "medium"
    else:
        severity = "low"
        confidence = "medium"

    return StaticFinding(
        rule_id=match.rule_id,
        vulnerability_class=match.vulnerability_class,
        language=source_file.language,
        severity=severity,
        confidence=confidence,
        file_path=str(source_file.path),
        line=match.line,
        tool_name=match.tool_name,
        sink=match.sink,
        symbol=match.symbol,
        code_snippet=match.snippet,
        score=score,
        evidence=match.evidence,
        message=match.message,
    )


def score_features(source_text: str, snippet: str) -> list[EvidenceFeature]:
    """Apply the shared scoring model to a matched sink."""

    evidence: list[EvidenceFeature] = []
    lowered_text = source_text.lower()
    lowered_snippet = snippet.lower()

    if "inputschema" in lowered_text or "argumentsschema" in lowered_text or "tool(" in lowered_text:
        evidence.append(
            EvidenceFeature(
                name="tool-input-to-sink",
                score=3,
                detail="File appears to define MCP tool inputs alongside the matched sink.",
            )
        )

    risky_fields = [
        field
        for field in RISKY_SCHEMA_FIELDS
        if re.search(rf"\b{re.escape(field)}\b", lowered_text)
    ]
    if risky_fields:
        evidence.append(
            EvidenceFeature(
                name="risky-parameter-name",
                score=2,
                detail=f"Schema or code references risky parameter names: {', '.join(sorted(set(risky_fields)))}.",
            )
        )

    risky_terms = [term for term in RISKY_DESCRIPTION_TERMS if term in lowered_text]
    if risky_terms or any(term in lowered_snippet for term in RISKY_DESCRIPTION_TERMS):
        evidence.append(
            EvidenceFeature(
                name="risky-description",
                score=1,
                detail="Descriptions or nearby code mention shell, network, or download behavior.",
            )
        )

    return evidence


def infer_tool_name(source_text: str, match_offset: int) -> str | None:
    """Infer the nearest preceding tool registration name for a sink match."""

    tool_pattern = re.compile(r"\btool\s*\(\s*[\"'](?P<name>[^\"']+)[\"']")
    tool_name: str | None = None
    for matched in tool_pattern.finditer(source_text):
        if matched.start() > match_offset:
            break
        tool_name = matched.group("name")
    return tool_name
