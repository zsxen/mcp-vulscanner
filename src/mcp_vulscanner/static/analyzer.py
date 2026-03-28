"""Top-level orchestration for the static-analysis MVP."""

from __future__ import annotations

from pathlib import Path
from collections import Counter

from mcp_vulscanner.models.finding import ScanReport

from .base import StaticAnalyzer, classify_scope_reason, collect_source_files, finalize_finding
from .javascript import JavaScriptAnalyzer
from .python import PythonAnalyzer


class StaticAnalysisEngine:
    """Coordinate language-specific analyzers behind a common interface."""

    def __init__(self, analyzers: list[StaticAnalyzer] | None = None) -> None:
        """Initialize the engine with registered analyzers."""

        self._analyzers = analyzers or [JavaScriptAnalyzer(), PythonAnalyzer()]

    def analyze_target(
        self,
        target: Path,
        *,
        mode: str,
        include_vendor: bool = False,
        include_tests: bool = False,
    ) -> ScanReport:
        """Analyze a file or directory and return a structured report."""

        resolved_target = target.resolve()
        if not resolved_target.exists():
            raise ValueError(f"Scan target does not exist: {resolved_target}")

        raw_findings = []
        for source_file in collect_source_files(resolved_target, self._analyzers):
            analyzer = next(
                item for item in self._analyzers if item.language == source_file.language
            )
            for match in analyzer.analyze(source_file):
                finding = finalize_finding(source_file, match)
                raw_findings.append(finding)

        raw_findings = _deduplicate_findings(raw_findings)
        scoped_findings = []
        suppression_reasons: Counter[str] = Counter()
        for finding in raw_findings:
            suppression_reason = (
                finding.suppression_reason
                or classify_scope_reason(
                    Path(finding.file_path),
                    include_vendor=include_vendor,
                    include_tests=include_tests,
                )
            )
            if suppression_reason:
                suppression_reasons[suppression_reason] += 1
                continue
            scoped_findings.append(finding)

        scoped_findings.sort(
            key=lambda item: (
                item.vulnerability_class,
                item.file_path,
                item.line,
                item.rule_id,
            )
        )
        return ScanReport(
            target=str(resolved_target),
            mode=mode,
            findings=scoped_findings,
            raw_findings=len(raw_findings),
            scope_excluded_findings=len(raw_findings) - len(scoped_findings),
            suppression_reasons=dict(sorted(suppression_reasons.items())),
        )


def _deduplicate_findings(findings: list) -> list:
    """Deduplicate findings that resolve to the same sink location."""

    deduplicated = {}
    for finding in findings:
        key = (
            finding.rule_id,
            finding.file_path,
            finding.line,
            finding.tool_name,
            finding.suppression_reason,
        )
        deduplicated.setdefault(key, finding)
    return list(deduplicated.values())
