"""Top-level orchestration for the static-analysis MVP."""

from __future__ import annotations

from pathlib import Path

from mcp_vulscanner.models.finding import ScanReport

from .base import StaticAnalyzer, collect_source_files, finalize_finding
from .javascript import JavaScriptAnalyzer
from .python import PythonAnalyzer


class StaticAnalysisEngine:
    """Coordinate language-specific analyzers behind a common interface."""

    def __init__(self, analyzers: list[StaticAnalyzer] | None = None) -> None:
        """Initialize the engine with registered analyzers."""

        self._analyzers = analyzers or [JavaScriptAnalyzer(), PythonAnalyzer()]

    def analyze_target(self, target: Path, *, mode: str) -> ScanReport:
        """Analyze a file or directory and return a structured report."""

        resolved_target = target.resolve()
        if not resolved_target.exists():
            raise ValueError(f"Scan target does not exist: {resolved_target}")

        findings = []
        for source_file in collect_source_files(resolved_target, self._analyzers):
            analyzer = next(
                item for item in self._analyzers if item.language == source_file.language
            )
            findings.extend(
                finalize_finding(source_file, match) for match in analyzer.analyze(source_file)
            )

        findings.sort(
            key=lambda item: (
                item.vulnerability_class,
                item.file_path,
                item.line,
                item.rule_id,
            )
        )
        return ScanReport(target=str(resolved_target), mode=mode, findings=findings)
