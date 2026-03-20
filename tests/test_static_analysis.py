"""Fixture-based tests for the static-analysis MVP."""

from __future__ import annotations

import json
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from mcp_vulscanner.cli import main
from mcp_vulscanner.static import StaticAnalysisEngine


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "static"


class StaticAnalysisEngineTests(unittest.TestCase):
    """Verify language-specific detection and patched behavior."""

    def setUp(self) -> None:
        """Create a reusable analysis engine."""

        self.engine = StaticAnalysisEngine()

    def test_javascript_vulnerable_fixture_triggers_all_target_classes(self) -> None:
        """Vulnerable JS fixture should produce all three target classes."""

        report = self.engine.analyze_target(FIXTURES_DIR / "js" / "vulnerable", mode="quick")
        classes = {finding.vulnerability_class for finding in report.findings}

        self.assertEqual(
            classes,
            {"command-injection", "ssrf", "arbitrary-file-write"},
        )

    def test_python_vulnerable_fixture_triggers_all_target_classes(self) -> None:
        """Vulnerable Python fixture should produce all three target classes."""

        report = self.engine.analyze_target(FIXTURES_DIR / "python" / "vulnerable", mode="quick")
        classes = {finding.vulnerability_class for finding in report.findings}

        self.assertEqual(
            classes,
            {"command-injection", "ssrf", "arbitrary-file-write"},
        )

    def test_patched_fixtures_do_not_trigger_target_findings(self) -> None:
        """Patched fixtures should avoid the sink patterns used by the MVP rules."""

        js_report = self.engine.analyze_target(FIXTURES_DIR / "js" / "patched", mode="quick")
        py_report = self.engine.analyze_target(FIXTURES_DIR / "python" / "patched", mode="quick")

        self.assertEqual(js_report.findings, [])
        self.assertEqual(py_report.findings, [])

    def test_cli_scan_quick_outputs_structured_json(self) -> None:
        """The CLI should render JSON findings for scan quick."""

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            exit_code = main(["scan", "quick", str(FIXTURES_DIR / "js" / "vulnerable")])

        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["mode"], "quick")
        self.assertGreaterEqual(payload["finding_count"], 3)
        self.assertTrue(
            all("score" in finding["static_finding"] for finding in payload["findings"])
        )
