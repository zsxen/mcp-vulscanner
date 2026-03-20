"""Tests for self-audit gate decisions and report generation."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from mcp_vulscanner.self_audit import SelfAuditWorkflow


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "dynamic"
STATIC_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "static"


class SelfAuditWorkflowTests(unittest.TestCase):
    """Verify quick/deep gate decisions and artifact outputs."""

    def setUp(self) -> None:
        """Create a workflow for each test."""

        self.workflow = SelfAuditWorkflow()

    def test_quick_scan_blocks_on_high_severity_finding(self) -> None:
        """Quick scan should BLOCK when static analysis finds high-severity issues."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            report = self.workflow.run_quick(
                STATIC_FIXTURES_DIR / "python" / "vulnerable",
                output_dir=Path(tmp_dir),
            )
            self.assertTrue(Path(report.markdown_report_path).exists())
            self.assertTrue(Path(report.json_report_path).exists())

        self.assertEqual(report.gate, "BLOCK")

    def test_quick_scan_passes_clean_fixture(self) -> None:
        """Quick scan should PASS when no findings are present."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            report = self.workflow.run_quick(
                STATIC_FIXTURES_DIR / "python" / "patched",
                output_dir=Path(tmp_dir),
            )

        self.assertEqual(report.gate, "PASS")

    def test_deep_scan_blocks_when_replay_confirms_finding(self) -> None:
        """Deep scan should BLOCK when dynamic replay confirms a high-priority issue."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            report = self.workflow.run_deep(
                FIXTURES_DIR / "stdio_vulnerable_server.py",
                output_dir=Path(tmp_dir),
            )

        self.assertEqual(report.gate, "BLOCK")
        self.assertTrue(report.reproduced_findings)
        self.assertTrue(
            any(
                finding.replay_trace and finding.replay_trace.verdict == "CONFIRMED"
                for finding in report.reproduced_findings
            )
        )

    def test_deep_scan_warns_when_high_severity_is_not_confirmed(self) -> None:
        """Deep scan should WARN when high-severity findings remain unreproduced."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "scan-config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "source_path": str(FIXTURES_DIR / "stdio_vulnerable_server.py"),
                        "replay": {
                            "transport": "stdio",
                            "command": [sys.executable, str(FIXTURES_DIR / "stdio_safe_server.py")],
                        },
                    }
                ),
                encoding="utf-8",
            )
            report = self.workflow.run_deep(config_path, output_dir=Path(tmp_dir) / "reports")

        self.assertEqual(report.gate, "WARN")

    def test_deep_scan_report_contains_remediation_guidance(self) -> None:
        """Generated JSON reports should include remediation guidance per finding."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            report = self.workflow.run_deep(
                FIXTURES_DIR / "stdio_vulnerable_server.py",
                output_dir=Path(tmp_dir),
            )
            payload = json.loads(Path(report.json_report_path).read_text(encoding="utf-8"))

        self.assertTrue(payload["findings"])
        self.assertTrue(all(item["remediation_guidance"] for item in payload["findings"]))
