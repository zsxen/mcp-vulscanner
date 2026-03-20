"""Tests for the dynamic replay MVP."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mcp_vulscanner.dynamic import DynamicReplayEngine
from mcp_vulscanner.static import StaticAnalysisEngine


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "dynamic"


class DynamicReplayEngineTests(unittest.TestCase):
    """Verify deterministic replay verdicts for stdio MCP fixtures."""

    def setUp(self) -> None:
        """Create shared engines for each test."""

        self.static_engine = StaticAnalysisEngine()
        self.dynamic_engine = DynamicReplayEngine()
        self.vulnerable_server = FIXTURES_DIR / "stdio_vulnerable_server.py"
        findings = self.static_engine.analyze_target(self.vulnerable_server, mode="quick").findings
        self.findings_by_class = {
            finding.vulnerability_class: finding
            for finding in findings
            if finding.tool_name is not None
        }

    def test_replay_confirms_command_injection(self) -> None:
        """Command injection replay should observe subprocess execution."""

        trace = self.dynamic_engine.replay_stdio(
            ["python3", str(self.vulnerable_server)],
            self.findings_by_class["command-injection"],
        )

        self.assertEqual(trace.verdict, "CONFIRMED")
        self.assertTrue(trace.side_effects.spawned_subprocesses)
        self.assertTrue(Path(trace.trace_path).exists())

    def test_replay_confirms_ssrf(self) -> None:
        """SSRF replay should observe an outbound request to the mock server."""

        trace = self.dynamic_engine.replay_stdio(
            ["python3", str(self.vulnerable_server)],
            self.findings_by_class["ssrf"],
        )

        self.assertEqual(trace.verdict, "CONFIRMED")
        self.assertIn("/ssrf-proof", "".join(trace.side_effects.outbound_requests))

    def test_replay_confirms_file_write(self) -> None:
        """File-write replay should observe workspace file creation."""

        trace = self.dynamic_engine.replay_stdio(
            ["python3", str(self.vulnerable_server)],
            self.findings_by_class["arbitrary-file-write"],
        )

        self.assertEqual(trace.verdict, "CONFIRMED")
        self.assertIn("dynamic-proof/output.txt", trace.side_effects.file_diffs.created)

    def test_replay_marks_probable_when_guard_blocks_payload(self) -> None:
        """A guarded server should produce a PROBABLE verdict via stderr/error traces."""

        trace = self.dynamic_engine.replay_stdio(
            ["python3", str(FIXTURES_DIR / "stdio_guarded_server.py")],
            self.findings_by_class["command-injection"],
        )

        self.assertEqual(trace.verdict, "PROBABLE")
        self.assertTrue(trace.side_effects.stderr_lines)

    def test_replay_marks_unconfirmed_without_side_effects(self) -> None:
        """A safe server should result in UNCONFIRMED when no side effects occur."""

        trace = self.dynamic_engine.replay_stdio(
            ["python3", str(FIXTURES_DIR / "stdio_safe_server.py")],
            self.findings_by_class["arbitrary-file-write"],
        )

        self.assertEqual(trace.verdict, "UNCONFIRMED")
        self.assertEqual(trace.side_effects.file_diffs.created, [])

    def test_trace_is_valid_json(self) -> None:
        """Persisted traces should be parseable JSON."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            trace = self.dynamic_engine.replay_stdio(
                ["python3", str(self.vulnerable_server)],
                self.findings_by_class["ssrf"],
                trace_directory=Path(tmp_dir),
            )
            payload = json.loads(Path(trace.trace_path).read_text(encoding="utf-8"))

        self.assertEqual(payload["verdict"], "CONFIRMED")
        self.assertEqual(payload["transport"], "stdio")
