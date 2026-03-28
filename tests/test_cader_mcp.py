"""Focused tests for CADER-MCP differential replay."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from mcp_vulscanner.dynamic import DynamicReplayEngine
from mcp_vulscanner.models.finding import StaticFinding
from mcp_vulscanner.self_audit import SelfAuditWorkflow


FIXTURES = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "dynamic"


def _finding(vulnerability_class: str, tool_name: str | None) -> StaticFinding:
    return StaticFinding(
        rule_id=f"test.{vulnerability_class}",
        vulnerability_class=vulnerability_class,
        language="python",
        severity="high",
        confidence="high",
        file_path=str(FIXTURES / "cader_stdio_server.py"),
        line=1,
        tool_name=tool_name,
        sink="test-sink",
        symbol=None,
        code_snippet=tool_name or "",
        score=6,
        evidence=[],
        message="fixture",
    )


class _DummyStaticEngine:
    def __init__(self, findings: list[StaticFinding]) -> None:
        self._findings = findings

    def analyze_target(self, target: Path, mode: str):  # noqa: ANN001
        return type("Report", (), {"findings": self._findings})()


class CaderMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = DynamicReplayEngine()

    def test_command_injection_confirmation(self) -> None:
        trace = self.engine.replay_stdio(
            [sys.executable, str(FIXTURES / "cader_stdio_server.py")],
            _finding("command-injection", "run_command"),
        )
        self.assertEqual(trace.verdict, "CONFIRMED")
        self.assertTrue(trace.baseline_attempt is not None)
        self.assertTrue(trace.malicious_attempts)

    def test_filesystem_allowed_root_vs_escape_differential_replay(self) -> None:
        trace = self.engine.replay_stdio(
            [sys.executable, str(FIXTURES / "cader_stdio_server.py")],
            _finding("arbitrary-file-write", "write_rooted"),
        )
        self.assertEqual(trace.verdict, "CONFIRMED")
        self.assertTrue(trace.runtime_contract is not None)
        self.assertTrue(trace.runtime_contract.roots_supported)
        self.assertTrue(trace.runtime_contract.roots_changed)

    def test_fetch_like_ssrf_differential_replay(self) -> None:
        trace = self.engine.replay_http(
            [sys.executable, str(FIXTURES / "cader_http_server.py")],
            "http://127.0.0.1:18921/mcp",
            _finding("ssrf", "fetch_url"),
        )
        self.assertEqual(trace.verdict, "CONFIRMED")
        self.assertTrue(trace.runtime_contract is not None)
        self.assertEqual(trace.runtime_contract.session_metadata.get("session_id"), "session-2")

    def test_root_bootstrap_lifecycle_correctness(self) -> None:
        trace = self.engine.replay_stdio(
            [sys.executable, str(FIXTURES / "cader_stdio_server.py")],
            _finding("arbitrary-file-write", "write_rooted"),
        )
        self.assertTrue(trace.runtime_contract is not None)
        self.assertIn("allowed-root", "".join(trace.runtime_contract.roots))
        self.assertTrue(any(log["phase"] == "baseline" for log in trace.replay_logs or []))

    def test_non_replayable_finding_suppression(self) -> None:
        workflow = SelfAuditWorkflow(
            static_engine=_DummyStaticEngine(
                [
                    _finding("arbitrary-file-write", "write_rooted"),
                    _finding("command-injection", "missing_tool"),
                ]
            )
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            report = workflow.run_deep(FIXTURES / "cader_stdio_server.py", output_dir=Path(tmp_dir))
        self.assertEqual(report.raw_findings, 2)
        self.assertEqual(report.scoped_findings, 2)
        self.assertEqual(report.replayable_findings, 1)
        self.assertEqual(report.confirmed_findings, 1)
        self.assertEqual(report.differential_confirmation_rate, 1.0)
