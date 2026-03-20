"""Tests for HTTP transport dynamic replay."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from mcp_vulscanner.dynamic import DynamicReplayEngine
from mcp_vulscanner.models.finding import StaticFinding


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "dynamic"


def _finding(tool_name: str) -> StaticFinding:
    """Build a minimal SSRF finding for replay tests."""

    return StaticFinding(
        rule_id="test.ssrf",
        vulnerability_class="ssrf",
        language="python",
        severity="high",
        confidence="high",
        file_path=str(FIXTURES_DIR / "placeholder.py"),
        line=1,
        tool_name=tool_name,
        sink="network-request",
        symbol=None,
        code_snippet=tool_name,
        score=6,
        evidence=[],
        message="fixture",
    )


class HttpDynamicReplayTests(unittest.TestCase):
    """Verify HTTP transport replay and request customization."""

    def setUp(self) -> None:
        """Create a replay engine and deterministic ports."""

        self.engine = DynamicReplayEngine()
        self.header_port = 18901
        self.base_url_port = 18902
        self.redirect_port = 18903

    def test_http_replay_confirms_header_based_ssrf(self) -> None:
        """HTTP replay should support custom headers and confirm SSRF."""

        trace = self.engine.replay_http(
            [
                sys.executable,
                str(FIXTURES_DIR / "http_header_ssrf_server.py"),
            ],
            endpoint=f"http://127.0.0.1:{self.header_port}/mcp",
            finding=_finding("fetch_with_headers"),
            headers={"X-SSRF-Probe": "header-proof"},
            trace_directory=Path(tempfile.mkdtemp(prefix="mcp-http-trace-")),
        )

        self.assertEqual(trace.transport, "http")
        self.assertEqual(trace.verdict, "CONFIRMED")
        self.assertTrue(
            any("x-ssrf-probe=header-proof" in item.lower() for item in trace.side_effects.outbound_requests)
        )

    def test_http_replay_confirms_base_url_override(self) -> None:
        """HTTP replay should allow alternate base URLs and query parameters."""

        trace = self.engine.replay_http(
            [
                sys.executable,
                str(FIXTURES_DIR / "http_base_url_ssrf_server.py"),
            ],
            endpoint=f"http://127.0.0.1:{self.base_url_port}/mcp",
            finding=_finding("fetch_with_base_url"),
            base_url_override="__MOCK_SERVER__",
            query_params={"trace": "base-url"},
            trace_directory=Path(tempfile.mkdtemp(prefix="mcp-http-trace-")),
        )

        self.assertEqual(trace.verdict, "CONFIRMED")
        self.assertTrue(any("trace=base-url" in item for item in trace.side_effects.outbound_requests))

    def test_http_replay_confirms_redirect_based_ssrf(self) -> None:
        """HTTP replay should confirm SSRF when the target follows redirects."""

        trace = self.engine.replay_http(
            [
                sys.executable,
                str(FIXTURES_DIR / "http_redirect_ssrf_server.py"),
            ],
            endpoint=f"http://127.0.0.1:{self.redirect_port}/mcp",
            finding=_finding("fetch_redirect"),
            trace_directory=Path(tempfile.mkdtemp(prefix="mcp-http-trace-")),
        )

        self.assertEqual(trace.verdict, "CONFIRMED")
        self.assertTrue(any("/redirect-landing" in item for item in trace.side_effects.outbound_requests))

    def test_http_trace_preserves_schema(self) -> None:
        """HTTP traces should use the same JSON structure as stdio traces."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            trace = self.engine.replay_http(
                [
                    sys.executable,
                    str(FIXTURES_DIR / "http_header_ssrf_server.py"),
                ],
                endpoint=f"http://127.0.0.1:{self.header_port}/mcp",
                finding=_finding("fetch_with_headers"),
                headers={"X-SSRF-Probe": "schema-check"},
                trace_directory=Path(tmp_dir),
            )
            payload = json.loads(Path(trace.trace_path).read_text(encoding="utf-8"))

        self.assertEqual(payload["transport"], "http")
        self.assertEqual(payload["verdict"], "CONFIRMED")
        self.assertIn("rpc_records", payload)
