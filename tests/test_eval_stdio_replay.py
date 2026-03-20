"""End-to-end test for the minimal paper stdio replay path."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from mcp_vulscanner.eval.stdio_replay import run_stdio_replay


FIXTURE = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "dynamic" / "paper_stdio_vulnerable_server.py"


class MinimalStdioReplayTests(unittest.TestCase):
    """Verify the minimal paper replay flow end to end."""

    def test_minimal_stdio_replay_confirms_file_write(self) -> None:
        """Running the vulnerable fixture should confirm a file write and save artifacts."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            result = run_stdio_replay(
                target_id="paper-fixture-1",
                command=f"{sys.executable} {FIXTURE}",
                tool_name="write_file",
                arguments={"path": "proof/output.txt", "content": "paper"},
                static_findings_count=1,
                output_dir=Path(tmp_dir),
            )
            trace_payload = json.loads(Path(result.trace_path).read_text(encoding="utf-8"))
            self.assertTrue(Path(result.report_path).exists())

        self.assertEqual(result.verdict, "CONFIRMED")
        self.assertTrue(result.dynamic_attempted)
        self.assertIn("proof/output.txt", result.evidence["created_files"])
        self.assertEqual(trace_payload["result"]["target_id"], "paper-fixture-1")
