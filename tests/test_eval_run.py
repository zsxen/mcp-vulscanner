"""Focused test for the minimal batch evaluation runner."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mcp_vulscanner.eval.run import run_batch


MANIFEST = Path(__file__).resolve().parents[1] / "data" / "corpus" / "targets.json"


class EvalBatchRunnerTests(unittest.TestCase):
    """Verify aggregate output from the minimal batch runner."""

    def test_run_batch_writes_aggregate_results(self) -> None:
        """Hybrid batch runs should write an aggregate JSON compatible with the table renderer."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            summary = run_batch(MANIFEST, mode="hybrid", output_root=Path(tmp_dir))
            aggregate_path = Path(summary["aggregate_path"])
            payload = json.loads(aggregate_path.read_text(encoding="utf-8"))

        self.assertIn("projects", payload)
        self.assertTrue(payload["projects"])
        self.assertTrue(all("project_name" in item for item in payload["projects"]))
        self.assertTrue(all("static_findings" in item for item in payload["projects"]))
