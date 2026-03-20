"""Tests for paper table rendering utilities."""

from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from mcp_vulscanner.eval import render_outputs


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "eval" / "sample-results.json"


class EvalTableRenderingTests(unittest.TestCase):
    """Verify Markdown, LaTeX, and CSV outputs for evaluation results."""

    def test_render_outputs_writes_all_artifacts(self) -> None:
        """Renderer should write Markdown, LaTeX, and CSV summaries."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            outputs = render_outputs(FIXTURE_PATH, Path(tmp_dir))
            markdown = outputs["markdown"].read_text(encoding="utf-8")
            latex = outputs["latex"].read_text(encoding="utf-8")
            with outputs["csv"].open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.reader(handle))

        self.assertIn("mcp-server-kubernetes", markdown)
        self.assertIn("Static Findings", markdown)
        self.assertIn(r"\begin{tabular}", latex)
        self.assertIn("Static$\\rightarrow$Hybrid", latex)
        self.assertEqual(rows[0][0], "project_name")
        self.assertEqual(len(rows), 4)

    def test_render_outputs_includes_expected_metrics(self) -> None:
        """Rendered artifacts should contain recall, confirmation, and FP rates."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            outputs = render_outputs(FIXTURE_PATH, Path(tmp_dir))
            markdown = outputs["markdown"].read_text(encoding="utf-8")
            csv_text = outputs["csv"].read_text(encoding="utf-8")

        self.assertIn("Recall", markdown)
        self.assertIn("Confirmation Rate", markdown)
        self.assertIn("False Positive Rate", markdown)
        self.assertIn("75.0%", markdown)
        self.assertIn("100.0%", csv_text)
