"""Focused tests for compact corpus validation."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from mcp_vulscanner.cli import main
from mcp_vulscanner.eval import validate_corpus


class EvalCorpusValidationTests(unittest.TestCase):
    """Verify minimal corpus validation and CLI summary output."""

    def test_validate_corpus_accepts_seed_manifests(self) -> None:
        """The checked-in paper corpus should validate and report expected counts."""

        summary = validate_corpus(Path(__file__).resolve().parents[1])
        self.assertEqual(summary.target_count, 10)
        self.assertEqual(summary.by_expected_label, {"negative": 4, "positive": 6})

    def test_validate_corpus_cli_prints_grouped_summary(self) -> None:
        """The CLI should print concise grouped counts for the corpus."""

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            exit_code = main(["eval", "validate-corpus"])

        self.assertEqual(exit_code, 0)
        output = buffer.getvalue()
        self.assertIn("Validated 10 corpus targets.", output)
        self.assertIn("By vulnerability_class:", output)
        self.assertIn("By expected_label:", output)
