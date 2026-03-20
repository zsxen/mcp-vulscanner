"""Unit tests for the CLI scaffold."""

from __future__ import annotations

import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from mcp_vulscanner.cli import main


class CliTests(unittest.TestCase):
    """Verify that the stub CLI routes commands correctly."""

    def run_cli(self, *argv: str) -> tuple[int, str]:
        """Execute the CLI and capture stdout."""

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            exit_code = main(argv)
        return exit_code, buffer.getvalue().strip()

    def test_dataset_sync_stub(self) -> None:
        """The dataset sync command should build a corpus and print a summary."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            advisories_dir = root / "data" / "advisories"
            corpus_dir = root / "data" / "corpus"
            advisories_dir.mkdir(parents=True)
            corpus_dir.mkdir(parents=True)
            payload = {
                "project_name": "demo-project",
                "repo_url": "https://github.com/example/demo-project",
                "package_name": "demo-project",
                "ecosystem": "npm",
                "advisory_source": "manual-curation",
                "advisory_url": "https://github.com/example/demo-project/security",
                "ghsa_id": None,
                "cve_id": None,
                "vulnerability_class": "ssrf",
                "affected_versions": ["<1.0.0"],
                "patched_versions": [">=1.0.0"],
                "transport_mode": "http",
                "entrypoint_kind": "url-fetch",
                "sink_kind": "outbound-request",
                "notes": "Fixture entry.",
            }
            (advisories_dir / "demo.json").write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            exit_code, output = self.run_cli("dataset", "sync", "--root", str(root))
            self.assertTrue((root / "data" / "corpus" / "advisory-corpus.json").exists())

        self.assertEqual(exit_code, 0)
        self.assertIn("Validated 1 advisory descriptors", output)
        self.assertIn("By vulnerability_class:", output)

    def test_scan_quick_stub(self) -> None:
        """The quick scan command should output a structured JSON report."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "server.py"
            target.write_text("def ok():\n    return None\n", encoding="utf-8")
            exit_code, output = self.run_cli("scan", "quick", str(target))

        self.assertEqual(exit_code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["mode"], "quick")
        self.assertEqual(payload["finding_count"], 0)

    def test_scan_deep_stub(self) -> None:
        """The deep scan command should output a structured JSON report."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "server.ts"
            target.write_text("export function ok() { return true; }\n", encoding="utf-8")
            exit_code, output = self.run_cli("scan", "deep", str(target))

        self.assertEqual(exit_code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["mode"], "deep")
        self.assertEqual(payload["finding_count"], 0)

    def test_report_render_stub(self) -> None:
        """The report render command should echo the input path."""

        exit_code, output = self.run_cli("report", "render", "findings.json")
        self.assertEqual(exit_code, 0)
        self.assertIn("findings.json", output)


if __name__ == "__main__":
    unittest.main()
