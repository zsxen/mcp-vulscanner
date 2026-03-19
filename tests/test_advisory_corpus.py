"""Tests for advisory validation and corpus generation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mcp_vulscanner.collectors.advisory_corpus import load_advisory_descriptors, sync_advisory_corpus
from mcp_vulscanner.models.advisory import NormalizedAdvisory


class AdvisoryModelTests(unittest.TestCase):
    """Exercise schema validation for advisory descriptors."""

    def test_normalized_advisory_requires_non_empty_fields(self) -> None:
        """Missing required strings should fail validation."""

        with self.assertRaises(ValueError):
            NormalizedAdvisory.from_mapping(
                {
                    "project_name": "",
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
                    "notes": None,
                }
            )

    def test_normalized_advisory_allows_optional_identifiers(self) -> None:
        """Optional IDs may be null when not yet curated."""

        advisory = NormalizedAdvisory.from_mapping(
            {
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
                "notes": None,
            }
        )
        self.assertIsNone(advisory.ghsa_id)
        self.assertIsNone(advisory.cve_id)


class AdvisoryCorpusSyncTests(unittest.TestCase):
    """Verify merge behavior across descriptor files."""

    def test_sync_merges_json_and_yaml_descriptors(self) -> None:
        """JSON and YAML descriptors should merge into a deterministic corpus."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            advisories_dir = root / "data" / "advisories"
            advisories_dir.mkdir(parents=True)

            self._write_json_descriptor(
                advisories_dir / "b-project.json",
                project_name="B Project",
                package_name="b-project",
                ecosystem="npm",
                vulnerability_class="ssrf",
            )
            (advisories_dir / "a-project.yaml").write_text(
                "\n".join(
                    [
                        "project_name: A Project",
                        "repo_url: https://github.com/example/a-project",
                        "package_name: a-project",
                        "ecosystem: pypi",
                        "advisory_source: manual-curation",
                        "advisory_url: https://github.com/example/a-project/security",
                        "ghsa_id: null",
                        "cve_id: null",
                        "vulnerability_class: command-injection",
                        "affected_versions:",
                        "  - <1.2.0",
                        "patched_versions:",
                        "  - >=1.2.0",
                        "transport_mode: stdio",
                        "entrypoint_kind: prompt-template",
                        "sink_kind: shell-command",
                        "notes: fixture",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            summary = sync_advisory_corpus(root)
            corpus_path = root / "data" / "corpus" / "advisory-corpus.json"
            corpus = json.loads(corpus_path.read_text(encoding="utf-8"))

        self.assertEqual(summary.descriptor_count, 2)
        self.assertEqual(summary.by_ecosystem, {"npm": 1, "pypi": 1})
        self.assertEqual(
            summary.by_vulnerability_class,
            {"command-injection": 1, "ssrf": 1},
        )
        self.assertEqual([item["package_name"] for item in corpus], ["b-project", "a-project"])

    def test_load_advisory_descriptors_rejects_invalid_files(self) -> None:
        """Invalid descriptors should surface file-specific validation errors."""

        with tempfile.TemporaryDirectory() as tmp_dir:
            advisories_dir = Path(tmp_dir)
            (advisories_dir / "bad.json").write_text(
                json.dumps({"project_name": "broken"}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "bad.json"):
                load_advisory_descriptors(advisories_dir)

    @staticmethod
    def _write_json_descriptor(
        path: Path,
        *,
        project_name: str,
        package_name: str,
        ecosystem: str,
        vulnerability_class: str,
    ) -> None:
        """Write a minimal valid JSON descriptor fixture."""

        path.write_text(
            json.dumps(
                {
                    "project_name": project_name,
                    "repo_url": f"https://github.com/example/{package_name}",
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "advisory_source": "manual-curation",
                    "advisory_url": f"https://github.com/example/{package_name}/security",
                    "ghsa_id": None,
                    "cve_id": None,
                    "vulnerability_class": vulnerability_class,
                    "affected_versions": ["<1.0.0"],
                    "patched_versions": [">=1.0.0"],
                    "transport_mode": "http",
                    "entrypoint_kind": "url-fetch",
                    "sink_kind": "outbound-request",
                    "notes": "fixture",
                }
            ),
            encoding="utf-8",
        )
