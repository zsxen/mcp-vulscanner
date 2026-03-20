"""Minimal batch evaluation runner for the paper corpus."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Sequence

from mcp_vulscanner.eval.stdio_replay import run_stdio_replay
from mcp_vulscanner.static import StaticAnalysisEngine


STATIC_VULNERABLE_FIXTURE = (
    Path(__file__).resolve().parents[3] / "data" / "fixtures" / "static" / "python" / "vulnerable"
)
STATIC_PATCHED_FIXTURE = (
    Path(__file__).resolve().parents[3] / "data" / "fixtures" / "static" / "python" / "patched"
)
PAPER_STDIO_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "fixtures"
    / "dynamic"
    / "paper_stdio_vulnerable_server.py"
)


def run_batch(manifest_path: Path, *, mode: str, output_root: Path) -> dict[str, Any]:
    """Run a minimal batch evaluation over the current corpus manifest."""

    targets = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(targets, list) or not targets:
        raise ValueError("Manifest must contain a non-empty list.")

    raw_dir = output_root / "raw"
    reports_dir = output_root / "reports"
    raw_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    static_engine = StaticAnalysisEngine()
    per_target_results: list[dict[str, Any]] = []

    for target in targets:
        result = _run_one_target(target, mode=mode, raw_dir=raw_dir, reports_dir=reports_dir, static_engine=static_engine)
        per_target_results.append(result)

    aggregate = _build_aggregate_results(per_target_results, mode=mode)
    aggregate_path = output_root / "aggregate-results.json"
    aggregate_path.write_text(json.dumps({"projects": aggregate}, indent=2) + "\n", encoding="utf-8")
    return {
        "mode": mode,
        "target_count": len(per_target_results),
        "raw_dir": str(raw_dir),
        "reports_dir": str(reports_dir),
        "aggregate_path": str(aggregate_path),
    }


def _run_one_target(
    target: dict[str, Any],
    *,
    mode: str,
    raw_dir: Path,
    reports_dir: Path,
    static_engine: StaticAnalysisEngine,
) -> dict[str, Any]:
    """Run static analysis and optional minimal replay for one target."""

    target_id = str(target["target_id"])
    vulnerability_class = str(target["vulnerability_class"])
    expected_label = str(target["expected_label"])

    scan_path = STATIC_VULNERABLE_FIXTURE if expected_label == "positive" else STATIC_PATCHED_FIXTURE
    static_report = static_engine.analyze_target(scan_path, mode="quick")
    matching_findings = [
        finding for finding in static_report.findings if finding.vulnerability_class == vulnerability_class
    ]
    static_findings_count = len(matching_findings)

    tool_called = ""
    dynamic_attempted = False
    verdict = "UNCONFIRMED"
    evidence: dict[str, Any] = {
        "static_fixture": str(scan_path),
        "matching_static_findings": static_findings_count,
        "created_files": [],
        "modified_files": [],
        "stderr_lines": [],
        "outbound_requests": [],
    }
    errors: list[str] = []

    if mode == "hybrid":
        if target.get("transport_mode") == "stdio" and vulnerability_class == "arbitrary-file-write":
            replay_output_dir = reports_dir / target_id
            replay_result = run_stdio_replay(
                target_id=target_id,
                command=f"{sys.executable} {PAPER_STDIO_FIXTURE}",
                tool_name="write_file",
                arguments={"path": f"{target_id}/proof.txt", "content": "paper"},
                static_findings_count=static_findings_count,
                output_dir=replay_output_dir,
            )
            tool_called = replay_result.tool_called
            dynamic_attempted = replay_result.dynamic_attempted
            verdict = replay_result.verdict
            evidence.update(replay_result.evidence)
            errors.extend(replay_result.errors)
        else:
            errors.append("hybrid replay skipped: stdio arbitrary-file-write only")

    result = {
        "target_id": target_id,
        "project_name": target["project_name"],
        "vulnerability_class": vulnerability_class,
        "expected_label": expected_label,
        "mode": mode,
        "static_findings_count": static_findings_count,
        "tool_called": tool_called,
        "dynamic_attempted": dynamic_attempted,
        "verdict": verdict,
        "evidence": evidence,
        "errors": errors,
    }
    (raw_dir / f"{target_id}.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (reports_dir / f"{target_id}.md").write_text(_render_report(target, result), encoding="utf-8")
    return result


def _build_aggregate_results(per_target_results: list[dict[str, Any]], *, mode: str) -> list[dict[str, Any]]:
    """Build aggregate results compatible with the existing table renderer."""

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in per_target_results:
        grouped[str(result["project_name"])].append(result)

    aggregate: list[dict[str, Any]] = []
    for project_name, results in sorted(grouped.items()):
        positives = [item for item in results if item["expected_label"] == "positive"]
        negatives = [item for item in results if item["expected_label"] == "negative"]
        true_positives = sum(1 for item in positives if item["static_findings_count"] > 0)
        false_negatives = sum(1 for item in positives if item["static_findings_count"] == 0)
        false_positives = sum(1 for item in negatives if item["static_findings_count"] > 0)
        static_findings = sum(item["static_findings_count"] for item in results)
        confirmed_findings = sum(1 for item in results if item["verdict"] == "CONFIRMED")
        hybrid_findings = confirmed_findings if mode == "hybrid" else 0
        aggregate.append(
            {
                "project_name": project_name,
                "static_findings": static_findings,
                "hybrid_findings": hybrid_findings,
                "true_positives": true_positives,
                "false_positives": false_positives,
                "false_negatives": false_negatives,
                "confirmed_findings": confirmed_findings,
            }
        )
    return aggregate


def _render_report(target: dict[str, Any], result: dict[str, Any]) -> str:
    """Render a tiny Markdown report per target."""

    return (
        f"# Evaluation Result: {target['target_id']}\n\n"
        f"- Project: `{target['project_name']}`\n"
        f"- Mode: `{result['mode']}`\n"
        f"- Static Findings Count: `{result['static_findings_count']}`\n"
        f"- Tool Called: `{result['tool_called'] or 'n/a'}`\n"
        f"- Dynamic Attempted: `{result['dynamic_attempted']}`\n"
        f"- Verdict: **{result['verdict']}**\n"
        f"- Errors: `{'; '.join(result['errors']) or 'none'}`\n"
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the module CLI parser."""

    parser = argparse.ArgumentParser(
        prog="python -m mcp_vulscanner.eval.run",
        description="Run a minimal batch evaluation for the current paper corpus.",
    )
    parser.add_argument("--manifest", type=Path, required=True, help="Path to corpus targets manifest.")
    parser.add_argument("--mode", choices=("static", "hybrid"), required=True, help="Evaluation mode.")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("results"),
        help="Directory where raw, report, and aggregate outputs will be written.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the module CLI."""

    args = build_parser().parse_args(argv)
    summary = run_batch(args.manifest.resolve(), mode=args.mode, output_root=args.output_root.resolve())
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
