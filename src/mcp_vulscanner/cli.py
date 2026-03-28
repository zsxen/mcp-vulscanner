"""Command-line interface for the MCP vulscanner research scaffold."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable, Sequence

from .collectors.advisory_corpus import sync_advisory_corpus
from .eval.run import run_batch
from .eval import validate_corpus
from .self_audit import SelfAuditWorkflow
from .static import StaticAnalysisEngine

Handler = Callable[[argparse.Namespace], int]


def handle_dataset_sync(args: argparse.Namespace) -> int:
    """Validate advisory descriptors and build the normalized corpus."""

    project_root = args.root.resolve()
    summary = sync_advisory_corpus(project_root)
    print(
        "Validated "
        f"{summary.descriptor_count} advisory descriptors from {summary.source_directory}."
    )
    print(f"Wrote normalized corpus to {summary.output_path}.")
    print("By vulnerability_class:")
    for name, count in summary.by_vulnerability_class.items():
        print(f"  {name}: {count}")
    print("By ecosystem:")
    for name, count in summary.by_ecosystem.items():
        print(f"  {name}: {count}")
    return 0


def handle_scan_quick(args: argparse.Namespace) -> int:
    """Run the quick self-audit workflow."""

    workflow = SelfAuditWorkflow(static_engine=StaticAnalysisEngine())
    report = workflow.run_quick(
        Path(args.target),
        output_dir=args.output_dir.resolve(),
        include_vendor=args.include_vendor,
        include_tests=args.include_tests,
    )
    print(render_cli_scan_summary(report))
    return 0


def handle_scan_deep(args: argparse.Namespace) -> int:
    """Run the deep self-audit workflow."""

    workflow = SelfAuditWorkflow(static_engine=StaticAnalysisEngine())
    report = workflow.run_deep(
        Path(args.target),
        output_dir=args.output_dir.resolve(),
        include_vendor=args.include_vendor,
        include_tests=args.include_tests,
    )
    print(render_cli_scan_summary(report))
    return 0


def handle_report_render(args: argparse.Namespace) -> int:
    """Return a placeholder result for report rendering."""

    input_path = Path(args.input)
    print(
        "[stub] report render: "
        f"TODO: render research report artifacts from '{input_path}'."
    )
    return 0


def handle_eval_validate_corpus(args: argparse.Namespace) -> int:
    """Validate the paper evaluation corpus manifests."""

    summary = validate_corpus(args.root.resolve())
    print(f"Validated {summary.target_count} corpus targets.")
    print("By vulnerability_class:")
    for name, count in summary.by_vulnerability_class.items():
        print(f"  {name}: {count}")
    print("By expected_label:")
    for name, count in summary.by_expected_label.items():
        print(f"  {name}: {count}")
    return 0


def handle_eval_run(args: argparse.Namespace) -> int:
    """Run a minimal batch evaluation over the compact paper corpus."""

    summary = run_batch(args.manifest.resolve(), mode=args.mode, output_root=args.output_root.resolve())
    print(json.dumps(summary, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""

    parser = argparse.ArgumentParser(
        prog="mcp-vulscanner",
        description="Research-only scaffold for MCP vulnerability scanning experiments.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    dataset_parser = subparsers.add_parser("dataset", help="Manage research datasets.")
    dataset_subparsers = dataset_parser.add_subparsers(dest="dataset_command", required=True)
    dataset_sync_parser = dataset_subparsers.add_parser(
        "sync",
        help="Sync advisories, corpora, and fixtures into the research workspace.",
    )
    dataset_sync_parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="Project root containing data/advisories and data/corpus directories.",
    )
    dataset_sync_parser.set_defaults(handler=handle_dataset_sync)

    scan_parser = subparsers.add_parser("scan", help="Run scanner experiments.")
    scan_subparsers = scan_parser.add_subparsers(dest="scan_command", required=True)

    scan_quick_parser = scan_subparsers.add_parser(
        "quick",
        help="Run a quick experimental scan against a target.",
    )
    scan_quick_parser.add_argument("target", help="Target identifier or path to inspect.")
    scan_quick_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports") / "self-audit",
        help="Directory where Markdown and JSON self-audit reports will be written.",
    )
    scan_quick_parser.add_argument(
        "--include-vendor",
        action="store_true",
        help="Include vendor/build/cache paths in the default scan scope.",
    )
    scan_quick_parser.add_argument(
        "--include-tests",
        action="store_true",
        help="Include test directories in the default scan scope.",
    )
    scan_quick_parser.set_defaults(handler=handle_scan_quick)

    scan_deep_parser = scan_subparsers.add_parser(
        "deep",
        help="Run a deep experimental scan against a target.",
    )
    scan_deep_parser.add_argument("target", help="Target identifier or path to inspect.")
    scan_deep_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports") / "self-audit",
        help="Directory where Markdown and JSON self-audit reports will be written.",
    )
    scan_deep_parser.add_argument(
        "--include-vendor",
        action="store_true",
        help="Include vendor/build/cache paths in the default scan scope.",
    )
    scan_deep_parser.add_argument(
        "--include-tests",
        action="store_true",
        help="Include test directories in the default scan scope.",
    )
    scan_deep_parser.set_defaults(handler=handle_scan_deep)

    eval_parser = subparsers.add_parser("eval", help="Manage evaluation artifacts.")
    eval_subparsers = eval_parser.add_subparsers(dest="eval_command", required=True)
    eval_validate_parser = eval_subparsers.add_parser(
        "validate-corpus",
        help="Validate the compact paper evaluation corpus manifests.",
    )
    eval_validate_parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="Project root containing data/corpus manifests.",
    )
    eval_validate_parser.set_defaults(handler=handle_eval_validate_corpus)
    eval_run_parser = eval_subparsers.add_parser(
        "run",
        help="Run a minimal batch evaluation over the current corpus manifest.",
    )
    eval_run_parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Path to the compact corpus manifest.",
    )
    eval_run_parser.add_argument(
        "--mode",
        choices=("static", "hybrid"),
        required=True,
        help="Whether to run static-only or static plus minimal stdio replay.",
    )
    eval_run_parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("results"),
        help="Directory where raw, report, and aggregate outputs will be written.",
    )
    eval_run_parser.set_defaults(handler=handle_eval_run)

    report_parser = subparsers.add_parser("report", help="Render research reports.")
    report_subparsers = report_parser.add_subparsers(dest="report_command", required=True)
    report_render_parser = report_subparsers.add_parser(
        "render",
        help="Render a report from an intermediate research artifact.",
    )
    report_render_parser.add_argument("input", help="Input artifact path.")
    report_render_parser.set_defaults(handler=handle_report_render)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and print a placeholder result."""

    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Handler = args.handler
    try:
        return handler(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def render_cli_scan_summary(report: object) -> str:
    """Render a concise CLI summary for a self-audit report."""

    payload = report.to_dict()
    return json.dumps(payload, indent=2)
