"""Render paper-ready tables from evaluation JSON results."""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


@dataclass(frozen=True)
class ProjectEvaluation:
    """Normalized per-project evaluation row."""

    project_name: str
    static_findings: int
    hybrid_findings: int
    true_positives: int
    false_positives: int
    false_negatives: int
    confirmed_findings: int

    @property
    def recall(self) -> float:
        """Return recall as TP / (TP + FN)."""

        denominator = self.true_positives + self.false_negatives
        return 0.0 if denominator == 0 else self.true_positives / denominator

    @property
    def confirmation_rate(self) -> float:
        """Return confirmation rate as confirmed / hybrid findings."""

        return 0.0 if self.hybrid_findings == 0 else self.confirmed_findings / self.hybrid_findings

    @property
    def false_positive_rate(self) -> float:
        """Return false positive rate as FP / (TP + FP)."""

        denominator = self.true_positives + self.false_positives
        return 0.0 if denominator == 0 else self.false_positives / denominator

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> "ProjectEvaluation":
        """Validate and normalize one project result row."""

        required_strings = ("project_name",)
        required_ints = (
            "static_findings",
            "hybrid_findings",
            "true_positives",
            "false_positives",
            "false_negatives",
            "confirmed_findings",
        )

        normalized: dict[str, Any] = {}
        for field_name in required_strings:
            value = payload.get(field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Field '{field_name}' must be a non-empty string.")
            normalized[field_name] = value.strip()
        for field_name in required_ints:
            value = payload.get(field_name)
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"Field '{field_name}' must be a non-negative integer.")
            normalized[field_name] = value
        return cls(**normalized)


def load_results(path: Path) -> list[ProjectEvaluation]:
    """Load and validate evaluation results."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        rows = payload.get("projects")
    else:
        rows = payload
    if not isinstance(rows, list) or not rows:
        raise ValueError("Evaluation JSON must contain a non-empty list of projects.")
    evaluations = [ProjectEvaluation.from_mapping(row) for row in rows]
    return sorted(evaluations, key=lambda item: item.project_name.lower())


def render_markdown_table(rows: list[ProjectEvaluation]) -> str:
    """Render a Markdown table."""

    header = (
        "| Project | Static Findings | Hybrid Findings | Recall | Confirmation Rate | "
        "False Positive Rate | Static vs Hybrid |\n"
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |\n"
    )
    body = "".join(
        [
            "| "
            f"{row.project_name} | "
            f"{row.static_findings} | "
            f"{row.hybrid_findings} | "
            f"{format_ratio(row.recall)} | "
            f"{format_ratio(row.confirmation_rate)} | "
            f"{format_ratio(row.false_positive_rate)} | "
            f"{row.static_findings} -> {row.hybrid_findings} |\n"
            for row in rows
        ]
    )
    return header + body


def render_latex_table(rows: list[ProjectEvaluation]) -> str:
    """Render a LaTeX-ready table."""

    lines = [
        r"\begin{tabular}{lrrrrrr}",
        r"\toprule",
        (
            "Project & Static & Hybrid & Recall & Confirmation & False Positive & "
            r"Static$\rightarrow$Hybrid \\"
        ),
        r"\midrule",
    ]
    for row in rows:
        lines.append(
            (
                f"{escape_latex(row.project_name)} & "
                f"{row.static_findings} & "
                f"{row.hybrid_findings} & "
                f"{format_ratio(row.recall)} & "
                f"{format_ratio(row.confirmation_rate)} & "
                f"{format_ratio(row.false_positive_rate)} & "
                f"{row.static_findings}$\\rightarrow${row.hybrid_findings} \\\\"
            )
        )
    lines.extend([r"\bottomrule", r"\end{tabular}"])
    return "\n".join(lines) + "\n"


def write_csv_summary(path: Path, rows: list[ProjectEvaluation]) -> None:
    """Write a CSV summary."""

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "project_name",
                "static_findings",
                "hybrid_findings",
                "recall",
                "confirmation_rate",
                "false_positive_rate",
                "static_vs_hybrid",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row.project_name,
                    row.static_findings,
                    row.hybrid_findings,
                    format_ratio(row.recall),
                    format_ratio(row.confirmation_rate),
                    format_ratio(row.false_positive_rate),
                    f"{row.static_findings}->{row.hybrid_findings}",
                ]
            )


def render_outputs(input_path: Path, output_dir: Path) -> dict[str, Path]:
    """Render Markdown, LaTeX, and CSV outputs from one evaluation JSON file."""

    rows = load_results(input_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    markdown_path = output_dir / "evaluation-summary.md"
    latex_path = output_dir / "evaluation-summary.tex"
    csv_path = output_dir / "evaluation-summary.csv"

    markdown_path.write_text(render_markdown_table(rows), encoding="utf-8")
    latex_path.write_text(render_latex_table(rows), encoding="utf-8")
    write_csv_summary(csv_path, rows)

    return {
        "markdown": markdown_path,
        "latex": latex_path,
        "csv": csv_path,
    }


def format_ratio(value: float) -> str:
    """Format a rate as a percentage string."""

    return f"{value * 100:.1f}\\%" if value > 1 else f"{value * 100:.1f}%"


def escape_latex(value: str) -> str:
    """Escape a string for LaTeX table output."""

    return (
        value.replace("\\", r"\textbackslash{}")
        .replace("_", r"\_")
        .replace("&", r"\&")
        .replace("%", r"\%")
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser for table rendering."""

    parser = argparse.ArgumentParser(
        prog="python -m mcp_vulscanner.eval.render_tables",
        description="Render paper-ready tables from evaluation JSON results.",
    )
    parser.add_argument("--input", type=Path, required=True, help="Path to evaluation JSON results.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory where rendered tables will be written.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the renderer CLI."""

    args = build_parser().parse_args(argv)
    outputs = render_outputs(args.input.resolve(), args.output_dir.resolve())
    print(json.dumps({name: str(path) for name, path in outputs.items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
