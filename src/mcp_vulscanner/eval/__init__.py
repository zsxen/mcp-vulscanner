"""Evaluation harnesses for benchmark experiments."""

from __future__ import annotations

from typing import Any

__all__ = ["CorpusSummary", "ProjectEvaluation", "render_outputs", "validate_corpus"]


def __getattr__(name: str) -> Any:
    """Lazily expose evaluation helpers without importing submodules eagerly."""

    if name in {"ProjectEvaluation", "render_outputs"}:
        from .render_tables import ProjectEvaluation, render_outputs

        exports = {
            "ProjectEvaluation": ProjectEvaluation,
            "render_outputs": render_outputs,
        }
        return exports[name]
    if name in {"CorpusSummary", "validate_corpus"}:
        from .corpus import CorpusSummary, validate_corpus

        exports = {
            "CorpusSummary": CorpusSummary,
            "validate_corpus": validate_corpus,
        }
        return exports[name]
    raise AttributeError(name)
