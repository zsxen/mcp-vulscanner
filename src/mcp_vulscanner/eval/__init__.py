"""Evaluation harnesses for benchmark experiments."""

from __future__ import annotations

from typing import Any

__all__ = ["ProjectEvaluation", "render_outputs"]


def __getattr__(name: str) -> Any:
    """Lazily expose evaluation helpers without importing submodules eagerly."""

    if name in {"ProjectEvaluation", "render_outputs"}:
        from .render_tables import ProjectEvaluation, render_outputs

        exports = {
            "ProjectEvaluation": ProjectEvaluation,
            "render_outputs": render_outputs,
        }
        return exports[name]
    raise AttributeError(name)
