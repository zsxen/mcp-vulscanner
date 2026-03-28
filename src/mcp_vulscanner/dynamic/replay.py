"""Replay engine entrypoints backed by CADER-MCP."""

from __future__ import annotations

from pathlib import Path

from mcp_vulscanner.models.finding import StaticFinding
from mcp_vulscanner.models.replay import ReplayTrace

from .cader import CaderMcpEngine


class DynamicReplayEngine:
    """Compatibility wrapper exposing stdio and HTTP replay methods."""

    def __init__(self) -> None:
        """Initialize the underlying CADER-MCP engine."""

        self._engine = CaderMcpEngine()

    def replay_stdio(
        self,
        target_command: list[str],
        finding: StaticFinding,
        *,
        trace_directory: Path | None = None,
    ) -> ReplayTrace:
        """Run contract-aware differential replay over stdio."""

        return self._engine.replay_stdio(
            target_command,
            finding,
            trace_directory=trace_directory,
        )

    def replay_http(
        self,
        target_command: list[str],
        endpoint: str,
        finding: StaticFinding,
        *,
        headers: dict[str, str] | None = None,
        query_params: dict[str, str] | None = None,
        base_url_override: str | None = None,
        trace_directory: Path | None = None,
    ) -> ReplayTrace:
        """Run contract-aware differential replay over Streamable HTTP."""

        return self._engine.replay_http(
            target_command,
            endpoint,
            finding,
            headers=headers,
            query_params=query_params,
            base_url_override=base_url_override,
            trace_directory=trace_directory,
        )
