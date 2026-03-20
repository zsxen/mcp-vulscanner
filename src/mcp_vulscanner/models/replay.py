"""Structured models for dynamic replay execution traces."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class RpcRecord:
    """A captured JSON-RPC request or response."""

    direction: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class FileDiffSummary:
    """Filesystem changes observed inside the replay workspace."""

    created: list[str]
    modified: list[str]
    deleted: list[str]


@dataclass(frozen=True)
class SideEffectSummary:
    """Observed side effects from a replay attempt."""

    spawned_subprocesses: list[str]
    outbound_requests: list[str]
    file_diffs: FileDiffSummary
    stderr_lines: list[str]


@dataclass(frozen=True)
class ReplayTrace:
    """A persisted dynamic replay result."""

    target_command: list[str]
    transport: str
    tool_name: str
    payload: dict[str, Any]
    vulnerability_class: str
    verdict: str
    rationale: str
    rpc_records: list[RpcRecord]
    side_effects: SideEffectSummary
    trace_path: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the trace."""

        return asdict(self)
