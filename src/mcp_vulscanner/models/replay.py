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
class ToolContract:
    """Runtime contract information for one tool."""

    name: str
    metadata: dict[str, Any]
    input_schema: dict[str, Any]
    required_fields: list[str]
    optional_fields: list[str]
    enum_hints: dict[str, list[str]]
    default_hints: dict[str, Any]


@dataclass(frozen=True)
class RuntimeContract:
    """Lifecycle-derived runtime contract for replay."""

    protocol_version: str | None
    transport: str
    tools: list[ToolContract]
    roots: list[str]
    roots_supported: bool
    roots_changed: bool
    session_metadata: dict[str, Any]


@dataclass(frozen=True)
class ReplayAttempt:
    """One baseline or malicious replay attempt."""

    label: str
    payload: dict[str, Any]
    response: dict[str, Any]
    rpc_records: list[RpcRecord]
    side_effects: "SideEffectSummary"
    errors: list[str]
    session_metadata: dict[str, Any]


@dataclass(frozen=True)
class BindingResult:
    """Mapping outcome from static finding to runtime tool."""

    tool_name: str | None
    replayable: bool
    reason: str | None


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
    runtime_contract: RuntimeContract | None = None
    binding: BindingResult | None = None
    baseline_attempt: ReplayAttempt | None = None
    malicious_attempts: list[ReplayAttempt] | None = None
    replay_logs: list[dict[str, Any]] | None = None
    contract_valid: bool = False
    replayable: bool = True
    non_replayable: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the trace."""

        return asdict(self)
