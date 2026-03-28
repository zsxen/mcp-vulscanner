"""Contract-Aware Differential Exploit Replay for MCP servers."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import threading
import time
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from mcp_vulscanner.models.finding import StaticFinding
from mcp_vulscanner.models.replay import (
    BindingResult,
    FileDiffSummary,
    ReplayAttempt,
    ReplayTrace,
    RpcRecord,
    RuntimeContract,
    SideEffectSummary,
    ToolContract,
)

from .protocol import HttpReplayOptions, JsonRpcHttpClient, JsonRpcStdioClient, TransportClient

MOCK_SERVER_BASE_TOKEN = "__MCP_VULSCANNER_MOCK_SERVER__"


@dataclass(frozen=True)
class ReplayPlan:
    """One baseline plus malicious variants for a replayable finding."""

    baseline: dict[str, Any]
    variants: list[tuple[str, dict[str, Any]]]


class CaderMcpEngine:
    """Run lifecycle-aware differential replay against MCP servers."""

    def replay_stdio(
        self,
        target_command: list[str],
        finding: StaticFinding,
        *,
        trace_directory: Path | None = None,
    ) -> ReplayTrace:
        """Run CADER-MCP over stdio."""

        return self._replay(
            transport="stdio",
            target_command=target_command,
            finding=finding,
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
        """Run CADER-MCP over Streamable HTTP."""

        return self._replay(
            transport="http",
            target_command=target_command,
            finding=finding,
            trace_directory=trace_directory,
            http_endpoint=endpoint,
            http_options=HttpReplayOptions(
                headers=headers or {},
                query_params=query_params or {},
            ),
            ssrf_base_url=base_url_override,
        )

    def _replay(
        self,
        *,
        transport: str,
        target_command: list[str],
        finding: StaticFinding,
        trace_directory: Path | None,
        http_endpoint: str | None = None,
        http_options: HttpReplayOptions | None = None,
        ssrf_base_url: str | None = None,
    ) -> ReplayTrace:
        """Execute one contract-aware differential replay."""

        root = Path(tempfile.mkdtemp(prefix="mcp-vulscanner-cader-"))
        trace_dir = trace_directory.resolve() if trace_directory else root
        trace_dir.mkdir(parents=True, exist_ok=True)
        trace_path = trace_dir / "execution-trace.json"

        contract, contract_records = self._extract_contract(
            transport=transport,
            target_command=target_command,
            http_endpoint=http_endpoint,
            http_options=http_options,
        )
        binding = bind_finding_to_contract(finding, contract)
        session_metadata = contract.session_metadata

        if not binding.replayable or not binding.tool_name:
            trace = ReplayTrace(
                target_command=target_command,
                transport=transport,
                tool_name=finding.tool_name or "",
                payload={},
                vulnerability_class=finding.vulnerability_class,
                verdict="UNCONFIRMED",
                rationale=binding.reason or "non_replayable",
                rpc_records=contract_records,
                side_effects=SideEffectSummary(
                    spawned_subprocesses=[],
                    outbound_requests=[],
                    file_diffs=FileDiffSummary(created=[], modified=[], deleted=[]),
                    stderr_lines=[],
                ),
                trace_path=str(trace_path),
                runtime_contract=contract,
                binding=binding,
                baseline_attempt=None,
                malicious_attempts=[],
                replay_logs=[{"phase": "binding", "status": "non_replayable", "reason": binding.reason}],
                contract_valid=True,
                replayable=False,
                non_replayable=True,
            )
            trace_path.write_text(json.dumps(trace.to_dict(), indent=2) + "\n", encoding="utf-8")
            return trace

        tool_contract = next(tool for tool in contract.tools if tool.name == binding.tool_name)
        roots = contract.roots or ["/tmp"]
        replay_logs: list[dict[str, Any]] = []
        plan = synthesize_plan(
            finding=finding,
            tool=tool_contract,
            roots=roots,
            mock_server_base=MOCK_SERVER_BASE_TOKEN,
            ssrf_base_url=ssrf_base_url,
            transport_headers=(http_options.headers if http_options else {}),
            transport_query_params=(http_options.query_params if http_options else {}),
        )

        baseline_attempt = self._run_attempt(
            transport=transport,
            target_command=target_command,
            label="baseline",
            tool_name=binding.tool_name,
            payload=plan.baseline,
            http_endpoint=http_endpoint,
            http_options=http_options,
        )
        replay_logs.append(
            {
                "phase": "baseline",
                "payload": plan.baseline,
                "errors": baseline_attempt.errors,
                "verdict_hint": "baseline-complete",
            }
        )

        malicious_attempts: list[ReplayAttempt] = []
        retry_budget = 4
        for label, payload in plan.variants[:retry_budget]:
            attempt = self._run_attempt(
                transport=transport,
                target_command=target_command,
                label=label,
                tool_name=binding.tool_name,
                payload=payload,
                http_endpoint=http_endpoint,
                http_options=http_options,
            )
            malicious_attempts.append(attempt)
            replay_logs.append(
                {
                    "phase": label,
                    "payload": payload,
                    "errors": attempt.errors,
                    "stderr": attempt.side_effects.stderr_lines,
                }
            )
            if _has_forbidden_delta(finding.vulnerability_class, baseline_attempt, attempt):
                break
            improved_payload = improve_payload_from_feedback(
                finding=finding,
                tool=tool_contract,
                payload=payload,
                attempt=attempt,
                roots=roots,
            )
            if improved_payload is not None:
                replay_logs.append({"phase": label, "feedback_retry": improved_payload})
                malicious_attempts.append(
                    self._run_attempt(
                        transport=transport,
                        target_command=target_command,
                        label=f"{label}-retry",
                        tool_name=binding.tool_name,
                        payload=improved_payload,
                        http_endpoint=http_endpoint,
                        http_options=http_options,
                    )
                )
                if _has_forbidden_delta(finding.vulnerability_class, baseline_attempt, malicious_attempts[-1]):
                    break

        verdict, rationale, decisive_attempt = determine_differential_verdict(
            finding.vulnerability_class,
            baseline_attempt,
            malicious_attempts,
        )
        side_effects = decisive_attempt.side_effects if decisive_attempt else baseline_attempt.side_effects
        final_session_metadata = (
            decisive_attempt.session_metadata
            if decisive_attempt and decisive_attempt.session_metadata
            else baseline_attempt.session_metadata
        )
        trace = ReplayTrace(
            target_command=target_command,
            transport=transport,
            tool_name=binding.tool_name,
            payload=decisive_attempt.payload if decisive_attempt else plan.baseline,
            vulnerability_class=finding.vulnerability_class,
            verdict=verdict,
            rationale=rationale,
            rpc_records=contract_records + baseline_attempt.rpc_records + [record for attempt in malicious_attempts for record in attempt.rpc_records],
            side_effects=side_effects,
            trace_path=str(trace_path),
            runtime_contract=RuntimeContract(
                protocol_version=contract.protocol_version,
                transport=contract.transport,
                tools=contract.tools,
                roots=contract.roots,
                roots_supported=contract.roots_supported,
                roots_changed=contract.roots_changed,
                session_metadata={**session_metadata, **final_session_metadata, "transport_kind": transport},
            ),
            binding=binding,
            baseline_attempt=baseline_attempt,
            malicious_attempts=malicious_attempts,
            replay_logs=replay_logs,
            contract_valid=True,
            replayable=True,
            non_replayable=False,
        )
        trace_path.write_text(json.dumps(trace.to_dict(), indent=2) + "\n", encoding="utf-8")
        return trace

    def _extract_contract(
        self,
        *,
        transport: str,
        target_command: list[str],
        http_endpoint: str | None,
        http_options: HttpReplayOptions | None,
    ) -> tuple[RuntimeContract, list[RpcRecord]]:
        """Perform initialize, initialized, tools/list, and optional roots bootstrap."""

        run = _run_client_session(
            transport=transport,
            target_command=target_command,
            http_endpoint=http_endpoint,
            http_options=http_options,
            tool_name=None,
            payload=None,
            lifecycle_only=True,
        )
        init_response = run["responses"]["initialize"]
        tools_response = run["responses"]["tools/list"]
        roots_response = run["responses"].get("roots/list")
        tools = []
        for tool in tools_response.get("result", {}).get("tools", []):
            schema = tool.get("inputSchema") or {}
            properties = schema.get("properties") or {}
            required = list(schema.get("required") or [])
            optional = [name for name in properties if name not in required]
            enum_hints = {
                name: list(value.get("enum", []))
                for name, value in properties.items()
                if isinstance(value, dict) and isinstance(value.get("enum"), list)
            }
            default_hints = {
                name: value.get("default")
                for name, value in properties.items()
                if isinstance(value, dict) and "default" in value
            }
            tools.append(
                ToolContract(
                    name=str(tool.get("name", "")),
                    metadata=tool,
                    input_schema=schema,
                    required_fields=required,
                    optional_fields=optional,
                    enum_hints=enum_hints,
                    default_hints=default_hints,
                )
            )

        roots = []
        if roots_response:
            roots = [item.get("uri", "") for item in roots_response.get("result", {}).get("roots", [])]
        contract = RuntimeContract(
            protocol_version=init_response.get("result", {}).get("protocolVersion"),
            transport=transport,
            tools=tools,
            roots=roots,
            roots_supported=roots_response is not None,
            roots_changed=any(
                record.payload.get("method") == "roots/list_changed"
                for record in run["rpc_records"]
                if record.direction == "response"
            ),
            session_metadata=run["session_metadata"],
        )
        return contract, run["rpc_records"]

    def _run_attempt(
        self,
        *,
        transport: str,
        target_command: list[str],
        label: str,
        tool_name: str,
        payload: dict[str, Any],
        http_endpoint: str | None,
        http_options: HttpReplayOptions | None,
    ) -> ReplayAttempt:
        """Run one baseline or malicious attempt in clean state."""

        run = _run_client_session(
            transport=transport,
            target_command=target_command,
            http_endpoint=http_endpoint,
            http_options=http_options,
            tool_name=tool_name,
            payload=payload,
            lifecycle_only=False,
        )
        return ReplayAttempt(
            label=label,
            payload=run["resolved_payload"],
            response=run["responses"].get("tools/call", {}),
            rpc_records=run["rpc_records"],
            side_effects=run["side_effects"],
            errors=run["errors"],
            session_metadata=run["session_metadata"],
        )


def bind_finding_to_contract(finding: StaticFinding, contract: RuntimeContract) -> BindingResult:
    """Bind a static finding to a concrete runtime tool."""

    if not finding.tool_name:
        return BindingResult(tool_name=None, replayable=False, reason="missing_static_tool_binding")
    if finding.tool_name not in {tool.name for tool in contract.tools}:
        return BindingResult(tool_name=finding.tool_name, replayable=False, reason="runtime_tool_not_found")
    return BindingResult(tool_name=finding.tool_name, replayable=True, reason=None)


def synthesize_plan(
    *,
    finding: StaticFinding,
    tool: ToolContract,
    roots: list[str],
    mock_server_base: str,
    ssrf_base_url: str | None,
    transport_headers: dict[str, str],
    transport_query_params: dict[str, str],
) -> ReplayPlan:
    """Create one benign baseline and malicious variants from the runtime contract."""

    baseline = build_baseline_payload(tool, roots=roots)
    variants = build_malicious_variants(
        finding=finding,
        tool=tool,
        baseline=baseline,
        roots=roots,
        mock_server_base=mock_server_base,
        ssrf_base_url=ssrf_base_url,
        transport_headers=transport_headers,
        transport_query_params=transport_query_params,
    )
    return ReplayPlan(baseline=baseline, variants=variants)


def build_baseline_payload(tool: ToolContract, *, roots: list[str]) -> dict[str, Any]:
    """Create a schema-valid benign payload."""

    properties = tool.input_schema.get("properties") or {}
    payload: dict[str, Any] = {}
    for field in tool.required_fields:
        schema = properties.get(field, {})
        payload[field] = _safe_value(field, schema, roots)
    for field, schema in properties.items():
        if field not in payload and "default" in schema:
            payload[field] = schema["default"]
    return payload


def build_malicious_variants(
    *,
    finding: StaticFinding,
    tool: ToolContract,
    baseline: dict[str, Any],
    roots: list[str],
    mock_server_base: str,
    ssrf_base_url: str | None,
    transport_headers: dict[str, str],
    transport_query_params: dict[str, str],
) -> list[tuple[str, dict[str, Any]]]:
    """Generate class-specific malicious variants while preserving JSON types."""

    variants: list[tuple[str, dict[str, Any]]] = []
    if finding.vulnerability_class == "command-injection":
        command_field = _find_field(tool, "cmd", "command")
        if command_field:
            payload = dict(baseline)
            payload[command_field] = "python3 -c \"open('cader-proof.txt','w').write('confirmed')\""
            variants.append(("command-injection", payload))
    elif finding.vulnerability_class == "ssrf":
        url_field = _find_field(tool, "url")
        headers_field = _find_field(tool, "headers", "custom_headers")
        base_field = _find_field(tool, "base_url")
        query_field = _find_field(tool, "query", "query_params", "params")
        if url_field:
            payload = dict(baseline)
            payload[url_field] = f"{mock_server_base}/ssrf-proof"
            variants.append(("ssrf-direct-url", payload))
            payload = dict(baseline)
            payload[url_field] = f"{mock_server_base}/redirect-source"
            variants.append(("ssrf-redirect-chain", payload))
        if headers_field:
            payload = dict(baseline)
            if url_field:
                payload[url_field] = f"{mock_server_base}/ssrf-proof"
            payload[headers_field] = dict(transport_headers) or {"X-SSRF-Probe": "header-override"}
            variants.append(("ssrf-header-override", payload))
        if base_field:
            payload = dict(baseline)
            payload[base_field] = ssrf_base_url or mock_server_base
            if "path" in (tool.input_schema.get("properties") or {}):
                payload["path"] = "ssrf-proof"
            if query_field and transport_query_params:
                payload[query_field] = dict(transport_query_params)
            variants.append(("ssrf-base-url-override", payload))
        if variants:
            priority_prefix = "ssrf-direct-url"
            if "redirect" in tool.name:
                priority_prefix = "ssrf-redirect-chain"
            elif "header" in tool.name or transport_headers:
                priority_prefix = "ssrf-header-override"
            elif "base_url" in tool.name or (base_field and not url_field):
                priority_prefix = "ssrf-base-url-override"
            variants.sort(key=lambda item: 0 if item[0] == priority_prefix else 1)
    elif finding.vulnerability_class == "arbitrary-file-write":
        path_field = _find_field(tool, "download_path", "path", "target_path", "file_path", "filename")
        if path_field:
            payload = dict(baseline)
            payload[path_field] = "dynamic-proof/output.txt"
            variants.append(("workspace-file-write", payload))
            payload = dict(baseline)
            payload[path_field] = "../escaped-proof.txt"
            variants.append(("path-traversal", payload))
            if roots:
                payload = dict(baseline)
                payload[path_field] = str(Path(roots[0]) / ".." / "escaped-proof.txt")
                variants.append(("allowed-root-escape", payload))
    return variants


def improve_payload_from_feedback(
    *,
    finding: StaticFinding,
    tool: ToolContract,
    payload: dict[str, Any],
    attempt: ReplayAttempt,
    roots: list[str],
) -> dict[str, Any] | None:
    """Use bounded feedback to produce one improved retry payload."""

    joined_errors = " ".join(attempt.errors + attempt.side_effects.stderr_lines).lower()
    if "root" in joined_errors and finding.vulnerability_class == "arbitrary-file-write" and roots:
        path_field = _find_field(tool, "download_path", "path", "target_path", "file_path", "filename")
        if path_field:
            improved = dict(payload)
            improved[path_field] = str(Path(roots[0]) / "nested" / "retry-proof.txt")
            return improved
    if "enum" in joined_errors:
        for field, values in tool.enum_hints.items():
            if values:
                improved = dict(payload)
                improved[field] = values[0]
                return improved
    return None


def determine_differential_verdict(
    vulnerability_class: str,
    baseline: ReplayAttempt,
    malicious_attempts: list[ReplayAttempt],
) -> tuple[str, str, ReplayAttempt | None]:
    """Compare baseline and malicious attempts to produce a differential verdict."""

    for attempt in malicious_attempts:
        if _has_forbidden_delta(vulnerability_class, baseline, attempt):
            return "CONFIRMED", f"malicious-only forbidden delta detected in {attempt.label}", attempt
    for attempt in malicious_attempts:
        if attempt.errors or attempt.side_effects.stderr_lines:
            return "PROBABLE", f"near-sink or blocked behavior observed in {attempt.label}", attempt
    return "UNCONFIRMED", "no meaningful differential evidence", malicious_attempts[-1] if malicious_attempts else None


def _has_forbidden_delta(vulnerability_class: str, baseline: ReplayAttempt, malicious: ReplayAttempt) -> bool:
    """Return whether malicious evidence shows a forbidden delta versus baseline."""

    if vulnerability_class == "command-injection":
        return bool(
            set(malicious.side_effects.spawned_subprocesses)
            - set(baseline.side_effects.spawned_subprocesses)
        )
    if vulnerability_class == "ssrf":
        return bool(set(malicious.side_effects.outbound_requests) - set(baseline.side_effects.outbound_requests))
    if vulnerability_class == "arbitrary-file-write":
        return bool(
            set(malicious.side_effects.file_diffs.created + malicious.side_effects.file_diffs.modified)
            - set(baseline.side_effects.file_diffs.created + baseline.side_effects.file_diffs.modified)
        )
    return False


def _safe_value(field_name: str, schema: dict[str, Any], roots: list[str]) -> Any:
    """Choose a benign value compatible with a simple JSON schema."""

    if "default" in schema:
        return schema["default"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    field_type = schema.get("type")
    if field_type == "boolean":
        return False
    if field_type == "integer":
        return 0
    if field_type == "number":
        return 0
    if field_type == "array":
        return []
    if field_type == "object":
        return {}
    if "path" in field_name or "file" in field_name:
        base_root = roots[0] if roots else "/tmp"
        return str(Path(base_root) / "allowed.txt")
    if "url" in field_name:
        return "https://example.com/benign"
    if "cmd" in field_name or "command" in field_name:
        return "echo benign"
    return "benign"


def _find_field(tool: ToolContract, *names: str) -> str | None:
    """Return the first matching property name from a tool schema."""

    properties = tool.input_schema.get("properties") or {}
    for name in names:
        if name in properties:
            return name
    return None


def _run_client_session(
    *,
    transport: str,
    target_command: list[str],
    http_endpoint: str | None,
    http_options: HttpReplayOptions | None,
    tool_name: str | None,
    payload: dict[str, Any] | None,
    lifecycle_only: bool,
) -> dict[str, Any]:
    """Run one isolated lifecycle session and optionally a tool call."""

    root = Path(tempfile.mkdtemp(prefix="mcp-vulscanner-cader-run-"))
    workspace = root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    subprocess_log = root / "subprocess.log"
    mock_server = _MockHttpCaptureServer()

    env = os.environ.copy()
    env["MCP_VULSCANNER_WORKSPACE"] = str(workspace)
    env["MCP_VULSCANNER_SUBPROCESS_LOG"] = str(subprocess_log)
    env["MCP_VULSCANNER_MOCK_SERVER"] = mock_server.base_url
    if transport == "http":
        assert http_endpoint is not None
        parsed = urllib.parse.urlparse(http_endpoint)
        env["MCP_VULSCANNER_HTTP_PORT"] = str(parsed.port or 80)
        env["MCP_VULSCANNER_HTTP_PATH"] = parsed.path or "/mcp"
    before_snapshot = _snapshot_files(workspace)
    process = subprocess.Popen(
        target_command,
        stdin=subprocess.PIPE if transport == "stdio" else subprocess.DEVNULL,
        stdout=subprocess.PIPE if transport == "stdio" else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        cwd=workspace,
        env=env,
        bufsize=1,
    )
    stderr_lines: list[str] = []
    stderr_thread = threading.Thread(target=_drain_stream, args=(process.stderr, stderr_lines), daemon=True)
    stderr_thread.start()

    if transport == "http":
        assert http_endpoint is not None
        client: TransportClient = JsonRpcHttpClient(endpoint=http_endpoint, options=http_options or HttpReplayOptions())
        _wait_for_http_target(client)
    else:
        client = JsonRpcStdioClient(process)

    rpc_records: list[RpcRecord] = []
    responses: dict[str, Any] = {}
    errors: list[str] = []
    resolved_payload = _materialize_payload(payload, mock_server.base_url)
    try:
        response, records = _request_with_reinit(
            client,
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {"roots": {"listChanged": True}},
                "clientInfo": {"name": "mcp-vulscanner", "version": "0.1.0"},
            },
        )
        responses["initialize"] = response
        rpc_records.extend(records)
        rpc_records.extend(client.notify("notifications/initialized", {}))
        tools_response, records = _request_with_reinit(client, "tools/list", {})
        responses["tools/list"] = tools_response
        rpc_records.extend(records)
        roots_supported = "roots" in (response.get("result", {}).get("capabilities", {}) or {})
        if roots_supported:
            roots_response, records = _request_with_reinit(client, "roots/list", {})
            responses["roots/list"] = roots_response
            rpc_records.extend(records)
        if not lifecycle_only and tool_name is not None and payload is not None:
            tool_response, records = _request_with_reinit(
                client,
                "tools/call",
                {"name": tool_name, "arguments": resolved_payload},
            )
            responses["tools/call"] = tool_response
            rpc_records.extend(records)
            if "error" in tool_response:
                errors.append(str(tool_response["error"]))
    except Exception as exc:  # pragma: no cover - exercised indirectly
        errors.append(str(exc))
    finally:
        client.close()
        mock_server.close()
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=2)
        stderr_thread.join(timeout=2)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()

    after_snapshot = _snapshot_files(workspace)
    side_effects = SideEffectSummary(
        spawned_subprocesses=_read_log_lines(subprocess_log),
        outbound_requests=mock_server.requests,
        file_diffs=_diff_snapshots(before_snapshot, after_snapshot),
        stderr_lines=stderr_lines,
    )
    session_metadata = {}
    if transport == "http" and isinstance(client, JsonRpcHttpClient):
        session_metadata = {
            "session_id": client.session_id,
            "protocol_version_header": client.protocol_version,
        }
    return {
        "responses": responses,
        "rpc_records": rpc_records,
        "errors": errors,
        "side_effects": side_effects,
        "session_metadata": session_metadata,
        "resolved_payload": resolved_payload or {},
    }


def _wait_for_http_target(client: JsonRpcHttpClient) -> None:
    """Wait for an HTTP target to come up."""

    for _ in range(40):
        try:
            client.request("initialize", {"probe": True})
            return
        except Exception:
            time.sleep(0.05)
    raise ValueError("http-target-not-ready")


def _request_with_reinit(
    client: TransportClient,
    method: str,
    params: dict[str, Any],
) -> tuple[dict[str, Any], list[RpcRecord]]:
    """Retry a request once when an HTTP session is lost."""

    try:
        return client.request(method, params)
    except ValueError as exc:
        if str(exc) != "http-session-lost" or not isinstance(client, JsonRpcHttpClient):
            raise
        init_response, init_records = client.request(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {"roots": {"listChanged": True}},
                "clientInfo": {"name": "mcp-vulscanner", "version": "0.1.0"},
            },
        )
        notify_records = client.notify("notifications/initialized", {})
        response, records = client.request(method, params)
        return response, init_records + notify_records + records


def _drain_stream(stream: Any, sink: list[str]) -> None:
    """Drain a text stream into a list."""

    if stream is None:
        return
    for line in stream:
        sink.append(line.rstrip("\n"))


def _snapshot_files(root: Path) -> dict[str, str]:
    """Capture a digest snapshot."""

    snapshot: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            snapshot[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


def _diff_snapshots(before: dict[str, str], after: dict[str, str]) -> FileDiffSummary:
    """Compute file-system differences."""

    created = sorted(path for path in after if path not in before)
    modified = sorted(path for path in after if path in before and after[path] != before[path])
    deleted = sorted(path for path in before if path not in after)
    return FileDiffSummary(created=created, modified=modified, deleted=deleted)


def _read_log_lines(path: Path) -> list[str]:
    """Read newline-delimited process logs if present."""

    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line]


def _materialize_payload(payload: dict[str, Any] | None, mock_server_base: str) -> dict[str, Any] | None:
    """Resolve placeholder URLs against the per-run mock server."""

    if payload is None:
        return None
    serialized = json.dumps(payload)
    serialized = serialized.replace(MOCK_SERVER_BASE_TOKEN, mock_server_base)
    serialized = serialized.replace("__MOCK_SERVER__", mock_server_base)
    return json.loads(serialized)


class _MockHttpCaptureServer:
    """Capture and normalize outbound HTTP requests from replay targets."""

    def __init__(self) -> None:
        requests: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                header_parts = [
                    f"{name}={value}"
                    for name, value in self.headers.items()
                    if name.lower().startswith("x-") or name.lower().startswith("mcp-")
                ]
                request_record = parsed.path
                if parsed.query:
                    request_record = f"{request_record}?{parsed.query}"
                if header_parts:
                    request_record = f"{request_record}|headers:{'&'.join(sorted(header_parts))}"
                requests.append(request_record)
                if parsed.path == "/redirect-source":
                    self.send_response(302)
                    self.send_header("Location", f"{self.server.base_url}/redirect-landing")
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
                return

        self._requests = requests
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.base_url = self.preview_base_url(self._server.server_address)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @staticmethod
    def preview_base_url(server_address: tuple[str, int] | None = None) -> str:
        """Return a preview base URL or build one from a server address."""

        if server_address is None:
            return "http://127.0.0.1:0"
        host, port = server_address
        return f"http://{host}:{port}"

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    @property
    def requests(self) -> list[str]:
        return list(self._requests)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)
