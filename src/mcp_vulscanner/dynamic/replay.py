"""Deterministic dynamic replay engine for stdio and HTTP MCP servers."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from mcp_vulscanner.models.finding import StaticFinding
from mcp_vulscanner.models.replay import FileDiffSummary, ReplayTrace, SideEffectSummary

from .payloads import build_payload
from .protocol import HttpReplayOptions, JsonRpcHttpClient, JsonRpcStdioClient, TransportClient


class DynamicReplayEngine:
    """Execute protocol-aware replay attempts for stdio and HTTP MCP servers."""

    def replay_stdio(
        self,
        target_command: list[str],
        finding: StaticFinding,
        *,
        trace_directory: Path | None = None,
    ) -> ReplayTrace:
        """Launch a target process, replay one finding, and persist a trace."""

        if not finding.tool_name:
            raise ValueError("Dynamic replay requires a finding with tool_name.")

        return self._replay_with_transport(
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
        """Launch an HTTP MCP target and replay one finding over HTTP."""

        return self._replay_with_transport(
            transport="http",
            target_command=target_command,
            finding=finding,
            trace_directory=trace_directory,
            http_endpoint=endpoint,
            http_options=HttpReplayOptions(),
            ssrf_headers=headers or {},
            ssrf_query_params=query_params or {},
            ssrf_base_url=base_url_override,
        )

    def _replay_with_transport(
        self,
        *,
        transport: str,
        target_command: list[str],
        finding: StaticFinding,
        trace_directory: Path | None,
        http_endpoint: str | None = None,
        http_options: HttpReplayOptions | None = None,
        ssrf_headers: dict[str, str] | None = None,
        ssrf_query_params: dict[str, str] | None = None,
        ssrf_base_url: str | None = None,
    ) -> ReplayTrace:
        """Replay a finding using the selected transport."""

        if not finding.tool_name:
            raise ValueError("Dynamic replay requires a finding with tool_name.")

        root = Path(tempfile.mkdtemp(prefix="mcp-vulscanner-replay-"))
        workspace = root / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        subprocess_log = root / "subprocess.log"
        trace_dir = trace_directory.resolve() if trace_directory else root
        trace_dir.mkdir(parents=True, exist_ok=True)
        trace_path = trace_dir / "execution-trace.json"

        mock_server = _MockHttpCaptureServer()
        env = os.environ.copy()
        env["MCP_VULSCANNER_WORKSPACE"] = str(workspace)
        env["MCP_VULSCANNER_SUBPROCESS_LOG"] = str(subprocess_log)
        env["MCP_VULSCANNER_MOCK_SERVER"] = mock_server.base_url
        if transport == "http":
            assert http_endpoint is not None
            parsed_endpoint = urllib.parse.urlparse(http_endpoint)
            env["MCP_VULSCANNER_HTTP_PORT"] = str(parsed_endpoint.port or 80)
            env["MCP_VULSCANNER_HTTP_PATH"] = parsed_endpoint.path or "/mcp"
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
        stderr_thread = threading.Thread(
            target=_drain_stream,
            args=(process.stderr, stderr_lines),
            daemon=True,
        )
        stderr_thread.start()

        if transport == "http":
            assert http_endpoint is not None
            self._wait_for_http_target(http_endpoint, http_options or HttpReplayOptions())
            client: TransportClient = JsonRpcHttpClient(
                endpoint=http_endpoint,
                options=http_options or HttpReplayOptions(),
            )
        else:
            client = JsonRpcStdioClient(process)

        rpc_records: list[Any] = []
        try:
            initialize_response, records = client.request(
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-vulscanner", "version": "0.1.0"},
                },
            )
            rpc_records.extend(records)
            if "error" in initialize_response:
                raise ValueError(f"Initialize failed: {initialize_response['error']}")

            tools_list_response, records = client.request("tools/list", {})
            rpc_records.extend(records)
            tools = tools_list_response.get("result", {}).get("tools", [])
            tool_descriptor = _select_tool_descriptor(tools, finding.tool_name)
            resolved_ssrf_base_url = (
                mock_server.base_url if ssrf_base_url == "__MOCK_SERVER__" else ssrf_base_url
            )
            payload = build_payload(
                finding,
                tool_descriptor,
                workspace=workspace,
                mock_server_url=mock_server.base_url,
                ssrf_request_headers=ssrf_headers,
                ssrf_query_params=ssrf_query_params,
                ssrf_base_url=resolved_ssrf_base_url,
            )

            tool_call_response, records = client.request(
                "tools/call",
                {"name": finding.tool_name, "arguments": payload},
            )
            rpc_records.extend(records)
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
        verdict, rationale = _determine_verdict(
            finding.vulnerability_class,
            side_effects,
            tool_call_response,
        )
        trace = ReplayTrace(
            target_command=target_command,
            transport=transport,
            tool_name=finding.tool_name,
            payload=payload,
            vulnerability_class=finding.vulnerability_class,
            verdict=verdict,
            rationale=rationale,
            rpc_records=rpc_records,
            side_effects=side_effects,
            trace_path=str(trace_path),
        )
        trace_path.write_text(json.dumps(trace.to_dict(), indent=2) + "\n", encoding="utf-8")
        return trace

    def _wait_for_http_target(self, endpoint: str, options: HttpReplayOptions) -> None:
        """Wait for an HTTP target to become responsive."""

        client = JsonRpcHttpClient(endpoint=endpoint, options=options)
        for _ in range(40):
            try:
                client.request("initialize", {"probe": True})
            except Exception:
                time.sleep(0.05)
                continue
            return
        raise ValueError(f"HTTP replay target did not become ready: {endpoint}")


def _select_tool_descriptor(tools: list[dict[str, Any]], tool_name: str) -> dict[str, Any]:
    """Select a tool descriptor by exact name."""

    for tool in tools:
        if tool.get("name") == tool_name:
            return tool
    raise ValueError(f"Tool '{tool_name}' not present in tools/list response.")


def _drain_stream(stream: Any, sink: list[str]) -> None:
    """Drain a text stream into a list."""

    if stream is None:
        return
    for line in stream:
        sink.append(line.rstrip("\n"))


def _snapshot_files(root: Path) -> dict[str, str]:
    """Capture a deterministic digest for each file under a workspace."""

    snapshot: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            relative = str(path.relative_to(root))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            snapshot[relative] = digest
    return snapshot


def _diff_snapshots(before: dict[str, str], after: dict[str, str]) -> FileDiffSummary:
    """Compute created, modified, and deleted files."""

    created = sorted(path for path in after if path not in before)
    modified = sorted(path for path in after if path in before and after[path] != before[path])
    deleted = sorted(path for path in before if path not in after)
    return FileDiffSummary(created=created, modified=modified, deleted=deleted)


def _read_log_lines(path: Path) -> list[str]:
    """Read newline-delimited side-effect logs if present."""

    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line]


def _determine_verdict(
    vulnerability_class: str,
    side_effects: SideEffectSummary,
    tool_call_response: dict[str, Any],
) -> tuple[str, str]:
    """Assign a dynamic replay verdict from observed side effects."""

    if vulnerability_class == "command-injection" and side_effects.spawned_subprocesses:
        return "CONFIRMED", "Observed subprocess execution during tool replay."
    if vulnerability_class == "ssrf" and side_effects.outbound_requests:
        return "CONFIRMED", "Observed outbound HTTP requests to the local mock server."
    if vulnerability_class == "arbitrary-file-write" and (
        side_effects.file_diffs.created or side_effects.file_diffs.modified
    ):
        return "CONFIRMED", "Observed filesystem changes inside the isolated workspace."

    if side_effects.stderr_lines or "error" in tool_call_response:
        return "PROBABLE", "Replay triggered an error path or stderr trace without full confirmation."

    return "UNCONFIRMED", "Replay completed without the expected confirming side effects."


class _MockHttpCaptureServer:
    """Capture deterministic local HTTP requests from replay payloads."""

    def __init__(self) -> None:
        """Start an ephemeral local HTTP capture server."""

        requests: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                header_parts = [
                    f"{name}={value}"
                    for name, value in self.headers.items()
                    if name.lower().startswith("x-")
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
        self._server.base_url = ""
        host, port = self._server.server_address
        self._server.base_url = f"http://{host}:{port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        """Return the capture server base URL."""

        host, port = self._server.server_address
        return f"http://{host}:{port}"

    @property
    def requests(self) -> list[str]:
        """Return the captured request paths."""

        return list(self._requests)

    def close(self) -> None:
        """Stop the capture server."""

        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)
