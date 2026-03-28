"""Transport clients for MCP replay."""

from __future__ import annotations

import json
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Protocol

from mcp_vulscanner.models.replay import RpcRecord


class TransportClient(Protocol):
    """Common request interface shared by stdio and HTTP transports."""

    def request(self, method: str, params: dict[str, Any]) -> tuple[dict[str, Any], list[RpcRecord]]:
        """Send one JSON-RPC request and return the response plus trace records."""

    def close(self) -> None:
        """Release any underlying transport resources."""

    def notify(self, method: str, params: dict[str, Any]) -> list[RpcRecord]:
        """Send one JSON-RPC notification when supported."""


@dataclass
class JsonRpcStdioClient:
    """A tiny line-delimited JSON-RPC client for fixture-friendly MCP servers."""

    process: subprocess.Popen[str]
    next_id: int = 1

    def request(self, method: str, params: dict[str, Any]) -> tuple[dict[str, Any], list[RpcRecord]]:
        """Send one request and wait for the matching response."""

        request_id = self.next_id
        self.next_id += 1
        request_payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(request_payload) + "\n")
        self.process.stdin.flush()

        records = [RpcRecord(direction="request", payload=request_payload)]
        assert self.process.stdout is not None
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise ValueError(f"Target process closed before responding to {method}.")
            response_payload = json.loads(line)
            records.append(RpcRecord(direction="response", payload=response_payload))
            if response_payload.get("id") == request_id:
                return response_payload, records

    def notify(self, method: str, params: dict[str, Any]) -> list[RpcRecord]:
        """Send a JSON-RPC notification over stdio."""

        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()
        return [RpcRecord(direction="request", payload=payload)]

    def close(self) -> None:
        """Stdio cleanup is handled by the caller's process lifecycle management."""

        return


@dataclass
class HttpReplayOptions:
    """Customization options for HTTP-based replay."""

    base_url_override: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    query_params: dict[str, str] = field(default_factory=dict)


@dataclass
class JsonRpcHttpClient:
    """A minimal JSON-RPC over HTTP client."""

    endpoint: str
    options: HttpReplayOptions = field(default_factory=HttpReplayOptions)
    next_id: int = 1
    session_id: str | None = None
    protocol_version: str | None = None

    def request(self, method: str, params: dict[str, Any]) -> tuple[dict[str, Any], list[RpcRecord]]:
        """POST a JSON-RPC request to an HTTP endpoint."""

        request_id = self.next_id
        self.next_id += 1
        request_payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        target_url = self._build_url()
        request = self._build_request(target_url, request_payload)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                response_payload = json.loads(response.read().decode("utf-8"))
                self._capture_session_headers(response.headers)
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and self.session_id:
                self.session_id = None
                raise ValueError("http-session-lost")
            raise
        records = [
            RpcRecord(
                direction="request",
                payload={**request_payload, "_url": target_url, "_headers": dict(request.header_items())},
            ),
            RpcRecord(
                direction="response",
                payload={
                    **response_payload,
                    "_session_id": self.session_id,
                    "_protocol_version": self.protocol_version,
                },
            ),
        ]
        return response_payload, records

    def notify(self, method: str, params: dict[str, Any]) -> list[RpcRecord]:
        """Send a JSON-RPC notification over HTTP."""

        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        target_url = self._build_url()
        request = self._build_request(target_url, payload)
        with urllib.request.urlopen(request, timeout=5) as response:
            self._capture_session_headers(response.headers)
            response.read()
        return [
            RpcRecord(
                direction="request",
                payload={**payload, "_url": target_url, "_headers": dict(request.header_items())},
            )
        ]

    def close(self) -> None:
        """HTTP requests are one-shot, so there is nothing persistent to close."""

        return

    def _build_url(self) -> str:
        """Build the final endpoint including override base URL and query parameters."""

        endpoint = self.endpoint
        if self.options.base_url_override:
            parsed_original = urllib.parse.urlparse(self.endpoint)
            parsed_override = urllib.parse.urlparse(self.options.base_url_override)
            endpoint = urllib.parse.urlunparse(
                (
                    parsed_override.scheme,
                    parsed_override.netloc,
                    parsed_original.path,
                    "",
                    "",
                    "",
                )
            )

        if not self.options.query_params:
            return endpoint

        parsed = urllib.parse.urlparse(endpoint)
        merged_query = urllib.parse.urlencode(self.options.query_params)
        return urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", merged_query, "")
        )

    def _build_request(self, target_url: str, payload: dict[str, Any]) -> urllib.request.Request:
        """Create an HTTP request with MCP session headers when available."""

        headers = {"Content-Type": "application/json", **self.options.headers}
        if self.session_id:
            headers["MCP-Session-Id"] = self.session_id
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        return urllib.request.Request(
            target_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

    def _capture_session_headers(self, headers: Any) -> None:
        """Capture session metadata from the server response."""

        session_id = headers.get("MCP-Session-Id")
        protocol_version = headers.get("MCP-Protocol-Version")
        if session_id:
            self.session_id = session_id
        if protocol_version:
            self.protocol_version = protocol_version
