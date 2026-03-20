"""Helpers for HTTP-based MCP fixture servers."""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable


ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


def serve_http_mcp(tools: list[dict[str, Any]], handlers: dict[str, ToolHandler]) -> None:
    """Serve a minimal JSON-RPC MCP endpoint over HTTP."""

    endpoint_path = os.environ.get("MCP_VULSCANNER_HTTP_PATH", "/mcp")
    port = int(os.environ["MCP_VULSCANNER_HTTP_PORT"])

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] != endpoint_path:
                self.send_response(404)
                self.end_headers()
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
            method = payload["method"]
            request_id = payload["id"]
            params = payload.get("params", {})

            if method == "initialize":
                self._write_json(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {"protocolVersion": "2025-03-26", "capabilities": {}},
                    }
                )
                return

            if method == "tools/list":
                self._write_json({"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}})
                return

            if method == "tools/call":
                tool_name = params["name"]
                arguments = params.get("arguments", {})
                try:
                    result = handlers[tool_name](arguments)
                    self._write_json(
                        {"jsonrpc": "2.0", "id": request_id, "result": {"content": result}}
                    )
                except Exception as exc:  # pragma: no cover - exercised through replay tests
                    print(f"http fixture error: {exc}", file=sys.stderr)
                    self._write_json(
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "error": {"code": -32000, "message": str(exc)},
                        }
                    )
                return

            self._write_json(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"Unknown method: {method}"},
                }
            )

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

        def _write_json(self, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()
