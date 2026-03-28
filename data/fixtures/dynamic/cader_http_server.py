"""CADER-MCP Streamable HTTP fixture with session loss and SSRF behavior."""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


CURRENT_SESSION = "session-1"
SESSION_LOST_ONCE = False
PORT = int(os.environ["MCP_VULSCANNER_HTTP_PORT"])
PATH = os.environ.get("MCP_VULSCANNER_HTTP_PATH", "/mcp")


TOOLS = [
    {
        "name": "fetch_url",
        "description": "Fetch a URL over HTTP",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "default": "https://example.com"},
                "headers": {"type": "object", "default": {}},
                "base_url": {"type": "string"},
                "path": {"type": "string", "default": "ssrf-proof"},
            },
            "required": ["url"],
        },
    }
]


def _write_json(handler: BaseHTTPRequestHandler, payload: dict[str, Any], *, session_id: str) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("MCP-Session-Id", session_id)
    handler.send_header("MCP-Protocol-Version", "2025-03-26")
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        global CURRENT_SESSION, SESSION_LOST_ONCE

        if self.path.split("?", 1)[0] != PATH:
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
        method = payload["method"]
        request_id = payload.get("id")
        params = payload.get("params", {})

        if method == "initialize":
            if SESSION_LOST_ONCE:
                CURRENT_SESSION = "session-2"
            _write_json(
                self,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"protocolVersion": "2025-03-26", "capabilities": {}},
                },
                session_id=CURRENT_SESSION,
            )
            return

        if self.headers.get("MCP-Session-Id") != CURRENT_SESSION:
            self.send_response(404)
            self.end_headers()
            return

        if method == "tools/list":
            _write_json(self, {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}, session_id=CURRENT_SESSION)
            return

        if method == "notifications/initialized":
            _write_json(self, {"jsonrpc": "2.0", "id": request_id, "result": {}}, session_id=CURRENT_SESSION)
            return

        if method == "tools/call":
            if not SESSION_LOST_ONCE:
                SESSION_LOST_ONCE = True
                CURRENT_SESSION = "session-2"
                self.send_response(404)
                self.end_headers()
                return
            arguments = params.get("arguments", {})
            url = str(arguments.get("url") or "https://example.com")
            headers = {key: str(value) for key, value in dict(arguments.get("headers", {})).items()}
            if "base_url" in arguments:
                url = str(arguments["base_url"]).rstrip("/") + "/" + str(arguments.get("path", "ssrf-proof")).lstrip("/")
            request = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(request, timeout=5) as response:
                status = response.status
            _write_json(
                self,
                {"jsonrpc": "2.0", "id": request_id, "result": {"content": {"status": status}}},
                session_id=CURRENT_SESSION,
            )
            return

        _write_json(
            self,
            {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": method}},
            session_id=CURRENT_SESSION,
        )

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return


server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
try:
    server.serve_forever()
finally:
    server.server_close()
