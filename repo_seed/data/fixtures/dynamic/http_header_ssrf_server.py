from __future__ import annotations

import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PORT = int(os.environ.get("MCP_VULSCANNER_HTTP_PORT", "18901"))
MCP_PATH = os.environ.get("MCP_VULSCANNER_HTTP_PATH", "/mcp")

TOOLS = [
    {
        "name": "fetch_with_headers",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "headers": {"type": "object"},
            },
            "required": ["url"],
        },
    }
]

def _rpc_response(request_id: Any, *, result: dict[str, Any] | None = None, error: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        payload["error"] = error
    else:
        payload["result"] = result or {}
    return payload

class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        payload = json.loads(body.decode("utf-8"))
        response = self._handle_rpc(payload)
        encoded = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _handle_rpc(self, payload: dict[str, Any]) -> dict[str, Any]:
        request_id = payload.get("id")
        method = payload.get("method")
        params = payload.get("params", {})
        if method == "initialize":
            return _rpc_response(request_id, result={"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}})
        if method == "tools/list":
            return _rpc_response(request_id, result={"tools": TOOLS})
        if method == "tools/call":
            args = params.get("arguments", {})
            request = urllib.request.Request(
                str(args["url"]),
                headers={str(k): str(v) for k, v in dict(args.get("headers", {})).items()},
                method="GET",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                status = response.status
            return _rpc_response(request_id, result={"status": status})
        return _rpc_response(request_id, error={"code": -32601, "message": f"unknown method: {method}"})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
