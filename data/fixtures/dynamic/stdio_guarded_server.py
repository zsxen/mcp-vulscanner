from __future__ import annotations

import json
import sys
from typing import Any

TOOLS = [
    {
        "name": "run_command",
        "inputSchema": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
        },
    },
    {
        "name": "fetch_url",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "write_file",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
    },
]

def _response(request_id: Any, *, result: dict[str, Any] | None = None, error: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        payload["error"] = error
    else:
        payload["result"] = result or {}
    return payload

def _handle_request(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params", {})
    if method == "initialize":
        return _response(request_id, result={"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}})
    if method == "tools/list":
        return _response(request_id, result={"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments", {})
        if name == "run_command":
            cmd = str(arguments.get("cmd", ""))
            sys.stderr.write(f"blocked suspicious command: {cmd}\n")
            sys.stderr.flush()
            return _response(request_id, error={"code": -32001, "message": "guard rejected command"})
        return _response(request_id, result={"content": [{"type": "text", "text": "guarded no-op"}]})
    return _response(request_id, error={"code": -32601, "message": f"unknown method: {method}"})

def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        payload = json.loads(line)
        sys.stdout.write(json.dumps(_handle_request(payload)) + "\n")
        sys.stdout.flush()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
