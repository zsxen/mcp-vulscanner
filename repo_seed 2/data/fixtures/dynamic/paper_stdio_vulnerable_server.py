from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

TOOLS = [
    {
        "name": "write_file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    }
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
        if params.get("name") != "write_file":
            return _response(request_id, error={"code": -32601, "message": "unknown tool"})
        arguments = params.get("arguments", {})
        target = Path(str(arguments.get("path", "output.txt")))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(arguments.get("content", "")), encoding="utf-8")
        return _response(request_id, result={"content": [{"type": "text", "text": str(target)}]})
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
