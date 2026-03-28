from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any, Callable

TOOLS: list[dict[str, Any]] = []

def tool(name: str, descriptor: dict[str, Any]):
    def decorator(handler: Callable[[dict[str, Any]], dict[str, Any]]) -> Callable[[dict[str, Any]], dict[str, Any]]:
        TOOLS.append({"name": name, "inputSchema": descriptor["inputSchema"], "handler": handler})
        return handler
    return decorator

def _write_subprocess_log(entry: str) -> None:
    log_path = os.environ.get("MCP_VULSCANNER_SUBPROCESS_LOG")
    if not log_path:
        return
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(entry + "\n")

@tool(
    "run_command",
    {
        "inputSchema": {
            "type": "object",
            "properties": {
                "cmd": {"type": "string", "description": "shell command to execute"}
            },
            "required": ["cmd"],
        }
    },
)
def run_command(arguments: dict[str, Any]) -> dict[str, Any]:
    cmd = str(arguments["cmd"])
    subprocess.run(cmd, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _write_subprocess_log(cmd)
    return {"content": [{"type": "text", "text": "command executed"}]}

@tool(
    "fetch_url",
    {
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "network url to fetch"}
            },
            "required": ["url"],
        }
    },
)
def fetch_url(arguments: dict[str, Any]) -> dict[str, Any]:
    url = str(arguments["url"])
    with urllib.request.urlopen(url, timeout=5) as response:
        body = response.read().decode("utf-8", errors="replace")
    return {"content": [{"type": "text", "text": body[:64]}]}

@tool(
    "write_file",
    {
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "download path"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        }
    },
)
def write_file(arguments: dict[str, Any]) -> dict[str, Any]:
    relative_path = str(arguments["path"])
    target = Path(relative_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(str(arguments.get("content", "")), encoding="utf-8")
    return {"content": [{"type": "text", "text": str(target)}]}

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
        return _response(
            request_id,
            result={
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fixture-stdio-vulnerable", "version": "0.1.0"},
            },
        )
    if method == "tools/list":
        tools = [{"name": item["name"], "inputSchema": item["inputSchema"]} for item in TOOLS]
        return _response(request_id, result={"tools": tools})
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments", {})
        for item in TOOLS:
            if item["name"] == name:
                try:
                    result = item["handler"](arguments)
                    return _response(request_id, result=result)
                except Exception as exc:  # noqa: BLE001
                    return _response(request_id, error={"code": -32000, "message": str(exc)})
        return _response(request_id, error={"code": -32601, "message": f"unknown tool: {name}"})
    return _response(request_id, error={"code": -32601, "message": f"unknown method: {method}"})

def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        payload = json.loads(line)
        response = _handle_request(payload)
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
