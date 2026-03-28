"""CADER-MCP stdio fixture server with roots and three vulnerable tools."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import urllib.request


INITIALIZED = False


def _write(payload: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def _notify(method: str, params: dict[str, object]) -> None:
    _write({"jsonrpc": "2.0", "method": method, "params": params})


def _subprocess_log(command: str) -> None:
    log_path = os.environ["MCP_VULSCANNER_SUBPROCESS_LOG"]
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(command + "\n")


def _run_command(arguments: dict[str, object]) -> dict[str, object]:
    command = str(arguments["cmd"])
    _subprocess_log(command)
    subprocess.run(command, shell=True, check=False)
    return {"ok": True}


def _fetch_url(arguments: dict[str, object]) -> dict[str, object]:
    url = str(arguments.get("url") or "https://example.com")
    headers = {key: str(value) for key, value in dict(arguments.get("headers", {})).items()}
    if "base_url" in arguments:
        url = str(arguments["base_url"]).rstrip("/") + "/" + str(arguments.get("path", "ssrf-proof")).lstrip("/")
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=5) as response:
        return {"status": response.status}


def _write_rooted(arguments: dict[str, object]) -> dict[str, object]:
    workspace = pathlib.Path(os.environ["MCP_VULSCANNER_WORKSPACE"])
    roots = [workspace / "allowed-root"]
    roots[0].mkdir(parents=True, exist_ok=True)
    target = pathlib.Path(str(arguments["path"]))
    destination = target if target.is_absolute() else roots[0] / target
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("cader-proof", encoding="utf-8")
    return {"path": str(destination)}


TOOLS = [
    {
        "name": "run_command",
        "description": "Run a shell command",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cmd": {"type": "string", "default": "echo benign"},
            },
            "required": ["cmd"],
        },
    },
    {
        "name": "fetch_url",
        "description": "Fetch a URL with optional override metadata",
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
    },
    {
        "name": "write_rooted",
        "description": "Write to a rooted filesystem path",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "default": "allowed.txt"},
            },
            "required": ["path"],
        },
    },
]


for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    params = request.get("params", {})
    request_id = request.get("id")

    if method == "initialize":
        _write(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"roots": {"listChanged": True}},
                },
            }
        )
    elif method == "notifications/initialized":
        INITIALIZED = True
    elif method == "tools/list":
        _write({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
    elif method == "roots/list":
        _notify("roots/list_changed", {"reason": "bootstrap"})
        workspace = pathlib.Path(os.environ["MCP_VULSCANNER_WORKSPACE"])
        roots = [{"uri": str(workspace / "allowed-root")}]
        _write({"jsonrpc": "2.0", "id": request_id, "result": {"roots": roots}})
    elif method == "tools/call":
        name = params["name"]
        arguments = params.get("arguments", {})
        if name == "run_command":
            result = _run_command(arguments)
        elif name == "fetch_url":
            result = _fetch_url(arguments)
        elif name == "write_rooted":
            result = _write_rooted(arguments)
        else:
            result = {"error": "unknown tool"}
        _write({"jsonrpc": "2.0", "id": request_id, "result": {"content": result}})
