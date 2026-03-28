#!/usr/bin/env bash
set -euo pipefail

# Run from repo root:
#   bash ./setup_ci_test_assets.sh

mkdir -p data/corpus
mkdir -p data/fixtures/eval
mkdir -p data/fixtures/static/js/vulnerable
mkdir -p data/fixtures/static/js/patched
mkdir -p data/fixtures/static/python/vulnerable
mkdir -p data/fixtures/static/python/patched
mkdir -p data/fixtures/dynamic

cat > data/corpus/targets.json <<'EOF'
[
  {
    "target_id": "pos-k8s-cmdi",
    "project_name": "mcp-server-kubernetes",
    "repo_url": "https://github.com/Flux159/mcp-server-kubernetes",
    "language": "javascript",
    "transport_mode": "stdio",
    "startup_command": "npx mcp-server-kubernetes",
    "vulnerability_class": "command-injection",
    "expected_label": "positive",
    "advisory_id": "seed-pos-001",
    "pinned_ref": "seed-dataset",
    "setup_notes": "Positive seed target for command-injection."
  },
  {
    "target_id": "pos-akoskm-cmdi",
    "project_name": "create-mcp-server-stdio",
    "repo_url": "https://github.com/akoskm/create-mcp-server-stdio",
    "language": "javascript",
    "transport_mode": "stdio",
    "startup_command": "npx @akoskm/create-mcp-server-stdio",
    "vulnerability_class": "command-injection",
    "expected_label": "positive",
    "advisory_id": "seed-pos-002",
    "pinned_ref": "seed-dataset",
    "setup_notes": "Positive seed target for command-injection."
  },
  {
    "target_id": "pos-figma-cmdi",
    "project_name": "figma-developer-mcp",
    "repo_url": "https://github.com/GLips/Figma-Context-MCP",
    "language": "javascript",
    "transport_mode": "stdio",
    "startup_command": "npx figma-developer-mcp",
    "vulnerability_class": "command-injection",
    "expected_label": "positive",
    "advisory_id": "seed-pos-003",
    "pinned_ref": "seed-dataset",
    "setup_notes": "Positive seed target for command-injection."
  },
  {
    "target_id": "pos-hackmd-ssrf",
    "project_name": "hackmd-mcp",
    "repo_url": "https://github.com/yuna0x0/hackmd-mcp",
    "language": "javascript",
    "transport_mode": "http",
    "startup_command": "npx hackmd-mcp",
    "vulnerability_class": "ssrf",
    "expected_label": "positive",
    "advisory_id": "seed-pos-004",
    "pinned_ref": "seed-dataset",
    "setup_notes": "Positive seed target for SSRF."
  },
  {
    "target_id": "pos-fetch-ssrf",
    "project_name": "mcp-fetch-server",
    "repo_url": "https://github.com/zcaceres/fetch-mcp",
    "language": "python",
    "transport_mode": "http",
    "startup_command": "npx mcp-fetch-server",
    "vulnerability_class": "ssrf",
    "expected_label": "positive",
    "advisory_id": "seed-pos-005",
    "pinned_ref": "seed-dataset",
    "setup_notes": "Positive seed target for SSRF."
  },
  {
    "target_id": "pos-atlassian-file",
    "project_name": "mcp-atlassian",
    "repo_url": "https://github.com/sooperset/mcp-atlassian",
    "language": "python",
    "transport_mode": "stdio",
    "startup_command": "python -m mcp_atlassian",
    "vulnerability_class": "arbitrary-file-write",
    "expected_label": "positive",
    "advisory_id": "seed-pos-006",
    "pinned_ref": "seed-dataset",
    "setup_notes": "Positive seed target for arbitrary file write."
  },
  {
    "target_id": "neg-safe-python-file",
    "project_name": "fixture-safe-python",
    "repo_url": "https://example.invalid/fixture-safe-python",
    "language": "python",
    "transport_mode": "stdio",
    "startup_command": "python safe_server.py",
    "vulnerability_class": "arbitrary-file-write",
    "expected_label": "negative",
    "advisory_id": "seed-neg-001",
    "pinned_ref": "seed-dataset",
    "setup_notes": "Negative control fixture."
  },
  {
    "target_id": "neg-safe-javascript-cmdi",
    "project_name": "fixture-safe-javascript",
    "repo_url": "https://example.invalid/fixture-safe-javascript",
    "language": "javascript",
    "transport_mode": "stdio",
    "startup_command": "node safe.js",
    "vulnerability_class": "command-injection",
    "expected_label": "negative",
    "advisory_id": "seed-neg-002",
    "pinned_ref": "seed-dataset",
    "setup_notes": "Negative control fixture."
  },
  {
    "target_id": "neg-safe-http-ssrf",
    "project_name": "fixture-safe-http",
    "repo_url": "https://example.invalid/fixture-safe-http",
    "language": "python",
    "transport_mode": "http",
    "startup_command": "python safe_http.py",
    "vulnerability_class": "ssrf",
    "expected_label": "negative",
    "advisory_id": "seed-neg-003",
    "pinned_ref": "seed-dataset",
    "setup_notes": "Negative control fixture."
  },
  {
    "target_id": "neg-safe-stdio-file",
    "project_name": "fixture-safe-stdio",
    "repo_url": "https://example.invalid/fixture-safe-stdio",
    "language": "python",
    "transport_mode": "stdio",
    "startup_command": "python safe_stdio.py",
    "vulnerability_class": "arbitrary-file-write",
    "expected_label": "negative",
    "advisory_id": "seed-neg-004",
    "pinned_ref": "seed-dataset",
    "setup_notes": "Negative control fixture."
  }
]
EOF

cat > data/corpus/ground-truth.json <<'EOF'
[
  {"target_id": "pos-k8s-cmdi", "expected_label": "positive"},
  {"target_id": "pos-akoskm-cmdi", "expected_label": "positive"},
  {"target_id": "pos-figma-cmdi", "expected_label": "positive"},
  {"target_id": "pos-hackmd-ssrf", "expected_label": "positive"},
  {"target_id": "pos-fetch-ssrf", "expected_label": "positive"},
  {"target_id": "pos-atlassian-file", "expected_label": "positive"},
  {"target_id": "neg-safe-python-file", "expected_label": "negative"},
  {"target_id": "neg-safe-javascript-cmdi", "expected_label": "negative"},
  {"target_id": "neg-safe-http-ssrf", "expected_label": "negative"},
  {"target_id": "neg-safe-stdio-file", "expected_label": "negative"}
]
EOF

cat > data/fixtures/eval/sample-results.json <<'EOF'
{
  "projects": [
    {
      "project_name": "mcp-atlassian",
      "static_findings": 1,
      "hybrid_findings": 1,
      "true_positives": 1,
      "false_positives": 0,
      "false_negatives": 0,
      "confirmed_findings": 1
    },
    {
      "project_name": "mcp-server-kubernetes",
      "static_findings": 4,
      "hybrid_findings": 3,
      "true_positives": 3,
      "false_positives": 1,
      "false_negatives": 1,
      "confirmed_findings": 3
    },
    {
      "project_name": "hackmd-mcp",
      "static_findings": 2,
      "hybrid_findings": 2,
      "true_positives": 2,
      "false_positives": 0,
      "false_negatives": 0,
      "confirmed_findings": 2
    }
  ]
}
EOF

cat > data/fixtures/static/js/vulnerable/index.js <<'EOF'
const { exec } = require("child_process");
const fs = require("fs");

function tool(name, descriptor, handler) {
  return { name, descriptor, handler };
}

const runCommand = tool("run_command", {
  inputSchema: {
    type: "object",
    properties: {
      cmd: { type: "string", description: "shell command to execute" }
    },
    required: ["cmd"]
  }
}, ({ cmd }) => {
  exec(cmd);
});

const fetchUrl = tool("fetch_url", {
  inputSchema: {
    type: "object",
    properties: {
      url: { type: "string", description: "http url to fetch over network" }
    },
    required: ["url"]
  }
}, ({ url }) => {
  fetch(url);
});

const writeFile = tool("write_file", {
  inputSchema: {
    type: "object",
    properties: {
      path: { type: "string", description: "download path" },
      content: { type: "string" }
    },
    required: ["path", "content"]
  }
}, ({ path, content }) => {
  fs.writeFileSync(path, content, "utf8");
});

module.exports = { runCommand, fetchUrl, writeFile };
EOF

cat > data/fixtures/static/js/patched/index.js <<'EOF'
const { spawn } = require("child_process");
const fs = require("fs");

function safeTool() {
  spawn("echo", ["safe"], { shell: false });
  fs.writeFileSync("safe-output.txt", "safe", "utf8");
  return { ok: true };
}

module.exports = { safeTool };
EOF

cat > data/fixtures/static/python/vulnerable/server.py <<'EOF'
from pathlib import Path
import subprocess
import urllib.request

TOOLS = []

def tool(name, descriptor):
    def decorator(handler):
        TOOLS.append({"name": name, "inputSchema": descriptor["inputSchema"], "handler": handler})
        return handler
    return decorator

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
def run_command(arguments):
    cmd = arguments["cmd"]
    subprocess.run(cmd, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"ok": True}

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
def fetch_url(arguments):
    url = arguments["url"]
    with urllib.request.urlopen(url, timeout=5) as response:
        return {"status": response.status}

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
def write_file(arguments):
    path = arguments["path"]
    Path(path).write_text(arguments["content"], encoding="utf-8")
    return {"ok": True}
EOF

cat > data/fixtures/static/python/patched/server.py <<'EOF'
from pathlib import Path
import subprocess

def safe_tool(arguments):
    subprocess.run(["echo", "safe"], shell=False, check=False)
    Path("safe-output.txt").write_text("safe", encoding="utf-8")
    return {"ok": True}
EOF

cat > data/fixtures/dynamic/stdio_vulnerable_server.py <<'EOF'
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
EOF

cat > data/fixtures/dynamic/stdio_guarded_server.py <<'EOF'
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
EOF

cat > data/fixtures/dynamic/stdio_safe_server.py <<'EOF'
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
    if method == "initialize":
        return _response(request_id, result={"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}})
    if method == "tools/list":
        return _response(request_id, result={"tools": TOOLS})
    if method == "tools/call":
        return _response(request_id, result={"content": [{"type": "text", "text": "safe no-op"}]})
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
EOF

cat > data/fixtures/dynamic/paper_stdio_vulnerable_server.py <<'EOF'
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
EOF

cat > data/fixtures/dynamic/http_header_ssrf_server.py <<'EOF'
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
EOF

cat > data/fixtures/dynamic/http_base_url_ssrf_server.py <<'EOF'
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PORT = int(os.environ.get("MCP_VULSCANNER_HTTP_PORT", "18902"))
MCP_PATH = os.environ.get("MCP_VULSCANNER_HTTP_PATH", "/mcp")

TOOLS = [
    {
        "name": "fetch_with_base_url",
        "inputSchema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string"},
                "path": {"type": "string"},
                "query": {"type": "object"},
            },
            "required": ["base_url", "path"],
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
            base_url = str(args["base_url"]).rstrip("/")
            path = str(args.get("path", "")).lstrip("/")
            target = f"{base_url}/{path}"
            query = dict(args.get("query", {}))
            if query:
                target = f"{target}?{urllib.parse.urlencode(query)}"
            with urllib.request.urlopen(target, timeout=5) as response:
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
EOF

cat > data/fixtures/dynamic/http_redirect_ssrf_server.py <<'EOF'
from __future__ import annotations

import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PORT = int(os.environ.get("MCP_VULSCANNER_HTTP_PORT", "18903"))
MCP_PATH = os.environ.get("MCP_VULSCANNER_HTTP_PATH", "/mcp")

TOOLS = [
    {
        "name": "fetch_redirect",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
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
            with urllib.request.urlopen(str(args["url"]), timeout=5) as response:
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
EOF

python3 - <<'EOF'
from pathlib import Path
for rel in [
    "data/corpus/targets.json",
    "data/corpus/ground-truth.json",
    "data/fixtures/eval/sample-results.json",
    "data/fixtures/static/js/vulnerable/index.js",
    "data/fixtures/static/js/patched/index.js",
    "data/fixtures/static/python/vulnerable/server.py",
    "data/fixtures/static/python/patched/server.py",
    "data/fixtures/dynamic/stdio_vulnerable_server.py",
    "data/fixtures/dynamic/stdio_guarded_server.py",
    "data/fixtures/dynamic/stdio_safe_server.py",
    "data/fixtures/dynamic/paper_stdio_vulnerable_server.py",
    "data/fixtures/dynamic/http_header_ssrf_server.py",
    "data/fixtures/dynamic/http_base_url_ssrf_server.py",
    "data/fixtures/dynamic/http_redirect_ssrf_server.py",
]:
    path = Path(rel)
    if not path.exists():
        raise SystemExit(f"missing: {rel}")
print("Created all seed corpus and fixture files.")
EOF

echo
echo "Run local tests:"
echo "  UV_CACHE_DIR=.uv-cache uv run python -m unittest discover -s tests -v"
echo
echo "Then commit:"
echo "  git add data/corpus data/fixtures"
echo "  git commit -m 'Add seed corpus and fixture files for CI'"
echo "  git push"
