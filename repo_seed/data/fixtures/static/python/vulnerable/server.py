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
