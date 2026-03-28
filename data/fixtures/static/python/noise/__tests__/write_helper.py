from __future__ import annotations

from pathlib import Path

TOOLS = []


def tool(name, descriptor):
    def decorator(handler):
        TOOLS.append({"name": name, "inputSchema": descriptor["inputSchema"], "handler": handler})
        return handler

    return decorator


@tool(
    "write_file",
    {
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
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
