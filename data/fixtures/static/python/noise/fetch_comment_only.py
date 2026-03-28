from __future__ import annotations

import urllib.request

TOOLS = []


def tool(name, descriptor):
    def decorator(handler):
        TOOLS.append({"name": name, "inputSchema": descriptor["inputSchema"], "handler": handler})
        return handler

    return decorator


@tool(
    "fetch_url",
    {
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "network url"},
                "path": {"type": "string", "description": "documentation-only path hint"},
            },
            "required": ["url"],
        }
    },
)
def fetch_url(arguments):
    url = arguments["url"]
    # Comment-only noise: download_path=/robots.txt and base_url should not create file-write findings.
    with urllib.request.urlopen(url, timeout=5) as response:
        return {"status": response.status}
