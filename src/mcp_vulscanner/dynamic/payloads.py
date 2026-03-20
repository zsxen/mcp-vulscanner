"""Payload generation templates for dynamic replay."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp_vulscanner.models.finding import StaticFinding


STRING_FALLBACK = "replay"


def build_payload(
    finding: StaticFinding,
    tool_descriptor: dict[str, Any],
    *,
    workspace: Path,
    mock_server_url: str,
    ssrf_request_headers: dict[str, str] | None = None,
    ssrf_query_params: dict[str, str] | None = None,
    ssrf_base_url: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic tool payload from a finding and tool schema."""

    schema = tool_descriptor.get("inputSchema") or {}
    properties = schema.get("properties") or {}
    required_fields = schema.get("required") or []

    payload: dict[str, Any] = {}
    for field_name in required_fields:
        payload[field_name] = _default_value(field_name)

    if finding.vulnerability_class == "command-injection":
        command_field = _first_present(properties, "cmd", "command") or "cmd"
        proof_path = workspace / "command-proof.txt"
        payload[command_field] = (
            "python3 -c "
            f"\"from pathlib import Path; Path(r'{proof_path}').write_text('confirmed', encoding='utf-8')\""
        )
    elif finding.vulnerability_class == "ssrf":
        url_field = _first_present(properties, "url", "base_url") or "url"
        target_url = f"{mock_server_url}/ssrf-proof"
        if finding.tool_name and "redirect" in finding.tool_name:
            target_url = f"{mock_server_url}/redirect-source"
        header_field = _first_present(properties, "headers", "custom_headers")
        if header_field and ssrf_request_headers:
            payload[header_field] = ssrf_request_headers
        query_field = _first_present(properties, "query", "query_params", "params")
        if query_field and ssrf_query_params:
            payload[query_field] = ssrf_query_params
        if "base_url" in properties and ssrf_base_url:
            payload["base_url"] = ssrf_base_url
            path_field = _first_present(properties, "path", "route")
            if path_field:
                payload[path_field] = "ssrf-proof"
            query_field = _first_present(properties, "query", "query_params", "params")
            if query_field and ssrf_query_params:
                payload[query_field] = ssrf_query_params
        else:
            payload[url_field] = target_url
    elif finding.vulnerability_class == "arbitrary-file-write":
        path_field = (
            _first_present(properties, "download_path", "path", "target_path", "file_path", "filename")
            or "download_path"
        )
        payload[path_field] = "dynamic-proof/output.txt"
        content_field = _first_present(properties, "content", "text", "body")
        if content_field:
            payload[content_field] = "dynamic replay proof"
    else:
        raise ValueError(f"Unsupported replay class: {finding.vulnerability_class}")

    for field_name in properties:
        payload.setdefault(field_name, _default_value(field_name))

    return payload


def _first_present(properties: dict[str, Any], *names: str) -> str | None:
    """Return the first property name present in a schema."""

    for name in names:
        if name in properties:
            return name
    return None


def _default_value(field_name: str) -> str:
    """Generate a deterministic fallback value for a string field."""

    if "url" in field_name:
        return "https://example.invalid/placeholder"
    if "path" in field_name or "file" in field_name:
        return "placeholder.txt"
    if "cmd" in field_name or "command" in field_name:
        return "echo safe"
    return STRING_FALLBACK
