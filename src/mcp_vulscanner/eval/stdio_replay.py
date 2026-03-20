"""Minimal stdio replay helper for paper experiments."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

from mcp_vulscanner.dynamic.protocol import JsonRpcStdioClient


@dataclass(frozen=True)
class MinimalReplayResult:
    """Compact replay result for paper experiments."""

    target_id: str
    mode: str
    static_findings_count: int
    tool_called: str
    dynamic_attempted: bool
    verdict: str
    evidence: dict[str, Any]
    errors: list[str]
    trace_path: str
    report_path: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return asdict(self)


def run_stdio_replay(
    *,
    target_id: str,
    command: str,
    tool_name: str,
    arguments: dict[str, Any],
    static_findings_count: int,
    output_dir: Path,
) -> MinimalReplayResult:
    """Run a minimal stdio replay and save trace/report artifacts."""

    output_dir.mkdir(parents=True, exist_ok=True)
    workspace = output_dir / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    trace_path = output_dir / "execution-trace.json"
    report_path = output_dir / "replay-report.md"

    before_files = _snapshot_workspace(workspace)
    env = os.environ.copy()
    env["MCP_VULSCANNER_WORKSPACE"] = str(workspace)
    process = subprocess.Popen(
        shlex.split(command),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=workspace,
        env=env,
        bufsize=1,
    )
    stderr_lines: list[str] = []
    stderr_thread = threading.Thread(
        target=_drain_stream,
        args=(process.stderr, stderr_lines),
        daemon=True,
    )
    stderr_thread.start()

    rpc_records: list[dict[str, Any]] = []
    errors: list[str] = []
    dynamic_attempted = False
    tool_call_response: dict[str, Any] = {}
    available_tools: list[dict[str, Any]] = []
    client = JsonRpcStdioClient(process)
    try:
        init_response, records = client.request(
            "initialize",
            {"protocolVersion": "2025-03-26", "capabilities": {}},
        )
        rpc_records.extend(_records_to_dicts(records))
        if "error" in init_response:
            errors.append(f"initialize: {init_response['error']}")

        tools_response, records = client.request("tools/list", {})
        rpc_records.extend(_records_to_dicts(records))
        available_tools = tools_response.get("result", {}).get("tools", [])
        if not any(tool.get("name") == tool_name for tool in available_tools):
            errors.append(f"tool not found: {tool_name}")
        else:
            dynamic_attempted = True
            tool_call_response, records = client.request(
                "tools/call",
                {"name": tool_name, "arguments": arguments},
            )
            rpc_records.extend(_records_to_dicts(records))
            if "error" in tool_call_response:
                errors.append(f"tools/call: {tool_call_response['error']}")
    finally:
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=2)
        stderr_thread.join(timeout=2)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()

    after_files = _snapshot_workspace(workspace)
    evidence = {
        "created_files": sorted(path for path in after_files if path not in before_files),
        "modified_files": sorted(
            path for path in after_files if path in before_files and after_files[path] != before_files[path]
        ),
        "stderr_lines": stderr_lines,
        "outbound_requests": [],
    }
    verdict = _determine_verdict(evidence, errors)
    result = MinimalReplayResult(
        target_id=target_id,
        mode="stdio",
        static_findings_count=static_findings_count,
        tool_called=tool_name,
        dynamic_attempted=dynamic_attempted,
        verdict=verdict,
        evidence=evidence,
        errors=errors,
        trace_path=str(trace_path),
        report_path=str(report_path),
    )

    trace_payload = {
        "result": result.to_dict(),
        "command": command,
        "arguments": arguments,
        "available_tools": available_tools,
        "rpc_records": rpc_records,
        "tool_call_response": tool_call_response,
    }
    trace_path.write_text(json.dumps(trace_payload, indent=2) + "\n", encoding="utf-8")
    report_path.write_text(_render_markdown_report(result), encoding="utf-8")
    return result


def _determine_verdict(evidence: dict[str, Any], errors: list[str]) -> str:
    """Classify the replay result with minimal heuristics."""

    if evidence["created_files"] or evidence["modified_files"]:
        return "CONFIRMED"
    if evidence["stderr_lines"] or errors:
        return "PROBABLE"
    return "UNCONFIRMED"


def _snapshot_workspace(workspace: Path) -> dict[str, bytes]:
    """Capture workspace file contents for diffing."""

    snapshot: dict[str, bytes] = {}
    for path in sorted(workspace.rglob("*")):
        if path.is_file():
            snapshot[str(path.relative_to(workspace))] = path.read_bytes()
    return snapshot


def _drain_stream(stream: Any, sink: list[str]) -> None:
    """Drain stderr into a list."""

    if stream is None:
        return
    for line in stream:
        sink.append(line.rstrip("\n"))


def _records_to_dicts(records: list[Any]) -> list[dict[str, Any]]:
    """Normalize RPC records for JSON output."""

    return [asdict(record) if hasattr(record, "__dataclass_fields__") else dict(record) for record in records]


def _render_markdown_report(result: MinimalReplayResult) -> str:
    """Render a short Markdown summary."""

    return (
        "# Minimal Stdio Replay Report\n\n"
        f"- Target ID: `{result.target_id}`\n"
        f"- Mode: `{result.mode}`\n"
        f"- Static Findings Count: `{result.static_findings_count}`\n"
        f"- Tool Called: `{result.tool_called}`\n"
        f"- Dynamic Attempted: `{result.dynamic_attempted}`\n"
        f"- Verdict: **{result.verdict}**\n"
        f"- Created Files: `{', '.join(result.evidence['created_files']) or 'none'}`\n"
        f"- Errors: `{'; '.join(result.errors) or 'none'}`\n"
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the module CLI parser."""

    parser = argparse.ArgumentParser(
        prog="python -m mcp_vulscanner.eval.stdio_replay",
        description="Run a minimal stdio replay for paper experiments.",
    )
    parser.add_argument("--target-id", required=True, help="Paper target identifier.")
    parser.add_argument("--command", required=True, help="Server startup command.")
    parser.add_argument("--tool", required=True, help="Tool name to call.")
    parser.add_argument("--args", default="{}", help="JSON object of tool arguments.")
    parser.add_argument(
        "--static-findings-count",
        type=int,
        default=1,
        help="Static findings count to record in the normalized result.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory where trace and Markdown report should be written.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the module CLI."""

    args = build_parser().parse_args(argv)
    result = run_stdio_replay(
        target_id=args.target_id,
        command=args.command,
        tool_name=args.tool,
        arguments=json.loads(args.args),
        static_findings_count=args.static_findings_count,
        output_dir=args.output_dir.resolve(),
    )
    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
