# Related Work

## Static Application Security Testing

Traditional SAST systems focus on source-sink reasoning, API misuse detection, and policy enforcement across mature software stacks. `mcp-vulscanner` fits closest to lightweight, rule-based SAST, but it is specialized for MCP server patterns such as tool schemas, protocol entrypoints, and transport-aware sink usage.

## Hybrid Static and Dynamic Security Analysis

Hybrid analysis combines broad static coverage with dynamic confirmation to reduce analyst time spent on false positives. The core design choice in `mcp-vulscanner` follows that pattern: static analysis nominates suspicious tool paths, then protocol-aware replay tests whether those paths reproduce meaningful side effects.

## SSRF and Command Execution Detection

Prior SSRF and command-injection scanners typically target web handlers, CI pipelines, or IaC/orchestration systems. MCP servers differ because the attacker-facing boundary is often a tool schema rather than an HTTP route, and because transports like stdio and streamable HTTP shape how replay must be driven.

## Agent and Tool Security

Work on LLM tool safety, prompt injection, and agent execution environments provides the broader motivation for auditing MCP servers. `mcp-vulscanner` contributes a narrower but practical angle: identifying when a server exposes risky sinks to tool-controlled inputs and validating that exposure through deterministic replay.

## Positioning

The closest conceptual neighborhood is a hybrid security checker for tool-serving agent infrastructure. The novelty claim should emphasize:

- MCP-specific source and sink modeling
- protocol-aware replay rather than generic request fuzzing
- deployment gating via PASS/WARN/BLOCK outputs
- evaluation that compares static-only versus hybrid confirmation quality
