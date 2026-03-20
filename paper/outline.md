# Paper Outline

## Working Title

Hybrid Self-Audit of MCP Servers with Static Detection and Protocol-Aware Replay

## Abstract Sketch

- Motivate MCP server security review as a fast-moving and under-instrumented problem.
- Present `mcp-vulscanner` as a research prototype combining static rules with dynamic replay.
- Highlight three target classes: command injection, SSRF, and arbitrary file write/path traversal.
- Summarize the core result: hybrid replay improves confirmation quality over static-only triage.

## Sections

### 1. Introduction

- MCP adoption and the need for security-focused server auditing.
- Why static-only linting is not enough for deployment gates.
- Research questions and contributions.

### 2. Threat Model

- Attacker controls tool inputs and indirectly influences transport metadata.
- Sensitive sinks: shell, filesystem, outbound network access.
- Scope boundaries and non-goals.

### 3. System Design

- Advisory corpus normalization.
- Rule-based static analyzer for JS/TS and Python.
- Dynamic replay engine for stdio and HTTP transports.
- Self-audit gating workflow with PASS/WARN/BLOCK outcomes.

### 4. Evaluation

- Dataset construction and project selection.
- Metrics: recall, confirmation rate, false positive rate.
- Static-only vs hybrid comparison.

### 5. Case Studies

- Representative confirmed findings.
- Replay traces that clarify exploitability.
- Remediation patterns observed across projects.

### 6. Limitations

- Rule-based heuristics versus true taint/dataflow.
- Replay coverage limits for multi-step or stateful tool flows.
- Incomplete transport coverage beyond stdio and HTTP.

### 7. Conclusion

- Key takeaways for MCP server authors and scanner designers.
- Future work on dataflow, transport expansion, and benchmark curation.
