# Evaluation Plan

## Goals

- Measure how well `mcp-vulscanner` identifies true MCP server vulnerabilities.
- Compare static-only detection with hybrid static-plus-replay confirmation.
- Quantify the tradeoff between recall and analyst-facing false positives.

## Primary Metrics

- Recall: `TP / (TP + FN)`
- Confirmation rate: `confirmed_findings / hybrid_findings`
- False positive rate: `FP / (TP + FP)`
- Per-project finding counts for both static-only and hybrid modes

## Experimental Conditions

### Static-Only Baseline

- Run `mcp-vulscanner scan quick <target>`
- Record per-project findings, severity distribution, and manual labels

### Hybrid Condition

- Run `mcp-vulscanner scan deep <target-or-config>`
- Record reproduced findings and replay verdicts
- Treat deep scan as CADER-MCP: contract extraction, runtime tool binding, baseline-versus-malicious replay, and differential evidence scoring
- Compare which static findings remain unreproduced versus confirmed

## Dataset Plan

- Use the curated advisory corpus as seed supervision for target selection
- Include intentionally vulnerable fixtures for regression testing
- Expand toward real open-source MCP servers with manually validated labels

## Analysis Outputs

- Markdown, CSV, and LaTeX tables for paper inclusion
- Per-project comparison of static-only versus hybrid findings
- Aggregate summary statistics across ecosystems and vulnerability classes

## CADER-MCP Report Counters

- `raw_findings`: all static findings before runtime scoping
- `scoped_findings`: findings that can be mapped to an MCP tool candidate
- `replayable_findings`: scoped findings that bind to a runtime tool and enter replay denominators
- `contract_valid_replays`: replays that completed the MCP lifecycle and yielded a usable runtime contract
- `binding_success_rate`: `replayable_findings / scoped_findings`
- `confirmed_findings`: replayable findings with a malicious-only forbidden delta versus baseline
- `differential_confirmation_rate`: `confirmed_findings / replayable_findings`
- `scope_noise_ratio`: `(raw_findings - scoped_findings) / raw_findings`

## Reporting Notes

- Separate scanner capability claims from dataset coverage claims
- Clearly mark manually curated labels and assumptions
- Report cases where replay is inconclusive or unavailable
- Exclude non-replayable findings from confirmation-rate denominators
