# mcp-vulscanner

Research-only Python scaffold for experimenting with MCP vulnerability collection, scanning, reporting, and evaluation workflows. This repository is intended for prototypes, benchmarks, datasets, and papers rather than the final distribution package.

## Repository purpose

- Keep exploratory scanner code, datasets, and evaluation artifacts in one place.
- Separate research outputs from any future production or release repository.
- Provide a stable CLI surface early so implementation can grow behind clean interfaces.

## Layout

```text
src/mcp_vulscanner/   Python package and CLI scaffold
tests/                Minimal unit tests
docs/                 Project notes and design docs
paper/                Manuscripts and figures
data/                 Research datasets and fixtures
```

## Quick start

```bash
uv run mcp-vulscanner dataset sync
uv run mcp-vulscanner scan quick sample-target
uv run mcp-vulscanner scan deep sample-target
uv run mcp-vulscanner report render sample-input.json
```

## CADER-MCP deep scan

`scan deep` now uses CADER-MCP: Contract-Aware Differential Exploit Replay for MCP servers. The deep path keeps the existing CLI stable while replacing single-shot replay with:

- lifecycle-aware contract extraction through `initialize`, `notifications/initialized`, `tools/list`, and optional roots bootstrap
- candidate-to-tool binding so only runtime-bound findings count toward replay confirmation
- differential replay with one schema-valid baseline input plus malicious variants
- evidence-oriented verdicts based on malicious-only deltas in process, file-system, HTTP, and error traces

Deep scan reports now expose paper-oriented counters:

- `raw_findings`
- `scoped_findings`
- `replayable_findings`
- `contract_valid_replays`
- `binding_success_rate`
- `confirmed_findings`
- `differential_confirmation_rate`
- `scope_noise_ratio`

## Development

```bash
make test
make tree
```
