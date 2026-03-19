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

## Development

```bash
make test
make tree
```
