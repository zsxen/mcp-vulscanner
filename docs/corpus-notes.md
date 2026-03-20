# Corpus Notes

This paper-support corpus is intentionally small and optimized for reproducible evaluation runs rather than broad ecosystem coverage.

## Scope

- 10 total targets
- 6 positive targets
- 4 negative targets
- Three vulnerability classes only: command injection, SSRF, and arbitrary file write

## Manifest Files

- `data/corpus/targets.json`: compact per-target manifest used by scripts and evaluation setup
- `data/corpus/ground-truth.json`: expected positive/negative labels for the same target set

## Notes

- `pinned_ref` values are research fixture identifiers for paper reproduction notes.
- `startup_command` is intentionally stored as a compact string because this corpus is meant for paper tracking first.
- Negative targets are class-matched control samples to support false-positive reporting quickly.
