# Quick Self-Audit Report

- Target: `/Users/sujinjeong/Git/mcp-vulscanner/data/fixtures/static/js/vulnerable`
- Gate: **BLOCK**
- Summary: BLOCK: 3 raw finding(s), 0 replayable findings after scope filtering.
- Raw Findings: `3`
- Scope-Excluded Findings: `0`
- Scoped Findings: `3`
- Replayable Findings: `0`
- Contract-Valid Replays: `0`
- Binding Success Rate: `0.00`
- Confirmed Findings: `0`
- Differential Confirmation Rate: `0.00`
- Scope Noise Ratio: `0.00`
- Suppression Reasons: `{}`

## Findings

### 1. arbitrary-file-write
- Severity: `high`
- Location: `/Users/sujinjeong/Git/mcp-vulscanner/data/fixtures/static/js/vulnerable/index.js:42`
- Tool: `write_file`
- Message: Potential file write or path traversal from user-controlled path input.
- Remediation: Constrain file output to an allowlisted workspace, resolve canonical paths, reject traversal segments, and separate user data from destination selection.

### 2. command-injection
- Severity: `high`
- Location: `/Users/sujinjeong/Git/mcp-vulscanner/data/fixtures/static/js/vulnerable/index.js:17`
- Tool: `run_command`
- Message: Potential command execution from user-controlled input.
- Remediation: Avoid shell execution with untrusted input. Prefer argument arrays, allowlists, and explicit command dispatch without string interpolation.

### 3. ssrf
- Severity: `high`
- Location: `/Users/sujinjeong/Git/mcp-vulscanner/data/fixtures/static/js/vulnerable/index.js:29`
- Tool: `fetch_url`
- Message: Potential outbound request from user-controlled URL or request metadata.
- Remediation: Disallow caller-controlled outbound destinations. Normalize and allowlist hosts, strip dangerous headers/query overrides, and block redirect chains to untrusted origins.
