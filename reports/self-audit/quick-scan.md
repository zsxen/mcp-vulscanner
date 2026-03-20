# Quick Self-Audit Report

- Target: `/Users/sujinjeong/Git/mcp-vulscanner/data/fixtures/static/js/vulnerable`
- Gate: **BLOCK**
- Summary: BLOCK: 3 finding(s), 0 reproduced via dynamic replay.

## Findings

### 1. arbitrary-file-write
- Severity: `high`
- Location: `/Users/sujinjeong/Git/mcp-vulscanner/data/fixtures/static/js/vulnerable/server.ts:22`
- Tool: `downloadArtifact`
- Message: Potential file write or path traversal from user-controlled path input.
- Remediation: Constrain file output to an allowlisted workspace, resolve canonical paths, reject traversal segments, and separate user data from destination selection.

### 2. command-injection
- Severity: `high`
- Location: `/Users/sujinjeong/Git/mcp-vulscanner/data/fixtures/static/js/vulnerable/server.ts:20`
- Tool: `downloadArtifact`
- Message: Potential command execution from user-controlled input.
- Remediation: Avoid shell execution with untrusted input. Prefer argument arrays, allowlists, and explicit command dispatch without string interpolation.

### 3. ssrf
- Severity: `high`
- Location: `/Users/sujinjeong/Git/mcp-vulscanner/data/fixtures/static/js/vulnerable/server.ts:21`
- Tool: `downloadArtifact`
- Message: Potential outbound request from user-controlled URL or request metadata.
- Remediation: Disallow caller-controlled outbound destinations. Normalize and allowlist hosts, strip dangerous headers/query overrides, and block redirect chains to untrusted origins.
