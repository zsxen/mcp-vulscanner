"""Rule-based JavaScript and TypeScript analyzer."""

from __future__ import annotations

import re
from pathlib import Path

from .base import RuleMatch, SourceFile, StaticAnalyzer, infer_tool_name, score_features


COMMAND_PATTERNS = (
    re.compile(r"\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{[^`]+\}[^`]*`"),
    re.compile(r"\b(?:exec|execSync)\s*\([^)\n]*(?:cmd|command|args|input)[^)\n]*\)"),
)
SSRF_PATTERNS = (
    re.compile(r"\bfetch\s*\([^)\n]*(?:url|baseUrl|base_url|input|headers|query|params)[^)\n]*\)"),
    re.compile(r"\baxios\.(?:get|post|request|create)\s*\([^)\n]*(?:url|baseUrl|base_url|headers|params)[^)\n]*\)"),
    re.compile(r"\bhttps?\.(?:request|get)\s*\([^)\n]*(?:url|host|path|headers)[^)\n]*\)"),
)
FILE_PATTERNS = (
    re.compile(
        r"\b(?:writeFile|writeFileSync|createWriteStream)\s*\([^)\n]*\b(?:download_path|target_path|file_path|filename|path)\b[^)\n]*\)"
    ),
    re.compile(
        r"\bpath\.join\s*\([^)\n]*\b(?:download_path|target_path|file_path|filename|path)\b[^)\n]*\)"
    ),
)


class JavaScriptAnalyzer(StaticAnalyzer):
    """Detect risky sink patterns in JS/TS MCP server code."""

    language = "javascript"
    suffixes = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

    def supports(self, path: Path) -> bool:
        """Return whether the file extension is supported."""

        return path.suffix.lower() in self.suffixes

    def analyze(self, source_file: SourceFile) -> list[RuleMatch]:
        """Analyze JS/TS content with regex-driven heuristics."""

        matches: list[RuleMatch] = []
        lines = source_file.content.splitlines()
        matches.extend(
            self._scan_patterns(
                source_file.content,
                lines,
                COMMAND_PATTERNS,
                "js.command-injection",
                "command-injection",
                "child_process.exec",
                "Potential command execution from user-controlled input.",
            )
        )
        matches.extend(
            self._scan_patterns(
                source_file.content,
                lines,
                SSRF_PATTERNS,
                "js.ssrf",
                "ssrf",
                "network-request",
                "Potential outbound request from user-controlled URL or request metadata.",
            )
        )
        matches.extend(
            self._scan_patterns(
                source_file.content,
                lines,
                FILE_PATTERNS,
                "js.file-write",
                "arbitrary-file-write",
                "filesystem-write",
                "Potential file write or path traversal from user-controlled path input.",
            )
        )
        return matches

    def _scan_patterns(
        self,
        source_text: str,
        lines: list[str],
        patterns: tuple[re.Pattern[str], ...],
        rule_id: str,
        vulnerability_class: str,
        sink: str,
        message: str,
    ) -> list[RuleMatch]:
        """Scan a content blob with one family of patterns."""

        findings: list[RuleMatch] = []
        seen_lines: set[int] = set()
        for pattern in patterns:
            for matched in pattern.finditer(source_text):
                line = source_text.count("\n", 0, matched.start()) + 1
                if line in seen_lines:
                    continue
                seen_lines.add(line)
                snippet = lines[line - 1].strip()
                findings.append(
                    RuleMatch(
                        rule_id=rule_id,
                        vulnerability_class=vulnerability_class,
                        line=line,
                        tool_name=infer_tool_name(source_text, matched.start()),
                        sink=sink,
                        symbol=None,
                        snippet=snippet,
                        evidence=score_features(source_text, snippet),
                        message=message,
                    )
                )
        return findings
