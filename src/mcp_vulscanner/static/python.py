"""Rule-based Python analyzer."""

from __future__ import annotations

import re
from pathlib import Path

from .base import RuleMatch, SourceFile, StaticAnalyzer, infer_tool_name, score_features


COMMAND_PATTERNS = (
    re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^)\n]*shell\s*=\s*True[^)\n]*\)"),
    re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^)\n]*(?:cmd|command)[^)\n]*\)"),
)
SSRF_PATTERNS = (
    re.compile(r"\brequests\.(?:get|post|put|patch|request)\s*\([^)\n]*(?:url|base_url|headers|params)[^)\n]*\)"),
    re.compile(r"\bhttpx\.(?:get|post|put|patch|request)\s*\([^)\n]*(?:url|base_url|headers|params)[^)\n]*\)"),
    re.compile(r"\burllib\.(?:request\.)?(?:urlopen|Request)\s*\([^)\n]*(?:url|headers)[^)\n]*\)"),
)
FILE_PATTERNS = (
    re.compile(
        r"\bopen\s*\([^)\n]*\b(?:download_path|target_path|file_path|filename|path)\b[^)\n]*,\s*[\"'](?:w|wb|a)[\"']"
    ),
    re.compile(
        r"(?:/|\bjoinpath\s*\(|\bPath\s*\(|\bpathlib\.Path\s*\()[^\n]*\b(?:download_path|target_path|file_path|filename|path)\b"
    ),
    re.compile(
        r"\bshutil\.(?:copy|copyfile|move)\s*\([^)\n]*\b(?:download_path|target_path|file_path|filename|path)\b[^)\n]*\)"
    ),
)


class PythonAnalyzer(StaticAnalyzer):
    """Detect risky sink patterns in Python MCP server code."""

    language = "python"

    def supports(self, path: Path) -> bool:
        """Return whether the file extension is supported."""

        return path.suffix.lower() == ".py"

    def analyze(self, source_file: SourceFile) -> list[RuleMatch]:
        """Analyze Python content with regex-driven heuristics."""

        matches: list[RuleMatch] = []
        lines = source_file.content.splitlines()
        matches.extend(
            self._scan_patterns(
                source_file.content,
                lines,
                COMMAND_PATTERNS,
                "py.command-injection",
                "command-injection",
                "subprocess",
                "Potential command execution from user-controlled input.",
            )
        )
        matches.extend(
            self._scan_patterns(
                source_file.content,
                lines,
                SSRF_PATTERNS,
                "py.ssrf",
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
                "py.file-write",
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
