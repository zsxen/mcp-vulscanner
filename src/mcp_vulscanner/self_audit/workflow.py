"""Self-audit orchestration for quick and deep scans."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_vulscanner.dynamic import DynamicReplayEngine
from mcp_vulscanner.models.finding import StaticFinding
from mcp_vulscanner.models.replay import ReplayTrace
from mcp_vulscanner.static import StaticAnalysisEngine


REMEDIATION_GUIDANCE = {
    "command-injection": (
        "Avoid shell execution with untrusted input. Prefer argument arrays, allowlists, "
        "and explicit command dispatch without string interpolation."
    ),
    "ssrf": (
        "Disallow caller-controlled outbound destinations. Normalize and allowlist hosts, "
        "strip dangerous headers/query overrides, and block redirect chains to untrusted origins."
    ),
    "arbitrary-file-write": (
        "Constrain file output to an allowlisted workspace, resolve canonical paths, "
        "reject traversal segments, and separate user data from destination selection."
    ),
}


@dataclass(frozen=True)
class AuditFinding:
    """A finding enriched with remediation and replay information."""

    static_finding: StaticFinding
    remediation_guidance: str
    replay_trace: ReplayTrace | None = None
    replayable: bool = True
    non_replayable_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        payload = {
            "static_finding": self.static_finding.to_dict(),
            "remediation_guidance": self.remediation_guidance,
            "replay_trace": self.replay_trace.to_dict() if self.replay_trace else None,
            "replayable": self.replayable,
            "non_replayable_reason": self.non_replayable_reason,
        }
        return payload


@dataclass(frozen=True)
class AuditReport:
    """A complete self-audit report for one target."""

    target: str
    mode: str
    gate: str
    summary: str
    findings: list[AuditFinding]
    reproduced_findings: list[AuditFinding]
    raw_findings: int
    scope_excluded_findings: int
    scoped_findings: int
    replayable_findings: int
    contract_valid_replays: int
    binding_success_rate: float
    confirmed_findings: int
    differential_confirmation_rate: float
    scope_noise_ratio: float
    suppression_reasons: dict[str, int]
    markdown_report_path: str
    json_report_path: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {
            "target": self.target,
            "mode": self.mode,
            "gate": self.gate,
            "summary": self.summary,
            "finding_count": len(self.findings),
            "reproduced_count": len(self.reproduced_findings),
            "raw_findings": self.raw_findings,
            "scope_excluded_findings": self.scope_excluded_findings,
            "scoped_findings": self.scoped_findings,
            "replayable_findings": self.replayable_findings,
            "contract_valid_replays": self.contract_valid_replays,
            "binding_success_rate": self.binding_success_rate,
            "confirmed_findings": self.confirmed_findings,
            "differential_confirmation_rate": self.differential_confirmation_rate,
            "scope_noise_ratio": self.scope_noise_ratio,
            "suppression_reasons": self.suppression_reasons,
            "findings": [finding.to_dict() for finding in self.findings],
            "reproduced_findings": [finding.to_dict() for finding in self.reproduced_findings],
            "markdown_report_path": self.markdown_report_path,
            "json_report_path": self.json_report_path,
        }


@dataclass(frozen=True)
class ReplayTarget:
    """Replay execution settings resolved from a path or config."""

    transport: str
    command: list[str]
    endpoint: str | None = None
    headers: dict[str, str] | None = None
    query_params: dict[str, str] | None = None
    base_url_override: str | None = None


@dataclass(frozen=True)
class ScanConfig:
    """Resolved scan configuration for the self-audit workflow."""

    source_path: Path
    replay_target: ReplayTarget | None


class SelfAuditWorkflow:
    """Run quick and deep self-audit scans with gating and reports."""

    def __init__(
        self,
        *,
        static_engine: StaticAnalysisEngine | None = None,
        dynamic_engine: DynamicReplayEngine | None = None,
    ) -> None:
        """Initialize reusable static and dynamic engines."""

        self._static_engine = static_engine or StaticAnalysisEngine()
        self._dynamic_engine = dynamic_engine or DynamicReplayEngine()

    def run_quick(
        self,
        target_or_config: Path,
        *,
        output_dir: Path,
        include_vendor: bool = False,
        include_tests: bool = False,
    ) -> AuditReport:
        """Run a static-analysis-only self-audit."""

        config = resolve_scan_config(target_or_config)
        static_report = self._analyze_static(
            config.source_path,
            mode="quick",
            include_vendor=include_vendor,
            include_tests=include_tests,
        )
        findings = [self._enrich_finding(finding) for finding in static_report.findings]
        gate = determine_quick_gate(findings)
        summary = summarize_gate(
            gate,
            findings,
            reproduced_findings=[],
            raw_findings=static_report.raw_findings,
            replayable_findings=0,
        )
        return write_audit_report(
            AuditReport(
                target=str(config.source_path.resolve()),
                mode="quick",
                gate=gate,
                summary=summary,
                findings=findings,
                reproduced_findings=[],
                raw_findings=static_report.raw_findings,
                scope_excluded_findings=static_report.scope_excluded_findings,
                scoped_findings=len(findings),
                replayable_findings=0,
                contract_valid_replays=0,
                binding_success_rate=0.0,
                confirmed_findings=0,
                differential_confirmation_rate=0.0,
                scope_noise_ratio=_scope_noise_ratio(static_report.raw_findings, len(findings)),
                suppression_reasons=static_report.suppression_reasons or {},
                markdown_report_path="",
                json_report_path="",
            ),
            output_dir=output_dir,
        )

    def run_deep(
        self,
        target_or_config: Path,
        *,
        output_dir: Path,
        include_vendor: bool = False,
        include_tests: bool = False,
    ) -> AuditReport:
        """Run static analysis and replay high-priority findings when possible."""

        config = resolve_scan_config(target_or_config)
        static_report = self._analyze_static(
            config.source_path,
            mode="deep",
            include_vendor=include_vendor,
            include_tests=include_tests,
        )
        findings = [self._enrich_finding(finding) for finding in static_report.findings]
        reproduced: list[AuditFinding] = []
        raw_findings = static_report.raw_findings
        scoped_findings = len(findings)
        replayable_findings = 0
        contract_valid_replays = 0
        confirmed_findings = 0

        if config.replay_target:
            replay_output_dir = output_dir / "replays"
            replay_output_dir.mkdir(parents=True, exist_ok=True)
            for index, audit_finding in enumerate(findings):
                if audit_finding.static_finding.severity != "high":
                    continue
                if audit_finding.static_finding.tool_name is None:
                    continue
                trace_dir = replay_output_dir / f"finding-{index + 1}"
                trace_dir.mkdir(parents=True, exist_ok=True)
                try:
                    replay_trace = self._replay_finding(
                        config.replay_target,
                        audit_finding.static_finding,
                        trace_dir,
                    )
                except ValueError:
                    findings[index] = AuditFinding(
                        static_finding=audit_finding.static_finding,
                        remediation_guidance=audit_finding.remediation_guidance,
                        replay_trace=None,
                        replayable=False,
                        non_replayable_reason="binding_failed",
                    )
                    continue
                if replay_trace.non_replayable:
                    findings[index] = AuditFinding(
                        static_finding=audit_finding.static_finding,
                        remediation_guidance=audit_finding.remediation_guidance,
                        replay_trace=replay_trace,
                        replayable=False,
                        non_replayable_reason=replay_trace.rationale,
                    )
                    continue
                replayable_findings += 1
                if replay_trace.contract_valid:
                    contract_valid_replays += 1
                enriched = AuditFinding(
                    static_finding=audit_finding.static_finding,
                    remediation_guidance=audit_finding.remediation_guidance,
                    replay_trace=replay_trace,
                    replayable=True,
                )
                findings[index] = enriched
                if replay_trace.verdict in {"CONFIRMED", "PROBABLE"}:
                    reproduced.append(enriched)
                if replay_trace.verdict == "CONFIRMED":
                    confirmed_findings += 1

        gate = determine_deep_gate(findings, reproduced)
        if gate == "PASS" and raw_findings > 0:
            gate = "WARN"
        summary = summarize_gate(
            gate,
            findings,
            reproduced,
            raw_findings=raw_findings,
            replayable_findings=replayable_findings,
        )
        binding_success_rate = 0.0 if scoped_findings == 0 else replayable_findings / scoped_findings
        differential_confirmation_rate = (
            0.0 if replayable_findings == 0 else confirmed_findings / replayable_findings
        )
        return write_audit_report(
            AuditReport(
                target=str(config.source_path.resolve()),
                mode="deep",
                gate=gate,
                summary=summary,
                findings=findings,
                reproduced_findings=reproduced,
                raw_findings=raw_findings,
                scope_excluded_findings=static_report.scope_excluded_findings,
                scoped_findings=scoped_findings,
                replayable_findings=replayable_findings,
                contract_valid_replays=contract_valid_replays,
                binding_success_rate=binding_success_rate,
                confirmed_findings=confirmed_findings,
                differential_confirmation_rate=differential_confirmation_rate,
                scope_noise_ratio=_scope_noise_ratio(raw_findings, scoped_findings),
                suppression_reasons=static_report.suppression_reasons or {},
                markdown_report_path="",
                json_report_path="",
            ),
            output_dir=output_dir,
        )

    def _enrich_finding(self, finding: StaticFinding) -> AuditFinding:
        """Attach remediation guidance to a static finding."""

        return AuditFinding(
            static_finding=finding,
            remediation_guidance=REMEDIATION_GUIDANCE.get(
                finding.vulnerability_class,
                "Review trust boundaries and restrict untrusted input from reaching sensitive sinks.",
            ),
        )

    def _replay_finding(
        self,
        replay_target: ReplayTarget,
        finding: StaticFinding,
        trace_dir: Path,
    ) -> ReplayTrace:
        """Replay one high-priority finding using the resolved transport."""

        if replay_target.transport == "stdio":
            return self._dynamic_engine.replay_stdio(
                replay_target.command,
                finding,
                trace_directory=trace_dir,
            )
        if replay_target.transport == "http":
            if replay_target.endpoint is None:
                raise ValueError("HTTP replay requires an endpoint.")
            return self._dynamic_engine.replay_http(
                replay_target.command,
                replay_target.endpoint,
                finding,
                headers=replay_target.headers,
                query_params=replay_target.query_params,
                base_url_override=replay_target.base_url_override,
                trace_directory=trace_dir,
            )
        raise ValueError(f"Unsupported replay transport: {replay_target.transport}")

    def _analyze_static(
        self,
        source_path: Path,
        *,
        mode: str,
        include_vendor: bool,
        include_tests: bool,
    ):
        """Call the static engine while remaining compatible with older test doubles."""

        try:
            report = self._static_engine.analyze_target(
                source_path,
                mode=mode,
                include_vendor=include_vendor,
                include_tests=include_tests,
            )
        except TypeError:
            report = self._static_engine.analyze_target(source_path, mode=mode)
        if not hasattr(report, "raw_findings"):
            report.raw_findings = len(report.findings)
        if not hasattr(report, "scope_excluded_findings"):
            report.scope_excluded_findings = 0
        if not hasattr(report, "suppression_reasons"):
            report.suppression_reasons = {}
        return report


def resolve_scan_config(target_or_config: Path) -> ScanConfig:
    """Resolve either a raw source path or a JSON config file into scan settings."""

    resolved = target_or_config.resolve()
    if not resolved.exists():
        raise ValueError(f"Scan target does not exist: {resolved}")

    if resolved.is_file() and resolved.suffix.lower() == ".json":
        payload = json.loads(resolved.read_text(encoding="utf-8"))
        source_path = Path(payload["source_path"]).resolve()
        replay_payload = payload.get("replay")
        replay_target = None
        if replay_payload:
            replay_target = ReplayTarget(
                transport=replay_payload["transport"],
                command=[str(item) for item in replay_payload["command"]],
                endpoint=replay_payload.get("endpoint"),
                headers=dict(replay_payload.get("headers", {})),
                query_params=dict(replay_payload.get("query_params", {})),
                base_url_override=replay_payload.get("base_url_override"),
            )
        return ScanConfig(source_path=source_path, replay_target=replay_target)

    replay_target = infer_replay_target(resolved)
    return ScanConfig(source_path=resolved, replay_target=replay_target)


def infer_replay_target(source_path: Path) -> ReplayTarget | None:
    """Infer a simple replay target when scanning a local executable fixture."""

    if source_path.is_file() and source_path.suffix == ".py":
        return ReplayTarget(transport="stdio", command=[sys.executable, str(source_path)])
    return None


def determine_quick_gate(findings: list[AuditFinding]) -> str:
    """Return PASS/WARN/BLOCK for a quick scan."""

    if any(finding.static_finding.severity == "high" for finding in findings):
        return "BLOCK"
    if findings:
        return "WARN"
    return "PASS"


def determine_deep_gate(findings: list[AuditFinding], reproduced: list[AuditFinding]) -> str:
    """Return PASS/WARN/BLOCK for a deep scan."""

    if any(
        finding.replay_trace and finding.replay_trace.verdict == "CONFIRMED"
        for finding in reproduced
    ):
        return "BLOCK"
    if any(finding.static_finding.severity == "high" for finding in findings):
        return "WARN"
    if findings:
        return "WARN"
    return "PASS"


def summarize_gate(
    gate: str,
    findings: list[AuditFinding],
    reproduced_findings: list[AuditFinding],
    *,
    raw_findings: int,
    replayable_findings: int,
) -> str:
    """Create a short human-readable summary."""

    if raw_findings > 0 and replayable_findings == 0:
        return f"{gate}: {raw_findings} raw finding(s), 0 replayable findings after scope filtering."
    return (
        f"{gate}: {len(findings)} finding(s), "
        f"{len(reproduced_findings)} reproduced via dynamic replay."
    )


def _scope_noise_ratio(raw_findings: int, scoped_findings: int) -> float:
    """Compute the proportion of findings that were not scoped to a tool."""

    return 0.0 if raw_findings == 0 else (raw_findings - scoped_findings) / raw_findings


def write_audit_report(report: AuditReport, *, output_dir: Path) -> AuditReport:
    """Persist Markdown and JSON audit outputs and return the updated report."""

    output_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"{report.mode}-scan"
    markdown_path = output_dir / f"{prefix}.md"
    json_path = output_dir / f"{prefix}.json"
    final_report = AuditReport(
        target=report.target,
        mode=report.mode,
        gate=report.gate,
        summary=report.summary,
        findings=report.findings,
        reproduced_findings=report.reproduced_findings,
        raw_findings=report.raw_findings,
        scope_excluded_findings=report.scope_excluded_findings,
        scoped_findings=report.scoped_findings,
        replayable_findings=report.replayable_findings,
        contract_valid_replays=report.contract_valid_replays,
        binding_success_rate=report.binding_success_rate,
        confirmed_findings=report.confirmed_findings,
        differential_confirmation_rate=report.differential_confirmation_rate,
        scope_noise_ratio=report.scope_noise_ratio,
        suppression_reasons=report.suppression_reasons,
        markdown_report_path=str(markdown_path),
        json_report_path=str(json_path),
    )
    markdown_path.write_text(render_markdown_report(final_report), encoding="utf-8")
    json_path.write_text(json.dumps(final_report.to_dict(), indent=2) + "\n", encoding="utf-8")
    return final_report


def render_markdown_report(report: AuditReport) -> str:
    """Render a human-readable Markdown report."""

    lines = [
        f"# {report.mode.title()} Self-Audit Report",
        "",
        f"- Target: `{report.target}`",
        f"- Gate: **{report.gate}**",
        f"- Summary: {report.summary}",
        f"- Raw Findings: `{report.raw_findings}`",
        f"- Scope-Excluded Findings: `{report.scope_excluded_findings}`",
        f"- Scoped Findings: `{report.scoped_findings}`",
        f"- Replayable Findings: `{report.replayable_findings}`",
        f"- Contract-Valid Replays: `{report.contract_valid_replays}`",
        f"- Binding Success Rate: `{report.binding_success_rate:.2f}`",
        f"- Confirmed Findings: `{report.confirmed_findings}`",
        f"- Differential Confirmation Rate: `{report.differential_confirmation_rate:.2f}`",
        f"- Scope Noise Ratio: `{report.scope_noise_ratio:.2f}`",
        f"- Suppression Reasons: `{json.dumps(report.suppression_reasons, sort_keys=True)}`",
        "",
        "## Findings",
    ]
    if not report.findings:
        lines.extend(["", "No findings detected."])
        return "\n".join(lines) + "\n"

    for index, finding in enumerate(report.findings, start=1):
        static_finding = finding.static_finding
        lines.extend(
            [
                "",
                f"### {index}. {static_finding.vulnerability_class}",
                f"- Severity: `{static_finding.severity}`",
                f"- Location: `{static_finding.file_path}:{static_finding.line}`",
                f"- Tool: `{static_finding.tool_name or 'n/a'}`",
                f"- Message: {static_finding.message}",
                f"- Remediation: {finding.remediation_guidance}",
            ]
        )
        if finding.replay_trace:
            lines.extend(
                [
                    f"- Replay verdict: `{finding.replay_trace.verdict}`",
                    f"- Replay rationale: {finding.replay_trace.rationale}",
                ]
            )

    return "\n".join(lines) + "\n"
