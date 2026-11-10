"""Read-only evidence-guided security repair agent for VANTAGE."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from vantage.analysis.python_security import Finding, analyze_python_file


@dataclass(frozen=True)
class AgentReport:
    schema_version: str
    agent: str
    decision: str
    summary: str
    findings: list[Finding]
    patch: None
    next_step: str
    safeguards: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "agent": self.agent,
            "decision": self.decision,
            "summary": self.summary,
            "findings": [item.to_dict() for item in self.findings],
            "patch": self.patch,
            "next_step": self.next_step,
            "safeguards": self.safeguards,
        }


class EvidenceRepairAgent:
    """Collect evidence and recommend human review without modifying source."""

    name = "vantage-evidence-repair"

    def analyze(self, path: Path, repo_root: Path | None = None) -> AgentReport:
        findings = analyze_python_file(path, repo_root)
        if findings:
            decision = "human_review_required"
            summary = f"Found {len(findings)} security-relevant code pattern(s); exploitability is unconfirmed."
            next_step = "Review each evidence item and validate data provenance, reachability, and intended behavior. Do not apply a fix without review."
        else:
            decision = "no_supported_finding"
            summary = "No supported pattern matched the current rules. This does not establish that the file is secure."
            next_step = "Use additional static analysis, dependency scanning, and security review as appropriate."
        return AgentReport(
            schema_version="0.1",
            agent=self.name,
            decision=decision,
            summary=summary,
            findings=findings,
            patch=None,
            next_step=next_step,
            safeguards=[
                "Read-only: the agent does not edit or execute repository code.",
                "No tests, issue descriptions, secrets, or external threat-intelligence feeds are read.",
                "Findings identify code patterns, not confirmed vulnerabilities.",
                "A future patch generator must return a reviewable diff and require explicit human approval before application.",
            ],
        )
