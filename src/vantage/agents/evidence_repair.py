"""Read-only evidence-guided security repair agent for VANTAGE."""

from __future__ import annotations

import difflib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from vantage.analysis.python_security import Finding, analyze_python_file


@dataclass(frozen=True)
class PatchProposal:
    proposal_id: str
    linked_evidence: list[str]
    patch: str
    rationale: str
    limitations: str
    status: str = "human_review_required"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AgentReport:
    schema_version: str
    agent: str
    decision: str
    summary: str
    findings: list[Finding]
    patch_proposals: list[PatchProposal]
    next_step: str
    safeguards: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "agent": self.agent,
            "decision": self.decision,
            "summary": self.summary,
            "findings": [item.to_dict() for item in self.findings],
            "patch_proposals": [item.to_dict() for item in self.patch_proposals],
            "next_step": self.next_step,
            "safeguards": self.safeguards,
        }


class EvidenceRepairAgent:
    """Collect evidence and propose narrow, reviewable mitigations."""

    name = "vantage-evidence-repair"

    @staticmethod
    def _yaml_loader_proposals(path: Path, findings: list[Finding]) -> list[PatchProposal]:
        source_lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        proposals: list[PatchProposal] = []
        for finding in findings:
            if finding.rule_id != "PYSEC-YAML-001":
                continue
            index = finding.line - 1
            if index < 0 or index >= len(source_lines):
                continue
            old_line = source_lines[index]
            tokens = ("yaml.load(", "yaml.full_load(", "yaml.unsafe_load(")
            matches = [token for token in tokens if old_line.count(token) == 1]
            if len(matches) != 1:
                continue
            new_line = old_line.replace(matches[0], "yaml.safe_load(", 1)
            revised = [*source_lines[:index], new_line, *source_lines[index + 1:]]
            diff = "".join(difflib.unified_diff(source_lines, revised, fromfile=f"a/{finding.file}", tofile=f"b/{finding.file}"))
            if diff:
                proposals.append(PatchProposal(
                    proposal_id=f"PATCH-{finding.rule_id}-{finding.line}",
                    linked_evidence=[finding.rule_id],
                    patch=diff,
                    rationale="Replace a visible unsafe YAML loader call with the data-only safe loader.",
                    limitations="This may reject custom Python YAML tags and change behavior. Confirm the input format and compatibility before accepting; the proposal is never applied automatically.",
                ))
        return proposals

    def analyze(self, path: Path, repo_root: Path | None = None) -> AgentReport:
        findings = analyze_python_file(path, repo_root)
        proposals = self._yaml_loader_proposals(path, findings)
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
            patch_proposals=proposals,
            next_step=next_step,
            safeguards=[
                "The agent does not edit or execute repository code; patch candidates are returned as diffs only.",
                "No tests, issue descriptions, secrets, or external threat-intelligence feeds are read.",
                "Findings identify code patterns, not confirmed vulnerabilities.",
                "Patch proposals require explicit human review and approval before application.",
            ],
        )
