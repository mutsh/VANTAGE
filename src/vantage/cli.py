"""Command-line entry point for the VANTAGE evidence-repair agent."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vantage.agents.evidence_repair import EvidenceRepairAgent
from vantage.analysis.python_security import SourceAnalysisError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vantage", description="Evidence-guided, read-only security analysis")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("repair-analyze", help="analyze a Python file and prepare evidence for human review")
    analyze.add_argument("--file", type=Path, required=True, help="Python source file")
    analyze.add_argument("--repo", type=Path, help="repository root used to make evidence paths relative")
    analyze.add_argument("--format", choices=("json", "text"), default="text")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        report = EvidenceRepairAgent().analyze(args.file, args.repo).to_dict()
    except (OSError, SourceAnalysisError) as exc:
        print(f"vantage: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return
    print(f"Decision: {report['decision']}")
    print(report["summary"])
    for finding in report["findings"]:
        print(f"\n[{finding['rule_id']}] {finding['title']} — {finding['file']}:{finding['line']}")
        print(f"Evidence: {finding['claim']}")
        print(f"Code: {finding['excerpt']}")
        print(f"Suggested review: {finding['remediation']}")
        print(f"Limit: {finding['limitations']}")
    for proposal in report["patch_proposals"]:
        print(f"\nPatch proposal: {proposal['proposal_id']} ({proposal['status']})")
        print(proposal["patch"])
        print(f"Review note: {proposal['limitations']}")
    print(f"\nNext step: {report['next_step']}")


if __name__ == "__main__":
    main()
