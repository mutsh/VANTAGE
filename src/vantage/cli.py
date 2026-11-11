"""Command-line entry point for the VANTAGE evidence-repair agent."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vantage.agents.evidence_repair import EvidenceRepairAgent
from vantage.pipeline import scan_repository, to_sarif
from vantage.workflow import MultiAgentWorkflow
from vantage.analysis.python_security import SourceAnalysisError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vantage", description="Evidence-guided, read-only security analysis")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("repair-analyze", help="analyze a Python file and prepare evidence for human review")
    analyze.add_argument("--file", type=Path, required=True, help="Python source file")
    analyze.add_argument("--repo", type=Path, help="repository root used to make evidence paths relative")
    analyze.add_argument("--format", choices=("json", "text"), default="text")
    scan = sub.add_parser("scan", help="scan repository Python source without execution")
    scan.add_argument("--repo", type=Path, required=True)
    scan.add_argument("--format", choices=("json", "sarif"), default="json")
    run = sub.add_parser("run", help="run the local multi-agent workflow")
    run.add_argument("--repo", type=Path, required=True)
    run.add_argument("--dynamic", action="store_true", help="execute repository test code in Docker workers")
    run.add_argument("--image", default="vantage-worker:local")
    run.add_argument("--model", help="installed Ollama model name; optional local AI repair generation")
    run.add_argument("--timeout", type=int, default=60)
    run.add_argument("--output", type=Path, required=True, help="JSON report path outside target repository")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "run":
        try:
            if args.output.resolve().is_relative_to(args.repo.resolve()):
                raise ValueError("Write the report outside the target repository")
            report = MultiAgentWorkflow().run(args.repo, args.dynamic, args.image, args.timeout, args.model)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"Run {report['status']}; report: {args.output}")
        except (OSError, ValueError) as exc:
            print(f"vantage: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
        raise SystemExit(2 if report["status"] == "incomplete" else 0)
    if args.command == "scan":
        try:
            scan = scan_repository(args.repo)
            print(json.dumps(to_sarif(scan) if args.format == "sarif" else scan, indent=2))
        except (OSError, ValueError) as exc:
            print(f"vantage: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
        raise SystemExit(2 if scan["errors"] else 0)
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
