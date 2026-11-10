import unittest
from pathlib import Path

from vantage.agents.evidence_repair import EvidenceRepairAgent
from vantage.analysis.python_security import SourceAnalysisError, analyze_python_source


ROOT = Path(__file__).parent


class EvidenceRepairTests(unittest.TestCase):
    def test_detects_high_risk_patterns_with_locations(self):
        report = EvidenceRepairAgent().analyze(ROOT / "fixtures" / "risky.py", ROOT)
        ids = {finding.rule_id for finding in report.findings}
        self.assertEqual(ids, {"PYSEC-SHELL-001", "PYSEC-SER-001", "PYSEC-SQL-001"})
        self.assertEqual(report.decision, "human_review_required")
        self.assertTrue(all(finding.line > 0 and finding.excerpt for finding in report.findings))

    def test_no_match_does_not_claim_secure(self):
        report = EvidenceRepairAgent().analyze(ROOT / "fixtures" / "ordinary.py", ROOT)
        self.assertEqual(report.decision, "no_supported_finding")
        self.assertIn("does not establish", report.summary)
        self.assertIsNone(report.patch)

    def test_eval_and_exec_are_reported_as_unconfirmed_risk_signals(self):
        findings = analyze_python_source("def f(x):\n    return eval(x)\n")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "PYSEC-DYN-001")
        self.assertIn("cannot determine", findings[0].claim)

    def test_invalid_python_is_rejected(self):
        with self.assertRaises(SourceAnalysisError):
            analyze_python_source("def broken(:\n pass")


if __name__ == "__main__":
    unittest.main()
