import tempfile
import unittest
from pathlib import Path

from vantage.pipeline import scan_repository, to_sarif
from vantage.agents.evidence_repair import EvidenceRepairAgent


class PipelineTests(unittest.TestCase):
    def test_partial_failure_is_visible_and_source_is_not_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'bad.py').write_text('def broken(:')
            (root / 'good.py').write_text("raise RuntimeError('must not execute')\neval(user_input)\n")
            report = scan_repository(root)
            self.assertEqual(report['status'], 'incomplete')
            self.assertEqual(report['files_analyzed'], 1)
            self.assertEqual(len(report['errors']), 1)
            sarif = to_sarif(report)
            self.assertFalse(sarif['runs'][0]['invocations'][0]['executionSuccessful'])
            self.assertEqual(len(sarif['runs'][0]['results']), 1)

    def test_symlink_and_test_directory_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tests').mkdir()
            (root / 'tests' / 'hidden.py').write_text('eval(x)')
            (root / 'link.py').symlink_to(root / 'tests' / 'hidden.py')
            self.assertEqual(scan_repository(root)['files_analyzed'], 0)

    def test_loader_arguments_do_not_generate_invalid_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source.py'
            for call in ['yaml.load(data, Loader=yaml.Loader)', 'yaml.load(data, yaml.Loader)', 'yaml.load(\n data\n)']:
                path.write_text('import yaml\n' + call + '\n')
                report = EvidenceRepairAgent().analyze(path)
                self.assertEqual(report.patch_proposals, [], call)
