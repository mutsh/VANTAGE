import tempfile
import unittest
import io
from pathlib import Path
from unittest.mock import patch, MagicMock

from vantage.dynamic import DynamicEvidenceAgent
from vantage.workflow import MultiAgentWorkflow, ReviewAgent, apply_candidate


class WorkflowTests(unittest.TestCase):
    def test_workflow_freezes_candidate_before_evaluation_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = 'import yaml\n\ndef load(x):\n    return yaml.unsafe_load(x)\n'
            (root / 'app.py').write_text(source)
            (root / '.env').write_text('secret')
            seen = []
            def evaluate(snapshot):
                self.assertFalse((snapshot / '.env').exists())
                changed = 'yaml.safe_load' in (snapshot / 'app.py').read_text()
                seen.append(changed)
                return {'status': 'completed', 'suites': {'functional': {'status': 'passed'},
                        'security': {'status': 'passed' if changed else 'failed'}}}
            with patch.object(DynamicEvidenceAgent, 'evaluate', side_effect=evaluate):
                report = MultiAgentWorkflow().run(root, dynamic=True)
            self.assertEqual(seen, [False, True])
            self.assertEqual(report['candidates'][0]['decision'], 'plausible_repair_human_review_required')
            self.assertEqual((root / 'app.py').read_text(), source)
            self.assertEqual(len(report['events']), 6)

    def test_no_dynamic_evidence_is_unverified(self):
        self.assertEqual(ReviewAgent().decide(None, None), 'unverified')
        self.assertEqual(ReviewAgent().decide({'status': 'unavailable'}, {'status': 'completed'}), 'unverified')

    def test_patch_cannot_escape_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                apply_candidate(Path(directory), '../outside.py', '')

    def test_missing_docker_returns_unavailable(self):
        with patch('vantage.dynamic.shutil.which', return_value=None):
            self.assertEqual(DynamicEvidenceAgent().evaluate(Path('.'))['status'], 'unavailable')

    def test_no_tests_cannot_be_treated_as_passed(self):
        b = {'status': 'incomplete', 'suites': {'functional': {'status': 'no_tests'}}}
        self.assertEqual(ReviewAgent().decide(b, b), 'unverified')

    def test_worker_is_restricted_and_zero_tests_is_not_success(self):
        process = MagicMock()
        process.stdout = io.BytesIO(b'Ran 0 tests in 0.001s\nOK\n')
        process.wait.return_value = 0
        with patch('vantage.dynamic.subprocess.Popen', return_value=process) as launch:
            with patch('vantage.dynamic.subprocess.run'):
                result = DynamicEvidenceAgent()._suite(Path('.'), 'sha256:example', 'test_security*.py')
        self.assertEqual(result['status'], 'no_tests')
        command = launch.call_args.args[0]
        self.assertIn('--read-only', command)
        self.assertIn('no-new-privileges', command)
        self.assertEqual(command[command.index('--network') + 1], 'none')
        self.assertEqual(command[command.index('--user') + 1], '10001:10001')
