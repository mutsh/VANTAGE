import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from vantage.local_model import LocalModelRepairAgent


class LocalModelTests(unittest.TestCase):
    def test_disallows_model_changes_to_tests_and_closes_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app.py').write_text('eval(x)')
            scan = {'reports': [{'file': 'app.py', 'report': {'findings': [{'rule_id': 'risk'}]}}]}
            answer = {'message': {'content': json.dumps({'proposals': [{'file': 'tests/test.py', 'patch': '', 'rationale': ''}]})}}
            connection = MagicMock()
            connection.getresponse.return_value.status = 200
            connection.getresponse.return_value.read.return_value = json.dumps(answer).encode()
            with patch('vantage.local_model.HTTPConnection', return_value=connection):
                with self.assertRaises(ValueError):
                    LocalModelRepairAgent().propose('installed-model', root, scan)
            connection.close.assert_called_once()
            payload = json.loads(connection.request.call_args.kwargs['body'])
            self.assertEqual(payload['options']['temperature'], 0)

    def test_empty_findings_do_not_call_model(self):
        with patch('vantage.local_model.HTTPConnection') as connection:
            self.assertEqual(LocalModelRepairAgent().propose('model', Path('.'), {'reports': []}), [])
            connection.assert_not_called()
