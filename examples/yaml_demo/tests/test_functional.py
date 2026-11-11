import unittest
from service import load_config


class FunctionalTests(unittest.TestCase):
    def test_ordinary_configuration(self):
        self.assertEqual(load_config('name: demo\ncount: 2'), {'name': 'demo', 'count': 2})
