import unittest
import yaml
from service import load_config


class SecurityTests(unittest.TestCase):
    def test_python_object_tag_is_rejected(self):
        # Non-destructive probe: resolves a builtin type; no command execution.
        with self.assertRaises(yaml.YAMLError):
            load_config('!!python/name:builtins.str')
