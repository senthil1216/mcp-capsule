import unittest
from pathlib import Path


class WorkspaceSmokeTest(unittest.TestCase):
    def test_workspace_has_readme(self):
        self.assertTrue(Path("README.md").exists())
