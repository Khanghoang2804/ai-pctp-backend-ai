import os
import unittest

from app.core.config import GitNexusSettings


class TestGitNexusSettings(unittest.TestCase):
    def setUp(self) -> None:
        self._env = dict(os.environ)

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._env)

    def test_default_settings(self) -> None:
        settings = GitNexusSettings.from_env()
        self.assertEqual(settings.package, "gitnexus@latest")
        self.assertTrue(settings.use_npx)


if __name__ == "__main__":
    unittest.main()
