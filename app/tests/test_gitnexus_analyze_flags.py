"""Unit tests: analyze() passes --skip-git when repo has no .git directory."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.core.gitnexus_command import CommandResult
from app.service.gitnexusService import GitNexusService


class TestAnalyzeSkipGit(unittest.TestCase):
    def test_analyze_without_git_passes_skip_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            captured: dict = {}

            def fake_run(**kwargs):
                captured.update(kwargs)
                return CommandResult(
                    command=kwargs["command"],
                    cwd=kwargs["cwd"],
                    stdout="ok",
                    stderr="",
                    returncode=0,
                )

            with patch("app.service.gitnexusService.run_command", side_effect=fake_run):
                GitNexusService().analyze(repo_path=str(repo))

            self.assertFalse(captured["require_git_repo"])
            self.assertIn("--skip-git", captured["command"])
            self.assertIn("--skip-agents-md", captured["command"])

    def test_analyze_with_git_does_not_pass_skip_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".git").mkdir()
            captured: dict = {}

            def fake_run(**kwargs):
                captured.update(kwargs)
                return CommandResult(
                    command=kwargs["command"],
                    cwd=kwargs["cwd"],
                    stdout="ok",
                    stderr="",
                    returncode=0,
                )

            with patch("app.service.gitnexusService.run_command", side_effect=fake_run):
                GitNexusService().analyze(repo_path=str(repo))

            self.assertTrue(captured["require_git_repo"])
            self.assertNotIn("--skip-git", captured["command"])


if __name__ == "__main__":
    unittest.main()
