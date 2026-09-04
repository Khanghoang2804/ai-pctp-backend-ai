"""Integration-style test: GitNexus CLI analyze + HTTP sync (optional; skipped nếu thiếu điều kiện).

Đặt biến môi trường trước khi chạy:
  GITNEXUS_TEST_REPO_PATH=/đường/dẫn/git/repo
  Cần: gitnexus CLI, gitnexus serve đang chạy, biến DB (SUPABASE_*) như khi chạy sync thật.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from typing import Optional

from app.service.gitnexus_sync_service import GitNexusSyncService
from app.service.gitnexusService import GitNexusService

REPO_ENV = "GITNEXUS_TEST_REPO_PATH"


def _registry_name_for_repo_path(service: GitNexusService, repo_path: Path) -> Optional[str]:
    wanted = repo_path.resolve()
    for entry in service.list_repos():
        p = entry.get("path") or entry.get("repoPath")
        if not p:
            continue
        if Path(str(p)).resolve() == wanted:
            name = entry.get("name")
            return str(name) if name else None
    return None


@unittest.skipUnless(os.getenv(REPO_ENV), f"set {REPO_ENV} to enable")
class TestGitNexusAnalyzeAndSync(unittest.TestCase):
    """Chạy `python -m unittest app.tests.test_gitnexus_service`."""

    def test_analyze_then_sync(self) -> None:
        repo_path = Path(os.environ[REPO_ENV]).resolve()
        self.assertTrue(repo_path.is_dir(), f"not a directory: {repo_path}")

        self.assertTrue(
            os.getenv("SUPABASE_PASSWORD"),
            "SUPABASE_PASSWORD required for sync",
        )

        gn = GitNexusService()
        self.assertTrue(
            gn.is_server_ready(),
            "gitnexus serve must be running (see GITNEXUS_SERVE_BASE_URL)",
        )

        result = gn.analyze(repo_path=str(repo_path))
        self.assertEqual(
            result.returncode,
            0,
            msg=f"analyze failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )

        repo_name = _registry_name_for_repo_path(gn, repo_path)
        self.assertIsNotNone(
            repo_name,
            f"repo not in registry after analyze; check list_repos for {repo_path}",
        )
        assert repo_name is not None

        sync = GitNexusSyncService(gn)
        payload = sync.sync_repo(repo_name=repo_name)
        self.assertGreaterEqual(len(payload.nodes), 0)


if __name__ == "__main__":
    unittest.main()
