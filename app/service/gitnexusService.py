import json
import uuid
from pathlib import Path
from typing import Any, Optional

from app.core.config import GitNexusSettings
from app.core.gitnexus_command import (
    CommandResult,
    run_command,
)
from app.core.gitnexus_http_client import GitNexusHttpClient


class GitNexusService:
    def __init__(
        self,
        settings: Optional[GitNexusSettings] = None,
    ) -> None:
        self.settings = settings or GitNexusSettings.from_env()
        self.http = GitNexusHttpClient(base_url=self.settings.serve_base_url)

    def _base_command(self) -> list[str]:
        if self.settings.local_cli_path:
            return [self.settings.local_cli_path]

        if self.settings.use_npx:
            return ["npx", "-y", self.settings.package]

        return ["gitnexus"]

    def _run(
        self,
        command: list[str],
        repo_path: str,
        timeout_seconds: int,
        *,
        env: Optional[dict[str, str]] = None,
        require_git_repo: bool = True,
    ) -> CommandResult:
        repo = Path(repo_path).resolve()
        return run_command(
            command=command,
            cwd=str(repo),
            timeout_seconds=timeout_seconds,
            env=env,
            require_git_repo=require_git_repo,
        )

    def analyze(
        self,
        repo_path: str,
        force: bool = False,
    ) -> CommandResult:
        repo = Path(repo_path).resolve()

        command = [*self._base_command(), "analyze", "--skip-git"]

        if force:
            command.append("--force")

        correlation_id = str(uuid.uuid4())
        env = {"GITNEXUS_CORRELATION_ID": correlation_id}

        return self._run(
            command=command,
            repo_path=str(repo),
            timeout_seconds=self.settings.analyze_timeout_seconds,
            env=env,
            require_git_repo=False,
        )

    def status(self, repo_path: str) -> CommandResult:
        return self._run(
            command=[*self._base_command(), "status"],
            repo_path=repo_path,
            timeout_seconds=self.settings.short_timeout_seconds,
        )

    def clean(self, repo_path: str, force: bool = False) -> CommandResult:
        command = [*self._base_command(), "clean"]

        if force:
            command.append("--force")

        return self._run(
            command=command,
            repo_path=repo_path,
            timeout_seconds=self.settings.short_timeout_seconds,
        )

    def query(
        self,
        repo_path: str,
        search_query: str,
        *,
        repo_name: Optional[str] = None,
        context: Optional[str] = None,
        goal: Optional[str] = None,
        limit: Optional[int] = None,
        include_content: bool = False,
    ) -> CommandResult:
        command = [*self._base_command(), "query", search_query]
        if repo_name:
            command.extend(["--repo", repo_name])
        if context:
            command.extend(["--context", context])
        if goal:
            command.extend(["--goal", goal])
        if limit is not None:
            command.extend(["--limit", str(limit)])
        if include_content:
            command.append("--content")

        return self._run(
            command=command,
            repo_path=repo_path,
            timeout_seconds=self.settings.medium_timeout_seconds,
        )

    def cypher(self, repo_path: str, query: str, repo_name: Optional[str] = None) -> CommandResult:
        command = [*self._base_command(), "cypher", query]
        if repo_name:
            command.extend(["--repo", repo_name])
        return self._run(
            command=command,
            repo_path=repo_path,
            timeout_seconds=self.settings.medium_timeout_seconds,
        )

    def registry_list_cli(self) -> CommandResult:
        """In danh sách repo đã index (lệnh `gitnexus list`).

        Không bắt buộc cài binary `gitnexus` globally: có thể dùng
        GITNEXUS_LOCAL_CLI_PATH (path tới …/dist/cli/index.js), npx hoặc node trong _base_command.
        cwd = $HOME — lệnh `list` chỉ đọc registry global, không phụ thuộc repo cwd.
        """
        return run_command(
            command=[*self._base_command(), "list"],
            cwd=str(Path.home()),
            timeout_seconds=self.settings.short_timeout_seconds,
            require_git_repo=False,
        )

    # ── HTTP API (requires gitnexus serve to be running) ─────────────────

    def serve(self, repo_path: str, port: int = 4747) -> CommandResult:
        """Starts gitnexus serve (blocks until killed — run in a background thread/process)."""
        command = [*self._base_command(), "serve", "--port", str(port)]
        return self._run(
            command=command,
            repo_path=repo_path,
            timeout_seconds=0,
            require_git_repo=False,
        )

    def is_server_ready(self) -> bool:
        return self.http.is_ready()

    def list_repos(self) -> list[Any]:
        return self.http.list_repos()

    def get_repo_info(self, repo_name: str) -> dict:
        return self.http.get_repo(repo_name)

    def get_graph(self, repo_name: Optional[str] = None, include_content: bool = False) -> dict:
        return self.http.get_graph(repo=repo_name, include_content=include_content)

    def cypher_http(self, cypher: str, repo_name: Optional[str] = None) -> dict:
        return self.http.cypher_query(cypher, repo=repo_name)

    def search(
        self,
        query: str,
        repo_name: Optional[str] = None,
        mode: str = "hybrid",
        limit: int = 10,
    ) -> dict:
        return self.http.search(query, repo=repo_name, mode=mode, limit=limit)

    def list_processes(self, repo_name: Optional[str] = None) -> dict:
        return self.http.list_processes(repo=repo_name)

    def list_clusters(self, repo_name: Optional[str] = None) -> dict:
        return self.http.list_clusters(repo=repo_name)

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def parse_json_output(result: CommandResult) -> dict:
        content = result.stdout.strip()
        if not content:
            return {}
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {"raw": content}
