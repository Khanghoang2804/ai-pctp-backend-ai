import urllib.error
import urllib.parse
import urllib.request
import json
from typing import Any, Optional


class GitNexusHttpError(Exception):
    def __init__(self, message: str, status_code: int, body: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class GitNexusHttpClient:
    """HTTP client for the GitNexus REST API (gitnexus serve)."""

    def __init__(self, base_url: str = "http://localhost:4747") -> None:
        self.base_url = base_url.rstrip("/")

    def _get(self, path: str, params: Optional[dict[str, str]] = None) -> Any:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        return self._send(req)

    def _post(self, path: str, body: dict) -> Any:
        url = self.base_url + path
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        return self._send(req)

    def _send(self, req: urllib.request.Request) -> Any:
        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            body_raw = exc.read().decode() if exc.fp else ""
            try:
                body = json.loads(body_raw)
            except json.JSONDecodeError:
                body = {"raw": body_raw}
            message = body.get("error") or body_raw or str(exc)
            raise GitNexusHttpError(message, exc.code, body) from exc
        except urllib.error.URLError as exc:
            raise GitNexusHttpError(
                f"Cannot reach GitNexus server at {self.base_url}: {exc.reason}. "
                "Run: gitnexus serve",
                0,
            ) from exc

    # ── Repos ────────────────────────────────────────────────────────────

    def list_repos(self) -> list[dict]:
        return self._get("/api/repos")

    def get_repo(self, repo: str) -> dict:
        return self._get("/api/repo", {"repo": repo})

    # ── Graph ────────────────────────────────────────────────────────────

    def get_graph(self, repo: Optional[str] = None, include_content: bool = False) -> dict:
        params: dict[str, str] = {}
        if repo:
            params["repo"] = repo
        if include_content:
            params["includeContent"] = "true"
        return self._get("/api/graph", params)

    # ── Query ────────────────────────────────────────────────────────────

    def cypher_query(self, cypher: str, repo: Optional[str] = None) -> dict:
        body: dict = {"cypher": cypher}
        if repo:
            body["repo"] = repo
        return self._post("/api/query", body)

    # ── Search ───────────────────────────────────────────────────────────

    def search(
        self,
        query: str,
        repo: Optional[str] = None,
        mode: str = "hybrid",
        limit: int = 10,
    ) -> dict:
        body: dict = {"query": query, "mode": mode, "limit": limit}
        if repo:
            body["repo"] = repo
        return self._post("/api/search", body)

    # ── Processes & Clusters ─────────────────────────────────────────────

    def list_processes(self, repo: Optional[str] = None) -> dict:
        params = {"repo": repo} if repo else {}
        return self._get("/api/processes", params)

    def get_process(self, name: str, repo: Optional[str] = None) -> dict:
        params: dict[str, str] = {"name": name}
        if repo:
            params["repo"] = repo
        return self._get("/api/process", params)

    def list_clusters(self, repo: Optional[str] = None) -> dict:
        params = {"repo": repo} if repo else {}
        return self._get("/api/clusters", params)

    def get_cluster(self, name: str, repo: Optional[str] = None) -> dict:
        params: dict[str, str] = {"name": name}
        if repo:
            params["repo"] = repo
        return self._get("/api/cluster", params)

    # ── Health ───────────────────────────────────────────────────────────

    def health(self) -> dict:
        return self._get("/api/health")

    def is_ready(self) -> bool:
        try:
            self.health()
            return True
        except GitNexusHttpError:
            return False
