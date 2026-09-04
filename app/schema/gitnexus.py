from typing import Any, Optional

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    repo_path: str
    force: bool = False


class QueryRequest(BaseModel):
    repo_path: str
    search_query: str
    repo_name: Optional[str] = None
    context: Optional[str] = None
    goal: Optional[str] = None
    limit: Optional[int] = Field(default=5, ge=1, le=100)
    include_content: bool = False


class CypherRequest(BaseModel):
    repo_path: str
    query: str
    repo_name: Optional[str] = None


class CleanRequest(BaseModel):
    repo_path: str
    force: bool = False


class CommandResponse(BaseModel):
    command: list[str]
    cwd: str
    returncode: int
    stdout: str
    stderr: str


# ── HTTP API request/response models ─────────────────────────────────────────

class SearchRequest(BaseModel):
    query: str
    repo_name: Optional[str] = None
    mode: str = Field(default="hybrid", pattern="^(hybrid|bm25|semantic)$")
    limit: int = Field(default=10, ge=1, le=100)


class CypherHttpRequest(BaseModel):
    cypher: str
    repo_name: Optional[str] = None


class GraphRequest(BaseModel):
    repo_name: Optional[str] = None
    include_content: bool = False


class RepoInfo(BaseModel):
    name: str
    path: str
    indexedAt: Optional[str] = None
    lastCommit: Optional[str] = None
    stats: Optional[dict[str, Any]] = None


class ServerReadyResponse(BaseModel):
    ready: bool


class AnalyzeAndSyncRequest(BaseModel):
    repo_path: str
    force: bool = False
    include_content: bool = True
    replace_repo: bool = True


class AnalyzeAndSyncResponse(BaseModel):
    repo_name: str
    analyze_stdout: str
    analyze_returncode: int
    stats_nodes: int
    stats_edges: int


class ParseFullGraphRequest(BaseModel):
    repo_name: str
    excluded_labels: Optional[list[str]] = None
    excluded_rel_types: Optional[list[str]] = None
    limit_nodes: int = 5000
    offset_nodes: int = 0


class ParseFullGraphResponse(BaseModel):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    stats: dict[str, Any]
