from pathlib import Path
from typing import Any, Optional
from app.service.ParseGraph import analyze_and_sync as _svc_analyze_and_sync
from fastapi import APIRouter, HTTPException, Query
from app.service.queryNodeAndRel import db_node_graph, db_nodes, db_relations
from app.core.gitnexus_command import CommandRunError
from app.service.queryNodeAndRel import db_full_graph
from app.core.gitnexus_http_client import GitNexusHttpError
from app.schema.gitnexus import (
    AnalyzeAndSyncRequest,
    AnalyzeAndSyncResponse,
    AnalyzeRequest,
    CleanRequest,
    CommandResponse,
    CypherHttpRequest,
    CypherRequest,
    GraphRequest,
    ParseFullGraphRequest,
    ParseFullGraphResponse,
    QueryRequest,
    RepoInfo,
    SearchRequest,
    ServerReadyResponse,
)
from app.schema.gitnexus_sync import TABLE_NODES, TABLE_RELATIONS
from app.service.gitnexus_sync_service import GitNexusSyncService
from app.service.gitnexusService import GitNexusService

router = APIRouter(prefix="/gitnexus", tags=["gitnexus"])
service = GitNexusService()
sync_service = GitNexusSyncService(service)


def _to_response(result) -> CommandResponse:
    return CommandResponse(
        command=result.command,
        cwd=result.cwd,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def _raise_http(err: CommandRunError) -> None:
    raise HTTPException(
        status_code=400,
        detail={
            "code": err.code.value,
            "message": str(err),
            "command": err.command,
            "cwd": err.cwd,
            "stdout": err.stdout,
            "stderr": err.stderr,
            "returncode": err.returncode,
        },
    )


def _raise_http_api(err: GitNexusHttpError) -> None:
    status = err.status_code if err.status_code > 0 else 502
    raise HTTPException(status_code=status, detail={"message": str(err), "body": err.body})


# @router.post("/analyze", response_model=CommandResponse)
# def analyze(payload: AnalyzeRequest) -> CommandResponse:
#     try:
#         result = service.analyze(
#             repo_path=payload.repo_path,
#             force=payload.force,
#         )
#         return _to_response(result)
#     except CommandRunError as err:
#         _raise_http(err)


@router.post("/analyze", response_model=AnalyzeAndSyncResponse, tags=["gitnexus"])
def analyze_and_sync(payload: AnalyzeAndSyncRequest) -> AnalyzeAndSyncResponse:
    try:
        return _svc_analyze_and_sync(payload)
    except CommandRunError as err:
        _raise_http(err)
    except GitNexusHttpError as err:
        _raise_http_api(err)


@router.get("/status", response_model=CommandResponse)
def status(repo_path: str) -> CommandResponse:
    try:
        return _to_response(service.status(repo_path))
    except CommandRunError as err:
        _raise_http(err)

@router.post("/parse-full-graph", response_model=ParseFullGraphResponse)
def parse_full_graph(payload: ParseFullGraphRequest) -> ParseFullGraphResponse:
    try:
        result = db_full_graph(
            repo_name=payload.repo_name,
            excluded_labels=payload.excluded_labels,
            excluded_rel_types=payload.excluded_rel_types,
            limit_nodes=payload.limit_nodes,
            offset_nodes=payload.offset_nodes,
        )
        return ParseFullGraphResponse(**result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

# @router.post("/clean", response_model=CommandResponse)
# def clean(payload: CleanRequest) -> CommandResponse:
#     try:
#         return _to_response(service.clean(payload.repo_path, force=payload.force))
#     except CommandRunError as err:
#         _raise_http(err)


# @router.post("/query", response_model=CommandResponse)
# def query(payload: QueryRequest) -> CommandResponse:
#     try:
#         result = service.query(
#             repo_path=payload.repo_path,
#             search_query=payload.search_query,
#             repo_name=payload.repo_name,
#             context=payload.context,
#             goal=payload.goal,
#             limit=payload.limit,
#             include_content=payload.include_content,
#         )
#         return _to_response(result)
#     except CommandRunError as err:
#         _raise_http(err)


# @router.post("/cypher", response_model=CommandResponse)
# def cypher(payload: CypherRequest) -> CommandResponse:
#     try:
#         return _to_response(
#             service.cypher(
#                 repo_path=payload.repo_path,
#                 query=payload.query,
#                 repo_name=payload.repo_name,
#             )
#         )
#     except CommandRunError as err:
#         _raise_http(err)


# ── HTTP API endpoints (requires gitnexus serve) ──────────────────────────────

@router.get("/server/ready", response_model=ServerReadyResponse, tags=["gitnexus-http"])
def server_ready() -> ServerReadyResponse:
    return ServerReadyResponse(ready=service.is_server_ready())


@router.get("/repos", response_model=list[RepoInfo], tags=["gitnexus-http"])
def list_repos() -> list[Any]:
    try:
        return service.list_repos()
    except GitNexusHttpError as err:
        _raise_http_api(err)


@router.get("/repos/{repo_name}", response_model=RepoInfo, tags=["gitnexus-http"])
def get_repo(repo_name: str) -> Any:
    try:
        return service.get_repo_info(repo_name)
    except GitNexusHttpError as err:
        _raise_http_api(err)


# @router.post("/graph", tags=["gitnexus-http"])
# def get_graph(payload: GraphRequest) -> Any:
#     try:
#         return service.get_graph(
#             repo_name=payload.repo_name,
#             include_content=payload.include_content,
#         )
#     except GitNexusHttpError as err:
#         _raise_http_api(err)


# @router.post("/cypher-http", tags=["gitnexus-http"])
# def cypher_http(payload: CypherHttpRequest) -> Any:
#     try:
#         return service.cypher_http(payload.cypher, repo_name=payload.repo_name)
#     except GitNexusHttpError as err:
#         _raise_http_api(err)


# @router.post("/search", tags=["gitnexus-http"])
# def search(payload: SearchRequest) -> Any:
#     try:
#         return service.search(
#             query=payload.query,
#             repo_name=payload.repo_name,
#             mode=payload.mode,
#             limit=payload.limit,
#         )
#     except GitNexusHttpError as err:
#         _raise_http_api(err)


# @router.get("/processes", tags=["gitnexus-http"], include_in_schema=False)
# def list_processes(repo_name: str | None = None) -> Any:
#     try:
#         return service.list_processes(repo_name=repo_name)
#     except GitNexusHttpError as err:
#         _raise_http_api(err)


# @router.get("/clusters", tags=["gitnexus-http"], include_in_schema=False)
# def list_clusters(repo_name: str | None = None) -> Any:
#     try:
#         return service.list_clusters(repo_name=repo_name)
#     except GitNexusHttpError as err:
#         _raise_http_api(err)


# ── DB endpoints (query from Postgres after sync) ─────────────────────────────

@router.get("/db/nodes", tags=["gitnexus-db"], include_in_schema=False)
def get_nodes(repo_name: str = Query(...), label: Optional[str] = Query(None), file_path: Optional[str] = Query(None), limit: int = Query(500, ge=1, le=5000), offset: int = Query(0, ge=0)) -> list[dict]:
    try:
        return db_nodes(repo_name=repo_name, label=label, file_path=file_path, limit=limit, offset=offset)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/db/relations", tags=["gitnexus-db"], include_in_schema=False)
def get_relations(
    repo_name: str = Query(...),
    relation_type: Optional[str] = Query(None),
    from_id: Optional[str] = Query(None),
    to_id: Optional[str] = Query(None),
    limit: int = Query(500, ge=1, le=10000),
    offset: int = Query(0, ge=0),
) -> list[dict]:
    try:
        return db_relations(repo_name=repo_name, relation_type=relation_type, from_id=from_id, to_id=to_id, limit=limit, offset=offset)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/db/node-graph", tags=["gitnexus-db"])
def get_node_graph(
    repo_name: str = Query(..., description="Tên repo trong registry GitNexus"),
    node_id: str = Query(..., description="ID của bất kỳ node nào: File:..., Class:..., Function:..., Method:..."),
    depth: int = Query(1, ge=1, le=3, description="Số hop BFS: 1=neighbors trực tiếp, 2=thêm CALLS giữa các method"),
    same_file: bool = Query(True, description="Chỉ lấy nodes cùng file với root (mặc định True). False=BFS tự do sang file khác"),
    include_variables: bool = Query(False, description="Hiện Variable nodes (mặc định ẩn)"),
    include_meta_relations: bool = Query(False, description="Hiện MEMBER_OF / STEP_IN_PROCESS (mặc định ẩn)"),
) -> dict:
    """Subgraph từ bất kỳ node nào — File, Class, Function, Method đều dùng được.

    Tự động tìm tất cả nodes kết nối qua relations trong DB và trả về graph sạch.
    Mọi edge đều có node tương ứng trong `nodes[]` (không có dangling edge).

    **Cách lấy node_id:**
    - Tất cả File: `GET /db/nodes?repo_name=X&label=File`
    - Tất cả Class: `GET /db/nodes?repo_name=X&label=Class`
    - Tất cả Function: `GET /db/nodes?repo_name=X&label=Function`

    Response:
    ```json
    {
      "root":  { "id", "label", "name", "file_path", "start_line", "end_line" },
      "nodes": [{ "id", "label", "name", "file_path", "start_line", "end_line" }, ...],
      "edges": [{ "from_id", "to_id", "relation_type", "confidence" }, ...],
      "stats": { "total_nodes": 8, "total_edges": 10 }
    }
    ```
    """
    return db_node_graph(
        repo_name=repo_name,
        node_id=node_id,
        depth=depth,
        same_file=same_file,
        include_variables=include_variables,
        include_meta_relations=include_meta_relations,
    )


