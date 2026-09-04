from fastapi import HTTPException
from app.schema.gitnexus import AnalyzeAndSyncRequest, AnalyzeAndSyncResponse
from app.service.gitnexusService import GitNexusService
from app.service.gitnexus_sync_service import GitNexusSyncService
from app.core.gitnexus_command import CommandRunError
from app.core.gitnexus_http_client import GitNexusHttpError
from pathlib import Path
from typing import Optional

service = GitNexusService()
sync_service = GitNexusSyncService(service)

def _raise_http(err: CommandRunError) -> None:
    raise HTTPException(
        status_code=422,
        detail={
            "message": "gitnexus command thất bại",
            "stdout": err.stdout,
            "stderr": err.stderr,
            "returncode": err.returncode,
        },
    )

def _raise_http_api(err: GitNexusHttpError) -> None:
    raise HTTPException(status_code=502, detail=str(err)) from err
def analyze_and_sync(payload: AnalyzeAndSyncRequest) -> AnalyzeAndSyncResponse:

    try:
        analyze_result = service.analyze(
            repo_path=payload.repo_path,
            force=payload.force,
        )
    except CommandRunError as err:
        _raise_http(err)

    if analyze_result.returncode != 0:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "gitnexus analyze thất bại",
                "stdout": analyze_result.stdout,
                "stderr": analyze_result.stderr,
            },
        )

    repo_path_resolved = Path(payload.repo_path).resolve()
    try:
        repos = service.list_repos()
    except GitNexusHttpError as err:
        _raise_http_api(err)

    repo_name: Optional[str] = None
    for entry in repos:
        entry_path = entry.get("path") or entry.get("repoPath", "")
        if Path(str(entry_path)).resolve() == repo_path_resolved:
            repo_name = str(entry.get("name", ""))
            break

    if not repo_name:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Repo {payload.repo_path} không tìm thấy trong registry sau analyze. "
                "Kiểm tra repo_path tồn tại và gitnexus serve/registry dùng chung GITNEXUS_HOME."
            ),
        )


    try:
        sync_payload = sync_service.sync_repo(
            repo_name=repo_name,
            repo_path=str(repo_path_resolved),
            include_content=payload.include_content,
            replace_repo=payload.replace_repo,
        )
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning("Bỏ qua lỗi sync đồ thị: %s", exc)
        return AnalyzeAndSyncResponse(
            repo_name=repo_name,
            analyze_stdout=analyze_result.stdout,
            analyze_returncode=analyze_result.returncode,
            stats_nodes=0,
            stats_edges=0,
        )

    return AnalyzeAndSyncResponse(
        repo_name=repo_name,
        analyze_stdout=analyze_result.stdout,
        analyze_returncode=analyze_result.returncode,
        stats_nodes=sync_payload.meta.stats_nodes or 0,
        stats_edges=sync_payload.meta.stats_edges or 0,
    )