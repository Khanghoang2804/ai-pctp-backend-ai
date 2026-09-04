from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv
from psycopg2.extras import Json

from app.core.database import execute, execute_many
from app.core.gitnexus_http_client import GitNexusHttpError
from app.schema.gitnexus_sync import (
    TABLE_NODES,
    TABLE_RELATIONS,
    TABLE_SYNC_RUNS,
    GitNexusGraphSyncPayload,
    GitNexusNodeRecord,
    GitNexusRelationRecord,
    GitNexusSyncMeta,
)
from app.service.gitnexusService import GitNexusService

logger = logging.getLogger(__name__)



NODE_USED_KEYS = {
    "name",
    "filePath",
    "startLine",
    "endLine",
    "content",
    "description",
    "isExported",
    "parameterCount",
    "returnType",
    "processType",
    "stepCount",
    "level",
}


UPSERT_NODE_SQL = f"""
INSERT INTO {TABLE_NODES} (
  repo_name, id, label, name, file_path, content, description,
  start_line, end_line, is_exported, raw_properties
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
ON CONFLICT (repo_name, id) DO UPDATE SET
  label = EXCLUDED.label,
  name = EXCLUDED.name,
  file_path = EXCLUDED.file_path,
  content = EXCLUDED.content,
  description = EXCLUDED.description,
  start_line = EXCLUDED.start_line,
  end_line = EXCLUDED.end_line,
  is_exported = EXCLUDED.is_exported,
  raw_properties = EXCLUDED.raw_properties
"""


UPSERT_RELATION_SQL = f"""
INSERT INTO {TABLE_RELATIONS} (
  repo_name, from_id, to_id, relation_type, confidence, reason, step
) VALUES (%s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (repo_name, from_id, relation_type, to_id, step) DO UPDATE SET
  confidence = EXCLUDED.confidence,
  reason = EXCLUDED.reason
"""


def to_node_record(repo_name: str, node: dict[str, Any]) -> GitNexusNodeRecord:
    props = node.get("properties") or {}

    node_id = node.get("id")
    if not node_id:
        raise ValueError("Missing node.id")

    raw_properties = {
        key: value
        for key, value in props.items()
        if key not in NODE_USED_KEYS and value is not None
    }

    return GitNexusNodeRecord(
        repo_name=repo_name,
        id=str(node_id),
        label=str(node.get("label") or "CodeElement"),
        name=props.get("name"),
        file_path=props.get("filePath"),
        content=props.get("content"),
        description=props.get("description"),
        start_line=props.get("startLine"),
        end_line=props.get("endLine"),
        is_exported=props.get("isExported"),
        parameter_count=props.get("parameterCount"),
        return_type=props.get("returnType"),
        process_type=props.get("processType"),
        step_count=props.get("stepCount"),
        level=props.get("level"),
        raw_properties=raw_properties,
    )


def to_relation_record(repo_name: str, rel: dict[str, Any]) -> GitNexusRelationRecord:
    return GitNexusRelationRecord(
        repo_name=repo_name,
        from_id=str(rel["sourceId"]),
        to_id=str(rel["targetId"]),
        relation_type=str(rel["type"]),
        confidence=rel.get("confidence"),
        reason=rel.get("reason"),
        step=int(rel["step"]) if rel.get("step") is not None else -1,
    )


def to_payload(
    repo_name: str,
    graph: dict[str, Any],
    *,
    repo_path: Optional[str] = None,
    indexed_at: Optional[str] = None,
) -> GitNexusGraphSyncPayload:
    nodes = [
        to_node_record(repo_name, node)
        for node in graph.get("nodes", [])
    ]

    relations = [
        to_relation_record(repo_name, rel)
        for rel in graph.get("relationships", [])
    ]

    meta = GitNexusSyncMeta(
        repo_name=repo_name,
        repo_path=repo_path,
        indexed_at=indexed_at,
        stats_nodes=len(nodes),
        stats_edges=len(relations),
    )

    return GitNexusGraphSyncPayload(
        meta=meta,
        nodes=nodes,
        relations=relations,
    )


def node_rows(records: list[GitNexusNodeRecord]) -> list[tuple]:
    return [
        (
            record.repo_name,
            record.id,
            record.label,
            record.name,
            record.file_path,
            record.content,
            record.description,
            record.start_line,
            record.end_line,
            record.is_exported,
            Json(record.raw_properties or {}),
        )
        for record in records
    ]


def relation_rows(records: list[GitNexusRelationRecord]) -> list[tuple]:
    return [
        (
            record.repo_name,
            record.from_id,
            record.to_id,
            record.relation_type,
            record.confidence,
            record.reason,
            record.step if record.step is not None else -1,
        )
        for record in records
    ]


class GitNexusSyncService:
    def __init__(self, gitnexus: Optional[GitNexusService] = None) -> None:
        self.gitnexus = gitnexus or GitNexusService()

    def sync_repo(
        self,
        repo_name: str,
        *,
        repo_path: Optional[str] = None,
        include_content: bool = False,
        replace_repo: bool = True,
    ) -> GitNexusGraphSyncPayload:
        if not self.gitnexus.is_server_ready():
            base = self.gitnexus.settings.serve_base_url.rstrip("/")
            raise RuntimeError(
                f"Không có GitNexus REST API tại {base}.\n"
                "  • Bật server: gitnexus serve (nếu đã cài global), "
                "hoặc từ thư mục gốc project này:\n"
                "      node GitNexus/gitnexus/dist/cli/index.js serve\n"
                "    — không được paste ký hiệu '...'; cần đường dẫn thật đến file.\n"
                f"  • Kiểm tra: curl '{base}/api/health'\n"
                "  • Port khác: GITNEXUS_SERVE_BASE_URL trong .env."
            )

        graph = self._get_graph(repo_name, repo_path=repo_path, include_content=include_content)
        indexed_at = self._get_indexed_at(repo_name)

        payload = to_payload(
            repo_name,
            graph,
            repo_path=repo_path,
            indexed_at=indexed_at,
        )

        self._write_payload(payload, replace_repo=replace_repo)

        logger.info(
            "Synced GitNexus repo=%s nodes=%s relations=%s",
            repo_name,
            len(payload.nodes),
            len(payload.relations),
        )

        return payload

    def _get_graph(self, repo_name: str, repo_path: Optional[str] = None, *, include_content: bool) -> dict[str, Any]:
        import subprocess
        import json
        if repo_path:
            script_path = "/app/app/dump_graph.js"
            if Path(script_path).exists():
                try:
                    res = subprocess.run(
                        ["node", script_path, repo_path, str(include_content).lower()],
                        capture_output=True, text=True, check=True
                    )
                    return json.loads(res.stdout)
                except Exception as exc:
                    logger.warning("dump_graph.js fallback failed: %s, stderr: %s", exc, getattr(exc, 'stderr', ''))
        
        try:
            return self.gitnexus.get_graph(
                repo_name=repo_name,
                include_content=include_content,
            )
        except GitNexusHttpError as exc:
            detail = ""
            if isinstance(exc.body, dict):
                detail = str(exc.body.get("error", "")).lower()
            if exc.status_code == 404 and "not found" in (detail or str(exc).lower()):
                raise RuntimeError(
                    f'Repository "{repo_name}" không có trên gitnexus serve. '
                ) from exc
            raise RuntimeError(str(exc)) from exc

    def _get_indexed_at(self, repo_name: str) -> Optional[str]:
        try:
            info = self.gitnexus.get_repo_info(repo_name)
            return info.get("indexedAt") or info.get("indexed_at")
        except GitNexusHttpError:
            return None

    def _write_payload(
        self,
        payload: GitNexusGraphSyncPayload,
        *,
        replace_repo: bool,
    ) -> None:
        repo_name = payload.meta.repo_name

        if replace_repo:
            execute(f"DELETE FROM {TABLE_RELATIONS} WHERE repo_name = %s", (repo_name,))
            execute(f"DELETE FROM {TABLE_NODES} WHERE repo_name = %s", (repo_name,))

        execute_many(UPSERT_NODE_SQL, node_rows(payload.nodes))
        execute_many(UPSERT_RELATION_SQL, relation_rows(payload.relations))

        execute(
            f"""
            INSERT INTO {TABLE_SYNC_RUNS}
              (repo_name, repo_path, indexed_at, source, stats_nodes, stats_edges)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                payload.meta.repo_name,
                payload.meta.repo_path,
                payload.meta.indexed_at,
                payload.meta.source,
                payload.meta.stats_nodes,
                payload.meta.stats_edges,
            ),
        )


def _load_dotenv_for_cli() -> None:
    here = Path(__file__).resolve()
    app_root = here.parent.parent
    project_root = app_root.parent
    for p in (project_root / ".env", app_root / ".env"):
        if p.is_file():
            load_dotenv(p, override=False)


if __name__ == "__main__":
    _load_dotenv_for_cli()
    parser = argparse.ArgumentParser(
        description="Đồng bộ graph GitNexus (HTTP) vào Postgres."
    )
    parser.add_argument(
        "repo_name",
        help=(
            "Tên trong registry GitNexus (trường 'name' của /api/repos hoặc cột đầu "
            "trong `gitnexus list`). Không phải đường dẫn thư mục trên disk."
        ),
    )
    parser.add_argument(
        "--no-replace",
        action="store_true",
        help="Không xóa dữ liệu cũ của repo trước khi upsert.",
    )
    parser.add_argument(
        "--include-content",
        action="store_true",
        help="Lấy đủ attributes từ graph (nặng hơn).",
    )
    args = parser.parse_args()
    try:
        service = GitNexusSyncService()
        service.sync_repo(
            repo_name=args.repo_name,
            include_content=args.include_content,
            replace_repo=not args.no_replace,
        )
    except (RuntimeError, GitNexusHttpError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)