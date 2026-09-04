"""
Cấu trúc dữ liệu để đồng bộ (sync) knowledge graph GitNexus sang DB riêng.

Bám theo Ladybug schema trong GitNexus：
- Nhiều loại node (`File`, `Function`, `Class`, …).
- Một loại cạnh logical `CodeRelation` với property `type` (CALLS, IMPORTS, …).

Dùng các model dưới đây làm contract giữa layer extract (HTTP/graph API, Cypher)
và layer load (Postgres/MySQL/…).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

# ── Bảng đích gợi ý (đặt tên tùy DB của bạn) ─────────────────────────────

TABLE_NODES = "gitnexus_nodes"
TABLE_RELATIONS = "gitnexus_relations"
TABLE_SYNC_RUNS = "gitnexus_sync_runs"

# Label node — khớp gitnexus-shared NODE_TABLES
GitNexusNodeLabel = Literal[
    "File",
    "Folder",
    "Function",
    "Class",
    "Interface",
    "Method",
    "CodeElement",
    "Community",
    "Process",
    "Section",
    "Struct",
    "Enum",
    "Macro",
    "Typedef",
    "Union",
    "Namespace",
    "Trait",
    "Impl",
    "TypeAlias",
    "Const",
    "Static",
    "Variable",
    "Property",
    "Record",
    "Delegate",
    "Annotation",
    "Constructor",
    "Template",
    "Module",
    "Route",
    "Tool",
]

# Kiểu quan hệ trên cạnh CodeRelation — khớp REL_TYPES
GitNexusRelationType = Literal[
    "CONTAINS",
    "DEFINES",
    "IMPORTS",
    "CALLS",
    "EXTENDS",
    "IMPLEMENTS",
    "HAS_METHOD",
    "HAS_PROPERTY",
    "ACCESSES",
    "METHOD_OVERRIDES",
    "OVERRIDES",
    "METHOD_IMPLEMENTS",
    "MEMBER_OF",
    "STEP_IN_PROCESS",
    "HANDLES_ROUTE",
    "FETCHES",
    "HANDLES_TOOL",
    "ENTRY_POINT_OF",
    "WRAPS",
    "QUERIES",
]


class GitNexusSyncMeta(BaseModel):
    """Metadata một lần đồng bộ (một dòng trong bảng sync_run)."""

    model_config = ConfigDict(extra="ignore")

    repo_name: str = Field(..., description="Tên repo trong registry GitNexus (~/.gitnexus/registry.json)")
    repo_path: Optional[str] = Field(None, description="Đường dẫn gốc repo trên disk, nếu có")
    indexed_at: Optional[str] = Field(None, description="ISO time từ meta.json / API")
    started_at: datetime = Field(default_factory=_utc_now)
    source: str = Field(default="gitnexus_http_api", description="http_api | cypher_dump | …")
    stats_nodes: Optional[int] = None
    stats_edges: Optional[int] = None


class GitNexusNodeRecord(BaseModel):
    """
    Một node trong graph — map 1:1 vào bảng flat `gitnexus_nodes`.

    Chỉ các field thường có; field không dùng cho label cụ thể để None.
    Payload thêm từ API có thể nhét vào raw_properties.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    repo_name: str

    id: str = Field(..., description="Primary key node trong GitNexus (vd: File:package.json)")
    label: str = Field(..., description="Loại node: File, Function, Class, …")

    name: Optional[str] = None
    file_path: Optional[str] = Field(None, alias="filePath", description="Khớp DB: filePath")
    content: Optional[str] = None
    description: Optional[str] = None

    start_line: Optional[int] = Field(None, alias="startLine")
    end_line: Optional[int] = Field(None, alias="endLine")
    is_exported: Optional[bool] = Field(None, alias="isExported")

    # Method / Route / Tool / Community / Process — tùy label
    parameter_count: Optional[int] = Field(None, alias="parameterCount")
    return_type: Optional[str] = Field(None, alias="returnType")
    process_type: Optional[str] = Field(None, alias="processType")
    step_count: Optional[int] = Field(None, alias="stepCount")
    level: Optional[int] = None

    raw_properties: dict[str, Any] = Field(default_factory=dict, description="Các field còn lại từ API chưa normalize")


class GitNexusRelationRecord(BaseModel):
    """
    Một cạnh CodeRelation — map 1:1 vào bảng `gitnexus_relations`.

    Primary key gợi ý khi insert: hash hoặc concat (repo, from_id, type, to_id, step).
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    repo_name: str

    from_id: str = Field(..., description="id node nguồn")
    to_id: str = Field(..., description="id node đích")
    relation_type: str = Field(..., description="Giá trị cột type trên CodeRelation: CALLS, IMPORTS, …")

    confidence: Optional[float] = None
    reason: Optional[str] = None
    step: Optional[int] = None


class GitNexusGraphSyncPayload(BaseModel):
    """Batch đầy đủ để một job sync ghi DB."""

    model_config = ConfigDict(extra="ignore")

    meta: GitNexusSyncMeta
    nodes: list[GitNexusNodeRecord] = Field(default_factory=list)
    relations: list[GitNexusRelationRecord] = Field(default_factory=list)


class GitNexusEmbeddingSyncRecord(BaseModel):
    """Chỉ khi bật embedding — bảng CodeEmbedding (tuỳ chọn sync)."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    repo_name: str
    id: str
    node_id: str = Field(..., alias="nodeId")
    chunk_index: int = Field(..., alias="chunkIndex")
    start_line: Optional[int] = Field(None, alias="startLine")
    end_line: Optional[int] = Field(None, alias="endLine")
    content_hash: Optional[str] = Field(None, alias="contentHash")
    # Vector thường không sync raw qua JSON nhỏ — lưu blob/path riêng nếu cần
    embedding_dims: Optional[int] = None


# ── Gợi ý DDL SQL (Postgres) — copy chỉnh sửa khi tạo migration ──────────────

SQL_SUGGEST_NODES = f"""
CREATE TABLE IF NOT EXISTS {TABLE_NODES} (
    repo_name     TEXT NOT NULL,
    id            TEXT NOT NULL,
    label         TEXT NOT NULL,
    name          TEXT,
    file_path     TEXT,
    content       TEXT,
    description   TEXT,
    start_line    BIGINT,
    end_line      BIGINT,
    is_exported   BOOLEAN,
    raw_properties JSONB DEFAULT '{{}}',
    PRIMARY KEY (repo_name, id)
);
CREATE INDEX IF NOT EXISTS idx_{TABLE_NODES}_label ON {TABLE_NODES} (repo_name, label);
CREATE INDEX IF NOT EXISTS idx_{TABLE_NODES}_file ON {TABLE_NODES} (repo_name, file_path);
"""

SQL_SUGGEST_RELATIONS = f"""
CREATE TABLE IF NOT EXISTS {TABLE_RELATIONS} (
    repo_name      TEXT NOT NULL,
    from_id        TEXT NOT NULL,
    to_id          TEXT NOT NULL,
    relation_type  TEXT NOT NULL,
    confidence     DOUBLE PRECISION,
    reason         TEXT,
    step           INTEGER NOT NULL DEFAULT -1,
    PRIMARY KEY (repo_name, from_id, relation_type, to_id, step)
);
CREATE INDEX IF NOT EXISTS idx_{TABLE_RELATIONS}_from ON {TABLE_RELATIONS} (repo_name, from_id);
CREATE INDEX IF NOT EXISTS idx_{TABLE_RELATIONS}_to   ON {TABLE_RELATIONS} (repo_name, to_id);
CREATE INDEX IF NOT EXISTS idx_{TABLE_RELATIONS}_type ON {TABLE_RELATIONS} (repo_name, relation_type);
"""

SQL_SUGGEST_SYNC_RUNS = f"""
CREATE TABLE IF NOT EXISTS {TABLE_SYNC_RUNS} (
    id           BIGSERIAL PRIMARY KEY,
    repo_name    TEXT NOT NULL,
    repo_path    TEXT,
    indexed_at   TEXT,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source       TEXT NOT NULL,
    stats_nodes  INTEGER,
    stats_edges  INTEGER
);
"""


def gitnexus_graph_sql_ddl_postgres() -> str:
    """Trả về DDL gợi ý dạng một chuỗi để paste vào migration."""
    return "\n\n".join(
        [
            SQL_SUGGEST_NODES.strip(),
            SQL_SUGGEST_RELATIONS.strip(),
            SQL_SUGGEST_SYNC_RUNS.strip(),
        ]
    )
