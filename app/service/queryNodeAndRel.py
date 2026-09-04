from typing import Any, Optional
from fastapi import HTTPException
from app.core.database import querydb_dicts
from app.schema.gitnexus_sync import TABLE_NODES, TABLE_RELATIONS


# ── helpers ───────────────────────────────────────────────────────────────────

# Labels quá chi tiết — ẩn khỏi graph visualization mặc định
_NOISE_LABELS = frozenset({"Variable", "Community", "Process", "Section"})

# Relation types nội bộ clustering/process — ẩn mặc định
_META_REL_TYPES = frozenset({"MEMBER_OF", "STEP_IN_PROCESS", "ENTRY_POINT_OF"})


def _extract_file_path_from_id(node_id: str) -> Optional[str]:
    """File:src/foo.py → src/foo.py | Function:src/foo.py:bar → src/foo.py."""
    parts = node_id.split(":", 2)
    if len(parts) >= 2:
        return parts[1]
    return None

def db_nodes(
    repo_name: str,
    label: Optional[str] = None,
    file_path: Optional[str] = None,
    limit: int = 10000,
    offset: int = 0,
) -> list[dict]:
    """Trả toàn bộ node của một repo đã sync vào Postgres.

    Hỗ trợ lọc thêm theo `label` (vd. Function) và `file_path` (ILIKE).
    """
    conditions = ["repo_name = %s"]
    params: list[Any] = [repo_name]

    if label:
        conditions.append("label = %s")
        params.append(label)
    if file_path:
        conditions.append("file_path ILIKE %s")
        params.append(f"%{file_path}%")

    where = " AND ".join(conditions)
    sql = (
        f"SELECT id, label, name, file_path, description, content,"
        f"start_line, end_line, is_exported, raw_properties "
        f"FROM {TABLE_NODES} "
        f"WHERE {where} "
        f"ORDER BY label, name "
        f"LIMIT %s OFFSET %s"
    )
    params.extend([limit, offset])

    try:
        return querydb_dicts(sql, tuple(params))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def _fetch_edges_for_ids(
    repo_name: str,
    node_ids: list[str],
    excluded_rels: list[str],
) -> list[dict]:
    """Lấy tất cả edges có from_id hoặc to_id nằm trong node_ids."""
    if not node_ids:
        return []
    if excluded_rels:
        rel_ph = ", ".join(["%s"] * len(excluded_rels))
        return querydb_dicts(
            f"SELECT from_id, to_id, relation_type, confidence, reason "
            f"FROM {TABLE_RELATIONS} "
            f"WHERE repo_name = %s AND (from_id = ANY(%s) OR to_id = ANY(%s)) "
            f"  AND relation_type NOT IN ({rel_ph}) "
            f"ORDER BY relation_type",
            (repo_name, node_ids, node_ids, *excluded_rels),
        )
    return querydb_dicts(
        f"SELECT from_id, to_id, relation_type, confidence, reason "
        f"FROM {TABLE_RELATIONS} "
        f"WHERE repo_name = %s AND (from_id = ANY(%s) OR to_id = ANY(%s)) "
        f"ORDER BY relation_type",
        (repo_name, node_ids, node_ids),
    )


def _fetch_nodes_by_ids(
    repo_name: str,
    node_ids: list[str],
    excluded_labels: list[str],
    restrict_file_path: Optional[str] = None,
    include_content: bool = False,
) -> list[dict]:
    """Fetch nodes theo danh sách ID, lọc noise labels.
    Nếu restrict_file_path được đặt, chỉ lấy nodes cùng file_path đó.
    """
    if not node_ids:
        return []
    cols = "id, label, name, file_path, description, start_line, end_line, is_exported"
    if include_content:
        cols += ", content"
    label_filter = ""
    label_params: tuple = ()
    if excluded_labels:
        label_ph = ", ".join(["%s"] * len(excluded_labels))
        label_filter = f" AND label NOT IN ({label_ph})"
        label_params = tuple(excluded_labels)
    if restrict_file_path:
        return querydb_dicts(
            f"SELECT {cols} "
            f"FROM {TABLE_NODES} "
            f"WHERE repo_name = %s AND id = ANY(%s) "
            f"  {label_filter} "
            f"  AND file_path = %s "
            f"ORDER BY start_line",
            (repo_name, node_ids, *label_params, restrict_file_path),
        )
    return querydb_dicts(
        f"SELECT {cols} "
        f"FROM {TABLE_NODES} "
        f"WHERE repo_name = %s AND id = ANY(%s) "
        f"  {label_filter} "
        f"ORDER BY label, name",
        (repo_name, node_ids, *label_params),
    )


def db_resolve_file_node_id(repo_name: str, bare_file_path: str) -> Optional[str]:
    """Tìm id node File trong DB khớp đường dẫn relative.

    GitNexus thường lưu id dạng `File:<file_path>` trùng cột file_path; có khi chỉ khớp qua file_path.
    """
    if not bare_file_path.strip():
        return None
    canonical = f"File:{bare_file_path}"
    hit = querydb_dicts(
        f"SELECT id FROM {TABLE_NODES} WHERE repo_name = %s AND id = %s LIMIT 1",
        (repo_name, canonical),
    )
    if hit:
        return str(hit[0]["id"])
    hit = querydb_dicts(
        f"SELECT id FROM {TABLE_NODES} WHERE repo_name = %s AND label = 'File' AND file_path = %s LIMIT 1",
        (repo_name, bare_file_path),
    )
    if hit:
        return str(hit[0]["id"])
    return None


def db_node_graph(
    repo_name: str,
    node_id: str,
    depth: int = 1,
    same_file: bool = True,
    include_variables: bool = False,
    include_meta_relations: bool = False,
    include_content: bool = False,
) -> dict:
    """Subgraph từ bất kỳ node nào (File, Class, Function, Method, ...).

    - `same_file=True` (mặc định): chỉ lấy neighbor nodes cùng file với root.
      Chọn Class → chỉ thấy Methods của class đó + CALLS giữa chúng.
      Không bị lẫn File/Folder parent hay nodes từ file khác CALL vào.
    - `same_file=False`: BFS tự do, thấy cả nodes từ file khác.
    - `depth=1`: neighbors trực tiếp. `depth=2`: thêm 1 lớp nữa.
    """
    depth = max(1, min(depth, 3))

    # 1. Lấy root node
    root_cols = "id, label, name, file_path, description, start_line, end_line, is_exported"
    if include_content:
        root_cols += ", content"
    root_rows = querydb_dicts(
        f"SELECT {root_cols} "
        f"FROM {TABLE_NODES} WHERE repo_name = %s AND id = %s",
        (repo_name, node_id),
    )
    if not root_rows:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Node '{node_id}' không tìm thấy trong repo '{repo_name}'. "
                "Dùng GET /db/nodes để xem danh sách node ID hợp lệ."
            ),
        )
    root = root_rows[0]
    restrict_path: Optional[str] = root["file_path"] if same_file else None

    excluded_rels = list(_META_REL_TYPES) if not include_meta_relations else []
    base_noise = _NOISE_LABELS if not include_variables else (_NOISE_LABELS - {"Variable"})
    # Khi same_file: bỏ thêm File/Folder (chúng là parent container, không phải symbol)
    extra_noise = {"File", "Folder"} if same_file and root["label"] not in {"File", "Folder"} else set()
    excluded_labels = list(base_noise | extra_noise)

    # 2. BFS theo depth
    visited_ids: set[str] = {node_id}
    all_nodes: list[dict] = [root]
    all_edges: list[dict] = []
    frontier: list[str] = [node_id]

    for _ in range(depth):
        edges = _fetch_edges_for_ids(repo_name, frontier, excluded_rels)
        seen_edges = {(e["from_id"], e["to_id"], e["relation_type"]) for e in all_edges}
        new_edges = [
            e for e in edges
            if (e["from_id"], e["to_id"], e["relation_type"]) not in seen_edges
        ]
        all_edges.extend(new_edges)

        neighbor_ids = list(
            ({e["from_id"] for e in new_edges} | {e["to_id"] for e in new_edges}) - visited_ids
        )
        if not neighbor_ids:
            break

        neighbor_nodes = _fetch_nodes_by_ids(
            repo_name, neighbor_ids, excluded_labels,
            restrict_file_path=restrict_path,
            include_content=include_content,
        )
        found_ids = {n["id"] for n in neighbor_nodes}
        all_nodes.extend(neighbor_nodes)
        visited_ids |= found_ids
        frontier = list(found_ids)

    # 3. Loại bỏ dangling edges — chỉ giữ edge mà cả from và to đều có trong nodes
    valid_ids = {n["id"] for n in all_nodes}
    clean_edges = [
        e for e in all_edges
        if e["from_id"] in valid_ids and e["to_id"] in valid_ids
    ]

    # 4. Thêm display_name (bỏ arity suffix #N)
    for node in all_nodes:
        raw = node.get("name") or ""
        node["display_name"] = raw.split("#")[0] if "#" in raw else raw

    return {
        "root": root,
        "nodes": all_nodes,
        "edges": clean_edges,
        "stats": {
            "total_nodes": len(all_nodes),
            "total_edges": len(clean_edges),
            "depth": depth,
            "same_file": same_file,
        },
    }

def db_full_graph(
    repo_name: str,
    excluded_labels: Optional[list[str]] = None,
    excluded_rel_types: Optional[list[str]] = None,
    limit_nodes: int = 5000,
    offset_nodes: int = 0,
) -> dict:
    """Trả toàn bộ nodes + edges của một repo trong một lần gọi — dùng để render full graph.

    - `excluded_labels`: bỏ qua node có label này (mặc định bỏ noise labels).
    - `excluded_rel_types`: bỏ qua edge có relation_type này (mặc định bỏ meta rels).
    - `limit_nodes`: giới hạn số node tối đa (mặc định 5000).
    - `offset_nodes`: dùng để phân trang.
    """
    excl_labels = excluded_labels if excluded_labels is not None else list(_NOISE_LABELS)
    excl_rels = excluded_rel_types if excluded_rel_types is not None else list(_META_REL_TYPES)

    label_ph = ", ".join(["%s"] * len(excl_labels)) if excl_labels else None
    node_sql = (
        f"SELECT id, label, name, file_path, description, start_line, end_line, is_exported "
        f"FROM {TABLE_NODES} "
        f"WHERE repo_name = %s"
        + (f" AND label NOT IN ({label_ph})" if label_ph else "")
        + f" ORDER BY label, name LIMIT %s OFFSET %s"
    )
    node_params = (repo_name, *excl_labels, limit_nodes, offset_nodes) if label_ph else (repo_name, limit_nodes, offset_nodes)
    nodes = querydb_dicts(node_sql, node_params)

    node_ids = [n["id"] for n in nodes]
    if not node_ids:
        return {"nodes": [], "edges": [], "stats": {"total_nodes": 0, "total_edges": 0}}

    rel_ph = ", ".join(["%s"] * len(excl_rels)) if excl_rels else None
    edge_sql = (
        f"SELECT from_id, to_id, relation_type, confidence, reason "
        f"FROM {TABLE_RELATIONS} "
        f"WHERE repo_name = %s AND from_id = ANY(%s) AND to_id = ANY(%s)"
        + (f" AND relation_type NOT IN ({rel_ph})" if rel_ph else "")
        + f" ORDER BY relation_type"
    )
    edge_params = (repo_name, node_ids, node_ids, *excl_rels) if rel_ph else (repo_name, node_ids, node_ids)
    edges = querydb_dicts(edge_sql, edge_params)

    for node in nodes:
        raw = node.get("name") or ""
        node["display_name"] = raw.split("#")[0] if "#" in raw else raw

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {"total_nodes": len(nodes), "total_edges": len(edges)},
    }


def db_relations(
    repo_name: str,
    relation_type: Optional[str] = None,
    from_id: Optional[str] = None,
    to_id: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
) -> list[dict]:

    conditions = ["repo_name = %s"]
    params: list[Any] = [repo_name]

    if relation_type:
        conditions.append("relation_type = %s")
        params.append(relation_type)
    if from_id:
        conditions.append("from_id = %s")
        params.append(from_id)
    if to_id:
        conditions.append("to_id = %s")
        params.append(to_id)

    where = " AND ".join(conditions)
    sql = (
        f"SELECT from_id, to_id, relation_type, confidence, reason, step "
        f"FROM {TABLE_RELATIONS} "
        f"WHERE {where} "
        f"ORDER BY relation_type, from_id "
        f"LIMIT %s OFFSET %s"
    )
    params.extend([limit, offset])

    try:
        return querydb_dicts(sql, tuple(params))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def db_taint_path(
    repo_name: str,
    target_node_id: str,
    max_depth: int = 10,
    exclude_nodes: list = None
) -> dict:
    """Thuật toán Graph Traversal (Recursive CTE) thay thế Agent 1.
    Duyệt ngược từ Sink (target_node_id) lên Source qua các cạnh CALLS.
    Hỗ trợ exclude_nodes để loại bỏ các Node bị Z3 chặn.
    """
    exclude_condition = ""
    params = [repo_name, target_node_id]
    if exclude_nodes:
        exclude_condition = "AND NOT (from_id = ANY(%s) OR to_id = ANY(%s))"
        params.extend([exclude_nodes, exclude_nodes])

    recur_exclude_condition = ""
    recur_params = [repo_name, max_depth]
    if exclude_nodes:
        recur_exclude_condition = "AND NOT (r.from_id = ANY(%s) OR r.to_id = ANY(%s))"
        recur_params.extend([exclude_nodes, exclude_nodes])

    query = f"""
    WITH RECURSIVE taint_path AS (
        SELECT from_id, to_id, relation_type, 1 AS depth, ARRAY[to_id, from_id] AS path_array
        FROM {TABLE_RELATIONS}
        WHERE repo_name = %s AND to_id = %s AND relation_type IN ('CALLS', 'DATA_DEPENDS_ON')
        {exclude_condition}

        UNION ALL

        SELECT r.from_id, r.to_id, r.relation_type, tp.depth + 1, tp.path_array || r.from_id
        FROM {TABLE_RELATIONS} r
        JOIN taint_path tp ON r.to_id = tp.from_id
        WHERE r.repo_name = %s 
          AND r.relation_type IN ('CALLS', 'DATA_DEPENDS_ON')
          AND tp.depth < %s
          AND NOT r.from_id = ANY(tp.path_array)
          {recur_exclude_condition}
    )
    SELECT path_array FROM taint_path ORDER BY depth DESC LIMIT 10;
    """
    
    final_params = tuple(params + recur_params)
    rows = querydb_dicts(query, final_params)
    
    if not rows:
        msg = f"Không tìm thấy luồng dữ liệu (Data-Flow Path) nào gọi tới {target_node_id}"
        if exclude_nodes:
            msg += f" (đã loại trừ các node: {exclude_nodes})"
        return {"error": msg}
        
    # Lấy path dài nhất (hoặc tất cả các path)
    paths = []
    node_ids = set()
    for row in rows:
        # path_array đi từ sink -> source (do đệ quy ngược)
        # Ta cần đảo ngược lại thành source -> sink
        arr = row["path_array"][::-1] 
        paths.append(" -> ".join(arr))
        node_ids.update(arr)
        
    # Truy vấn nội dung các node trên đường đi
    node_contents = ""
    if node_ids:
        nodes = _fetch_nodes_by_ids(repo_name, list(node_ids), [], include_content=True)
        for n in nodes:
            node_contents += f"\n--- Node: {n['id']} ---\n{n.get('content', 'No content')}\n"
            
    return {
        "algorithmic_paths": paths,
        "nodes_content": node_contents
    }