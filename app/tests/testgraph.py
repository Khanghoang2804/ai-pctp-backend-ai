from pathlib import Path
from app.service.queryNodeAndRel import db_node_graph, db_nodes
from app.service.ScanLayers import ScanLayers


def build_scan_index(scan_results: list[dict]) -> tuple[dict, dict]:
    file_issues: dict[str, list] = {}
    func_issues: dict[str, dict] = {}
    for item in scan_results:
        fp = item.get("file_path", "")
        if fp.startswith("Function:"):
            func_issues[fp] = item
        elif fp.startswith("File:"):
            file_issues[fp] = item.get("findings", [])
    return file_issues, func_issues


def format_findings_for_llm(findings: list[dict]) -> str:
    seen: set[tuple] = set()
    lines = []
    for f in findings:
        for rule in f.get("rules", []):
            key = (f["line"], rule.get("rule_id"))
            if key in seen:
                continue
            seen.add(key)
            severity = rule.get("severity", "")
            source = rule.get("source", "")
            lines.append(
                f"  ⚠ [{severity.upper()}][{source}] Line {f['line']}: "
                f"{rule['name']} — {rule['description'][:100]}"
            )
    return "\n".join(lines)


def build_call_chain(
    start_id: str,
    edges: list[dict],
    node_name_map: dict[str, str],
    max_depth: int = 4,
) -> list[list[str]]:
    """BFS trên CALLS edges để tìm tất cả call chains từ start_id."""
    call_edges: dict[str, list[str]] = {}
    for e in edges:
        if e["relation_type"] == "CALLS" and e["from_id"] != e["to_id"]:
            call_edges.setdefault(e["from_id"], []).append(e["to_id"])

    chains: list[list[str]] = []
    queue: list[tuple[str, list[str]]] = [(start_id, [node_name_map.get(start_id, start_id)])]
    visited_paths: set[tuple] = set()

    while queue:
        current_id, path = queue.pop(0)
        if len(path) > max_depth:
            chains.append(path)
            continue
        callees = call_edges.get(current_id, [])
        if not callees:
            chains.append(path)
            continue
        for callee_id in callees:
            callee_name = node_name_map.get(callee_id, callee_id)
            path_key = tuple(path + [callee_name])
            if path_key not in visited_paths:
                visited_paths.add(path_key)
                queue.append((callee_id, path + [callee_name]))

    return [c for c in chains if len(c) > 1]


def format_graph_for_llm(graph: dict, scan_results: list[dict] | None = None) -> str:
    root = graph["root"]
    nodes = graph["nodes"]
    # Fix 1: Remove self-loop edges
    edges = [e for e in graph["edges"] if e["from_id"] != e["to_id"]]

    file_issues, func_issues = build_scan_index(scan_results or [])
    root_id = root["id"]
    root_file = root["file_path"]
    node_name_map = {n["id"]: n["name"] for n in nodes}

    lines = []

    # 1. File content + issues
    lines.append(f"## File: {root_file}  ← BUGGY FILE")
    root_findings = file_issues.get(root_id, [])
    if root_findings:
        lines.append("### ⚠ Issues detected in this file:")
        lines.append(format_findings_for_llm(root_findings))
    if root.get("content"):
        lines.append("```python")
        lines.append(root["content"])
        lines.append("```")
    lines.append("")

    # 2. Symbols nội bộ
    own_symbols = [n for n in nodes if n["label"] != "File" and n.get("file_path") == root_file]
    if own_symbols:
        lines.append("## Symbols in this file:")
        for node in own_symbols:
            func_result = func_issues.get(node["id"])
            label_tag = ""
            if func_result:
                result = func_result.get("result", {})
                lbl = result.get("label", "")
                conf = result.get("confidence", 0)
                label_tag = f" 🔴 [{lbl} {conf:.0%}]" if lbl == "VULNERABLE" else f" ✅ [{lbl}]"
            lines.append(
                f"- [{node['label']}] `{node['name']}` "
                f"(lines {node.get('start_line')}–{node.get('end_line')}){label_tag}"
            )
    lines.append("")

    # 3. Fix 2: External references — rõ ràng ai gọi đến file lỗi
    external_nodes = [n for n in nodes if n.get("file_path") != root_file and n["label"] != "File"]
    external_files = {n["file_path"] for n in external_nodes}

    if external_files:
        lines.append("## ⚡ External references (files that import/call this buggy file):")
        for ext_file in sorted(external_files):
            ext_file_id = f"File:{ext_file}"
            ext_findings = file_issues.get(ext_file_id, [])
            status = " ⚠ (also has issues)" if ext_findings else ""
            lines.append(f"\n### {ext_file}{status}")

            cross_edges = [
                e for e in edges
                if (ext_file in e["from_id"] and root_file in e["to_id"])
                or (root_file in e["from_id"] and ext_file in e["to_id"])
            ]
            for e in cross_edges:
                lines.append(f"  - {e['from_id']} --[{e['relation_type']}]--> {e['to_id']}")
    else:
        lines.append("## ℹ No other files reference this file in the graph.")
        lines.append("  → Impact is isolated within this file. Propagation risk: LOW.")
    lines.append("")

    # 4. Fix 3: Affected execution path — call chain từ các function có issue
    vulnerable_funcs = [
        n for n in own_symbols
        if func_issues.get(n["id"]) or any(
            f["line"] >= (n.get("start_line") or 0) and f["line"] <= (n.get("end_line") or 999)
            for f in root_findings
        )
    ]

    if vulnerable_funcs:
        lines.append("## 🔗 Potential impact propagation:")

        # Tổng hợp issues
        all_issue_names = set()
        for f in root_findings:
            for rule in f.get("rules", []):
                all_issue_names.add(rule["name"])
        for n in vulnerable_funcs:
            fr = func_issues.get(n["id"])
            if fr:
                all_issue_names.add(fr.get("result", {}).get("label", ""))

        lines.append(f"Issues: {', '.join(sorted(all_issue_names))}")
        lines.append("")
        lines.append("Affected execution paths:")

        for vfunc in vulnerable_funcs:
            chains = build_call_chain(vfunc["id"], edges, node_name_map)
            if chains:
                for chain in chains:
                    lines.append("  " + " -> ".join(chain))
            else:
                lines.append(f"  {vfunc['name']} (no outgoing calls found)")

    return "\n".join(lines)


def test_db_node_graph():
    repo_name = "aicaller"
    model_path = Path(__file__).parent.parent / "service" / "codebert-binary-final_v69_"

    scan_results = ScanLayers(repo_name, model_path).scan()
    file_issues, func_issues = build_scan_index(scan_results)

    buggy_file_ids = set(file_issues.keys()) | {
        "File:" + fp.split(":")[1]
        for fp in func_issues
    }

    sections = []
    for file_id in buggy_file_ids:
        try:
            graph = db_node_graph(
                repo_name=repo_name,
                node_id=file_id,
                depth=2,
                same_file=False,
                include_content=True,
            )
        except Exception:
            continue
        sections.append(format_graph_for_llm(graph, scan_results))

    print("\n\n---\n\n".join(sections))


if __name__ == "__main__":
    test_db_node_graph()
