#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from graphrag_ablation_benchmark import (  # noqa: E402
    Candidate,
    build_functions,
    build_graph,
    collect_files,
    evidence_ranked_graph_context,
    graph_context,
    is_nonruntime_path,
    local_context,
    scan_candidates,
    text_context,
)
from app.service.ScanLayer3 import QwenLLMClient, ScanLayer3  # noqa: E402
from app.service.ScanLayer3_Tools import (  # noqa: E402
    DependencyCheckerTool,
    SearchCWEPayloadTool,
    SendHTTPRequestTool,
    SyntaxCheckerTool,
    UnitTestRunnerTool,
    Z3SolverTool,
)


CWE_BY_CATEGORY = {
    "injection": ["CWE-89", "CWE-94", "CWE-78", "CWE-79"],
    "dangerous_function": ["CWE-94", "CWE-78"],
    "xss": ["CWE-79", "CWE-81"],
    "path_traversal": ["CWE-22", "CWE-23"],
    "ssrf": ["CWE-918"],
    "deserialization": ["CWE-502"],
    "hardcoded_secret": ["CWE-798", "CWE-259"],
    "weak_crypto": ["CWE-327", "CWE-328", "CWE-338"],
    "misconfiguration": ["CWE-352", "CWE-200", "CWE-16", "CWE-284"],
    "open_redirect": ["CWE-601"],
    "auth_bypass": ["CWE-639", "CWE-862", "CWE-863", "CWE-287"],
    "sensitive_log": ["CWE-532", "CWE-209"],
    "dos": ["CWE-1333", "CWE-400"],
}

DEFAULT_CWES = [
    "CWE-89",
    "CWE-78",
    "CWE-79",
    "CWE-22",
    "CWE-918",
    "CWE-502",
    "CWE-94",
    "CWE-798",
    "CWE-352",
    "CWE-601",
    "CWE-327",
    "CWE-200",
    "CWE-639",
    "CWE-307",
]


AGENT_VALIDATOR_SYSTEM = """
You are the Layer 3 Vulnerability Validator in AICP.
Your task is to decide whether the candidate finding is practically exploitable using the retrieved repository context.

All relevant code context has already been provided in the prompt.
Do NOT request files, do NOT call read_file/file.read, and do NOT emit XML-style or JSON-style tool calls.
Do not invent files or relationships that are not present in the provided context.
Return a concise Vietnamese exploitability assessment for the remediation agent.
""".strip()


AGENT_REMEDIATION_SYSTEM = """
You are the Layer 3 Remediation Architect in AICP.
Use the validator assessment, retrieved repository context, and allowed CWE dictionary to produce the final report.

All relevant code context has already been provided in the prompt.
Do NOT request files, do NOT call read_file/file.read, and do NOT emit tool calls.

Final answer MUST be exactly one root-level JSON object with this schema:
{
  "selected_cwe_id": "CWE-XXX or UNMAPPED",
  "selected_cwe_name": "string",
  "selected_cwe_reason": "string in Vietnamese",
  "candidate_comparison": [
    {"cwe_id": "string", "fit": "strong|medium|weak", "reason": "string in Vietnamese"}
  ],
  "root_cause": "string in Vietnamese",
  "attack_path": ["string in Vietnamese"],
  "impact": "string in Vietnamese",
  "severity": "Critical|High|Medium|Low|Unknown",
  "evidence_strength": "strong|medium|weak",
  "remediation": ["string in Vietnamese"],
  "secure_code_example": "string or null"
}

If the retrieved context does not contain enough evidence to support exploitability, use selected_cwe_id = "UNMAPPED", severity = "Unknown", and evidence_strength = "weak".
Do not wrap the JSON in markdown fences.
""".strip()


def load_cwe_dictionary() -> list[dict[str, str]]:
    data = json.loads((REPO_ROOT / "cwe_dictionary.json").read_text(encoding="utf-8"))
    by_id = {
        str(item.get("cwe_id", "")).upper(): {
            "cwe_id": str(item.get("cwe_id", "")).upper(),
            "cwe_name": item.get("cwe_name") or item.get("name") or "",
            "cwe_description": item.get("cwe_description") or item.get("description") or "",
        }
        for item in data
        if isinstance(item, dict)
    }
    return list(by_id.values())


def cwe_candidates(category: str, dictionary: list[dict[str, str]]) -> list[dict[str, str]]:
    by_id = {item["cwe_id"]: item for item in dictionary}
    ids = CWE_BY_CATEGORY.get(category, []) + DEFAULT_CWES
    selected = []
    seen = set()
    for cwe_id in ids:
        if cwe_id in by_id and cwe_id not in seen:
            selected.append(by_id[cwe_id])
            seen.add(cwe_id)
    return selected[:16]


def choose_repos(repo_dir: Path) -> list[Path]:
    expected = ["NodeGoat-1.4", "VAmPI-master", "pygoat-2.0.1"]
    repos = [repo_dir / name for name in expected if (repo_dir / name).is_dir()]
    if repos:
        return repos
    return sorted([p for p in repo_dir.iterdir() if p.is_dir()])


def sorted_candidates(repo_name: str, candidates: list[Candidate]) -> list[Candidate]:
    return sorted(
        candidates,
        key=lambda c: (
            0 if c.oracle_label == "TP" else 1,
            c.category,
            c.file_path,
            c.line,
            c.rule_id,
        ),
    )


def select_balanced(candidates: list[Candidate], limit: int) -> list[Candidate]:
    if limit <= 0 or len(candidates) <= limit:
        return candidates
    tps = [c for c in candidates if c.oracle_label == "TP"]
    fps = [c for c in candidates if c.oracle_label == "FP"]
    tp_limit = limit // 2 + limit % 2
    fp_limit = limit // 2
    selected = tps[:tp_limit] + fps[:fp_limit]
    if len(selected) < limit:
        selected += [c for c in candidates if c not in selected][: limit - len(selected)]
    return selected[:limit]


def build_dataset(repo_dir: Path, max_candidates_per_repo: int, exclude_nonruntime_candidates: bool = False):
    all_files = []
    all_functions = []
    all_candidates = []
    for repo in choose_repos(repo_dir):
        files = collect_files(repo)
        functions = build_functions(files)
        candidates = sorted_candidates(repo.name, scan_candidates(repo.name, files, functions))
        if exclude_nonruntime_candidates:
            candidates = [c for c in candidates if not is_nonruntime_path(c.file_path)]
        selected = select_balanced(candidates, max_candidates_per_repo)
        all_files.extend(files)
        all_functions.extend(functions)
        all_candidates.extend(selected)
    functions_by_id = {fn.node_id: fn for fn in all_functions}
    files_by_key = {(f.repo, f.path): f for f in all_files}
    graph = build_graph(all_functions, all_files)
    return all_files, all_functions, all_candidates, functions_by_id, files_by_key, graph


def make_context_builders(all_functions, functions_by_id, files_by_key, graph, max_nodes: int, depth: int) -> dict[str, Callable[[Candidate], tuple[str, list[str]]]]:
    return {
        "Local function only": lambda cand: local_context(cand, functions_by_id, files_by_key),
        "Text-based retrieval": lambda cand: text_context(cand, all_functions, functions_by_id, max_nodes),
        "GraphRAG traversal": lambda cand: graph_context(cand, graph, functions_by_id, max_nodes, depth),
        "Evidence-ranked GraphRAG": lambda cand: evidence_ranked_graph_context(
            cand,
            graph,
            functions_by_id,
            files_by_key,
            max_nodes,
            depth,
        ),
    }


def create_llm():
    from crewai import LLM

    model = os.getenv("OPENAI_MODEL", "qwen3-coder-next")
    if "/" not in model:
        model = f"openai/{model}"
    return LLM(
        model=model,
        base_url=os.getenv("OPENAI_BASE_URL", "https://ckey.vn/v1"),
        api_key=os.getenv("OPENAI_API_KEY", ""),
        temperature=0.1,
        timeout=int(os.getenv("LLM_TIMEOUT_SECONDS", "180")),
    )


def make_evidence(candidate: Candidate, retrieved_nodes: list[str]) -> dict[str, Any]:
    return {
        "candidate_id": candidate.candidate_id,
        "repo": candidate.repo,
        "file_path": candidate.file_path,
        "line": candidate.line,
        "rule_id": candidate.rule_id,
        "rule_name": candidate.rule_name,
        "category": candidate.category,
        "matched_text": candidate.matched_text,
        "function_id": candidate.function_id,
        "retrieved_nodes": retrieved_nodes,
    }


def run_layer3_candidate(
    *,
    llm,
    direct_client: QwenLLMClient,
    parser: ScanLayer3,
    candidate: Candidate,
    strategy: str,
    context: str,
    retrieved_nodes: list[str],
    cwe_dictionary: list[dict[str, str]],
    max_context_chars: int,
    enable_tools: bool,
    engine: str,
) -> dict[str, Any]:
    if engine == "direct":
        return run_layer3_candidate_direct(
            direct_client=direct_client,
            parser=parser,
            candidate=candidate,
            strategy=strategy,
            context=context,
            retrieved_nodes=retrieved_nodes,
            cwe_dictionary=cwe_dictionary,
            max_context_chars=max_context_chars,
        )

    from crewai import Agent, Crew, Process, Task

    evidence = make_evidence(candidate, retrieved_nodes)
    trimmed_context = parser.truncate_middle(context, max_context_chars)
    cwes = cwe_candidates(candidate.category, cwe_dictionary)
    evidence_str = json.dumps(evidence, indent=2, ensure_ascii=False)
    cwe_str = json.dumps(cwes, indent=2, ensure_ascii=False)

    factual_context = f"""
[Repository]
{candidate.repo}

[Retrieval Strategy]
{strategy}

[Target Candidate]
{evidence_str}

[Retrieved Repository Context]
{trimmed_context}

[Important]
The retrieved context above is the complete evidence available to this run. Do not ask for or call external file-reading tools.
""".strip()

    validator_tools = [SearchCWEPayloadTool(), Z3SolverTool(), SendHTTPRequestTool()] if enable_tools else []
    architect_tools = [SyntaxCheckerTool(), UnitTestRunnerTool(), DependencyCheckerTool()] if enable_tools else []

    validator = Agent(
        role="Vulnerability Validator",
        goal="Validate whether the candidate vulnerability is reachable and exploitable from the retrieved code context.",
        backstory=factual_context + "\n\n" + AGENT_VALIDATOR_SYSTEM,
        llm=llm,
        tools=validator_tools,
        verbose=False,
        max_iter=2,
    )

    architect = Agent(
        role="Remediation Architect",
        goal="Map the validated issue to CWE and produce a concise remediation report.",
        backstory=factual_context + "\n\n" + AGENT_REMEDIATION_SYSTEM,
        llm=llm,
        tools=architect_tools,
        verbose=False,
        max_iter=2,
    )

    task_validate = Task(
        description=f"""
Assess the candidate finding using the retrieved context.

You should identify:
1. whether external/user-controlled input can reach the suspicious operation,
2. whether the retrieved context contains sanitization, validation, authorization, or other blocking logic,
3. whether the candidate should proceed as a vulnerability or be treated as a false positive.

Candidate evidence:
{evidence_str}
""".strip(),
        expected_output="Vietnamese exploitability verdict with evidence, reachability, and severity.",
        agent=validator,
    )

    task_report = Task(
        description=f"""
Using the validator assessment and the retrieved repository context, produce the final JSON report.

Allowed CWE dictionary:
{cwe_str}

Remember: if evidence is insufficient, return UNMAPPED with weak evidence.
""".strip(),
        expected_output="Exactly one JSON object matching the required Layer 3 schema.",
        agent=architect,
        context=[task_validate],
    )

    start = time.time()
    raw_response = "{}"
    error = None
    try:
        crew = Crew(
            agents=[validator, architect],
            tasks=[task_validate, task_report],
            process=Process.sequential,
            verbose=False,
        )
        raw_response = str(crew.kickoff())
    except Exception as exc:
        error = str(exc)

    parsed = parser.parse_llm_json(raw_response)
    predicted_vulnerable = is_predicted_vulnerable(parsed)
    return {
        "strategy": strategy,
        "candidate": asdict(candidate),
        "retrieved_nodes": retrieved_nodes,
        "raw_response": raw_response[:8000],
        "parsed": parsed,
        "predicted_label": "TP" if predicted_vulnerable else "FP",
        "actual_label": candidate.oracle_label,
        "correct": predicted_vulnerable == (candidate.oracle_label == "TP"),
        "elapsed_seconds": round(time.time() - start, 1),
        "error": error,
    }


def run_layer3_candidate_direct(
    *,
    direct_client: QwenLLMClient,
    parser: ScanLayer3,
    candidate: Candidate,
    strategy: str,
    context: str,
    retrieved_nodes: list[str],
    cwe_dictionary: list[dict[str, str]],
    max_context_chars: int,
) -> dict[str, Any]:
    evidence = make_evidence(candidate, retrieved_nodes)
    trimmed_context = parser.truncate_middle(context, max_context_chars)
    cwes = cwe_candidates(candidate.category, cwe_dictionary)
    evidence_str = json.dumps(evidence, indent=2, ensure_ascii=False)
    cwe_str = json.dumps(cwes, indent=2, ensure_ascii=False)

    validator_messages = [
        {
            "role": "system",
            "content": (
                "You are the AICP Layer 3 Vulnerability Validator. You are running in an offline benchmark. "
                "All available source code context is included in the user message. "
                "Do not ask to read files. Do not emit tool calls. Do not use markdown. "
                "Return a concise Vietnamese exploitability assessment grounded only in the provided context."
            ),
        },
        {
            "role": "user",
            "content": f"""
[Candidate Evidence]
{evidence_str}

[Retrieval Strategy]
{strategy}

[Retrieved Repository Context: COMPLETE EVIDENCE FOR THIS RUN]
{trimmed_context}

Determine whether the finding is a true exploitable vulnerability or a false positive. Explain source, sink, guard/sanitization evidence, reachability, and severity in Vietnamese.
""".strip(),
        },
    ]

    start = time.time()
    raw_validator = ""
    raw_response = "{}"
    error = None
    try:
        raw_validator = direct_client.chat(validator_messages, max_tokens=1400)
        architect_messages = [
            {
                "role": "system",
                "content": (
                    "You are the AICP Layer 3 Remediation Architect. "
                "You must output exactly one valid JSON object and nothing else. "
                "Do not ask to read files. Do not emit tool calls. Do not use markdown fences. "
                "If exploitability is not supported by the provided context, return selected_cwe_id='UNMAPPED', severity='Unknown', evidence_strength='weak'."
            ),
        },
            {
                "role": "user",
                "content": f"""
[Candidate Evidence]
{evidence_str}

[Retrieval Strategy]
{strategy}

[Retrieved Repository Context]
{trimmed_context}

[Validator Assessment]
{raw_validator}

[Allowed CWE Dictionary]
{cwe_str}

Return exactly this JSON schema:
{{
  "selected_cwe_id": "CWE-XXX or UNMAPPED",
  "selected_cwe_name": "string",
  "selected_cwe_reason": "string in Vietnamese",
  "candidate_comparison": [
    {{"cwe_id": "string", "fit": "strong|medium|weak", "reason": "string in Vietnamese"}}
  ],
  "root_cause": "string in Vietnamese",
  "attack_path": ["string in Vietnamese"],
  "impact": "string in Vietnamese",
  "severity": "Critical|High|Medium|Low|Unknown",
  "evidence_strength": "strong|medium|weak",
  "remediation": ["string in Vietnamese"],
  "secure_code_example": null
}}
""".strip(),
            },
        ]
        raw_response = direct_client.chat(architect_messages, max_tokens=2200)
    except Exception as exc:
        error = str(exc)

    parsed = parser.parse_llm_json(raw_response)
    predicted_vulnerable = is_predicted_vulnerable(parsed)
    return {
        "strategy": strategy,
        "engine": "direct",
        "candidate": asdict(candidate),
        "retrieved_nodes": retrieved_nodes,
        "validator_response": raw_validator[:5000],
        "raw_response": raw_response[:8000],
        "parsed": parsed,
        "predicted_label": "TP" if predicted_vulnerable else "FP",
        "actual_label": candidate.oracle_label,
        "correct": predicted_vulnerable == (candidate.oracle_label == "TP"),
        "elapsed_seconds": round(time.time() - start, 1),
        "error": error,
    }


def is_predicted_vulnerable(parsed: dict[str, Any]) -> bool:
    cwe_id = str(parsed.get("selected_cwe_id") or "UNMAPPED").upper()
    severity = str(parsed.get("severity") or "Unknown").lower()
    evidence = str(parsed.get("evidence_strength") or "weak").lower()
    if cwe_id == "UNMAPPED":
        return False
    if severity in {"low", "unknown", "none"}:
        return False
    if evidence == "weak":
        return False
    return True


def compute_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for item in results:
        pred = item["predicted_label"] == "TP"
        actual = item["actual_label"] == "TP"
        if pred and actual:
            tp += 1
        elif pred and not actual:
            fp += 1
        elif not pred and actual:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(results) if results else 0.0
    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "f1": round(f1, 2),
        "accuracy": round(accuracy * 100, 1),
        "total": len(results),
    }


def load_existing(path: Path) -> dict[str, Any]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def run_key(candidate: Candidate, strategy: str) -> str:
    return f"{candidate.repo}|{candidate.candidate_id}|{candidate.file_path}|{candidate.line}|{candidate.rule_id}|{strategy}"


def write_outputs(output_path: Path, payload: dict[str, Any]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path = output_path.with_suffix(".md")
    md_path.write_text(to_markdown(payload), encoding="utf-8")


def to_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Layer 3 End-to-End Retrieval Ablation",
        "",
        f"Generated at: {payload.get('timestamp', '')}",
        "",
        "## Dataset",
        "",
        "| Repository | Candidates |",
        "|---|---:|",
    ]
    for repo, count in payload.get("repo_counts", {}).items():
        lines.append(f"| {repo} | {count} |")
    lines.append(f"| **Total** | **{sum(payload.get('repo_counts', {}).values())}** |")
    labels = payload.get("label_counts", {})
    lines.extend(["", f"Labels: TP={labels.get('TP', 0)}, FP={labels.get('FP', 0)}", ""])
    lines.extend([
        "## Results",
        "",
        "| Layer 3 Retrieval Strategy | Precision | Recall | F1 | False Positives | Total |",
        "|---|---:|---:|---:|---:|---:|",
    ])
    for metric in payload.get("metrics", []):
        lines.append(
            f"| {metric['strategy']} | {metric['precision']}% | {metric['recall']}% | "
            f"{metric['f1']:.2f} | {metric['FP']} | {metric['total']} |"
        )
    lines.append("")
    lines.append("Note: this benchmark runs the Layer 3 agent workflow over the same candidate set while varying only the retrieval context strategy.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Layer 3 end-to-end retrieval ablation with CrewAI agents.")
    parser.add_argument("--repo-dir", default="/app/benchmark_inputs/repos")
    parser.add_argument("--output", default="/app/benchmark_outputs/layer3_end_to_end/layer3_end_to_end_results.json")
    parser.add_argument("--max-candidates-per-repo", type=int, default=4)
    parser.add_argument("--max-nodes", type=int, default=8)
    parser.add_argument("--graph-depth", type=int, default=2)
    parser.add_argument("--max-context-chars", type=int, default=9000)
    parser.add_argument("--strategies", nargs="*", default=["Local function only", "Text-based retrieval", "GraphRAG traversal"])
    parser.add_argument("--engine", choices=["direct", "crewai"], default="direct")
    parser.add_argument("--enable-tools", action="store_true", help="Enable CrewAI tools. Default is off for stable retrieval ablation.")
    parser.add_argument("--exclude-nonruntime-candidates", action="store_true", help="Exclude obvious test/spec/build/support candidates from the benchmark sample.")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    if not os.getenv("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY is not set in the container environment.")

    repo_dir = Path(args.repo_dir)
    output_path = Path(args.output)
    all_files, all_functions, candidates, functions_by_id, files_by_key, graph = build_dataset(
        repo_dir,
        args.max_candidates_per_repo,
        args.exclude_nonruntime_candidates,
    )
    contexts = make_context_builders(all_functions, functions_by_id, files_by_key, graph, args.max_nodes, args.graph_depth)
    strategies = [s for s in args.strategies if s in contexts]
    parser_layer3 = ScanLayer3(repo_name="layer3-end-to-end-ablation", prompt_dump_dir=None)
    cwe_dictionary = load_cwe_dictionary()

    existing = load_existing(output_path) if args.resume else {}
    completed = {
        run_key(Candidate(**item["candidate"]), item["strategy"]): item
        for item in existing.get("results", [])
        if isinstance(item, dict) and item.get("candidate")
    }

    results = list(completed.values())
    total_runs = len(candidates) * len(strategies)
    print(f"Candidates: {len(candidates)} | Strategies: {len(strategies)} | Planned runs: {total_runs} | Completed: {len(completed)}", flush=True)

    run_index = len(completed)
    for candidate in candidates:
        for strategy in strategies:
            key = run_key(candidate, strategy)
            if key in completed:
                continue
            run_index += 1
            context, retrieved_nodes = contexts[strategy](candidate)
            print(
                f"[{run_index}/{total_runs}] {strategy} | {candidate.repo}:{candidate.file_path}:{candidate.line} "
                f"| oracle={candidate.oracle_label} | {candidate.rule_id}",
                flush=True,
            )
            result = run_layer3_candidate(
                llm=create_llm() if args.engine == "crewai" else None,
                direct_client=QwenLLMClient(),
                parser=parser_layer3,
                candidate=candidate,
                strategy=strategy,
                context=context,
                retrieved_nodes=retrieved_nodes,
                cwe_dictionary=cwe_dictionary,
                max_context_chars=args.max_context_chars,
                enable_tools=args.enable_tools,
                engine=args.engine,
            )
            results.append(result)

            payload = build_payload(args, candidates, results)
            write_outputs(output_path, payload)
            print(
                f"  -> predicted={result['predicted_label']} correct={result['correct']} "
                f"elapsed={result['elapsed_seconds']}s cwe={result['parsed'].get('selected_cwe_id')}",
                flush=True,
            )

    final_payload = build_payload(args, candidates, results)
    write_outputs(output_path, final_payload)
    print(to_markdown(final_payload), flush=True)
    return 0


def build_payload(args: argparse.Namespace, candidates: list[Candidate], results: list[dict[str, Any]]) -> dict[str, Any]:
    repo_counts = dict(Counter(c.repo for c in candidates))
    label_counts = dict(Counter(c.oracle_label for c in candidates))
    by_strategy = defaultdict(list)
    for item in results:
        by_strategy[item["strategy"]].append(item)
    metrics = []
    for strategy in args.strategies:
        if strategy in by_strategy:
            metric = compute_metrics(by_strategy[strategy])
            metric["strategy"] = strategy
            metrics.append(metric)
    return {
        "timestamp": datetime.now().isoformat(),
        "repo_dir": args.repo_dir,
        "config": {
            "max_candidates_per_repo": args.max_candidates_per_repo,
            "max_nodes": args.max_nodes,
            "graph_depth": args.graph_depth,
            "max_context_chars": args.max_context_chars,
            "strategies": args.strategies,
            "enable_tools": args.enable_tools,
            "engine": args.engine,
            "exclude_nonruntime_candidates": args.exclude_nonruntime_candidates,
        },
        "repo_counts": repo_counts,
        "label_counts": label_counts,
        "metrics": metrics,
        "results": results,
    }


if __name__ == "__main__":
    raise SystemExit(main())
