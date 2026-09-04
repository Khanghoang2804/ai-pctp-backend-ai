#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from app.service.ScanLayer2 import ScanLayer2  # noqa: E402
from app.service.ScanLayer3 import QwenLLMClient, ScanLayer3  # noqa: E402
from graphrag_ablation_benchmark import (  # noqa: E402
    Candidate,
    build_functions,
    build_graph,
    collect_files,
    graph_context,
)
from layer3_end_to_end_ablation import (  # noqa: E402
    cwe_candidates,
    is_predicted_vulnerable,
    load_cwe_dictionary,
)
from repository_baseline_benchmark import (  # noqa: E402
    DEFAULT_OUTPUT_DIR,
    DEFAULT_REPO_DIR,
    build_oracle,
    choose_repos,
    summarize,
)


DEFAULT_MODEL = REPO_ROOT / "app" / "service" / "codebert-binary-final_v69_"
DEFAULT_OUTPUT = DEFAULT_OUTPUT_DIR / "aicp_full_pipeline_metrics.json"


def collect_graph_inputs(repo_dir: Path):
    all_files = []
    all_functions = []
    for repo in choose_repos(repo_dir):
        files = collect_files(repo)
        functions = build_functions(files)
        all_files.extend(files)
        all_functions.extend(functions)
    return all_files, all_functions, {fn.node_id: fn for fn in all_functions}, build_graph(all_functions, all_files)


def build_layer2_results(
    *,
    candidates: list[Candidate],
    functions_by_id: dict[str, Any],
    model_path: Path,
    batch_size: int,
) -> dict[str, dict[str, Any]]:
    unique_ids = []
    seen = set()
    for candidate in candidates:
        if candidate.function_id in seen:
            continue
        seen.add(candidate.function_id)
        unique_ids.append(candidate.function_id)
    codes = [functions_by_id.get(function_id).content if functions_by_id.get(function_id) else "" for function_id in unique_ids]
    scanner = ScanLayer2(Path("."), model_path, repo_name="aicp-full-pipeline")
    results = scanner.predict_function_code_batch(codes, batch_size=batch_size)
    return dict(zip(unique_ids, results))


def vulnerability_probability(result: dict[str, Any]) -> float | None:
    if not result.get("ok"):
        return None
    value = result.get("prob_by_label_id", {}).get(1)
    return float(value) if value is not None else None


def candidate_public_dict(candidate: Candidate) -> dict[str, Any]:
    data = asdict(candidate)
    data.pop("oracle_label", None)
    data.pop("oracle_reason", None)
    return data


def run_layer3_direct(
    *,
    direct_client: QwenLLMClient,
    parser: ScanLayer3,
    candidate: Candidate,
    layer2_result: dict[str, Any],
    context: str,
    retrieved_nodes: list[str],
    cwe_dictionary: list[dict[str, str]],
    max_context_chars: int,
    layer2_threshold: float,
) -> dict[str, Any]:
    vul_prob = vulnerability_probability(layer2_result)
    evidence = {
        **candidate_public_dict(candidate),
        "layer1_candidate_source": "rule-based candidate generated from the target repository",
        "layer2_codebert_softmax": {
            "label": layer2_result.get("label"),
            "label_id": layer2_result.get("label_id"),
            "confidence": layer2_result.get("confidence"),
            "vulnerable_probability": vul_prob,
            "threshold": layer2_threshold,
            "passes_threshold": bool(vul_prob is not None and vul_prob > layer2_threshold),
        },
        "layer3_retrieval": {
            "strategy": "GraphRAG traversal",
            "retrieved_nodes": retrieved_nodes,
        },
    }
    trimmed_context = parser.truncate_middle(context, max_context_chars)
    cwes = cwe_candidates(candidate.category, cwe_dictionary)
    evidence_str = json.dumps(evidence, indent=2, ensure_ascii=False)
    cwe_str = json.dumps(cwes, indent=2, ensure_ascii=False)

    validator_messages = [
        {
            "role": "system",
            "content": (
                "You are the AICP three-layer vulnerability validator. "
                "Layer 1 produced the candidate, Layer 2 produced the CodeBERT semantic score, "
                "and Layer 3 retrieved graph context using GraphRAG traversal. "
                "Use only the provided evidence and context. Do not ask to read files. "
                "Do not emit tool calls. Return a concise Vietnamese exploitability assessment."
            ),
        },
        {
            "role": "user",
            "content": f"""
[Layer 1 + Layer 2 Candidate Evidence]
{evidence_str}

[Layer 3 GraphRAG Traversal Context]
{trimmed_context}

Decide whether the candidate is a true exploitable vulnerability or a false positive.
Ground the decision in source/sink reachability, guard/sanitization evidence, and the CodeBERT semantic score.
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
                    "You are the AICP Layer 3 remediation architect. "
                    "Output exactly one valid JSON object and nothing else. "
                    "If exploitability is not supported by the provided evidence, return "
                    "selected_cwe_id='UNMAPPED', severity='Unknown', evidence_strength='weak'."
                ),
            },
            {
                "role": "user",
                "content": f"""
[Layer 1 + Layer 2 Candidate Evidence]
{evidence_str}

[Layer 3 GraphRAG Traversal Context]
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
        "candidate": asdict(candidate),
        "retrieved_nodes": retrieved_nodes,
        "layer2_result": layer2_result,
        "validator_response": raw_validator[:5000],
        "raw_response": raw_response[:8000],
        "parsed": parsed,
        "predicted_label": "TP" if predicted_vulnerable else "FP",
        "actual_label": candidate.oracle_label,
        "correct": predicted_vulnerable == (candidate.oracle_label == "TP"),
        "elapsed_seconds": round(time.time() - start, 1),
        "error": error,
    }


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
        "false_positive_count": fp,
        "total": len(results),
    }


def run_key(candidate: Candidate) -> str:
    return f"{candidate.repo}|{candidate.candidate_id}|{candidate.file_path}|{candidate.line}|{candidate.rule_id}"


def load_existing(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def build_payload(args: argparse.Namespace, candidates: list[Candidate], results: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = compute_metrics(results) if results else {
        "TP": 0,
        "FP": 0,
        "FN": 0,
        "TN": 0,
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
        "accuracy": 0.0,
        "false_positive_count": 0,
        "total": 0,
    }
    return {
        "timestamp": datetime.now().isoformat(),
        "tool": "AICP",
        "benchmark_note": (
            "Full AICP benchmark: Layer 1 controlled rule candidates, Layer 2 CodeBERT semantic score, "
            "and Layer 3 GraphRAG traversal reasoning. Layer 2 is included as semantic evidence; "
            "Layer 3 makes the final vulnerability decision."
        ),
        "repo_counts": dict(Counter(c.repo for c in candidates)),
        "label_counts": dict(Counter(c.oracle_label for c in candidates)),
        "config": {
            "repo_dir": args.repo_dir,
            "model_path": args.model_path,
            "max_candidates_per_repo": args.max_candidates_per_repo,
            "max_nodes": args.max_nodes,
            "graph_depth": args.graph_depth,
            "max_context_chars": args.max_context_chars,
            "layer2_threshold": args.layer2_threshold,
            "batch_size": args.batch_size,
        },
        "metrics": metrics,
        "details": results,
    }


def to_markdown(payload: dict[str, Any]) -> str:
    m = payload["metrics"]
    lines = [
        "# AICP Full Three-Layer Pipeline Metrics",
        "",
        payload.get("benchmark_note", ""),
        "",
        "| Accuracy | Precision | Recall | F1 | False Positives | Total |",
        "|---:|---:|---:|---:|---:|---:|",
        f"| {m['accuracy']}% | {m['precision']}% | {m['recall']}% | {m['f1']:.2f} | {m['false_positive_count']} | {m['total']} |",
        "",
        f"Layer 2 threshold recorded in evidence: {payload.get('config', {}).get('layer2_threshold')}",
    ]
    return "\n".join(lines) + "\n"


def write_outputs(output_path: Path, payload: dict[str, Any]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    output_path.with_suffix(".md").write_text(to_markdown(payload), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run full AICP three-layer benchmark on the controlled repository oracle.")
    parser.add_argument("--repo-dir", default=str(DEFAULT_REPO_DIR))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--model-path", default=str(DEFAULT_MODEL))
    parser.add_argument("--max-candidates-per-repo", type=int, default=35)
    parser.add_argument("--max-nodes", type=int, default=8)
    parser.add_argument("--graph-depth", type=int, default=2)
    parser.add_argument("--max-context-chars", type=int, default=9000)
    parser.add_argument("--layer2-threshold", type=float, default=0.5)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    if not os.getenv("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY is not set in the container environment.")

    repo_dir = Path(args.repo_dir)
    output_path = Path(args.output)
    candidates = build_oracle(repo_dir, args.max_candidates_per_repo)
    _, all_functions, functions_by_id, graph = collect_graph_inputs(repo_dir)
    layer2_by_function_id = build_layer2_results(
        candidates=candidates,
        functions_by_id=functions_by_id,
        model_path=Path(args.model_path),
        batch_size=args.batch_size,
    )

    existing = load_existing(output_path) if args.resume else {}
    completed = {
        run_key(Candidate(**item["candidate"])): item
        for item in existing.get("details", [])
        if isinstance(item, dict) and item.get("candidate")
    }
    results = list(completed.values())

    cwe_dictionary = load_cwe_dictionary()

    print(f"Candidates: {len(candidates)} | Completed: {len(completed)} | Output: {output_path}", flush=True)

    def evaluate_candidate(candidate: Candidate) -> dict[str, Any]:
        parser_layer3 = ScanLayer3(repo_name="aicp-full-pipeline-benchmark", prompt_dump_dir=None)
        direct_client = QwenLLMClient()
        layer2_result = layer2_by_function_id.get(candidate.function_id, {"ok": False, "error": "Missing function content"})
        context, retrieved_nodes = graph_context(candidate, graph, functions_by_id, args.max_nodes, args.graph_depth)
        result = None
        for attempt in range(max(1, args.retries + 1)):
            result = run_layer3_direct(
                direct_client=direct_client,
                parser=parser_layer3,
                candidate=candidate,
                layer2_result=layer2_result,
                context=context,
                retrieved_nodes=retrieved_nodes,
                cwe_dictionary=cwe_dictionary,
                max_context_chars=args.max_context_chars,
                layer2_threshold=args.layer2_threshold,
            )
            if not result.get("error"):
                return result
            if attempt < args.retries:
                time.sleep(3 * (attempt + 1))
        return result or {
            "candidate": asdict(candidate),
            "retrieved_nodes": [],
            "layer2_result": layer2_result,
            "raw_response": "{}",
            "parsed": {},
            "predicted_label": "FP",
            "actual_label": candidate.oracle_label,
            "correct": candidate.oracle_label == "FP",
            "elapsed_seconds": 0,
            "error": "No result produced",
        }

    pending = []
    for candidate in candidates:
        key = run_key(candidate)
        if key in completed:
            continue
        pending.append(candidate)

    if args.workers <= 1:
        run_index = len(completed)
        for candidate in pending:
            run_index += 1
            layer2_result = layer2_by_function_id.get(candidate.function_id, {"ok": False, "error": "Missing function content"})
            vul_prob = vulnerability_probability(layer2_result)
            print(
                f"[{run_index}/{len(candidates)}] AICP | {candidate.repo}:{candidate.file_path}:{candidate.line} "
                f"| rule={candidate.rule_id} | l2_p={vul_prob if vul_prob is not None else 'NA'} | oracle={candidate.oracle_label}",
                flush=True,
            )
            result = evaluate_candidate(candidate)
            results.append(result)
            payload = build_payload(args, candidates, results)
            write_outputs(output_path, payload)
            print(
                f"  -> predicted={result['predicted_label']} correct={result['correct']} "
                f"elapsed={result['elapsed_seconds']}s cwe={result['parsed'].get('selected_cwe_id')}",
                flush=True,
            )
    else:
        print(f"Running pending candidates with workers={args.workers}", flush=True)
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {}
            for idx, candidate in enumerate(pending, start=len(completed) + 1):
                layer2_result = layer2_by_function_id.get(candidate.function_id, {"ok": False, "error": "Missing function content"})
                vul_prob = vulnerability_probability(layer2_result)
                print(
                    f"[submit {idx}/{len(candidates)}] AICP | {candidate.repo}:{candidate.file_path}:{candidate.line} "
                    f"| rule={candidate.rule_id} | l2_p={vul_prob if vul_prob is not None else 'NA'} | oracle={candidate.oracle_label}",
                    flush=True,
                )
                futures[executor.submit(evaluate_candidate, candidate)] = candidate

            completed_count = len(completed)
            for future in as_completed(futures):
                candidate = futures[future]
                completed_count += 1
                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "candidate": asdict(candidate),
                        "retrieved_nodes": [],
                        "layer2_result": layer2_by_function_id.get(candidate.function_id, {}),
                        "raw_response": "{}",
                        "parsed": {},
                        "predicted_label": "FP",
                        "actual_label": candidate.oracle_label,
                        "correct": candidate.oracle_label == "FP",
                        "elapsed_seconds": 0,
                        "error": str(exc),
                    }
                results.append(result)
                payload = build_payload(args, candidates, results)
                write_outputs(output_path, payload)
                print(
                    f"[done {completed_count}/{len(candidates)}] {candidate.repo}:{candidate.file_path}:{candidate.line} "
                    f"-> predicted={result['predicted_label']} correct={result['correct']} "
                    f"elapsed={result['elapsed_seconds']}s cwe={result.get('parsed', {}).get('selected_cwe_id')}",
                    flush=True,
                )

    final_payload = build_payload(args, candidates, results)
    write_outputs(output_path, final_payload)
    print(to_markdown(final_payload), flush=True)
    summarize(output_path.parent, [output_path])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
