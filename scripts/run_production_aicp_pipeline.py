#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import sys
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.service.ScanLayers import ScanLayers  # noqa: E402
from app.service.ScanLayer3 import ScanLayer3  # noqa: E402


DEFAULT_REPO_DIR = REPO_ROOT / "benchmark_inputs" / "repos"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "benchmark_outputs" / "production_pipeline"
DEFAULT_MODEL = REPO_ROOT / "app" / "service" / "codebert-binary-final_v69_"
DEFAULT_CWE = REPO_ROOT / "cwe_dictionary.json"


CWE_MAP = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "path_traversal": "CWE-22",
    "ssrf": "CWE-918",
    "deserialization": "CWE-502",
    "command_injection": "CWE-78",
    "injection": "CWE-94",
    "weak_crypto": "CWE-327",
    "hardcoded_secret": "CWE-798",
    "xxe": "CWE-611",
    "file_upload": "CWE-434",
    "dangerous_function": "CWE-94",
    "insecure_network": "CWE-295",
    "misconfiguration": "CWE-352",
    "SEC034": "CWE-78",
    "SEC022": "CWE-78",
    "SEC094": "CWE-94",
    "SEC001": "CWE-798",
    "SEC043": "CWE-434",
    "SEC089": "CWE-89",
    "SEC079": "CWE-79",
    "SEC502": "CWE-502",
    "SEC918": "CWE-918",
    "SEC611": "CWE-611",
    "SEC327": "CWE-327",
    "SEC352": "CWE-352",
    "SEC295": "CWE-295",
}


def first_items_by_node(scan_results: list[dict[str, Any]], layer3: ScanLayer3) -> list[tuple[str, dict[str, Any]]]:
    seen: set[str] = set()
    jobs: list[tuple[str, dict[str, Any]]] = []
    for item in scan_results:
        node_id = layer3.extract_node_id(item)
        if not node_id or node_id in seen:
            continue
        seen.add(node_id)
        jobs.append((node_id, item))
    return jobs


def flat_layer1_results(repo_name: str, scan_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flat: list[dict[str, Any]] = []
    for file_item in scan_results:
        file_path = file_item.get("file_path", "")
        for finding in file_item.get("findings", []):
            for rule in finding.get("rules", []):
                cwe_id = CWE_MAP.get(rule.get("category", ""), rule.get("rule_id", "UNKNOWN"))
                flat.append(
                    {
                        "repo_name": repo_name,
                        "node_id": f"File:{file_path}",
                        "file_path": file_path,
                        "selected_cwe_id": cwe_id,
                        "selected_cwe_name": rule.get("name", "Vulnerability"),
                        "severity": str(rule.get("severity", "High")).capitalize(),
                        "selected_cwe_reason": (
                            f"Line {finding.get('line')}: {rule.get('description', '')}\n"
                            f"Code: {finding.get('line_content', '').strip()}"
                        ),
                        "root_cause": (
                            f"Detected by Layer 1 rule at line {finding.get('line')} of {file_path}. "
                            f"{rule.get('description', '')}"
                        ),
                        "attack_path": "",
                        "impact": "",
                        "remediation": rule.get("recommendation", "Follow secure coding guidance."),
                        "secure_code_example": None,
                        "layer1_raw": True,
                    }
                )
    return flat


def layer3_worker(
    queue: mp.Queue,
    repo_name: str,
    repo_root: str,
    cwe_dictionary: str,
    node_id: str,
    item: dict[str, Any],
    depth: int,
) -> None:
    try:
        os.environ.setdefault("SCAN_LAYER3_FAST_MODE", "1")
        scanner = ScanLayer3(
            repo_name,
            cwe_dictionary_path=cwe_dictionary,
            prompt_dump_dir=None,
            repo_root=repo_root,
        )
        result = scanner.scan_layer_results([item], limit=None, depth=depth, debug_prompt=False, max_workers=1)
        queue.put({"ok": True, "node_id": node_id, "results": result})
    except Exception as exc:
        queue.put({"ok": False, "node_id": node_id, "error": str(exc)})


def run_layer3_job(
    *,
    repo_name: str,
    repo_root: Path,
    cwe_dictionary: Path,
    node_id: str,
    item: dict[str, Any],
    depth: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    queue: mp.Queue = mp.Queue()
    proc = mp.Process(
        target=layer3_worker,
        args=(queue, repo_name, str(repo_root), str(cwe_dictionary), node_id, item, depth),
    )
    proc.start()
    proc.join(timeout_seconds)
    if proc.is_alive():
        proc.terminate()
        proc.join(10)
        return {
            "ok": False,
            "node_id": node_id,
            "timeout": True,
            "error": f"Layer 3 timed out after {timeout_seconds}s",
            "results": [
                {
                    "repo_name": repo_name,
                    "node_id": node_id,
                    "file_path": node_id.removeprefix("File:"),
                    "selected_cwe_id": "TIMEOUT",
                    "selected_cwe_name": "Layer 3 timeout",
                    "severity": "Unknown",
                    "selected_cwe_reason": f"Layer 3 timed out after {timeout_seconds}s.",
                    "root_cause": "",
                    "attack_path": "",
                    "impact": "",
                    "evidence_strength": "weak",
                    "remediation": [],
                    "secure_code_example": None,
                }
            ],
        }
    if not queue.empty():
        return queue.get()
    return {
        "ok": False,
        "node_id": node_id,
        "error": "Layer 3 worker exited without returning a result",
        "results": [],
    }


def load_existing(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_payload(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def run_repo(args: argparse.Namespace, repo_name: str) -> dict[str, Any]:
    repo_root = Path(args.repo_dir) / repo_name
    output_path = Path(args.output_dir) / f"{repo_name}_production_runner.json"
    model_path = Path(args.model_path)
    cwe_dictionary = Path(args.cwe_dictionary)

    started_at = time.time()
    print(f"=== {repo_name}: production Layer 1 + Layer 2 ===", flush=True)
    scanner = ScanLayers(
        repo_name=repo_name,
        root=repo_root,
        model_path=model_path,
        cwe_dictionary_path=cwe_dictionary,
        prompt_dump_dir=None,
    )
    scan_results = scanner.scan()
    layer1_files = [item for item in scan_results if "findings" in item]
    layer2_items = [item for item in scan_results if "result" in item]
    layer1_findings = sum(len(item.get("findings", [])) for item in layer1_files)

    layer3 = scanner.scan_layer3
    jobs = first_items_by_node(scan_results, layer3)

    existing = load_existing(output_path) if args.resume else {}
    completed_by_node = {
        item.get("node_id"): item
        for item in existing.get("layer3_job_results", [])
        if item.get("node_id")
    }
    layer3_job_results = list(completed_by_node.values())

    print(
        f"{repo_name}: scan_results={len(scan_results)}, layer1_findings={layer1_findings}, "
        f"layer2_items={len(layer2_items)}, layer3_jobs={len(jobs)}, completed={len(layer3_job_results)}",
        flush=True,
    )

    payload: dict[str, Any] = {
        "repo": repo_name,
        "repo_root": str(repo_root),
        "mode": "production Layer1/Layer2 plus fast GraphRAG Layer3 evaluation runner",
        "config": {
            "depth": args.depth,
            "timeout_seconds": args.timeout_seconds,
            "model_path": str(model_path),
            "cwe_dictionary": str(cwe_dictionary),
            "scan_layer3_fast_mode": os.getenv("SCAN_LAYER3_FAST_MODE", "1"),
            "scan_layer3_fast_context_chars": os.getenv("SCAN_LAYER3_FAST_CONTEXT_CHARS", "9000"),
            "scan_layer3_fast_max_tokens": os.getenv("SCAN_LAYER3_FAST_MAX_TOKENS", "2600"),
        },
        "counts": {
            "scan_result_items": len(scan_results),
            "layer1_files": len(layer1_files),
            "layer1_findings": layer1_findings,
            "layer2_items": len(layer2_items),
            "layer3_jobs": len(jobs),
        },
        "scan_results": scan_results,
        "layer3_job_results": layer3_job_results,
    }

    for index, (node_id, item) in enumerate(jobs, start=1):
        if node_id in completed_by_node:
            print(f"[{repo_name} {index}/{len(jobs)}] skip completed {node_id}", flush=True)
            continue
        print(f"[{repo_name} {index}/{len(jobs)}] Layer 3 {node_id}", flush=True)
        result = run_layer3_job(
            repo_name=repo_name,
            repo_root=repo_root,
            cwe_dictionary=cwe_dictionary,
            node_id=node_id,
            item=item,
            depth=args.depth,
            timeout_seconds=args.timeout_seconds,
        )
        layer3_job_results.append(result)
        payload["layer3_job_results"] = layer3_job_results
        payload["elapsed_seconds"] = round(time.time() - started_at, 1)
        write_payload(output_path, payload)
        status = "ok" if result.get("ok") else "error"
        extra = " timeout" if result.get("timeout") else ""
        print(f"  -> {status}{extra}", flush=True)

    layer3_llm_results: list[dict[str, Any]] = []
    for job in layer3_job_results:
        layer3_llm_results.extend(job.get("results") or [])

    payload["layer3_llm_results"] = layer3_llm_results
    payload["endpoint_like_layer3_results"] = layer3_llm_results + flat_layer1_results(repo_name, scan_results)
    payload["elapsed_seconds"] = round(time.time() - started_at, 1)
    write_payload(output_path, payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the built AST production AICP layers with checkpointed Layer 3 jobs.")
    parser.add_argument("--repo-dir", default=str(DEFAULT_REPO_DIR))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--model-path", default=str(DEFAULT_MODEL))
    parser.add_argument("--cwe-dictionary", default=str(DEFAULT_CWE))
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--timeout-seconds", type=int, default=90)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("repos", nargs="*", default=["NodeGoat-1.4", "VAmPI-master", "pygoat-2.0.1"])
    args = parser.parse_args()
    os.environ.setdefault("SCAN_LAYER3_FAST_MODE", "1")
    os.environ.setdefault("SCAN_LAYER3_FAST_CONTEXT_CHARS", "9000")
    os.environ.setdefault("SCAN_LAYER3_FAST_MAX_TOKENS", "2600")

    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    summaries = []
    for repo_name in args.repos:
        payload = run_repo(args, repo_name)
        summaries.append(
            {
                "repo": repo_name,
                **payload.get("counts", {}),
                "layer3_results": len(payload.get("layer3_llm_results", [])),
                "elapsed_seconds": payload.get("elapsed_seconds"),
            }
        )
    summary_path = Path(args.output_dir) / "production_runner_summary.json"
    write_payload(summary_path, {"summaries": summaries})
    print(json.dumps({"summaries": summaries}, indent=2, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
