#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from app.service.ScanLayer2 import ScanLayer2  # noqa: E402
from graphrag_ablation_benchmark import build_functions, collect_files  # noqa: E402
from repository_baseline_benchmark import (  # noqa: E402
    DEFAULT_OUTPUT_DIR,
    DEFAULT_REPO_DIR,
    ToolFinding,
    build_oracle,
    choose_repos,
    compute_metrics,
    metrics_markdown,
    summarize,
)


DEFAULT_MODEL = REPO_ROOT / "app" / "service" / "codebert-binary-final_v69_"


def collect_function_map(repo_dir: Path) -> dict[str, str]:
    function_map: dict[str, str] = {}
    for repo in choose_repos(repo_dir):
        files = collect_files(repo)
        for fn in build_functions(files):
            function_map[fn.node_id] = fn.content
    return function_map


def safe_tool_name(tool: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", tool.lower())


def write_metrics(tool: str, metrics: dict[str, Any], output_dir: Path, extra: dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        **extra,
        "tool": tool,
        "metrics": {k: v for k, v in metrics.items() if k != "details"},
        "details": metrics["details"],
    }
    json_path = output_dir / f"{safe_tool_name(tool)}_metrics.json"
    md_path = output_dir / f"{safe_tool_name(tool)}_metrics.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(metrics_markdown(payload), encoding="utf-8")
    summarize(output_dir, [json_path])
    return json_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate CodeBERT + Softmax over repository benchmark candidates.")
    parser.add_argument("--repo-dir", default=str(DEFAULT_REPO_DIR))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--model-path", default=str(DEFAULT_MODEL))
    parser.add_argument("--max-candidates-per-repo", type=int, default=35)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--tool-name", default="CodeBERT + Softmax")
    parser.add_argument("--line-window", type=int, default=5)
    args = parser.parse_args()

    repo_dir = Path(args.repo_dir)
    output_dir = Path(args.output_dir)
    candidates = build_oracle(repo_dir, args.max_candidates_per_repo)
    function_map = collect_function_map(repo_dir)

    unique_ids = []
    seen = set()
    for candidate in candidates:
        if candidate.function_id in seen:
            continue
        seen.add(candidate.function_id)
        unique_ids.append(candidate.function_id)

    codes = [function_map.get(function_id, "") for function_id in unique_ids]
    scanner = ScanLayer2(Path("."), Path(args.model_path), repo_name="repository-benchmark")
    results = scanner.predict_function_code_batch(codes, batch_size=args.batch_size)
    by_function_id = dict(zip(unique_ids, results))

    findings: list[ToolFinding] = []
    for candidate in candidates:
        result = by_function_id.get(candidate.function_id) or {}
        vulnerable_probability = None
        if result.get("ok"):
            vulnerable_probability = result.get("prob_by_label_id", {}).get(1)
        predicted_vulnerable = vulnerable_probability is not None and float(vulnerable_probability) > args.threshold
        if not predicted_vulnerable:
            continue
        findings.append(
            ToolFinding(
                tool=args.tool_name,
                repo=candidate.repo,
                file_path=candidate.file_path,
                line=candidate.line,
                rule_id="CodeBERT-Softmax",
                category=candidate.category,
                severity="",
                message=f"vulnerable_probability={float(vulnerable_probability):.4f}",
                raw={
                    "candidate": asdict(candidate),
                    "model_result": result,
                },
            )
        )

    metrics = compute_metrics(candidates, findings, args.line_window)
    metric_path = write_metrics(
        args.tool_name,
        metrics,
        output_dir,
        {
            "model_path": str(Path(args.model_path)),
            "threshold": args.threshold,
            "unique_functions": len(unique_ids),
            "predicted_findings": len(findings),
        },
    )
    print(metric_path)
    print(metrics_markdown(json.loads(metric_path.read_text(encoding="utf-8"))))
    print(f"Unique functions evaluated: {len(unique_ids)}")
    print(f"Predicted vulnerable candidates: {len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
