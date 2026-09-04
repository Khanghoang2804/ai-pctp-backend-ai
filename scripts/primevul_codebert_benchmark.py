#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.service.ScanLayer2 import ScanLayer2  # noqa: E402


DEFAULT_DATASET = REPO_ROOT / "benchmark_inputs" / "primevul" / "primevul_test.jsonl"
DEFAULT_MODEL = REPO_ROOT / "app" / "service" / "codebert-binary-final_v69_"
DEFAULT_OUTPUT = REPO_ROOT / "benchmark_outputs" / "primevul_codebert" / "codebert_primevul_results.json"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def select_rows(rows: list[dict[str, Any]], mode: str, max_rows: int, seed: int) -> list[dict[str, Any]]:
    if mode == "all":
        return rows[:max_rows] if max_rows > 0 else rows

    vulnerable = [r for r in rows if int(r.get("target", 0)) == 1]
    benign = [r for r in rows if int(r.get("target", 0)) == 0]
    rng = random.Random(seed)
    rng.shuffle(vulnerable)
    rng.shuffle(benign)
    n = min(len(vulnerable), len(benign))
    if max_rows > 0:
        n = min(n, max_rows // 2)
    selected = vulnerable[:n] + benign[:n]
    rng.shuffle(selected)
    return selected


def compute_metrics(predictions: list[int], targets: list[int]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for pred, target in zip(predictions, targets):
        if target == 1 and pred == 1:
            tp += 1
        elif target == 0 and pred == 1:
            fp += 1
        elif target == 1 and pred == 0:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(targets) if targets else 0.0
    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "accuracy": round(accuracy * 100, 1),
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "f1": round(f1, 2),
        "total": len(targets),
    }


def write_outputs(payload: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    output_path.with_suffix(".md").write_text(to_markdown(payload), encoding="utf-8")


def to_markdown(payload: dict[str, Any]) -> str:
    m = payload["metrics"]
    lines = [
        "# CodeBERT + Softmax on PrimeVul",
        "",
        f"Dataset: `{payload['dataset']}`",
        f"Selection: `{payload['selection_mode']}`",
        f"Rows: {payload['row_count']} (TP labels={payload['label_counts'].get('1', 0)}, benign labels={payload['label_counts'].get('0', 0)})",
        "",
        "| Accuracy | Precision | Recall | F1 | FP | FN | Total |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        f"| {m['accuracy']}% | {m['precision']}% | {m['recall']}% | {m['f1']:.2f} | {m['FP']} | {m['FN']} | {m['total']} |",
        "",
        f"Threshold: vulnerable probability > {payload['threshold']}",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate local CodeBERT + Softmax model on PrimeVul.")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--model-path", default=str(DEFAULT_MODEL))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--selection", choices=["balanced", "all"], default="balanced")
    parser.add_argument("--max-rows", type=int, default=1200)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()

    rows = load_jsonl(Path(args.dataset))
    selected = select_rows(rows, args.selection, args.max_rows, args.seed)
    targets = [int(row.get("target", 0)) for row in selected]
    codes = [str(row.get("func") or "") for row in selected]

    scanner = ScanLayer2(Path("."), Path(args.model_path), repo_name="primevul")
    batch_results = scanner.predict_function_code_batch(codes, batch_size=args.batch_size)

    predictions = []
    details = []
    for row, target, result in zip(selected, targets, batch_results):
        vul_prob = None
        if result.get("ok"):
            vul_prob = result.get("prob_by_label_id", {}).get(1)
        pred = 1 if vul_prob is not None and float(vul_prob) > args.threshold else 0
        predictions.append(pred)
        details.append(
            {
                "idx": row.get("idx"),
                "project": row.get("project"),
                "file_name": row.get("file_name"),
                "cwe": row.get("cwe"),
                "cve": row.get("cve"),
                "target": target,
                "prediction": pred,
                "vulnerable_probability": vul_prob,
                "model_result": result,
            }
        )

    metrics = compute_metrics(predictions, targets)
    payload = {
        "timestamp": datetime.now().isoformat(),
        "dataset": str(Path(args.dataset)),
        "model_path": str(Path(args.model_path)),
        "selection_mode": args.selection,
        "seed": args.seed,
        "threshold": args.threshold,
        "row_count": len(selected),
        "label_counts": {str(k): v for k, v in Counter(targets).items()},
        "metrics": metrics,
        "details": details,
    }
    write_outputs(payload, Path(args.output))
    print(to_markdown(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
