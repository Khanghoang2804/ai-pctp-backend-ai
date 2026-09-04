#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from graphrag_ablation_benchmark import (  # noqa: E402
    Candidate,
    TP_HINT_PARTS,
    build_functions,
    collect_files,
    scan_candidates,
)


DEFAULT_REPO_NAMES = ["NodeGoat-1.4", "VAmPI-master", "pygoat-2.0.1"]
DEFAULT_REPO_DIR = REPO_ROOT / "benchmark_inputs" / "repos"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "benchmark_outputs" / "repository_baselines"


@dataclass
class ToolFinding:
    tool: str
    repo: str
    file_path: str
    line: int
    rule_id: str = ""
    category: str = ""
    severity: str = ""
    message: str = ""
    raw: dict[str, Any] | None = None


def choose_repos(repo_dir: Path) -> list[Path]:
    repos = [repo_dir / name for name in DEFAULT_REPO_NAMES if (repo_dir / name).is_dir()]
    if repos:
        return repos
    return sorted([p for p in repo_dir.iterdir() if p.is_dir()])


def build_oracle(repo_dir: Path, max_candidates_per_repo: int) -> list[Candidate]:
    candidates: list[Candidate] = []
    for repo in choose_repos(repo_dir):
        files = collect_files(repo)
        functions = build_functions(files)
        repo_candidates = scan_candidates(repo.name, files, functions)
        repo_candidates = sorted(
            repo_candidates,
            key=lambda c: (
                0 if set(Path(c.file_path).parts) & TP_HINT_PARTS else 1,
                c.repo,
                c.file_path,
                c.line,
            ),
        )
        if max_candidates_per_repo > 0:
            repo_candidates = repo_candidates[:max_candidates_per_repo]
        candidates.extend(repo_candidates)
    return candidates


def normalize_path(path: str) -> str:
    path = path.replace("\\", "/")
    path = re.sub(r"^\./", "", path)
    return path


def infer_repo_and_path(path: str, repo_names: list[str]) -> tuple[str, str] | None:
    norm = normalize_path(path)
    parts = norm.split("/")
    for idx, part in enumerate(parts):
        if part in repo_names:
            return part, "/".join(parts[idx + 1 :])
    if len(repo_names) == 1:
        return repo_names[0], norm
    return None


def parse_semgrep_json(path: Path, repo_names: list[str]) -> list[ToolFinding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: list[ToolFinding] = []
    for item in data.get("results", []):
        location = item.get("start") or {}
        parsed = infer_repo_and_path(str(item.get("path") or ""), repo_names)
        if not parsed:
            continue
        repo, file_path = parsed
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        findings.append(
            ToolFinding(
                tool="Semgrep",
                repo=repo,
                file_path=file_path,
                line=int(location.get("line") or 1),
                rule_id=str(item.get("check_id") or ""),
                category=str(metadata.get("category") or metadata.get("technology") or ""),
                severity=str(extra.get("severity") or ""),
                message=str(extra.get("message") or ""),
                raw=item,
            )
        )
    return findings


def parse_codeql_sarif(path: Path, repo_names: list[str]) -> list[ToolFinding]:
    sarif = json.loads(path.read_text(encoding="utf-8"))
    findings: list[ToolFinding] = []
    for run in sarif.get("runs", []):
        rules = {
            rule.get("id"): rule
            for rule in (run.get("tool", {}).get("driver", {}).get("rules", []) or [])
            if rule.get("id")
        }
        for result in run.get("results", []) or []:
            locs = result.get("locations") or []
            if not locs:
                continue
            physical = (locs[0].get("physicalLocation") or {})
            artifact = physical.get("artifactLocation") or {}
            region = physical.get("region") or {}
            parsed = infer_repo_and_path(str(artifact.get("uri") or ""), repo_names)
            if not parsed:
                continue
            repo, file_path = parsed
            rule_id = str(result.get("ruleId") or "")
            rule = rules.get(rule_id) or {}
            props = rule.get("properties") or {}
            findings.append(
                ToolFinding(
                    tool="CodeQL",
                    repo=repo,
                    file_path=file_path,
                    line=int(region.get("startLine") or 1),
                    rule_id=rule_id,
                    category=",".join(props.get("tags") or []),
                    severity=str(props.get("problem.severity") or props.get("security-severity") or ""),
                    message=str((result.get("message") or {}).get("text") or ""),
                    raw=result,
                )
            )
    return findings


def parse_generic_findings(path: Path, tool: str, repo_names: list[str]) -> list[ToolFinding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("findings", data if isinstance(data, list) else [])
    findings: list[ToolFinding] = []
    for item in rows:
        raw_path = str(item.get("file_path") or item.get("path") or item.get("file") or "")
        parsed = infer_repo_and_path(raw_path, repo_names)
        if not parsed and item.get("repo"):
            parsed = (str(item["repo"]), normalize_path(raw_path))
        if not parsed:
            continue
        repo, file_path = parsed
        findings.append(
            ToolFinding(
                tool=tool,
                repo=repo,
                file_path=file_path,
                line=int(item.get("line") or item.get("start_line") or 1),
                rule_id=str(item.get("rule_id") or item.get("rule") or ""),
                category=str(item.get("category") or ""),
                severity=str(item.get("severity") or ""),
                message=str(item.get("message") or item.get("description") or ""),
                raw=item,
            )
        )
    return findings


def load_findings(path: Path, tool: str, repo_names: list[str]) -> list[ToolFinding]:
    if tool.lower() == "semgrep":
        return parse_semgrep_json(path, repo_names)
    if tool.lower() == "codeql":
        return parse_codeql_sarif(path, repo_names)
    return parse_generic_findings(path, tool, repo_names)


def match_candidate(candidate: Candidate, findings: list[ToolFinding], line_window: int) -> list[ToolFinding]:
    matches = []
    for finding in findings:
        if finding.repo != candidate.repo:
            continue
        if normalize_path(finding.file_path) != normalize_path(candidate.file_path):
            continue
        if abs(int(finding.line) - int(candidate.line)) <= line_window:
            matches.append(finding)
    return matches


def compute_metrics(candidates: list[Candidate], findings: list[ToolFinding], line_window: int) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    details = []
    for candidate in candidates:
        matched = match_candidate(candidate, findings, line_window)
        predicted = bool(matched)
        actual = candidate.oracle_label == "TP"
        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif actual and not predicted:
            fn += 1
        else:
            tn += 1
        details.append(
            {
                **asdict(candidate),
                "predicted_label": "TP" if predicted else "FP",
                "correct": predicted == actual,
                "matched_findings": [asdict(item) for item in matched[:5]],
                "matched_count": len(matched),
            }
        )
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(candidates) if candidates else 0.0
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
        "total": len(candidates),
        "details": details,
    }


def write_oracle(candidates: list[Candidate], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "repository_oracle.json"
    repo_counts = Counter(c.repo for c in candidates)
    label_counts = Counter(c.oracle_label for c in candidates)
    payload = {
        "timestamp": datetime.now().isoformat(),
        "repo_counts": dict(repo_counts),
        "label_counts": dict(label_counts),
        "candidates": [asdict(c) for c in candidates],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    (output_dir / "repository_oracle.md").write_text(oracle_markdown(payload), encoding="utf-8")
    return path


def oracle_markdown(payload: dict[str, Any]) -> str:
    lines = ["# Repository Benchmark Oracle", "", "| Repository | Candidates |", "|---|---:|"]
    for repo, count in payload["repo_counts"].items():
        lines.append(f"| {repo} | {count} |")
    lines.append(f"| **Total** | **{sum(payload['repo_counts'].values())}** |")
    labels = payload["label_counts"]
    lines.append("")
    lines.append(f"Labels: TP={labels.get('TP', 0)}, FP={labels.get('FP', 0)}")
    return "\n".join(lines) + "\n"


def write_metrics(tool: str, metrics: dict[str, Any], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now().isoformat(),
        "tool": tool,
        "metrics": {k: v for k, v in metrics.items() if k != "details"},
        "details": metrics["details"],
    }
    safe_tool = re.sub(r"[^A-Za-z0-9_.-]+", "_", tool.lower())
    json_path = output_dir / f"{safe_tool}_metrics.json"
    md_path = output_dir / f"{safe_tool}_metrics.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(metrics_markdown(payload), encoding="utf-8")
    return json_path


def metrics_markdown(payload: dict[str, Any]) -> str:
    m = payload["metrics"]
    lines = [
        f"# {payload['tool']} Repository Benchmark Metrics",
        "",
        "| Accuracy | Precision | Recall | F1 | False Positives | Total |",
        "|---:|---:|---:|---:|---:|---:|",
        f"| {m['accuracy']}% | {m['precision']}% | {m['recall']}% | {m['f1']:.2f} | {m['false_positive_count']} | {m['total']} |",
        "",
        "Evaluation note: findings outside the controlled oracle are retained in raw tool output but are not counted as TP/FP because their ground truth is unknown.",
    ]
    return "\n".join(lines) + "\n"


def summarize(output_dir: Path, metric_paths: list[Path]) -> None:
    rows = []
    available_paths = sorted(output_dir.glob("*_metrics.json")) or metric_paths
    for path in available_paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        m = data["metrics"]
        rows.append(
            [
                data["tool"],
                f"{m['accuracy']}%",
                f"{m['precision']}%",
                f"{m['recall']}%",
                f"{m['f1']:.2f}",
                str(m["false_positive_count"]),
            ]
        )
    lines = [
        "# Repository Baseline Summary",
        "",
        "| Approach | Accuracy | Precision | Recall | F1 | False Positives |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Repository-level baseline benchmark for controlled AICP candidates.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_oracle = sub.add_parser("oracle")
    p_oracle.add_argument("--repo-dir", default=str(DEFAULT_REPO_DIR))
    p_oracle.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    p_oracle.add_argument("--max-candidates-per-repo", type=int, default=35)

    p_eval = sub.add_parser("evaluate")
    p_eval.add_argument("--repo-dir", default=str(DEFAULT_REPO_DIR))
    p_eval.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    p_eval.add_argument("--max-candidates-per-repo", type=int, default=35)
    p_eval.add_argument("--tool", required=True)
    p_eval.add_argument("--findings", required=True)
    p_eval.add_argument("--line-window", type=int, default=5)

    args = parser.parse_args()
    repo_dir = Path(getattr(args, "repo_dir", DEFAULT_REPO_DIR))
    output_dir = Path(getattr(args, "output_dir", DEFAULT_OUTPUT_DIR))
    candidates = build_oracle(repo_dir, getattr(args, "max_candidates_per_repo", 35))

    if args.cmd == "oracle":
        path = write_oracle(candidates, output_dir)
        print(path)
        print(oracle_markdown(json.loads(path.read_text(encoding="utf-8"))))
        return 0

    repo_names = [repo.name for repo in choose_repos(repo_dir)]
    findings = load_findings(Path(args.findings), args.tool, repo_names)
    metrics = compute_metrics(candidates, findings, args.line_window)
    metric_path = write_metrics(args.tool, metrics, output_dir)
    summarize(output_dir, [metric_path])
    print(metric_path)
    print(metrics_markdown(json.loads(metric_path.read_text(encoding="utf-8"))))
    print(f"Loaded findings: {len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
