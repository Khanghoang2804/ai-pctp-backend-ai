import re
import os
import sys
import json
import shutil
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from app.service.ConfigScanLayer1 import SKIP_DIRS, SKIP_PATH_PARTS, PATTERNS, SCAN_FILENAMES, SCAN_EXTENSIONS
from app.service.queryNodeAndRel import db_nodes
UPLOADS_DIR = Path(os.environ.get("REPO_UPLOADS_DIR", "/app/temp_uploads"))


class ScanLayer1:
    def __init__(self, repo_name: str, root: Path | None = None, codeql_root: Path | None = None):
        self.patterns = [{**rule, "_compiled": re.compile(rule["pattern"], re.MULTILINE)} for rule in PATTERNS]
        self.repo_name = repo_name
        # Ưu tiên: root được truyền vào → uploads_dir/repo_name → None (dùng DB content)
        if root:
            self.root = Path(root)
        elif (UPLOADS_DIR / repo_name).exists():
            self.root = UPLOADS_DIR / repo_name
        else:
            self.root = None
        # codeql_root: thư mục CodeQL scan riêng, mặc định dùng self.root
        self.codeql_root: Path | None = Path(codeql_root) if codeql_root else self.root

    def get_all_files_from_db(self) -> list[dict]:
        """Trả về toàn bộ File node của repo."""
        return db_nodes(repo_name=self.repo_name, label="File")

    def scan_content(self, path: Path, content: str) -> list[dict]:
        findings = []
        lines = content.splitlines()

        for rule in self.patterns:
            compiled = rule["_compiled"]

            for match in compiled.finditer(content):
                matched_text = match.group(0)

                if self._is_whitelisted(rule, matched_text):
                    continue

                line_no = content[:match.start()].count("\n") + 1
                col_no = match.start() - content.rfind("\n", 0, match.start())
                line_text = lines[line_no - 1].strip() if line_no <= len(lines) else ""

                findings.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "category": rule["category"],
                    "file": str(path),
                    "line": line_no,
                    "column": col_no,
                    "matched_text": matched_text,
                    "line_content": line_text,
                    "description": rule["description"],
                })

        return findings

    def run_scan(self, use_codeql: bool = True) -> list[dict]:
        # Kết quả từ regex scan, grouped theo file_path (relative)
        file_map: dict[str, dict] = {}

        db_files = self.get_all_files_from_db()
        for file_node in db_files:
            rel_path = file_node["file_path"]

            if not self.should_scan_file(Path(rel_path)):
                continue

            # Ưu tiên đọc content từ DB, fallback sang filesystem nếu có root
            content: str | None = file_node.get("content")
            if not content:
                if self.root is None:
                    continue
                abs_path = Path(rel_path) if Path(rel_path).is_absolute() else self.root / rel_path
                if self.should_skip_path(abs_path):
                    continue
                try:
                    content = abs_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

            findings = self.scan_content(rel_path, content)
            if not findings:
                continue

            rel = file_node["file_path"]
            if rel not in file_map:
                file_map[rel] = {"id": file_node["id"], "file_path": rel, "findings": {}}

            for f in findings:
                line = f["line"]
                if line not in file_map[rel]["findings"]:
                    file_map[rel]["findings"][line] = {
                        "line": line,
                        "column": f["column"],
                        "line_content": f["line_content"],
                        "rules": [],
                    }
                file_map[rel]["findings"][line]["rules"].append({
                    "rule_id": f["rule_id"],
                    "name": f["name"],
                    "category": f["category"],
                    "cwe": [],
                    "severity": "critical",
                    "matched_text": f["matched_text"],
                    "description": f["description"],
                    "source": "regex",
                })

        # Merge kết quả từ CodeQL nếu có
        if use_codeql and shutil.which("codeql") and self.codeql_root:
            try:
                from app.service.CodeqlScan import CodeQLScanLayer1
                scanner = CodeQLScanLayer1(self.repo_name, self.codeql_root)
                try:
                    codeql_results = scanner.run_scan()
                    for item in codeql_results:
                        rel = item["file_path"]
                        if rel not in file_map:
                            file_map[rel] = {"id": f"File:{rel}", "file_path": rel, "findings": {}}
                        for finding in item["findings"]:
                            line = finding["line"]
                            if line not in file_map[rel]["findings"]:
                                file_map[rel]["findings"][line] = {
                                    "line": line,
                                    "column": finding["column"],
                                    "line_content": finding["line_content"],
                                    "rules": [],
                                }
                            for rule in finding["rules"]:
                                rule["source"] = "codeql"
                                file_map[rel]["findings"][line]["rules"].append(rule)
                finally:
                    scanner.cleanup()
            except Exception as exc:
                import logging
                logging.getLogger(__name__).warning("CodeQL scan failed: %s", exc)

        return [
            {
                "file_path": v["file_path"],
                "findings": list(v["findings"].values()),
            }
            for v in file_map.values()
        ]

    
    def should_skip_path(self, path: Path) -> bool:
        parts = set(path.parts)
        if parts & SKIP_DIRS:
            return True
        if parts & SKIP_PATH_PARTS:
            return True
        name = path.name.lower()
        if name.startswith("test_"):
            return True
        if name.startswith("conftest"):
            return True
        return False


    def should_scan_file(self, path: Path) -> bool:
        if path.name in SCAN_FILENAMES:
            return True
        if path.suffix.lower() in SCAN_EXTENSIONS:
            return True
        return False


    def _collect_files(self, root: Path) -> list[Path]:
        files = []
        for f in root.rglob("*"):
            if not f.is_file():
                continue
            if self.should_skip_path(f):
                continue
            if self.should_scan_file(f):
                files.append(f)

        return sorted(files)

    def _is_whitelisted(self, rule: dict, text: str) -> bool:
        whitelist_pattern = rule.get("whitelist_pattern")

        if not whitelist_pattern:
            return False

        return re.search(whitelist_pattern, text, re.MULTILINE) is not None

    # def _mask_secrets(self, text: str) -> str:
    #     if not text:
    #         return text
    #     text = re.sub(
    #         r"(['\"]?)[A-Za-z0-9_\-+/=]{20,}(['\"]?)",
    #         r"\1***MASKED***\2",
    #         text,
    #     )
    #     text = re.sub(
    #         r"(Bearer\s+)[A-Za-z0-9._\-]{20,}",
    #         r"\1***MASKED***",
    #         text,
    #         flags=re.IGNORECASE,
    #     )
    #     text = re.sub(
    #         r"(://[^:\s'\"]+:)[^@\s'\"]+(@)",
    #         r"\1***MASKED***\2",
    #         text,
    #     )
    #     return text


def main():
    parser = argparse.ArgumentParser(
        description="Layer 1 Security Scanner — Regex scanner for repo files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "repo",
        nargs="?",
        default=".",
        help="Path to the repo root directory (default: current directory)",
    )

    parser.add_argument(
        "--output", "-o",
        default=str(Path.cwd() / "scan_layer1_results.json"),
        help="Write JSON result to file",
    )

    parser.add_argument(
        "--repo-name",
        default="aicaller",
        help="Repo name stored in graph DB",
    )

    args = parser.parse_args()

    root = Path(args.repo).resolve()

    if not root.exists():
        print(f"Error: path not found: {root}", file=sys.stderr)
        sys.exit(2)

    if not root.is_dir():
        print(f"Error: not a directory: {root}", file=sys.stderr)
        sys.exit(2)

    scanner = ScanLayer1(args.repo_name, root=root)

    output_path = Path(args.output)
    results = scanner.run_scan()

    output_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")

    total_findings = sum(len(r["findings"]) for r in results)

    print(
        f"Results written to: {output_path}\n"
        f"Files with issues: {len(results)} | Total findings: {total_findings}",
        file=sys.stderr
    )

    sys.exit(0 if len(results) == 0 else 1)

if __name__ == "__main__":
    # import json
    # print(json.dumps(ScanLayer1().run_scan(Path("/Users/tiendat/Desktop/aicaller")), indent=2))
    main()