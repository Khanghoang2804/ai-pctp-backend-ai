import json
import shutil
import subprocess
import tempfile
import hashlib
import os
from pathlib import Path
from typing import Optional


class CodeQLScanLayer1:
    def __init__(
        self,
        repo_name: str,
        root: Path | str,
        language: str = "python",
        query_suite: str = "codeql/python-queries:codeql-suites/python-security-and-quality.qls",
        work_dir: Optional[Path | str] = None,
        codeql_bin: str = "codeql",
        keep_temp: bool = False,
    ):
        self.repo_name = repo_name
        self.root = Path(root).resolve()
        self.language = language
        self.query_suite = query_suite
        self.codeql_bin = codeql_bin
        
        # Use persistent cache directory if work_dir not provided
        self.is_persistent_cache = False
        if work_dir:
            self.work_dir = Path(work_dir).resolve()
            self.keep_temp = keep_temp
        else:
            self.work_dir = Path("/app/temp_uploads") / f"{repo_name}_codeql_cache"
            self.keep_temp = True
            self.is_persistent_cache = True

        self.db_dir = self.work_dir / "codeql-db"
        self.sarif_path = self.work_dir / "result.sarif"
        self.hash_file = self.work_dir / "repo_hash.txt"

    def _hash_source_code(self) -> str:
        """Calculate a simple hash based on file modification times in the repo root to detect changes."""
        mtimes = []
        for file_path in self.root.rglob("*"):
            if file_path.is_file() and not file_path.is_symlink() and ".git" not in file_path.parts:
                mtimes.append(str(file_path.stat().st_mtime))
        return hashlib.md5("".join(mtimes).encode('utf-8')).hexdigest()

    def run_scan(self) -> list[dict]:
        self._validate()
        self._create_database()
        self._analyze_database()
        sarif = self._load_sarif()
        return self._sarif_to_layer1_format(sarif)

    def _validate(self) -> None:
        if not self.root.exists():
            raise FileNotFoundError(f"Repo path not found: {self.root}")

        if not self.root.is_dir():
            raise NotADirectoryError(f"Repo path is not a directory: {self.root}")

        if shutil.which(self.codeql_bin) is None:
            raise RuntimeError(
                f"CodeQL CLI not found: {self.codeql_bin}. "
                f"Please install CodeQL CLI and add it to PATH."
            )

        self.work_dir.mkdir(parents=True, exist_ok=True)

    def _create_database(self) -> None:
        current_hash = self._hash_source_code()
        
        # Check cache hit
        if self.is_persistent_cache and self.db_dir.exists() and self.hash_file.exists():
            saved_hash = self.hash_file.read_text().strip()
            if saved_hash == current_hash:
                return  # Skip creating DB, it's already built and code hasn't changed

        # If cache miss or force create
        if self.db_dir.exists():
            shutil.rmtree(self.db_dir, ignore_errors=True)

        cmd = [
            self.codeql_bin,
            "database",
            "create",
            str(self.db_dir),
            f"--language={self.language}",
            f"--source-root={self.root}",
            "--overwrite",
        ]

        self._run_cmd(cmd, step="create CodeQL database")
        
        # Save new hash
        if self.is_persistent_cache:
            self.hash_file.write_text(current_hash)

    def _analyze_database(self) -> None:
        cmd = [
            self.codeql_bin,
            "database",
            "analyze",
            str(self.db_dir),
            self.query_suite,
            "--format=sarif-latest",
            f"--output={self.sarif_path}",
        ]

        self._run_cmd(cmd, step="analyze CodeQL database")

    def _run_cmd(self, cmd: list[str], step: str) -> None:
        try:
            completed = subprocess.run(
                cmd,
                cwd=str(self.root),
                text=True,
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"CodeQL failed during step: {step}\n"
                f"Command: {' '.join(cmd)}\n"
                f"STDOUT:\n{e.stdout}\n"
                f"STDERR:\n{e.stderr}"
            ) from e

    def _load_sarif(self) -> dict:
        if not self.sarif_path.exists():
            raise FileNotFoundError(f"SARIF output not found: {self.sarif_path}")

        with self.sarif_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _sarif_to_layer1_format(self, sarif: dict) -> list[dict]:
        runs = sarif.get("runs", [])
        if not runs:
            return []

        run = runs[0]
        rules_map = self._build_rules_map(run)
        results = run.get("results", [])

        grouped_files: dict[str, dict] = {}

        for result in results:
            rule_id = result.get("ruleId", "unknown-rule")
            rule = rules_map.get(rule_id, {})

            message = result.get("message", {}).get("text", "")
            locations = result.get("locations", [])

            if not locations:
                continue

            physical = locations[0].get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})

            file_path = artifact.get("uri")
            if not file_path:
                continue

            line = region.get("startLine", 1)
            column = region.get("startColumn", 1)

            abs_file = self.root / file_path
            line_content = self._read_line(abs_file, line)

            cwe_list = self._extract_cwe(rule)

            finding_rule = {
                "rule_id": rule_id,
                "name": rule.get("name") or rule.get("shortDescription", {}).get("text", rule_id),
                "category": self._extract_category(rule),
                "cwe": cwe_list,
                "severity": self._extract_severity(rule),
                "matched_text": "",
                "description": message or rule.get("fullDescription", {}).get("text", ""),
            }

            if file_path not in grouped_files:
                grouped_files[file_path] = {
                    "file_path": file_path,
                    "findings": [],
                }

            existing_line = None
            for item in grouped_files[file_path]["findings"]:
                if item["line"] == line:
                    existing_line = item
                    break

            if existing_line is None:
                grouped_files[file_path]["findings"].append({
                    "line": line,
                    "column": column,
                    "line_content": line_content,
                    "rules": [finding_rule],
                })
            else:
                existing_line["rules"].append(finding_rule)

        return list(grouped_files.values())

    def _build_rules_map(self, run: dict) -> dict:
        rules_map = {}

        driver = run.get("tool", {}).get("driver", {})
        rules = driver.get("rules", [])

        for rule in rules:
            rule_id = rule.get("id")
            if rule_id:
                rules_map[rule_id] = rule

        return rules_map

    def _extract_cwe(self, rule: dict) -> list[str]:
        properties = rule.get("properties", {})
        tags = properties.get("tags", [])

        cwes = []
        for tag in tags:
            tag_lower = tag.lower()
            if "cwe" in tag_lower:
                # example: external/cwe/cwe-089 -> CWE-089
                cwe_id = tag.split("/")[-1].upper()
                cwes.append(cwe_id)

        return sorted(set(cwes))

    def _extract_category(self, rule: dict) -> str:
        properties = rule.get("properties", {})
        tags = properties.get("tags", [])

        if "security" in tags:
            return "security"

        if "correctness" in tags:
            return "correctness"

        if tags:
            return tags[0]

        return "codeql"

    def _extract_severity(self, rule: dict) -> str:
        properties = rule.get("properties", {})

        return (
            properties.get("problem.severity")
            or properties.get("security-severity")
            or properties.get("precision")
            or "warning"
        )

    def _read_line(self, path: Path, line_no: int) -> str:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            if 1 <= line_no <= len(lines):
                return lines[line_no - 1].strip()
        except OSError:
            pass

        return ""

    def cleanup(self) -> None:
        if not self.keep_temp and self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)
if __name__ == "__main__":
    scanner = CodeQLScanLayer1("aicaller", root="/Users/tiendat/Desktop/aicaller")
    infected_files = scanner.run_scan()
    print(json.dumps(infected_files, indent=2, ensure_ascii=False))