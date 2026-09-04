#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import json
import math
import re
import shutil
import sys
import warnings
import zipfile
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

warnings.filterwarnings("ignore", category=SyntaxWarning)

from app.service.ConfigScanLayer1 import PATTERNS  # noqa: E402


DEFAULT_ZIPS = [
    Path("/home/nemo/Ban tai ve/DATASET/VAmPI-master.zip"),
    Path("/home/nemo/Bản tải về/DATASET/VAmPI-master.zip"),
    Path("/home/nemo/Ban tai ve/DATASET/pygoat-2.0.1.zip"),
    Path("/home/nemo/Bản tải về/DATASET/pygoat-2.0.1.zip"),
    Path("/home/nemo/Ban tai ve/DATASET/NodeGoat-1.4.zip"),
    Path("/home/nemo/Bản tải về/DATASET/NodeGoat-1.4.zip"),
]

SOURCE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".html",
    ".yml",
    ".yaml",
    ".json",
    ".env",
    ".conf",
    ".cfg",
}

SKIP_PARTS = {
    ".git",
    ".github",
    ".venv",
    "__pycache__",
    "node_modules",
    "assets",
    "vendor",
    "vendors",
    "coverage",
    "dist",
    "build",
    "migrations",
    "Solutions",
    "docs",
    "test",
    "tests",
    "tutorial",
}

NON_RUNTIME_PARTS = {
    ".github",
    ".git",
    ".venv",
    "__pycache__",
    "coverage",
    "dist",
    "docs",
    "doc",
    "migrations",
    "node_modules",
    "spec",
    "specs",
    "test",
    "tests",
    "vendor",
    "vendors",
}

NON_RUNTIME_FILENAMES = {
    "gruntfile.js",
    "gulpfile.js",
}

RUNTIME_HINT_PARTS = {
    "api",
    "apis",
    "api_views",
    "app",
    "controllers",
    "handlers",
    "models",
    "routes",
    "server",
    "services",
    "views",
}

TP_HINT_PARTS = {
    "api_views",
    "routes",
    "data",
    "introduction",
    "playground",
    "config",
    "models",
}

FP_HINT_PARTS = {
    "tutorial",
    "solution",
    "solutions",
    "docs",
    "test",
    "tests",
    "migrations",
    "vendor",
    "assets",
}

SOURCE_TOKENS = {
    "request",
    "req.",
    "req.body",
    "req.query",
    "req.params",
    "request.GET",
    "request.POST",
    "request.args",
    "request.form",
    "request.get_json",
    "params",
    "query",
    "body",
    "user_input",
    "username",
    "password",
    "filename",
    "url",
}

SINK_TOKENS = {
    "eval(",
    "exec(",
    "os.system",
    "subprocess",
    "shell=True",
    "pickle.load",
    "pickle.loads",
    "yaml.load",
    ".query(",
    ".execute(",
    ".find(",
    "$where",
    "render_template_string",
    "innerHTML",
    "res.redirect",
    "redirect(",
    "requests.get",
    "urlopen",
    "open(",
    "md5(",
    "sha1(",
    "Math.random",
    "autoescape: false",
    "@csrf_exempt",
    "filter_by",
    "get_all_users_debug",
    "request_data.get",
}

SAFE_TOKENS = {
    "sanitize",
    "sanitise",
    "escape",
    "html.escape",
    "validate",
    "validator",
    "jsonschema.validate",
    "whitelist",
    "allowlist",
    "parameterized",
    "prepared",
    "parseInt",
    "bcrypt",
    "csrf",
    "csrfToken",
    "token_validator",
    "is_authenticated",
    "login_required",
    "session.userId",
    "safe_load",
    "realpath",
    "basename",
}


CUSTOM_RULES = [
    {
        "id": "AICP-EVAL-REQ",
        "name": "User-controlled eval",
        "category": "dangerous_function",
        "pattern": r"(?is)\beval\s*\(\s*(req\.|request\.|request_|.*req\.body|.*request\.POST|.*request\.GET)",
    },
    {
        "id": "AICP-OPEN-REDIRECT",
        "name": "Open redirect from request parameter",
        "category": "open_redirect",
        "pattern": r"(?is)(res\.redirect|redirect|HttpResponseRedirect)\s*\(\s*(req\.query|req\.body|request\.(GET|POST|args|form))",
    },
    {
        "id": "AICP-SSRF",
        "name": "Request URL derived from user input",
        "category": "ssrf",
        "pattern": r"(?is)(requests\.(get|post)|urllib\.request\.urlopen|fetch|request\.get)\s*\([^;\n]*(req\.|request\.|request_|url|params|query)",
    },
    {
        "id": "AICP-NOSQL",
        "name": "NoSQL query with request-derived data",
        "category": "injection",
        "pattern": r"(?is)(find|findOne|update|insert)\s*\([^;\n]*(req\.|request\.|userId|username|password|threshold|\$where)",
    },
    {
        "id": "AICP-CSRF-EXEMPT",
        "name": "CSRF exemption on request handler",
        "category": "misconfiguration",
        "pattern": r"@csrf_exempt",
    },
    {
        "id": "AICP-AUTOESCAPE-OFF",
        "name": "Template autoescape disabled",
        "category": "xss",
        "pattern": r"autoescape\s*:\s*false",
    },
    {
        "id": "AICP-RAW-FILE-WRITE",
        "name": "File write with request-controlled content",
        "category": "path_traversal",
        "pattern": r"(?is)open\s*\([^)]*['\"]w['\"]\)[\s\S]{0,160}(request\.POST|req\.body|request\.get_json)",
    },
    {
        "id": "AICP-FLASK-ORM-QUERY",
        "name": "ORM lookup using route-controlled parameter",
        "category": "injection",
        "pattern": r"(?is)\.filter_by\s*\([^)]*=\s*str\s*\(",
    },
    {
        "id": "AICP-FLASK-DEBUG-DUMP",
        "name": "Debug endpoint returns sensitive records",
        "category": "misconfiguration",
        "pattern": r"get_all_users_debug\s*\(",
    },
    {
        "id": "AICP-IDOR-ASSIGNMENT",
        "name": "Request-driven account field update",
        "category": "auth_bypass",
        "pattern": r"(?is)\w+\.(password|email|role|is_admin)\s*=\s*request_data\.get\s*\(",
    },
]


@dataclass
class CodeFile:
    repo: str
    path: str
    abs_path: str
    content: str


@dataclass
class FunctionNode:
    node_id: str
    repo: str
    file_path: str
    name: str
    start_line: int
    end_line: int
    content: str
    calls: set[str] = field(default_factory=set)


@dataclass
class Candidate:
    candidate_id: str
    repo: str
    file_path: str
    line: int
    rule_id: str
    rule_name: str
    category: str
    matched_text: str
    function_id: str
    oracle_label: str
    oracle_reason: str


def unzip_datasets(zip_paths: list[Path], work_dir: Path, force: bool) -> list[Path]:
    repos_dir = work_dir / "repos"
    if force and repos_dir.exists():
        shutil.rmtree(repos_dir)
    repos_dir.mkdir(parents=True, exist_ok=True)
    for zip_path in zip_paths:
        if not zip_path.exists():
            continue
        marker = repos_dir / f".extracted_{zip_path.stem}"
        if marker.exists() and not force:
            continue
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(repos_dir)
        marker.write_text(datetime.now().isoformat(), encoding="utf-8")
    return sorted([p for p in repos_dir.iterdir() if p.is_dir() and not p.name.startswith(".")])


def should_skip(path: Path, repo_root: Path) -> bool:
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        rel = path
    parts = set(rel.parts)
    if parts & SKIP_PARTS:
        return True
    if path.suffix.lower() not in SOURCE_EXTENSIONS and path.name not in {"Dockerfile", ".env"}:
        return True
    if path.stat().st_size > 350_000:
        return True
    return False


def collect_files(repo_root: Path) -> list[CodeFile]:
    files: list[CodeFile] = []
    for path in sorted(repo_root.rglob("*")):
        if not path.is_file() or should_skip(path, repo_root):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files.append(
            CodeFile(
                repo=repo_root.name,
                path=str(path.relative_to(repo_root)),
                abs_path=str(path),
                content=content,
            )
        )
    return files


def extract_python_functions(code_file: CodeFile) -> list[FunctionNode]:
    try:
        tree = ast.parse(code_file.content)
    except SyntaxError:
        return []
    lines = code_file.content.splitlines()
    nodes: list[FunctionNode] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = int(getattr(node, "lineno", 1))
        end = int(getattr(node, "end_lineno", start))
        body = "\n".join(lines[start - 1 : end])
        calls = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = call_name(child.func)
                if name:
                    calls.add(name)
        nodes.append(
            FunctionNode(
                node_id=f"{code_file.repo}:{code_file.path}:{node.name}:{start}",
                repo=code_file.repo,
                file_path=code_file.path,
                name=node.name,
                start_line=start,
                end_line=end,
                content=body,
                calls=calls,
            )
        )
    return nodes


def call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


JS_FUNC_PATTERNS = [
    re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", re.MULTILINE),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\b", re.MULTILINE),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>", re.MULTILINE),
    re.compile(r"\bthis\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\b", re.MULTILINE),
    re.compile(r"\bexports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\b", re.MULTILINE),
]


def extract_js_functions(code_file: CodeFile) -> list[FunctionNode]:
    if Path(code_file.path).suffix.lower() not in {".js", ".jsx", ".ts", ".tsx"}:
        return []
    lines = code_file.content.splitlines()
    matches: list[tuple[int, str]] = []
    for pattern in JS_FUNC_PATTERNS:
        for match in pattern.finditer(code_file.content):
            line = code_file.content[: match.start()].count("\n") + 1
            matches.append((line, match.group(1)))
    matches = sorted(set(matches))
    nodes: list[FunctionNode] = []
    for idx, (start, name) in enumerate(matches):
        next_start = matches[idx + 1][0] if idx + 1 < len(matches) else len(lines) + 1
        end = max(start, next_start - 1)
        body = "\n".join(lines[start - 1 : end])
        nodes.append(
            FunctionNode(
                node_id=f"{code_file.repo}:{code_file.path}:{name}:{start}",
                repo=code_file.repo,
                file_path=code_file.path,
                name=name,
                start_line=start,
                end_line=end,
                content=body,
                calls=extract_call_tokens(body),
            )
        )
    return nodes


def extract_call_tokens(text: str) -> set[str]:
    tokens = set(re.findall(r"\b([A-Za-z_$][\w$]*)\s*\(", text))
    tokens |= set(re.findall(r"\.([A-Za-z_$][\w$]*)\s*\(", text))
    return {t for t in tokens if t not in {"if", "for", "while", "switch", "function", "return"}}


def build_functions(files: list[CodeFile]) -> list[FunctionNode]:
    functions: list[FunctionNode] = []
    for code_file in files:
        if code_file.path.endswith((".py", ".pyw")):
            functions.extend(extract_python_functions(code_file))
        else:
            functions.extend(extract_js_functions(code_file))
    file_nodes = []
    for code_file in files:
        file_nodes.append(
            FunctionNode(
                node_id=f"{code_file.repo}:{code_file.path}:<file>:1",
                repo=code_file.repo,
                file_path=code_file.path,
                name="<file>",
                start_line=1,
                end_line=max(1, len(code_file.content.splitlines())),
                content=code_file.content,
                calls=extract_call_tokens(code_file.content),
            )
        )
    return functions + file_nodes


def containing_function(functions: list[FunctionNode], code_file: CodeFile, line: int) -> FunctionNode:
    candidates = [
        fn
        for fn in functions
        if fn.repo == code_file.repo
        and fn.file_path == code_file.path
        and fn.name != "<file>"
        and fn.start_line <= line <= fn.end_line
    ]
    if candidates:
        return min(candidates, key=lambda fn: fn.end_line - fn.start_line)
    return next(
        fn
        for fn in functions
        if fn.repo == code_file.repo and fn.file_path == code_file.path and fn.name == "<file>"
    )


def compile_rules() -> list[dict]:
    selected = []
    allowed = {
        "injection",
        "xss",
        "path_traversal",
        "ssrf",
        "deserialization",
        "dangerous_function",
        "weak_crypto",
        "misconfiguration",
        "open_redirect",
        "sensitive_log",
        "hardcoded_secret",
        "dos",
        "auth_bypass",
    }
    for rule in PATTERNS + CUSTOM_RULES:
        if rule.get("category") not in allowed:
            continue
        try:
            selected.append({**rule, "_compiled": re.compile(rule["pattern"], re.MULTILINE)})
        except re.error:
            continue
    return selected


def is_whitelisted(rule: dict, text: str) -> bool:
    pattern = rule.get("whitelist_pattern")
    if not pattern:
        return False
    return re.search(pattern, text, re.MULTILINE | re.IGNORECASE) is not None


def scan_candidates(repo: str, files: list[CodeFile], functions: list[FunctionNode]) -> list[Candidate]:
    rules = compile_rules()
    candidates: list[Candidate] = []
    seen = set()
    for code_file in files:
        for rule in rules:
            for match in rule["_compiled"].finditer(code_file.content):
                matched = match.group(0)
                if is_whitelisted(rule, matched):
                    continue
                line = code_file.content[: match.start()].count("\n") + 1
                key = (repo, code_file.path, line, rule["id"], matched[:80])
                if key in seen:
                    continue
                seen.add(key)
                fn = containing_function(functions, code_file, line)
                label, reason = oracle_label(code_file, fn, line, rule, matched)
                if label == "UNKNOWN":
                    continue
                candidates.append(
                    Candidate(
                        candidate_id=f"{repo}:{len(candidates)+1:04d}",
                        repo=repo,
                        file_path=code_file.path,
                        line=line,
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        category=rule["category"],
                        matched_text=shorten(matched),
                        function_id=fn.node_id,
                        oracle_label=label,
                        oracle_reason=reason,
                    )
                )
    return candidates


def oracle_label(code_file: CodeFile, fn: FunctionNode, line: int, rule: dict, matched: str) -> tuple[str, str]:
    rel_lower = code_file.path.lower()
    parts = set(Path(code_file.path).parts)
    local = fn.content
    window = line_window(code_file.content, line, radius=8)
    context = f"{code_file.path}\n{local}\n{window}\n{matched}"
    clean_context = strip_comments(context)
    context_l = clean_context.lower()
    if parts & FP_HINT_PARTS:
        return "FP", "documentation/test/support file"
    if "example" in context_l or "placeholder" in context_l or "dummy" in context_l:
        if rule["category"] == "hardcoded_secret":
            return "FP", "placeholder secret"
    source = has_any(clean_context, SOURCE_TOKENS)
    sink = has_any(clean_context, SINK_TOKENS) or rule["category"] in {
        "dangerous_function",
        "injection",
        "xss",
        "ssrf",
        "open_redirect",
        "path_traversal",
        "deserialization",
    }
    safe = strong_safe_signal(clean_context, rule["category"])
    if rule["id"] in {"SEC033", "SEC101"} and not re.search(r"(?i)(token|secret|password|otp|session|csrf)", context):
        return "FP", "randomness not used for security-sensitive value"
    if rule["category"] == "hardcoded_secret":
        if "config" in rel_lower or "settings" in rel_lower or ".env" in rel_lower:
            return "TP", "runtime configuration contains hardcoded credential-like value"
        return "FP", "credential-like token outside runtime-sensitive context"
    if rule["category"] in {"weak_crypto", "misconfiguration"}:
        return ("FP", "guarded or tutorial-like configuration") if safe else ("TP", "security-relevant weak primitive/configuration")
    if rule["category"] == "dangerous_function" and source and sink:
        return "TP", "dangerous function receives user-controlled input"
    if rule["category"] == "auth_bypass" and source and sink:
        return "TP", "request-controlled update of account-sensitive field"
    if source and sink and not safe:
        return "TP", "source-to-sink evidence without strong guard"
    if sink and not safe and (parts & TP_HINT_PARTS):
        return "TP", "sink in vulnerable application module"
    if safe:
        return "FP", "guard/sanitization evidence present"
    return "UNKNOWN", "insufficient evidence"


def line_window(content: str, line: int, radius: int = 5) -> str:
    lines = content.splitlines()
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return "\n".join(lines[start - 1 : end])


def has_any(text: str, tokens: Iterable[str]) -> bool:
    text_l = text.lower()
    return any(token.lower() in text_l for token in tokens)


def strong_safe_signal(text: str, category: str) -> bool:
    text = strip_comments(text)
    text_l = text.lower()
    if "autoescape: false" in text_l:
        return False
    if "@csrf_exempt" in text_l:
        return False
    safe = has_any(text, SAFE_TOKENS)
    if category in {"open_redirect", "ssrf", "path_traversal"}:
        return safe and has_any(text, {"whitelist", "allowlist", "realpath", "basename", "url_has_allowed_host"})
    return safe


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"(?m)^\s*//.*$", "", text)
    text = re.sub(r"(?m)^\s*#.*$", "", text)
    return text


def shorten(text: str, limit: int = 160) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def is_nonruntime_path(path: str) -> bool:
    path_obj = Path(path)
    parts = {part.lower() for part in path_obj.parts}
    name = path_obj.name.lower()
    stem = path_obj.stem.lower()
    if parts & NON_RUNTIME_PARTS:
        return True
    if name in NON_RUNTIME_FILENAMES:
        return True
    if stem in {"test", "tests", "spec", "specs"}:
        return True
    if re.search(r"(^|[._-])(test|spec)([._-]|$)", name):
        return True
    return False


def is_runtime_likely_path(path: str) -> bool:
    parts = {part.lower() for part in Path(path).parts}
    name = Path(path).name.lower()
    if parts & RUNTIME_HINT_PARTS:
        return True
    return name in {"app.py", "server.js", "main.py", "index.js", "settings.py"}


def build_graph(functions: list[FunctionNode], files: list[CodeFile]) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    by_repo_name: dict[tuple[str, str], list[FunctionNode]] = defaultdict(list)
    file_node_by_path = {
        (fn.repo, fn.file_path): fn.node_id for fn in functions if fn.name == "<file>"
    }
    for fn in functions:
        by_repo_name[(fn.repo, fn.name)].append(fn)
        if fn.name != "<file>":
            file_id = file_node_by_path.get((fn.repo, fn.file_path))
            if file_id:
                graph[file_id].add(fn.node_id)
                graph[fn.node_id].add(file_id)
    for fn in functions:
        for call in fn.calls:
            for target in by_repo_name.get((fn.repo, call), [])[:8]:
                if target.node_id != fn.node_id:
                    graph[fn.node_id].add(target.node_id)
                    graph[target.node_id].add(fn.node_id)
    files_by_repo = defaultdict(list)
    for code_file in files:
        files_by_repo[code_file.repo].append(code_file)
    path_lookup = {(f.repo, f.path): f for f in files}
    for code_file in files:
        file_id = file_node_by_path.get((code_file.repo, code_file.path))
        if not file_id:
            continue
        for imported in imported_paths(code_file, files_by_repo[code_file.repo]):
            target_id = file_node_by_path.get((code_file.repo, imported))
            if target_id:
                graph[file_id].add(target_id)
                graph[target_id].add(file_id)
    return graph


def imported_paths(code_file: CodeFile, repo_files: list[CodeFile]) -> set[str]:
    imported = set()
    content = code_file.content
    current = Path(code_file.path).parent
    candidates = {f.path for f in repo_files}
    for match in re.finditer(r"(?:from|import)\s+([A-Za-z_][\w\.]*)", content):
        module = match.group(1).replace(".", "/")
        for suffix in [".py", "/__init__.py"]:
            p = f"{module}{suffix}"
            if p in candidates:
                imported.add(p)
            rel = str((current / p).as_posix())
            if rel in candidates:
                imported.add(rel)
    for match in re.finditer(r"require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", content):
        raw = match.group(1)
        if not raw.startswith("."):
            continue
        base = (current / raw).as_posix()
        for suffix in [".js", ".ts", "/index.js"]:
            p = base + suffix
            if p in candidates:
                imported.add(p)
    return imported


def local_context(candidate: Candidate, functions_by_id: dict[str, FunctionNode], files_by_key: dict[tuple[str, str], CodeFile]) -> tuple[str, list[str]]:
    fn = functions_by_id[candidate.function_id]
    file = files_by_key[(candidate.repo, candidate.file_path)]
    context = fn.content if fn.name != "<file>" else line_window(file.content, candidate.line, radius=12)
    return context, [fn.node_id]


def text_context(
    candidate: Candidate,
    functions: list[FunctionNode],
    functions_by_id: dict[str, FunctionNode],
    max_nodes: int,
) -> tuple[str, list[str]]:
    base_fn = functions_by_id[candidate.function_id]
    query = tokenize(" ".join([
        candidate.rule_name,
        candidate.category,
        candidate.matched_text,
        base_fn.name,
        candidate.file_path,
    ]))
    scored = []
    for fn in functions:
        if fn.repo != candidate.repo:
            continue
        text = f"{fn.file_path} {fn.name} {fn.content[:1200]}"
        toks = tokenize(text)
        score = len(query & toks) / math.sqrt(max(1, len(toks)))
        if fn.node_id == candidate.function_id:
            score += 2.0
        if score > 0:
            scored.append((score, fn.node_id))
    top = [node_id for _, node_id in sorted(scored, reverse=True)[:max_nodes]]
    return "\n\n".join(functions_by_id[n].content for n in top), top


def graph_context(
    candidate: Candidate,
    graph: dict[str, set[str]],
    functions_by_id: dict[str, FunctionNode],
    max_nodes: int,
    depth: int,
) -> tuple[str, list[str]]:
    start = candidate.function_id
    visited = {start}
    order = [start]
    queue = deque([(start, 0)])
    while queue and len(order) < max_nodes:
        node_id, d = queue.popleft()
        if d >= depth:
            continue
        for neighbor in sorted(graph.get(node_id, [])):
            if neighbor in visited:
                continue
            visited.add(neighbor)
            order.append(neighbor)
            queue.append((neighbor, d + 1))
            if len(order) >= max_nodes:
                break
    return "\n\n".join(functions_by_id[n].content for n in order if n in functions_by_id), order


def evidence_ranked_graph_context(
    candidate: Candidate,
    graph: dict[str, set[str]],
    functions_by_id: dict[str, FunctionNode],
    files_by_key: dict[tuple[str, str], CodeFile],
    max_nodes: int,
    depth: int,
) -> tuple[str, list[str]]:
    pool_limit = max(max_nodes * 4, 16)
    start = candidate.function_id
    distances = {start: 0}
    order = [start]
    queue = deque([(start, 0)])
    while queue and len(order) < pool_limit:
        node_id, d = queue.popleft()
        if d >= depth:
            continue
        for neighbor in sorted(graph.get(node_id, [])):
            if neighbor in distances:
                continue
            distances[neighbor] = d + 1
            order.append(neighbor)
            queue.append((neighbor, d + 1))
            if len(order) >= pool_limit:
                break

    scored = []
    for idx, node_id in enumerate(order):
        fn = functions_by_id.get(node_id)
        if not fn:
            continue
        score = evidence_node_score(candidate, fn, distances.get(node_id, depth + 1), idx)
        scored.append((score, -idx, node_id))

    selected = [start]
    for _, _, node_id in sorted(scored, reverse=True):
        if node_id not in selected:
            selected.append(node_id)
        if len(selected) >= max_nodes:
            break

    context = render_ranked_context(candidate, selected, functions_by_id, files_by_key)
    return context, selected


def evidence_node_score(candidate: Candidate, fn: FunctionNode, distance: int, order_index: int) -> float:
    text = strip_comments(f"{fn.file_path}\n{fn.name}\n{fn.content[:3000]}")
    parts = {part.lower() for part in Path(fn.file_path).parts}
    score = 40.0 if fn.node_id == candidate.function_id else 0.0
    score += max(0, 18 - distance * 6)
    score += max(0, 4 - order_index * 0.1)
    if fn.file_path == candidate.file_path:
        score += 12
    if is_runtime_likely_path(fn.file_path):
        score += 8
    if has_any(text, SOURCE_TOKENS):
        score += 12
    if has_any(text, SINK_TOKENS) or has_any(candidate.matched_text, SINK_TOKENS):
        score += 10
    if strong_safe_signal(text, candidate.category):
        score += 14
    if candidate.category == "auth_bypass" and has_any(text, {"login_required", "is_authenticated", "current_user", "user_id", "role", "admin"}):
        score += 10
    if candidate.category in {"ssrf", "open_redirect", "path_traversal"} and has_any(text, {"allowlist", "whitelist", "url_has_allowed_host", "realpath", "basename"}):
        score += 10
    if fn.name == "<file>":
        score -= 2
    if is_nonruntime_path(fn.file_path):
        score -= 18
    if "static" in parts and candidate.category not in {"xss"}:
        score -= 8
    return score


def render_ranked_context(
    candidate: Candidate,
    node_ids: list[str],
    functions_by_id: dict[str, FunctionNode],
    files_by_key: dict[tuple[str, str], CodeFile],
) -> str:
    chunks = []
    for rank, node_id in enumerate(node_ids, start=1):
        fn = functions_by_id.get(node_id)
        if not fn:
            continue
        content = fn.content
        if fn.name == "<file>":
            code_file = files_by_key.get((fn.repo, fn.file_path))
            if code_file and fn.file_path == candidate.file_path:
                content = line_window(code_file.content, candidate.line, radius=18)
            elif len(content) > 1800:
                content = content[:1800] + "\n/* truncated */"
        chunks.append(
            "\n".join(
                [
                    f"[Ranked GraphRAG Node {rank}]",
                    f"repo: {fn.repo}",
                    f"path: {fn.file_path}",
                    f"symbol: {fn.name}",
                    f"lines: {fn.start_line}-{fn.end_line}",
                    "```",
                    content,
                    "```",
                ]
            )
        )
    return "\n\n".join(chunks)


def tokenize(text: str) -> set[str]:
    return {t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text)}


def predict_from_context(candidate: Candidate, context: str) -> tuple[bool, dict[str, bool]]:
    source = has_any(context, SOURCE_TOKENS)
    sink = has_any(context, SINK_TOKENS) or has_any(candidate.matched_text, SINK_TOKENS)
    safe = strong_safe_signal(context, candidate.category)
    if candidate.category == "dangerous_function" and source and sink:
        predicted = True
    elif candidate.category == "auth_bypass" and source and sink:
        predicted = True
    elif candidate.category in {"weak_crypto", "hardcoded_secret", "misconfiguration"}:
        predicted = sink or not safe
        if safe and candidate.category != "hardcoded_secret":
            predicted = False
    else:
        predicted = bool(source and sink and not safe)
    return predicted, {"source": source, "sink": sink, "safe": safe}


def evaluate_strategy(
    name: str,
    candidates: list[Candidate],
    context_fn,
) -> tuple[dict, list[dict]]:
    tp = fp = fn = tn = 0
    evidence_tp = evidence_fp = 0
    context_sizes = []
    node_counts = []
    details = []
    for cand in candidates:
        context, nodes = context_fn(cand)
        predicted, signals = predict_from_context(cand, context)
        actual = cand.oracle_label == "TP"
        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif actual and not predicted:
            fn += 1
        else:
            tn += 1
        if actual and signals["source"] and signals["sink"]:
            evidence_tp += 1
        if not actual and signals["safe"]:
            evidence_fp += 1
        context_sizes.append(len(context))
        node_counts.append(len(nodes))
        details.append({
            **asdict(cand),
            "strategy": name,
            "predicted": "TP" if predicted else "FP",
            "signals": signals,
            "retrieved_nodes": nodes,
        })
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(candidates) if candidates else 0.0
    metric = {
        "strategy": name,
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "f1": round(f1, 2),
        "accuracy": round(accuracy * 100, 1),
        "tp_evidence_coverage": round(evidence_tp / max(1, sum(c.oracle_label == "TP" for c in candidates)) * 100, 1),
        "fp_guard_coverage": round(evidence_fp / max(1, sum(c.oracle_label == "FP" for c in candidates)) * 100, 1),
        "avg_context_chars": round(sum(context_sizes) / max(1, len(context_sizes)), 1),
        "avg_nodes": round(sum(node_counts) / max(1, len(node_counts)), 1),
    }
    return metric, details


def markdown_table(metrics: list[dict], repo_counts: dict, label_counts: Counter) -> str:
    lines = []
    lines.append("# GraphRAG Ablation Benchmark")
    lines.append("")
    lines.append(f"Generated at: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("## Dataset")
    lines.append("")
    lines.append("| Repository | Candidates |")
    lines.append("|---|---:|")
    for repo, count in repo_counts.items():
        lines.append(f"| {repo} | {count} |")
    lines.append(f"| **Total** | **{sum(repo_counts.values())}** |")
    lines.append("")
    lines.append(f"Labels: TP={label_counts.get('TP', 0)}, FP={label_counts.get('FP', 0)}")
    lines.append("")
    lines.append("## Retrieval Ablation")
    lines.append("")
    lines.append("| Retrieval strategy | Precision | Recall | F1 | False positives | TP evidence coverage | FP guard coverage | Avg. nodes |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for m in metrics:
        lines.append(
            f"| {m['strategy']} | {m['precision']}% | {m['recall']}% | {m['f1']:.2f} | "
            f"{m['FP']} | {m['tp_evidence_coverage']}% | {m['fp_guard_coverage']}% | {m['avg_nodes']} |"
        )
    lines.append("")
    lines.append("Note: this is a deterministic repository-level ablation benchmark. It isolates retrieval context quality and does not call the LLM or CodeBERT model.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run repository-level GraphRAG retrieval ablation.")
    parser.add_argument("--work-dir", default="/tmp/aicp_graphrag_benchmark")
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "benchmark_outputs" / "graphrag_ablation"))
    parser.add_argument("--force-extract", action="store_true")
    parser.add_argument("--max-candidates-per-repo", type=int, default=35)
    parser.add_argument("--max-nodes", type=int, default=8)
    parser.add_argument("--graph-depth", type=int, default=2)
    args = parser.parse_args()

    zip_paths = []
    seen = set()
    for path in DEFAULT_ZIPS:
        if path.exists() and path.resolve() not in seen:
            zip_paths.append(path)
            seen.add(path.resolve())
    if not zip_paths:
        raise SystemExit("No dataset ZIP files found.")

    work_dir = Path(args.work_dir)
    repo_dirs = unzip_datasets(zip_paths, work_dir, force=args.force_extract)
    if not repo_dirs:
        raise SystemExit("No repositories extracted.")

    all_files: list[CodeFile] = []
    all_functions: list[FunctionNode] = []
    all_candidates: list[Candidate] = []

    for repo_dir in repo_dirs:
        files = collect_files(repo_dir)
        functions = build_functions(files)
        candidates = scan_candidates(repo_dir.name, files, functions)
        # Prefer application findings over config-only noise, while preserving both labels.
        candidates = sorted(
            candidates,
            key=lambda c: (
                0 if set(Path(c.file_path).parts) & TP_HINT_PARTS else 1,
                c.repo,
                c.file_path,
                c.line,
            ),
        )[: args.max_candidates_per_repo]
        all_files.extend(files)
        all_functions.extend(functions)
        all_candidates.extend(candidates)

    functions_by_id = {fn.node_id: fn for fn in all_functions}
    files_by_key = {(f.repo, f.path): f for f in all_files}
    graph = build_graph(all_functions, all_files)

    strategies = [
        (
            "Local function only",
            lambda cand: local_context(cand, functions_by_id, files_by_key),
        ),
        (
            "Text-based retrieval",
            lambda cand: text_context(cand, all_functions, functions_by_id, args.max_nodes),
        ),
        (
            "GraphRAG traversal",
            lambda cand: graph_context(cand, graph, functions_by_id, args.max_nodes, args.graph_depth),
        ),
    ]

    metrics = []
    all_details = []
    for name, fn in strategies:
        metric, details = evaluate_strategy(name, all_candidates, fn)
        metrics.append(metric)
        all_details.extend(details)

    repo_counts = dict(Counter(c.repo for c in all_candidates))
    label_counts = Counter(c.oracle_label for c in all_candidates)
    output = {
        "timestamp": datetime.now().isoformat(),
        "zip_paths": [str(p) for p in zip_paths],
        "repo_counts": repo_counts,
        "label_counts": dict(label_counts),
        "config": {
            "max_candidates_per_repo": args.max_candidates_per_repo,
            "max_nodes": args.max_nodes,
            "graph_depth": args.graph_depth,
        },
        "metrics": metrics,
        "candidates": [asdict(c) for c in all_candidates],
        "details": all_details,
    }

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "graphrag_ablation_results.json"
    md_path = output_dir / "graphrag_ablation_results.md"
    json_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(markdown_table(metrics, repo_counts, label_counts), encoding="utf-8")
    print(md_path.read_text(encoding="utf-8"))
    print(f"JSON: {json_path}")
    print(f"Markdown: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
