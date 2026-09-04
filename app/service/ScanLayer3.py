# file: server_python/app/service/ScanLayer3.py
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv

# Import các Prompts Hệ thống Đa đại lý mới (Đã thiết kế ở bước trước)
from app.prompts.scan_layer3_prompt import (
    build_scan_layer3_messages,
    build_scan_layer3_repository_messages,
    AGENT_2_SYSTEM,
    build_agent2_user_prompt,
    AGENT_3_SYSTEM,
    LAYER3_TASK_EXPECTED_OUTPUT,
    build_agent3_user_prompt,
)
from app.service.queryNodeAndRel import db_node_graph, db_resolve_file_node_id, db_taint_path

# Thư viện Đa đại lý mới
from crewai import Agent, Task, Crew, LLM, Process
from app.service.ScanLayer3_Tools import GraphCallerTool, GraphCalleeTool, GraphNodeContentTool, SearchCWEPayloadTool, Z3SolverTool, SendHTTPRequestTool, SyntaxCheckerTool, UnitTestRunnerTool, DependencyCheckerTool, CheckImpactRadiusTool, SearchAlternativeGraphPathTool
import io
import contextlib
import threading
import sys

class ThreadLocalStdout:
    def __init__(self, fallback):
        self.fallback = fallback
        self.local = threading.local()

    def write(self, data):
        if hasattr(self.local, 'capture') and self.local.capture is not None:
            self.local.capture.write(data)
        else:
            self.fallback.write(data)

    def flush(self):
        if hasattr(self.local, 'capture') and self.local.capture is not None:
            self.local.capture.flush()
        else:
            self.fallback.flush()

    def __getattr__(self, name):
        return getattr(self.fallback, name)

# Apply thread-safe stdout/stderr redirection globally so CrewAI logging isolated per thread
if not isinstance(sys.stdout, ThreadLocalStdout):
    sys.stdout = ThreadLocalStdout(sys.stdout)
if not isinstance(sys.stderr, ThreadLocalStdout):
    sys.stderr = ThreadLocalStdout(sys.stderr)

# --- MONKEY PATCH CREWAI TOOL PARSER ---
import crewai.tools.tool_usage

def _extract_first_json_object(text: str) -> str:
    """Extract the first complete JSON object from text using balanced-brace counting.
    Properly handles quoted strings containing braces (e.g. C code in Check_Syntax).
    Examples:
      '[{"cwe_id":"CWE-78"},{"x":1}]'  ->  '{"cwe_id":"CWE-78"}'
      '{"node_id":"foo"}, extra junk'   ->  '{"node_id":"foo"}'
      'blah {"a":1} blah'               ->  '{"a":1}'
    """
    start = text.find('{')
    if start == -1:
        return text
    depth = 0
    in_string = False
    escape_next = False
    for i in range(start, len(text)):
        c = text[i]
        if escape_next:
            escape_next = False
            continue
        if c == '\\' and in_string:
            escape_next = True
            continue
        if c == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return text[start:i+1]
    # Fallback: couldn't find balanced braces, use rfind
    end = text.rfind('}')
    if end >= start:
        return text[start:end+1]
    return text

_orig_validate = crewai.tools.tool_usage.ToolUsage._validate_tool_input
def _patched_validate(self, tool_input):
    if isinstance(tool_input, str):
        tool_input = _extract_first_json_object(tool_input.strip())
    return _orig_validate(self, tool_input)
crewai.tools.tool_usage.ToolUsage._validate_tool_input = _patched_validate
# ---------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_layer3_dotenv() -> None:
    app_root = Path(__file__).resolve().parent.parent
    for path in (PROJECT_ROOT / ".env", app_root / ".env"):
        if path.is_file():
            load_dotenv(path, override=False)


_load_layer3_dotenv()

_MASK_PATTERNS = [
    (re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"), "sk-***MASKED***"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA***MASKED***"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "ghp_***MASKED***"),
    (re.compile(r"glpat-[A-Za-z0-9\-]{20,}"), "glpat-***MASKED***"),
    (re.compile(r"hf_[A-Za-z0-9]{20,}"), "hf_***MASKED***"),
    (re.compile(r"pypi-[A-Za-z0-9_\-]{20,}"), "pypi-***MASKED***"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{20,}", flags=re.IGNORECASE), r"\1***MASKED***"),
    (re.compile(r"(?i)(api[_-]?key|apikey|api_secret|secret_key|access_token|auth_token|secret|token|password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s,}}]+['\"]?"), r"\1=***MASKED***"),
    (re.compile(r"(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s'\"]+:[^@\s'\"]+@[^'\"\s]+"), r"\1://***MASKED***:***MASKED***@***MASKED***")
]

DEFAULT_PROMPT_DUMP_DIR = PROJECT_ROOT / "scan_layer3_prompts"

IGNORE_PATH_KEYWORDS = (
    "node_modules",
    "vendor",
    "fixtures",
    "test/fixtures",
    "test/",
    "tests/",
    "e2e/",
    "spec/",
    "specs/",
    "__tests__",
    "docs/",
    "openapi_specs/",
    "postman",
    "artifacts/",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "coverage",
    ".git",
)

IMPORTANT_SEVERITIES = {"critical", "error", "warning"}
SECURITY_CATEGORIES = {
    "security",
    "hardcoded_secret",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "correctness",
    "injection",
    "command_injection",
    "path_injection",
    "sql_injection",
    "ssrf",
    "traversal",
    "auth",
    "auth_bypass",
    "deserialization",
}
NOISE_CATEGORIES = {"quality", "style", "maintainability", "recommendation"}
NOISE_RULE_ID_PARTS = (
    "unused-import",
    "commented-out-code",
    "unnecessary-lambda",
    "procedure-return-value-used",
    "duplicate-key-dict-literal",
)
SEVERITY_RANK = {
    "critical": 4,
    "error": 3,
    "warning": 2,
    "recommendation": 1,
    "info": 0,
}


def _resolve_prompt_dump_dir(explicit: Optional[str | Path]) -> Optional[Path]:
    """Thư mục ghi JSON prompt trước khi gọi LLM. None = tắt."""
    if os.getenv("SCAN_LAYER3_PROMPT_DUMP", "1").strip().lower() in {"0", "false", "no", "off"}:
        return None
    if explicit:
        return Path(explicit).expanduser().resolve()
    env_dir = os.getenv("SCAN_LAYER3_PROMPT_DIR", "").strip()
    if env_dir:
        return Path(env_dir).expanduser().resolve()
    return DEFAULT_PROMPT_DUMP_DIR.resolve()


def _sanitize_prompt_filename_fragment(value: str, max_len: int = 120) -> str:
    cleaned = re.sub(r"[^\w.\-]+", "_", value.strip())
    return cleaned[:max_len] if cleaned else "unknown"


def _cwe_path_from_env() -> Optional[Path]:
    raw = os.getenv("CWE_DICTIONARY_PATH", "").strip()
    return Path(raw).expanduser() if raw else None


DEFAULT_CWE_PATHS = (
    _cwe_path_from_env(),
    PROJECT_ROOT / "cwe_dictionary.json",
    PROJECT_ROOT / "cwe_dictionary (1).json",
    Path(__file__).resolve().parent / "cwe_dictionary.json",
    Path(__file__).resolve().parent / "cwe_dictionary (1).json",
    Path.home() / "Downloads" / "cwe_dictionary (1).json",
)


class QwenLLMClient:
    """Client gọi API LLM (Giữ lại để hỗ trợ tính tương thích ngược cho hàm scan_repository_findings)"""
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        resolved_base_url = base_url or os.getenv("OPENAI_BASE_URL", "https://ckey.vn/v1")

        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.base_url = self._normalize_base_url(resolved_base_url)
        self.model = model or os.getenv("OPENAI_MODEL", "qwen3-coder-next")
        self.timeout = timeout if timeout is not None else int(os.getenv("LLM_TIMEOUT_SECONDS", "180"))

    @staticmethod
    def _normalize_base_url(value: str) -> str:
        value = value.rstrip("/")
        suffix = "/chat/completions"
        if value.endswith(suffix):
            return value[: -len(suffix)]
        return value

    def chat(self, messages: list[dict[str, str]], max_tokens: int = 4096) -> str:
        if not self.api_key:
            raise RuntimeError("Missing OPENAI_API_KEY in environment.")

        body = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": max_tokens,
        }

        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "ai-pctp-scanlayer3/1.0",
            },
            method="POST",
        )

        try:
            import ssl
            import certifi
            ssl_ctx = ssl.create_default_context(cafile=certifi.where())
            with urllib.request.urlopen(request, timeout=self.timeout, context=ssl_ctx) as response:
                data = json.loads(response.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as exc:
            error_text = exc.read().decode("utf-8") if exc.fp else ""
            if exc.code == 403:
                raise RuntimeError(
                    "LLM API HTTP 403 Forbidden. Kiểm tra OPENAI_API_KEY/OPENAI_BASE_URL, "
                    "quyền truy cập model, hoặc endpoint đang chặn request HTTP client. "
                    f"Response: {error_text[:500]}"
                ) from exc
            raise RuntimeError(f"LLM API HTTP {exc.code}: {error_text[:500]}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Cannot connect to LLM API at {self.base_url}: {exc.reason}") from exc


class ScanLayer3:
    """
    Reasoning layer based on graph context - NÂNG CẤP KIẾN TRÚC ĐA ĐẠI LÝ (MULTI-AGENT)
    """

    def __init__(
        self,
        repo_name: str,
        cwe_dictionary_path: Optional[str | Path] = None,
        llm_client: Optional[QwenLLMClient] = None,
        max_graph_chars: int = 22000,
        prompt_dump_dir: Optional[str | Path] = None,
        repo_root: Optional[str | Path] = None,
    ) -> None:
        self.repo_name = repo_name
        self.repo_root = Path(repo_root) if repo_root else None
        self.max_graph_chars = max_graph_chars
        self.max_repository_files = int(os.getenv("SCAN_LAYER3_REPOSITORY_MAX_FILES", "30"))
        
        self.cwe_dictionary_path = self.resolve_cwe_dictionary_path(cwe_dictionary_path)
        self.cwe_dictionary = self.load_cwe_dictionary(self.cwe_dictionary_path)
        self.prompt_dump_dir = _resolve_prompt_dump_dir(prompt_dump_dir)
        self._last_repository_filter_stats: dict[str, Any] = {}

        # 1. Giữ LLM Client cũ cho tính tương thích ngược (Repo mode)
        self.llm = llm_client or QwenLLMClient()
        
        # 2. Khởi tạo LLM Client của CrewAI (model string khớp OPENAI_MODEL)
        llm_model = os.getenv("OPENAI_MODEL", "qwen3-coder-next")
        if "/" not in llm_model:
            llm_model = f"openai/{llm_model}"
        self.agent_llm = LLM(
            model=llm_model,
            base_url=os.getenv("OPENAI_BASE_URL", "https://ckey.vn/v1"),
            api_key=os.getenv("OPENAI_API_KEY", ""),
            temperature=0.1,
            timeout=int(os.getenv("LLM_TIMEOUT_SECONDS", "180")),
        )

        # 3. Cache system
        self.layer3_cache_file = Path("/app/temp_uploads") / f"{self.repo_name}_layer3_cache.json"
        self.layer3_cache = self._load_cache()

    def _load_cache(self) -> dict[str, Any]:
        if self.layer3_cache_file.exists():
            try:
                with open(self.layer3_cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_cache(self) -> None:
        try:
            with open(self.layer3_cache_file, "w", encoding="utf-8") as f:
                json.dump(self.layer3_cache, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _get_cache_key(self, file_path: str, evidence: dict[str, Any], algorithmic_path_str: str) -> str:
        import hashlib
        evidence_str = str(evidence.get("matched_text", "")) + str(evidence.get("line_content", "")) + str(evidence.get("rules", ""))
        raw = f"{file_path}|{evidence_str}|{algorithmic_path_str}"
        return hashlib.md5(raw.encode('utf-8')).hexdigest()

    def _dump_llm_prompt_payload(self, *, graph: dict[str, Any], messages: list[dict[str, str]], graph_context: str, safe_evidence: dict[str, Any], cwe_dictionary: list[dict[str, Any]]) -> Optional[Path]:
        """Ghi JSON prompt LLM nhận được (Giữ nguyên)"""
        if not self.prompt_dump_dir:
            return None
        root = graph.get("root") or {}
        root_id = str(root.get("id") or root.get("file_path") or "unknown")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_node = _sanitize_prompt_filename_fragment(root_id)
        self.prompt_dump_dir.mkdir(parents=True, exist_ok=True)
        path = self.prompt_dump_dir / f"prompt_{stamp}_{safe_node}_{uuid.uuid4().hex[:8]}.json"

        payload: dict[str, Any] = {
            "dumped_at": datetime.now(timezone.utc).isoformat(),
            "repo_name": self.repo_name,
            "root_node_id": root.get("id"),
            "root_file_path": root.get("file_path"),
            "max_graph_chars": self.max_graph_chars,
            "evidence": safe_evidence,
            "graph_context": graph_context,
            "messages": messages,
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def _dump_repository_prompt_payload(self, *, messages: list[dict[str, str]], findings_blocks: list[dict[str, Any]], cwe_dictionary: list[dict[str, Any]]) -> Optional[Path]:
        """Ghi JSON prompt repository-mode (Giữ nguyên)"""
        if not self.prompt_dump_dir:
            return None
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe = _sanitize_prompt_filename_fragment(f"{self.repo_name}_repository")
        self.prompt_dump_dir.mkdir(parents=True, exist_ok=True)
        path = self.prompt_dump_dir / f"prompt_repo_{stamp}_{safe}_{uuid.uuid4().hex[:8]}.json"

        payload: dict[str, Any] = {
            "dumped_at": datetime.now(timezone.utc).isoformat(),
            "mode": "repository",
            "repo_name": self.repo_name,
            "findings_blocks": findings_blocks,
            "messages": messages,
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def scan_node(self, node_id: str, evidence: Optional[dict[str, Any]] = None, depth: int = 1, same_file: bool = True, debug_prompt: bool = False) -> dict[str, Any]:
        node_id = self.normalize_to_file_node_id(node_id)
        graph = db_node_graph(repo_name=self.repo_name, node_id=node_id, depth=depth, same_file=same_file, include_content=True)
        return self.scan_graph(graph, evidence=evidence, debug_prompt=debug_prompt)

    # =========================================================================================
    # LÕI ĐÃ ĐƯỢC NÂNG CẤP LÊN MULTI-AGENT KIẾN TRÚC MEMPALACE
    # =========================================================================================
    def _prefilter_cwe_by_evidence(self, dictionary: list[dict[str, Any]], evidence: dict[str, Any]) -> list[dict[str, Any]]:
        evidence_str = json.dumps(evidence).lower()
        keywords = ["injection", "sql", "xss", "cross-site", "secret", "credential", "auth", "path", "traversal", "command", "deserialization", "ssrf"]
        matched_keywords = [k for k in keywords if k in evidence_str]
        filtered = []
        for cwe in dictionary:
            cwe_id = str(cwe.get("cwe_id", "")).lower()
            cwe_name = str(cwe.get("cwe_name", "")).lower()
            if cwe_id and cwe_id in evidence_str:
                filtered.append(cwe)
                continue
            if any(k in cwe_name for k in matched_keywords):
                filtered.append(cwe)
        if len(filtered) < 3:
            return dictionary
        return self.unique_cwe_candidates(filtered)

    def scan_graph(self, graph: dict[str, Any], evidence: Optional[dict[str, Any]] = None, debug_prompt: bool = False) -> dict[str, Any]:
        
        root = graph.get("root") or {}
        target_node_id = root.get("id", "unknown")
        file_path = root.get("file_path", "unknown")

        # 1. Trích xuất và làm sạch dữ liệu
        graph_context = self.format_graph_for_llm(graph)
        graph_context = self.truncate_middle(self.mask_secrets(graph_context), self.max_graph_chars)
        safe_evidence = self.mask_json(evidence or {})
        safe_evidence_str = json.dumps(safe_evidence, indent=2, ensure_ascii=False)
        
        cwe_dictionary = self.unique_cwe_candidates(self.cwe_dictionary)
        cwe_dictionary = self._prefilter_cwe_by_evidence(cwe_dictionary, safe_evidence)
        cwe_dict_str = json.dumps(cwe_dictionary, indent=2, ensure_ascii=False)

        # 2. Xây dựng không gian bộ nhớ MemPalace & Chạy thuật toán tìm đường (Graph Traversal)
        room_name = _sanitize_prompt_filename_fragment(file_path)
        
        taint_result = db_taint_path(self.repo_name, target_node_id, max_depth=10)
        algorithmic_path_str = "No algorithmic path found."
        nodes_content_str = ""
        if "algorithmic_paths" in taint_result and taint_result["algorithmic_paths"]:
            algorithmic_path_str = "\n".join(taint_result["algorithmic_paths"])
            nodes_content_str = taint_result.get("nodes_content", "")
            
        factual_context = (
            f"[Repository: {self.repo_name} | Target File: {file_path}]\n"
            f"[ALGORITHMIC TAINT PATH (SOURCE -> SINK)]\n{algorithmic_path_str}\n\n"
            f"[NODES CONTENT ALONG THE PATH]\n{nodes_content_str}\n"
        )

        if os.getenv("SCAN_LAYER3_FAST_MODE", "0").strip().lower() not in {"0", "false", "no", "off"}:
            return self.scan_graph_fast(
                root=root,
                file_path=file_path,
                graph_context=graph_context,
                factual_context=factual_context,
                safe_evidence=safe_evidence,
                cwe_dictionary=cwe_dictionary,
            )

        # --- KIỂM TRA CACHE TRƯỚC KHI CHẠY LLM ---
        cache_key = self._get_cache_key(file_path, safe_evidence, algorithmic_path_str)
        if cache_key in self.layer3_cache:
            import logging
            logging.getLogger(__name__).info("Layer 3 Cache Hit cho file: %s (Key: %s)", file_path, cache_key)
            parsed = self.layer3_cache[cache_key]
            return {
                "repo_name": self.repo_name,
                "node_id": root.get("id"),
                "file_path": root.get("file_path"),
                "label": root.get("label"),
                "name": root.get("name"),
                "start_line": root.get("start_line"),
                "end_line": root.get("end_line"),
                "cwe_dictionary_count": len(cwe_dictionary),
                "raw_llm_response": "CACHED",
                "agent_logs": parsed.get("agent_logs", "CACHED"),
                "prompt_dump_path": None,
                **parsed
            }

        # 3. Kích hoạt 2 Đặc Vụ AI với đầy đủ Tools (Nhưng giới hạn max_iter=2 để chạy nhanh)
        agent2_tools = [SearchCWEPayloadTool(), Z3SolverTool(), SendHTTPRequestTool()]
        agent3_tools = [SyntaxCheckerTool(), CheckImpactRadiusTool(repo_name=self.repo_name), UnitTestRunnerTool(), DependencyCheckerTool()]

        agent_hacker = Agent(
            role='Vulnerability Validator',
            goal='Thẩm định tính Reachability và thiết kế kịch bản tấn công thực tế',
            backstory=factual_context + AGENT_2_SYSTEM,
            llm=self.agent_llm,
            tools=agent2_tools,
            verbose=False,
            max_iter=2,
        )

        agent_architect = Agent(
            role='Remediation Architect',
            goal='Đối chiếu ma trận CWE, sinh bản vá an toàn không phá vỡ liên kết hệ thống',
            backstory=factual_context + AGENT_3_SYSTEM,
            llm=self.agent_llm,
            tools=agent3_tools,
            verbose=False,
            max_iter=2,
        )

        # 4. Giao việc cho các Agent
        task_exploit = Task(
            description=build_agent2_user_prompt(
                attack_path_trace="(See the ALGORITHMIC TAINT PATH in the context provided above by the system.)", 
                evidence_str=safe_evidence_str
            ),
            expected_output="Biên bản thẩm định khả thi, kịch bản tấn công tiếng Việt và điểm nguy cơ.",
            agent=agent_hacker
        )

        task_patch = Task(
            description=build_agent3_user_prompt(
                agent1_data="(See the ALGORITHMIC TAINT PATH in the context.)", 
                agent2_data="(See the Exploit scenario from Task 1 in the context.)", 
                cwe_dictionary_str=cwe_dict_str
            ),
            expected_output=LAYER3_TASK_EXPECTED_OUTPUT,
            agent=agent_architect,
            context=[task_exploit],
        )

        # Dump payload cũ ra file để Debug như hệ thống cũ của bạn
        prompt_dump_path = self._dump_llm_prompt_payload(
            graph=graph, 
            messages=[{"role": "system", "content": "MULTI-AGENT ENGINE RUNNING"}], 
            graph_context=graph_context, 
            safe_evidence=safe_evidence, 
            cwe_dictionary=cwe_dictionary
        )

        raw_response = ""
        agent_logs_str = ""
        
        try:
            import logging
            import io
            import contextlib
            stdout_capture = io.StringIO()
            
            from pathlib import Path
            if self.repo_root and self.repo_root.is_dir():
                live_log_path = self.repo_root / ".agent_logs.txt"
            else:
                live_log_path = Path("/tmp") / f".agent_logs_{self.repo_name}.txt"
                
            with open(live_log_path, "a", encoding="utf-8") as f:
                f.write(f"\n[START] Bắt đầu quét file: {file_path}...\n")
            
            log_handler = logging.StreamHandler(stdout_capture)
            log_handler.setLevel(logging.DEBUG)
            logging.getLogger().addHandler(log_handler)
            logging.getLogger("crewai").addHandler(log_handler)
            
            try:
                sys.stdout.local.capture = stdout_capture
                sys.stderr.local.capture = stdout_capture
                
                # 5. Khởi chạy toàn bộ hệ thống
                crew = Crew(
                    agents=[agent_hacker, agent_architect],
                    tasks=[task_exploit, task_patch],
                    process=Process.sequential,
                    verbose=True,
                )
                raw_response = str(crew.kickoff())
            finally:
                sys.stdout.local.capture = None
                sys.stderr.local.capture = None
                logging.getLogger().removeHandler(log_handler)
                logging.getLogger("crewai").removeHandler(log_handler)
                
            with open(live_log_path, "a", encoding="utf-8") as f:
                f.write(f"[DONE] Hoàn tất phân tích và đề xuất bản vá (Layer 3) cho: {file_path}\n")
            
            agent_logs_str = stdout_capture.getvalue()
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("ScanLayer3 LLM parsing failed: %s", exc)
            if 'stdout_capture' in locals():
                agent_logs_str = stdout_capture.getvalue()
            if not agent_logs_str:
                agent_logs_str = f"CrewAI Error: {str(exc)}"
            raw_response = "{}"
        
        # 6. Parse kết quả trả về đúng chuẩn cũ cho Node.js Frontend
        parsed = self.parse_llm_json(raw_response)
        parsed["agent_logs"] = agent_logs_str

        # CACHE IT
        self.layer3_cache[cache_key] = parsed
        self._save_cache()

        return {
            "repo_name": self.repo_name,
            "node_id": root.get("id"),
            "file_path": root.get("file_path"),
            "label": root.get("label"),
            "name": root.get("name"),
            "start_line": root.get("start_line"),
            "end_line": root.get("end_line"),
            "selected_cwe_id": parsed.get("selected_cwe_id", "UNMAPPED"),
            "selected_cwe_name": parsed.get("selected_cwe_name", "CWE not mapped"),
            "selected_cwe_reason": parsed.get("selected_cwe_reason", ""),
            "root_cause": parsed.get("root_cause", ""),
            "attack_path": parsed.get("attack_path", ""),
            "impact": parsed.get("impact", ""),
            "severity": parsed.get("severity", "Unknown"),
            "evidence_strength": parsed.get("evidence_strength", "weak"),
            "candidate_comparison": parsed.get("candidate_comparison", []),
            "remediation": parsed.get("remediation", []),
            "secure_code_example": parsed.get("secure_code_example"),
            "cwe_dictionary_count": len(cwe_dictionary),
            "raw_llm_response": raw_response,
            "agent_logs": parsed.get("agent_logs", ""),
            "prompt_dump_path": str(prompt_dump_path) if prompt_dump_path else None,
        }

    def scan_graph_fast(
        self,
        *,
        root: dict[str, Any],
        file_path: str,
        graph_context: str,
        factual_context: str,
        safe_evidence: dict[str, Any],
        cwe_dictionary: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Fast Layer 3 path for benchmark/production scanning.

        It keeps the built graph retrieval, CWE grounding, and LLM reasoning, but avoids
        the CrewAI tool loop that can block on long prompts or malformed tool calls.
        """
        compact_context = self.truncate_middle(
            f"{factual_context}\n\n[GRAPH CONTEXT]\n{graph_context}",
            int(os.getenv("SCAN_LAYER3_FAST_CONTEXT_CHARS", "9000")),
        )
        max_cwes = int(os.getenv("SCAN_LAYER3_FAST_MAX_CWES", "12"))
        messages = build_scan_layer3_messages(
            root=root,
            evidence=safe_evidence,
            graph_context=compact_context,
            cwe_dictionary=cwe_dictionary[:max_cwes],
        )
        raw_response = ""
        error_text = ""
        try:
            raw_response = self.llm.chat(
                messages,
                max_tokens=int(os.getenv("SCAN_LAYER3_FAST_MAX_TOKENS", "2600")),
            )
        except Exception as exc:
            error_text = str(exc)
            raw_response = "{}"

        parsed = self.parse_llm_json(raw_response)
        if error_text and parsed.get("selected_cwe_id") == "UNMAPPED":
            parsed["selected_cwe_reason"] = f"Fast Layer 3 LLM call failed: {error_text[:500]}"

        return {
            "repo_name": self.repo_name,
            "node_id": root.get("id"),
            "file_path": root.get("file_path"),
            "label": root.get("label"),
            "name": root.get("name"),
            "start_line": root.get("start_line"),
            "end_line": root.get("end_line"),
            "selected_cwe_id": parsed.get("selected_cwe_id", "UNMAPPED"),
            "selected_cwe_name": parsed.get("selected_cwe_name", "CWE not mapped"),
            "selected_cwe_reason": parsed.get("selected_cwe_reason", ""),
            "root_cause": parsed.get("root_cause", ""),
            "attack_path": parsed.get("attack_path", ""),
            "impact": parsed.get("impact", ""),
            "severity": parsed.get("severity", "Unknown"),
            "evidence_strength": parsed.get("evidence_strength", "weak"),
            "candidate_comparison": parsed.get("candidate_comparison", []),
            "remediation": parsed.get("remediation", []),
            "secure_code_example": parsed.get("secure_code_example"),
            "cwe_dictionary_count": len(cwe_dictionary),
            "raw_llm_response": raw_response,
            "agent_logs": "FAST_LAYER3_MODE",
            "prompt_dump_path": None,
        }

    # =========================================================================================
    # CÁC HÀM TIỆN ÍCH DƯỚI ĐÂY LÀ NGUYÊN BẢN CỦA BẠN (GIỮ NGUYÊN 100%)
    # =========================================================================================

    def _is_high_priority(self, item: dict[str, Any]) -> bool:
        """Pre-filter: chỉ giữ lại các findings có severity >= medium."""
        severity = str(item.get("severity") or item.get("result", {}).get("severity", "") if isinstance(item.get("result"), dict) else "").lower().strip()
        if severity in ("info", "low", "none", ""):
            # Kiểm tra thêm trong findings con
            findings = item.get("findings", [])
            if findings:
                has_high = False
                for f in findings:
                    f_sev = str(f.get("severity", "")).lower()
                    if f_sev and f_sev not in ("info", "low", "none", ""):
                        has_high = True
                        break
                    for rule in f.get("rules", []):
                        r_sev = str(rule.get("severity", "")).lower()
                        if r_sev and r_sev not in ("info", "low", "none", ""):
                            has_high = True
                            break
                    if has_high:
                        break
                if not has_high:
                    return False
        return True

    def scan_layer_results(self, scan_results: list[dict[str, Any]], limit: Optional[int] = None, depth: int = 1, debug_prompt: bool = False, max_workers: int = 2) -> list[dict[str, Any]]:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import logging
        logger = logging.getLogger(__name__)

        layer1_map: dict[str, list[dict[str, Any]]] = {}
        for item in scan_results:
            if "findings" in item:
                raw = str(item.get("file_path", ""))
                key = raw.removeprefix("File:")
                if key:
                    layer1_map[key] = item.get("findings", [])

        items = scan_results[:limit] if limit is not None else scan_results

        # --- Tối ưu 1: Loại bỏ file trùng lặp (dedup by node_id) ---
        seen_node_ids: set[str] = set()
        scan_jobs: list[tuple[str, dict[str, Any]]] = []
        skipped_low: list[dict[str, Any]] = []

        for item in items:
            node_id = self.extract_node_id(item)
            if not node_id:
                skipped_low.append({"error": "Cannot infer graph node_id from scan result.", "evidence": self.mask_json(item)})
                continue
            if node_id in seen_node_ids:
                continue
            seen_node_ids.add(node_id)

            if self.should_ignore_file(node_id.removeprefix("File:")):
                skipped_low.append({
                    "node_id": node_id, "file_path": node_id.removeprefix("File:"),
                    "selected_cwe_id": "SKIPPED", "selected_cwe_name": "Ignored benchmark/non-application path",
                    "severity": "Low", "selected_cwe_reason": "Bỏ qua file test/docs/openapi/postman/artifacts/dependency/generated output.",
                })
                logger.info("Layer3: Skipping ignored path %s", node_id)
                continue

            # --- Tối ưu 2: Bỏ qua file severity thấp ---
            if not self._is_high_priority(item):
                skipped_low.append({
                    "node_id": node_id, "file_path": node_id.removeprefix("File:"),
                    "selected_cwe_id": "SKIPPED", "selected_cwe_name": "Low-priority finding skipped",
                    "severity": "Low", "selected_cwe_reason": "Bỏ qua do severity thấp (info/low).",
                })
                logger.info("Layer3: Skipping low-priority file %s", node_id)
                continue

            evidence = item
            if "result" in item and "findings" not in item:
                bare_file = node_id.removeprefix("File:")
                if bare_file in layer1_map:
                    evidence = {**item, "layer1_findings": layer1_map[bare_file]}

            scan_jobs.append((node_id, evidence))

        logger.info("Layer3: %d files to scan (skipped %d low-priority), max_workers=%d", len(scan_jobs), len(skipped_low), max_workers)

        # --- Tối ưu 3: Xử lý song song nhiều file ---
        results: list[dict[str, Any]] = list(skipped_low)

        if max_workers <= 1 or len(scan_jobs) <= 1:
            # Fallback: tuần tự
            for node_id, evidence in scan_jobs:
                results.append(self.scan_node(node_id, evidence=evidence, depth=depth, debug_prompt=debug_prompt))
        else:
            # Song song với ThreadPoolExecutor
            future_map = {}
            with ThreadPoolExecutor(max_workers=min(max_workers, len(scan_jobs))) as executor:
                for node_id, evidence in scan_jobs:
                    future = executor.submit(self.scan_node, node_id, evidence=evidence, depth=depth, debug_prompt=debug_prompt)
                    future_map[future] = node_id

                for future in as_completed(future_map):
                    nid = future_map[future]
                    try:
                        results.append(future.result())
                    except Exception as exc:
                        logger.warning("Layer3: scan_node(%s) failed: %s", nid, exc)
                        results.append({
                            "node_id": nid, "file_path": nid.removeprefix("File:"),
                            "selected_cwe_id": "ERROR", "selected_cwe_name": "Scan failed",
                            "severity": "Unknown", "selected_cwe_reason": f"Lỗi khi quét: {str(exc)[:500]}",
                        })

        return results

    def should_ignore_file(self, path: str) -> bool:
        normalized = path.replace("\\", "/").removeprefix("File:").lower()
        parts = [part for part in normalized.split("/") if part]
        part_set = set(parts)
        if part_set.intersection({"node_modules", "vendor", "fixtures", "__pycache__", ".venv", "venv", "dist", "build", "coverage", ".git"}):
            return True
        return any(keyword in normalized for keyword in IGNORE_PATH_KEYWORDS if "/" in keyword)

    def rule_rank(self, rule: dict[str, Any]) -> int:
        severity = str(rule.get("severity") or "").lower().strip()
        return SEVERITY_RANK.get(severity, 0)

    def is_important_rule(self, rule: dict[str, Any]) -> bool:
        severity = str(rule.get("severity") or "").lower().strip()
        category = str(rule.get("category") or "").lower().strip()
        rule_id = str(rule.get("rule_id") or rule.get("name") or "").lower().strip()
        cwes = rule.get("cwe") or []

        if severity not in IMPORTANT_SEVERITIES:
            return False
        if any(part in rule_id for part in NOISE_RULE_ID_PARTS):
            return False
        if category in NOISE_CATEGORIES:
            return False
        if category in SECURITY_CATEGORIES:
            return True
        if cwes and severity in {"critical", "error"}:
            return True
        return severity in {"critical", "error"} and category not in NOISE_CATEGORIES

    def filter_layer1_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        filtered: list[dict[str, Any]] = []
        for finding in findings:
            rules = finding.get("rules") or []
            important_rules = [rule for rule in rules if isinstance(rule, dict) and self.is_important_rule(rule)]
            if not important_rules:
                continue
            important_rules.sort(key=self.rule_rank, reverse=True)
            filtered.append({**finding, "rules": important_rules})
        filtered.sort(key=lambda item: max((self.rule_rank(rule) for rule in item.get("rules", [])), default=0), reverse=True)
        return filtered

    def file_rank(self, bucket: dict[str, Any]) -> int:
        ranks = [
            self.rule_rank(rule)
            for finding in bucket.get("layer1_findings", [])
            for rule in finding.get("rules", [])
            if isinstance(rule, dict)
        ]
        if bucket.get("layer2_items"):
            ranks.append(2)
        return max(ranks, default=0)

    def group_findings_by_file(self, scan_results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        stats = {
            "input_items": len(scan_results),
            "ignored_path_items": 0,
            "dropped_low_value_layer1_items": 0,
            "layer1_findings_kept": 0,
            "layer2_items_kept": 0,
            "files_before_cap": 0,
            "files_after_cap": 0,
            "max_repository_files": self.max_repository_files,
        }

        for item in scan_results:
            if "findings" in item:
                raw = str(item.get("file_path", "")).removeprefix("File:")
                if not raw.strip(): continue
                if self.should_ignore_file(raw):
                    stats["ignored_path_items"] += 1
                    continue
                findings = self.filter_layer1_findings(item.get("findings") or [])
                if not findings:
                    stats["dropped_low_value_layer1_items"] += 1
                    continue
                entry = grouped.setdefault(raw, {"layer1_findings": [], "layer2_items": []})
                entry["layer1_findings"].extend(findings)
                stats["layer1_findings_kept"] += len(findings)
            elif "result" in item:
                node_id = self.extract_node_id(item)
                bare = node_id.removeprefix("File:")
                if not bare.strip(): continue
                if self.should_ignore_file(bare):
                    stats["ignored_path_items"] += 1
                    continue
                entry = grouped.setdefault(bare, {"layer1_findings": [], "layer2_items": []})
                entry["layer2_items"].append(item)
                stats["layer2_items_kept"] += 1

        ranked_items = sorted(grouped.items(), key=lambda pair: (-self.file_rank(pair[1]), pair[0]))
        stats["files_before_cap"] = len(ranked_items)
        if self.max_repository_files > 0:
            ranked_items = ranked_items[: self.max_repository_files]
        stats["files_after_cap"] = len(ranked_items)
        self._last_repository_filter_stats = stats
        return dict(ranked_items)

    def file_path_from_node_id(self, node_id: str) -> str:
        if node_id.startswith("File:"): return node_id.removeprefix("File:")
        if node_id.startswith(("Function:", "Class:", "Method:")):
            parts = node_id.split(":", 2)
            if len(parts) >= 2: return parts[1]
        return ""

    def node_display(self, node_id: str, nodes_by_id: dict[str, dict[str, Any]]) -> str:
        node = nodes_by_id.get(node_id) or {}
        label = node.get("label") or node_id.split(":", 1)[0]
        name = node.get("display_name") or node.get("name")
        file_path = node.get("file_path") or self.file_path_from_node_id(node_id)
        if name: return f"{label}:{file_path}:{name}"
        return node_id

    def build_graph_impact_context(self, graph: dict[str, Any]) -> dict[str, Any]:
        root = graph.get("root") or {}
        root_file = str(root.get("file_path") or self.file_path_from_node_id(str(root.get("id") or "")))
        nodes = graph.get("nodes") or []
        edges = graph.get("edges") or []
        nodes_by_id = {str(node.get("id")): node for node in nodes if node.get("id")}

        defined_symbols, entrypoints = [], []
        internal_calls, cross_file_edges, upstream_callers, downstream_callees = [], [], [], []
        related_files: set[str] = set()

        for edge in edges:
            from_id = str(edge.get("from_id") or "")
            to_id = str(edge.get("to_id") or "")
            relation = str(edge.get("relation_type") or "other")
            from_file = self.file_path_from_node_id(from_id)
            to_file = self.file_path_from_node_id(to_id)

            if relation in {"DEFINES", "HAS_METHOD"} and from_file == root_file and to_file == root_file:
                defined_symbols.append(self.node_display(to_id, nodes_by_id))
            if relation == "CALLS" and from_id == f"File:{root_file}":
                entrypoints.append(self.node_display(to_id, nodes_by_id))
            if relation == "CALLS" and from_file == root_file and to_file == root_file and not from_id.startswith("File:"):
                internal_calls.append({
                    "caller": self.node_display(from_id, nodes_by_id),
                    "callee": self.node_display(to_id, nodes_by_id),
                    "impact": "Nguy cơ lỗi dây chuyền",
                })
            if from_file and to_file and from_file != to_file:
                related_files.update({from_file, to_file})
                item = {"source_file": from_file, "target_file": to_file, "relation": relation, "source": self.node_display(from_id, nodes_by_id), "target": self.node_display(to_id, nodes_by_id)}
                cross_file_edges.append(item)
                if to_file == root_file: upstream_callers.append(item)
                if from_file == root_file: downstream_callees.append(item)

        related_files.discard(root_file)
        return {
            "root_file": root_file,
            "defined_symbols": sorted(set(defined_symbols)),
            "entrypoints": sorted(set(entrypoints)),
            "internal_call_chain": internal_calls,
            "cross_file_edges": cross_file_edges,
            "upstream_callers": upstream_callers,
            "downstream_callees": downstream_callees,
            "related_files": sorted(related_files),
        }

    def scan_repository_findings(self, scan_results: list[dict[str, Any]], depth: int = 1, debug_prompt: bool = False) -> dict[str, Any]:
        """Giữ nguyên luồng Repository cũ sử dụng QwenLLMClient"""
        grouped = self.group_findings_by_file(scan_results)
        if not grouped:
            return {"repo_name": self.repo_name, "repository_summary": "Không có findings", "findings": [], "cross_file_impact": []}

        cwe_dictionary = self.unique_cwe_candidates(self.cwe_dictionary)
        all_evidence = {"results": scan_results}
        cwe_dictionary = self._prefilter_cwe_by_evidence(cwe_dictionary, all_evidence)
        findings_blocks: list[dict[str, Any]] = []

        for file_path in grouped.keys():
            bucket = grouped[file_path]
            evidence_raw = {"layer1_findings": bucket.get("layer1_findings", []), "layer2_items": bucket.get("layer2_items", [])}
            safe_evidence = self.mask_json(evidence_raw)
            resolved_id = db_resolve_file_node_id(self.repo_name, file_path)

            if not resolved_id: continue
            try:
                graph = db_node_graph(repo_name=self.repo_name, node_id=resolved_id, depth=depth, same_file=False, include_content=True)
                graph_context = self.format_graph_for_llm(graph)
                graph_context = self.truncate_middle(self.mask_secrets(graph_context), self.max_graph_chars)
                impact_context = self.build_graph_impact_context(graph)
            except Exception:
                continue

            findings_blocks.append({
                "file_path": file_path, "resolved_node_id": resolved_id, "evidence": safe_evidence,
                "impact_context": impact_context, "graph_context": graph_context
            })

        messages = build_scan_layer3_repository_messages(repo_name=self.repo_name, findings_blocks=findings_blocks, cwe_dictionary=cwe_dictionary)
        raw_response = self.llm.chat(messages, max_tokens=8192)
        parsed = self.parse_repository_llm_json(raw_response)
        
        return {
            "repo_name": self.repo_name,
            "repository_summary": str(parsed.get("repository_summary", "")),
            "findings": parsed.get("findings", []),
            "cross_file_impact": parsed.get("cross_file_impact", []),
        }

    def extract_node_id(self, item: dict[str, Any]) -> str:
        raw = str(item.get("file_path") or item.get("node_id") or item.get("id") or item.get("file") or "")
        if raw.startswith(("File:", "Function:", "Class:", "Method:")): return self.normalize_to_file_node_id(raw)
        if raw: return f"File:{raw}"
        return ""

    def normalize_to_file_node_id(self, node_id: str) -> str:
        if node_id.startswith("File:"): return node_id
        if node_id.startswith(("Function:", "Class:", "Method:")):
            parts = node_id.split(":", 2)
            if len(parts) >= 2: return f"File:{parts[1]}"
        return node_id

    def format_graph_for_llm(self, graph: dict[str, Any]) -> str:
        root = graph.get("root") or {}
        nodes = graph.get("nodes") or []
        edges = graph.get("edges") or []
        lines = [f"## File: {root.get('file_path', '')}"]
        if root.get("content"):
            ext = Path(root.get("file_path", "")).suffix.lstrip(".")
            lang_map = {"py": "python", "js": "javascript", "ts": "typescript", "go": "go", "rb": "ruby", "java": "java", "c": "c", "cpp": "cpp", "cs": "csharp", "php": "php", "rs": "rust"}
            lang = lang_map.get(ext, ext or "text")
            lines.extend((f"```{lang}", str(root["content"]), "```", ""))
        symbols = [node for node in nodes if node.get("label") != "File"]
        if symbols:
            lines.append("## Symbols:")
            for node in symbols:
                lines.append(f"- [{node.get('label')}] `{node.get('name')}` (lines {node.get('start_line')}-{node.get('end_line')})")
        if edges:
            lines.extend(("", "## Relations:"))
            for edge in edges:
                lines.append(f"- {edge.get('from_id')} --[{edge.get('relation_type')}]--> {edge.get('to_id')}")
        return "\n".join(lines)

    def parse_llm_json(self, raw: str) -> dict[str, Any]:
        parsed = self.parse_json_object(raw)
        normalized = self.normalize_layer3_payload(parsed) if parsed else {}
        if normalized.get("selected_cwe_id"):
            return normalized
        return {
            "selected_cwe_id": "UNMAPPED",
            "selected_cwe_name": "CWE not mapped",
            "selected_cwe_reason": "LLM did not return valid JSON matching Layer 3 schema.",
            "candidate_comparison": [],
            "root_cause": (raw or "")[:2000],
            "attack_path": "",
            "impact": "",
            "severity": "Unknown",
            "evidence_strength": "weak",
            "remediation": ["Kiểm tra raw_llm_response vì model không trả JSON đúng schema."],
            "secure_code_example": None,
        }

    def normalize_layer3_payload(self, data: dict[str, Any]) -> dict[str, Any]:
        """Chuẩn hóa JSON Agent 3 (flat hoặc nested) về schema FE/Node."""
        if not data:
            return {}

        flat = self._find_layer3_flat_object(data)
        if not flat.get("selected_cwe_id"):
            flat = {**flat, **self._synthesize_layer3_from_nested(data)}
        if not flat:
            return {}

        attack_path = flat.get("attack_path")
        if isinstance(attack_path, list):
            parts = []
            for item in attack_path:
                if isinstance(item, dict):
                    parts.append(json.dumps(item, ensure_ascii=False))
                else:
                    parts.append(str(item))
            attack_path = "\n".join(parts)
        elif isinstance(attack_path, dict):
            attack_path = json.dumps(attack_path, ensure_ascii=False)

        remediation = flat.get("remediation")
        if isinstance(remediation, str):
            remediation = [remediation]
        elif not isinstance(remediation, list):
            remediation = []

        comparison = flat.get("candidate_comparison")
        if not isinstance(comparison, list):
            comparison = []

        cwe_id = str(flat.get("selected_cwe_id") or "UNMAPPED").strip().upper()
        if cwe_id and not cwe_id.startswith("CWE-") and cwe_id != "UNMAPPED":
            if cwe_id.isdigit():
                cwe_id = f"CWE-{cwe_id}"

        return {
            "selected_cwe_id": cwe_id or "UNMAPPED",
            "selected_cwe_name": str(flat.get("selected_cwe_name") or "CWE not mapped"),
            "selected_cwe_reason": str(flat.get("selected_cwe_reason") or ""),
            "candidate_comparison": comparison,
            "root_cause": str(flat.get("root_cause") or ""),
            "attack_path": str(attack_path or ""),
            "impact": str(flat.get("impact") or ""),
            "severity": str(flat.get("severity") or "Unknown"),
            "evidence_strength": str(flat.get("evidence_strength") or "weak"),
            "remediation": [str(x) for x in remediation if x],
            "secure_code_example": flat.get("secure_code_example"),
        }

    def _synthesize_layer3_from_nested(self, data: dict[str, Any]) -> dict[str, Any]:
        """Fallback khi model bọc trong security_report / cwe_matrix."""
        report = data.get("security_report") if isinstance(data.get("security_report"), dict) else data
        summary = report.get("vulnerability_summary") if isinstance(report.get("vulnerability_summary"), dict) else {}
        cwe_matrix = report.get("cwe_matrix") if isinstance(report.get("cwe_matrix"), dict) else {}

        attack_path = summary.get("attack_path") or report.get("attack_path") or ""
        root_cause = summary.get("root_cause") or report.get("root_cause") or ""
        impact = summary.get("impact") or report.get("impact") or ""

        selected_cwe_id = ""
        selected_cwe_name = ""
        for key, value in cwe_matrix.items():
            if isinstance(value, dict) and (value.get("selected") or value.get("fit") == "strong"):
                selected_cwe_id = str(key).upper()
                selected_cwe_name = str(value.get("name") or value.get("cwe_name") or "")
                break
        if not selected_cwe_id and isinstance(cwe_matrix.get("primary_cwe"), str):
            selected_cwe_id = cwe_matrix["primary_cwe"].upper()

        if not (attack_path or root_cause or selected_cwe_id):
            return {}

        return {
            "selected_cwe_id": selected_cwe_id or "UNMAPPED",
            "selected_cwe_name": selected_cwe_name or "CWE not mapped",
            "selected_cwe_reason": str(report.get("selected_cwe_reason") or summary.get("summary") or ""),
            "candidate_comparison": [],
            "root_cause": str(root_cause),
            "attack_path": attack_path,
            "impact": str(impact),
            "severity": str(summary.get("severity") or report.get("severity") or "Unknown"),
            "evidence_strength": "medium",
            "remediation": [],
            "secure_code_example": None,
        }

    def _find_layer3_flat_object(self, data: Any, depth: int = 0) -> dict[str, Any]:
        if depth > 6 or data is None:
            return {}
        if isinstance(data, dict):
            if data.get("selected_cwe_id"):
                return data
            for key in (
                "security_report",
                "vulnerability_summary",
                "security_analysis",
                "final_report",
                "report",
                "result",
                "output",
                "analysis",
            ):
                if key in data and isinstance(data[key], dict):
                    found = self._find_layer3_flat_object(data[key], depth + 1)
                    if found:
                        return found
            for value in data.values():
                if isinstance(value, dict):
                    found = self._find_layer3_flat_object(value, depth + 1)
                    if found:
                        return found
        return {}

    def parse_repository_llm_json(self, raw: str) -> dict[str, Any]:
        parsed = self.parse_json_object(raw)
        if not parsed: return {"repository_summary": "LLM không trả JSON hợp lệ.", "findings": [], "cross_file_impact": []}
        return {"repository_summary": str(parsed.get("repository_summary", "")), "findings": parsed.get("findings", []), "cross_file_impact": parsed.get("cross_file_impact", [])}

    def parse_json_object(self, raw: str) -> dict[str, Any]:
        text = raw.strip()
        
        # Thử tìm block ```json ... ```
        json_blocks = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL | re.IGNORECASE)
        if json_blocks:
            text = json_blocks[-1] # Lấy block cuối cùng (thường là final report)
        else:
            if text.startswith("```"):
                text = re.sub(r"^`{3}(?:json)?", "", text, flags=re.IGNORECASE).strip()
                text = re.sub(r"`{3}$", "", text).strip()

        # Tự động sửa lỗi escape regex do LLM sinh ra (vd: \. thành \\.)
        text = re.sub(r'\\(?![/"\\bfnrtu])', r'\\\\', text)
        
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            pass
        # Balanced brace extraction — ignore braces inside quoted strings and
        # try every complete object, preferring later objects because LLMs often
        # reason first and place the final JSON at the end.
        candidates: list[str] = []
        start: Optional[int] = None
        depth = 0
        in_string = False
        escape_next = False
        for i, ch in enumerate(text):
            if escape_next:
                escape_next = False
                continue
            if in_string and ch == "\\":
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}" and depth:
                depth -= 1
                if depth == 0 and start is not None:
                    candidates.append(text[start:i + 1])
                    start = None

        for candidate in reversed(candidates):
            try:
                parsed = json.loads(candidate)
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                continue
        return {}

    def resolve_cwe_dictionary_path(self, path: Optional[str | Path]) -> Path:
        if path:
            resolved = Path(path).expanduser()
            if resolved.exists():
                return resolved
            raise FileNotFoundError(f"CWE dictionary not found: {resolved}")

        for candidate in DEFAULT_CWE_PATHS:
            if candidate and candidate.exists():
                return candidate

        searched = ", ".join(str(p) for p in DEFAULT_CWE_PATHS if p)
        raise FileNotFoundError(
            "CWE dictionary not found. Set CWE_DICTIONARY_PATH in the server environment, "
            "or pass cwe_dictionary_path when constructing ScanLayer3. "
            f"Searched: {searched}"
        )

    def load_cwe_dictionary(self, path: Path) -> list[dict[str, Any]]:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("CWE dictionary must be a JSON list.")
        return [self.normalize_cwe(item) for item in data if isinstance(item, dict)]

    def normalize_cwe(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "cwe_id": str(item.get("cwe_id") or "").upper(),
            "cwe_name": item.get("cwe_name") or item.get("name") or "",
            "cwe_description": item.get("cwe_description") or item.get("description") or "",
        }

    def unique_cwe_candidates(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in candidates:
            cwe_id = str(item.get("cwe_id") or "").upper().strip()
            if not cwe_id or cwe_id in seen:
                continue
            seen.add(cwe_id)
            result.append({**item, "cwe_id": cwe_id})
        return result

    def mask_json(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: self.mask_json(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.mask_json(v) for v in value]
        if isinstance(value, str):
            return self.mask_secrets(value)
        if isinstance(value, (int, float, bool, type(None))):
            return value
        return self.mask_secrets(str(value))

    def mask_secrets(self, text: str) -> str:
        if not text:
            return text
        for pattern, replacement in _MASK_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def truncate_middle(self, text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        head = max_chars // 2
        tail = max_chars - head
        return (
            text[:head]
            + "\n\n... [TRUNCATED: middle omitted to fit LLM context] ...\n\n"
            + text[-tail:]
        )
