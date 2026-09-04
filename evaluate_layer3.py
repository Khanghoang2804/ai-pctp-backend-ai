#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║  EVALUATE_LAYER3.PY — Script đánh giá hiệu quả giảm False Positive    ║
║  của vòng lặp Neuro-Symbolic (Z3 Solver) ở Layer 3                     ║
║                                                                        ║
║  Mục tiêu: Chạy 3 cấu hình khác nhau trên cùng một tập dữ liệu để    ║
║  tạo ra Bảng 5 trong báo cáo AICP.                                    ║
║                                                                        ║
║  3 cấu hình:                                                           ║
║    1. LLM-only:           Không có Z3SolverTool                        ║
║    2. Z3 + 1 Iteration:   Có Z3SolverTool, max_iter=1                  ║
║    3. Z3 + 2 Iterations:  Có Z3SolverTool, max_iter=2                  ║
║                                                                        ║
║  Chạy: docker compose exec api python3 evaluate_layer3.py              ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# ── Cấu hình logging ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("evaluate_layer3")

# ── Import hệ thống ──
from app.core.database import querydb_dicts
from app.service.queryNodeAndRel import db_taint_path, db_node_graph
from app.service.ScanLayer3_Tools import (
    SearchCWEPayloadTool, Z3SolverTool, SendHTTPRequestTool,
    SyntaxCheckerTool, CheckImpactRadiusTool, UnitTestRunnerTool,
    DependencyCheckerTool, SearchAlternativeGraphPathTool,
)
from app.prompts.scan_layer3_prompt import (
    AGENT_2_SYSTEM, build_agent2_user_prompt,
    AGENT_3_SYSTEM, build_agent3_user_prompt,
    LAYER3_TASK_EXPECTED_OUTPUT,
)
from crewai import Agent, Task, Crew, LLM, Process

from dotenv import load_dotenv
load_dotenv()

# ══════════════════════════════════════════════════════════════════════════
# BỘ DỮ LIỆU KIỂM THỬ (Ground Truth)
# ══════════════════════════════════════════════════════════════════════════
# Mỗi test case gồm:
#   - node_id: ID node trên đồ thị (hàm bị quét)
#   - evidence: Bằng chứng giả lập từ Layer 1/2
#   - ground_truth: TRUE_POSITIVE (thực sự có lỗ hổng) hoặc FALSE_POSITIVE (an toàn)
#   - description: Mô tả ngắn
#
# VAmPI-master là ứng dụng intentionally vulnerable, nên:
#   - Các hàm xử lý user input trực tiếp = TRUE POSITIVE
#   - Các hàm có validation/sanitization = FALSE POSITIVE (an toàn)
#   - Các hàm helper/utility = FALSE POSITIVE

TEST_CASES = [
    # ━━━━━━━━━━━━━━ TRUE POSITIVES (Thực sự có lỗ hổng) ━━━━━━━━━━━━━━
    {
        "node_id": "Function:api_views/users.py:get_by_username",
        "evidence": {
            "file_path": "api_views/users.py",
            "severity": "critical",
            "rules": [{"rule_id": "SEC-SQLI", "name": "SQL Injection via user input",
                        "category": "injection", "cwe": ["CWE-89"], "severity": "critical",
                        "description": "User input 'username' passed directly to SQLAlchemy filter without parameterization"}],
            "matched_text": "User.query.filter_by(username=str(username))",
        },
        "ground_truth": "TRUE_POSITIVE",
        "description": "SQL Injection — username từ URL truyền thẳng vào query",
    },
    {
        "node_id": "Function:api_views/books.py:get_by_title",
        "evidence": {
            "file_path": "api_views/books.py",
            "severity": "critical",
            "rules": [{"rule_id": "SEC-BOLA", "name": "Broken Object Level Authorization",
                        "category": "auth_bypass", "cwe": ["CWE-639"], "severity": "critical",
                        "description": "Book title used to query without ownership check; vuln flag enables BOLA"}],
            "matched_text": "Book.query.filter_by(book_title=str(book_title)).first()",
        },
        "ground_truth": "TRUE_POSITIVE",
        "description": "BOLA — Broken Object Level Authorization trên book endpoint",
    },
    {
        "node_id": "Function:api_views/users.py:debug",
        "evidence": {
            "file_path": "api_views/users.py",
            "severity": "critical",
            "rules": [{"rule_id": "SEC-INFO", "name": "Sensitive data exposure via debug endpoint",
                        "category": "security", "cwe": ["CWE-200"], "severity": "critical",
                        "description": "Debug endpoint exposes all user data including passwords"}],
            "matched_text": "User.get_all_users_debug()",
        },
        "ground_truth": "TRUE_POSITIVE",
        "description": "Information Disclosure — Debug endpoint lộ toàn bộ password hash",
    },
    {
        "node_id": "Function:api_views/users.py:register_user",
        "evidence": {
            "file_path": "api_views/users.py",
            "severity": "warning",
            "rules": [{"rule_id": "SEC-MASS", "name": "Mass Assignment vulnerability",
                        "category": "security", "cwe": ["CWE-915"], "severity": "warning",
                        "description": "Request JSON body bound directly to user model without field whitelist"}],
            "matched_text": "request_data = request.get_json()",
        },
        "ground_truth": "TRUE_POSITIVE",
        "description": "Mass Assignment — Không whitelist field khi tạo user",
    },
    {
        "node_id": "Function:api_views/users.py:login_user",
        "evidence": {
            "file_path": "api_views/users.py",
            "severity": "warning",
            "rules": [{"rule_id": "SEC-BRUTE", "name": "No rate limiting on login",
                        "category": "auth", "cwe": ["CWE-307"], "severity": "warning",
                        "description": "Login endpoint has no rate limiting, brute force possible"}],
            "matched_text": "User.query.filter_by(username=username).first()",
        },
        "ground_truth": "TRUE_POSITIVE",
        "description": "Brute Force — Login không có rate limiting",
    },
    {
        "node_id": "Function:api_views/users.py:update_password",
        "evidence": {
            "file_path": "api_views/users.py",
            "severity": "critical",
            "rules": [{"rule_id": "SEC-IDOR", "name": "IDOR on password update",
                        "category": "auth_bypass", "cwe": ["CWE-639"], "severity": "critical",
                        "description": "Password update does not verify old password; any authenticated user can change another user's password"}],
            "matched_text": "user.password = request_data.get('password')",
        },
        "ground_truth": "TRUE_POSITIVE",
        "description": "IDOR — Update password không verify quyền sở hữu",
    },
    {
        "node_id": "Function:api_views/users.py:update_email",
        "evidence": {
            "file_path": "api_views/users.py",
            "severity": "warning",
            "rules": [{"rule_id": "SEC-IDOR", "name": "IDOR on email update",
                        "category": "auth_bypass", "cwe": ["CWE-639"], "severity": "warning",
                        "description": "Email update allows changing email without verifying account ownership"}],
            "matched_text": "user.email = request_data.get('email')",
        },
        "ground_truth": "TRUE_POSITIVE",
        "description": "IDOR — Update email không verify quyền sở hữu",
    },
    {
        "node_id": "Function:api_views/users.py:delete_user",
        "evidence": {
            "file_path": "api_views/users.py",
            "severity": "critical",
            "rules": [{"rule_id": "SEC-PRIV", "name": "Privilege escalation on delete",
                        "category": "auth_bypass", "cwe": ["CWE-269"], "severity": "critical",
                        "description": "Any authenticated user can delete any other user account"}],
            "matched_text": "User.delete_user(username)",
        },
        "ground_truth": "TRUE_POSITIVE",
        "description": "Privilege Escalation — Delete user không kiểm tra quyền admin",
    },

    # ━━━━━━━━━━━━━━ FALSE POSITIVES (An toàn, bị báo nhầm) ━━━━━━━━━━━━━━
    {
        "node_id": "Function:api_views/users.py:token_validator",
        "evidence": {
            "file_path": "api_views/users.py",
            "severity": "warning",
            "rules": [{"rule_id": "SEC-AUTH", "name": "JWT token handling",
                        "category": "security", "cwe": ["CWE-287"], "severity": "warning",
                        "description": "JWT token decoded without proper validation chain"}],
            "matched_text": "User.decode_auth_token(auth_token)",
        },
        "ground_truth": "FALSE_POSITIVE",
        "description": "FP — token_validator thực ra là hàm BẢO VỆ, không phải lỗ hổng",
    },
    {
        "node_id": "Function:api_views/users.py:error_message_helper",
        "evidence": {
            "file_path": "api_views/users.py",
            "severity": "warning",
            "rules": [{"rule_id": "SEC-XSS", "name": "Error message reflection",
                        "category": "injection", "cwe": ["CWE-79"], "severity": "warning",
                        "description": "Error message may reflect user input in response body"}],
            "matched_text": "return '{\"status\": \"fail\", \"message\": \"' + msg + '\"}'",
        },
        "ground_truth": "FALSE_POSITIVE",
        "description": "FP — error_message_helper chỉ format JSON string chuẩn, không reflect XSS",
    },
    {
        "node_id": "Function:api_views/main.py:basic",
        "evidence": {
            "file_path": "api_views/main.py",
            "severity": "warning",
            "rules": [{"rule_id": "SEC-INFO", "name": "Version information disclosure",
                        "category": "security", "cwe": ["CWE-200"], "severity": "warning",
                        "description": "Response includes application metadata that could aid attackers"}],
            "matched_text": "response_text = '{ \"message\": \"VAmPI the Vulnerable API\"'",
        },
        "ground_truth": "FALSE_POSITIVE",
        "description": "FP — basic() chỉ trả về thông tin chào hỏi static, không leak sensitive data",
    },
    {
        "node_id": "Function:api_views/main.py:populate_db",
        "evidence": {
            "file_path": "api_views/main.py",
            "severity": "warning",
            "rules": [{"rule_id": "SEC-DESTROY", "name": "Database destruction endpoint",
                        "category": "security", "cwe": ["CWE-306"], "severity": "warning",
                        "description": "Endpoint drops all tables; no authentication required"}],
            "matched_text": "db.drop_all(); db.create_all()",
        },
        "ground_truth": "FALSE_POSITIVE",
        "description": "FP — populate_db là chức năng dev/test, không phải lỗ hổng code logic",
    },
    {
        "node_id": "Function:api_views/books.py:get_all_books",
        "evidence": {
            "file_path": "api_views/books.py",
            "severity": "warning",
            "rules": [{"rule_id": "SEC-SQLI", "name": "Potential SQL injection",
                        "category": "injection", "cwe": ["CWE-89"], "severity": "warning",
                        "description": "SQLAlchemy query without explicit parameterization"}],
            "matched_text": "Book.get_all_books()",
        },
        "ground_truth": "FALSE_POSITIVE",
        "description": "FP — get_all_books() không nhận user input, gọi ORM thuần túy",
    },
    {
        "node_id": "Function:api_views/users.py:get_all_users",
        "evidence": {
            "file_path": "api_views/users.py",
            "severity": "warning",
            "rules": [{"rule_id": "SEC-SQLI", "name": "Potential SQL injection",
                        "category": "injection", "cwe": ["CWE-89"], "severity": "warning",
                        "description": "SQLAlchemy query method called"}],
            "matched_text": "User.get_all_users()",
        },
        "ground_truth": "FALSE_POSITIVE",
        "description": "FP — get_all_users() không nhận user input, gọi ORM thuần túy",
    },
    {
        "node_id": "Function:api_views/users.py:me",
        "evidence": {
            "file_path": "api_views/users.py",
            "severity": "warning",
            "rules": [{"rule_id": "SEC-AUTH", "name": "Auth bypass potential",
                        "category": "auth", "cwe": ["CWE-287"], "severity": "warning",
                        "description": "User data returned based on token, potential token forgery"}],
            "matched_text": "resp = token_validator(request.headers.get('Authorization'))",
        },
        "ground_truth": "FALSE_POSITIVE",
        "description": "FP — me() có gọi token_validator (bộ lọc bảo vệ) nên không bypass được",
    },
    {
        "node_id": "Function:api_views/books.py:add_new_book",
        "evidence": {
            "file_path": "api_views/books.py",
            "severity": "warning",
            "rules": [{"rule_id": "SEC-VALID", "name": "JSON schema validation bypass",
                        "category": "injection", "cwe": ["CWE-20"], "severity": "warning",
                        "description": "JSON schema validation present but may be insufficient"}],
            "matched_text": "jsonschema.validate(request_data, add_book_schema)",
        },
        "ground_truth": "FALSE_POSITIVE",
        "description": "FP — add_new_book có jsonschema.validate + token_validator, đã sanitize",
    },
    {
        "node_id": "Function:config.py:custom_problem_handler",
        "evidence": {
            "file_path": "config.py",
            "severity": "warning",
            "rules": [{"rule_id": "SEC-ERR", "name": "Custom error handler may leak info",
                        "category": "security", "cwe": ["CWE-209"], "severity": "warning",
                        "description": "Custom error handler returns problem details"}],
            "matched_text": "def custom_problem_handler(e):",
        },
        "ground_truth": "FALSE_POSITIVE",
        "description": "FP — Error handler trả format chuẩn, không leak stack trace",
    },
]

# ══════════════════════════════════════════════════════════════════════════
# HÀM ĐÁNH GIÁ CHÍNH
# ══════════════════════════════════════════════════════════════════════════

REPO_NAME = "VAmPI-master"


def load_cwe_dictionary() -> list[dict[str, Any]]:
    """Load CWE dictionary."""
    for path in [Path("/app/cwe_dictionary.json"), Path("cwe_dictionary.json")]:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data[:50]  # Giới hạn để prompt không quá dài
    raise FileNotFoundError("cwe_dictionary.json not found")


def create_llm() -> LLM:
    """Tạo CrewAI LLM client."""
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


def run_layer3_single(
    node_id: str,
    evidence: dict[str, Any],
    cwe_dict_str: str,
    agent_llm: LLM,
    mode: str,  # "llm_only" | "z3_1iter" | "z3_2iter"
) -> dict[str, Any]:
    """Chạy Layer 3 cho một test case với cấu hình cụ thể."""

    file_path = evidence.get("file_path", "unknown")

    # 1. Truy vết taint path từ đồ thị
    taint_result = db_taint_path(REPO_NAME, node_id, max_depth=10)
    algorithmic_path_str = "No algorithmic path found."
    nodes_content_str = ""
    if "algorithmic_paths" in taint_result and taint_result["algorithmic_paths"]:
        algorithmic_path_str = "\n".join(taint_result["algorithmic_paths"])
        nodes_content_str = taint_result.get("nodes_content", "")

    factual_context = (
        f"[Repository: {REPO_NAME} | Target File: {file_path}]\n"
        f"[ALGORITHMIC TAINT PATH (SOURCE -> SINK)]\n{algorithmic_path_str}\n\n"
        f"[NODES CONTENT ALONG THE PATH]\n{nodes_content_str}\n"
    )

    safe_evidence_str = json.dumps(evidence, indent=2, ensure_ascii=False)

    # 2. Cấu hình tools và max_iter theo mode
    if mode == "llm_only":
        # Không có Z3SolverTool và SearchAlternativeGraphPathTool
        agent2_tools = [SearchCWEPayloadTool(), SendHTTPRequestTool()]
        max_iter = 2
    elif mode == "z3_1iter":
        agent2_tools = [SearchCWEPayloadTool(), Z3SolverTool(), SendHTTPRequestTool()]
        max_iter = 1
    elif mode == "z3_2iter":
        agent2_tools = [
            SearchCWEPayloadTool(), Z3SolverTool(), SendHTTPRequestTool(),
            SearchAlternativeGraphPathTool(repo_name=REPO_NAME),
        ]
        max_iter = 2
    else:
        raise ValueError(f"Unknown mode: {mode}")

    agent3_tools = [
        SyntaxCheckerTool(),
        CheckImpactRadiusTool(repo_name=REPO_NAME),
        UnitTestRunnerTool(),
        DependencyCheckerTool(),
    ]

    # 3. Tạo Agents
    agent_hacker = Agent(
        role='Vulnerability Validator',
        goal='Thẩm định tính Reachability và thiết kế kịch bản tấn công thực tế',
        backstory=factual_context + AGENT_2_SYSTEM,
        llm=agent_llm,
        tools=agent2_tools,
        verbose=False,
        max_iter=max_iter,
    )

    agent_architect = Agent(
        role='Remediation Architect',
        goal='Đối chiếu ma trận CWE, sinh bản vá an toàn không phá vỡ liên kết hệ thống',
        backstory=factual_context + AGENT_3_SYSTEM,
        llm=agent_llm,
        tools=agent3_tools,
        verbose=False,
        max_iter=max_iter,
    )

    # 4. Tạo Tasks
    task_exploit = Task(
        description=build_agent2_user_prompt(
            attack_path_trace="(See the ALGORITHMIC TAINT PATH in the context provided above by the system.)",
            evidence_str=safe_evidence_str
        ),
        expected_output="Biên bản thẩm định khả thi, kịch bản tấn công tiếng Việt và điểm nguy cơ.",
        agent=agent_hacker,
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

    # 5. Chạy Crew
    try:
        crew = Crew(
            agents=[agent_hacker, agent_architect],
            tasks=[task_exploit, task_patch],
            process=Process.sequential,
            verbose=False,
        )
        raw_response = str(crew.kickoff())
    except Exception as exc:
        logger.warning("CrewAI error for %s [%s]: %s", node_id, mode, exc)
        raw_response = "{}"

    # 6. Parse kết quả
    severity = "Unknown"
    evidence_strength = "weak"
    selected_cwe = "UNMAPPED"

    try:
        # Trích xuất JSON từ response
        import re
        json_match = re.search(r'\{.*\}', raw_response, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group())
            severity = parsed.get("severity", "Unknown")
            evidence_strength = parsed.get("evidence_strength", "weak")
            selected_cwe = parsed.get("selected_cwe_id", "UNMAPPED")
    except (json.JSONDecodeError, Exception):
        pass

    # 7. Xác định Layer 3 kết luận: có lỗ hổng hay không
    #    - Nếu severity >= Medium AND evidence_strength != weak -> VULNERABLE
    #    - Nếu severity in (Low, Unknown) OR evidence_strength == weak OR CWE == UNMAPPED -> SAFE
    is_flagged_vulnerable = (
        severity.lower() in ("critical", "high", "medium")
        and evidence_strength.lower() != "weak"
        and selected_cwe != "UNMAPPED"
    )

    return {
        "node_id": node_id,
        "mode": mode,
        "severity": severity,
        "evidence_strength": evidence_strength,
        "selected_cwe": selected_cwe,
        "is_flagged_vulnerable": is_flagged_vulnerable,
        "raw_response_len": len(raw_response),
    }


def compute_metrics(results: list[dict], test_cases: list[dict]) -> dict[str, Any]:
    """Tính Precision, Recall, F1, FP count từ kết quả."""
    tp = fp = fn = tn = 0

    for result, tc in zip(results, test_cases):
        gt = tc["ground_truth"]
        predicted = result["is_flagged_vulnerable"]

        if gt == "TRUE_POSITIVE" and predicted:
            tp += 1  # Đúng: Có lỗi + Hệ thống báo có lỗi
        elif gt == "FALSE_POSITIVE" and predicted:
            fp += 1  # Sai: Không lỗi nhưng hệ thống báo có lỗi (Dương tính giả!)
        elif gt == "TRUE_POSITIVE" and not predicted:
            fn += 1  # Sai: Có lỗi nhưng hệ thống báo an toàn (Âm tính giả!)
        elif gt == "FALSE_POSITIVE" and not predicted:
            tn += 1  # Đúng: Không lỗi + Hệ thống báo an toàn

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) > 0 else 0.0

    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "Precision": round(precision * 100, 1),
        "Recall": round(recall * 100, 1),
        "F1": round(f1, 2),
        "Accuracy": round(accuracy * 100, 1),
        "FP_count": fp,
        "total": len(results),
    }


def print_table(all_metrics: dict[str, dict]) -> None:
    """In bảng kết quả dạng đẹp."""
    print("\n" + "═" * 90)
    print("║  BẢNG 5: HIỆU QUẢ CHẶN LỌC DƯƠNG TÍNH GIẢ CỦA BỘ GIẢI TOÁN HÌNH THỨC Z3 SOLVER  ║")
    print("═" * 90)
    print(f"{'Cấu hình Layer 3':<42} {'FP':>4}  {'Precision':>10}  {'Recall':>8}  {'F1':>5}")
    print("─" * 90)

    for mode_label, metrics in all_metrics.items():
        fp_str = f"{metrics['FP_count']} ca"
        prec_str = f"{metrics['Precision']}%"
        rec_str = f"{metrics['Recall']}%"
        f1_str = f"{metrics['F1']}"
        print(f"{mode_label:<42} {fp_str:>4}  {prec_str:>10}  {rec_str:>8}  {f1_str:>5}")

    print("─" * 90)
    print(f"Tổng số test case: {len(TEST_CASES)} "
          f"(TP ground truth: {sum(1 for tc in TEST_CASES if tc['ground_truth'] == 'TRUE_POSITIVE')}, "
          f"FP ground truth: {sum(1 for tc in TEST_CASES if tc['ground_truth'] == 'FALSE_POSITIVE')})")
    print("═" * 90)


def main():
    logger.info("=" * 70)
    logger.info("BẮT ĐẦU ĐÁNH GIÁ LAYER 3 — 3 CẤU HÌNH")
    logger.info("=" * 70)
    logger.info("Repo: %s | Test cases: %d", REPO_NAME, len(TEST_CASES))

    # Tải CWE dictionary
    cwe_dict = load_cwe_dictionary()
    cwe_dict_str = json.dumps(cwe_dict, indent=2, ensure_ascii=False)
    logger.info("Loaded %d CWE entries", len(cwe_dict))

    # Tạo LLM
    agent_llm = create_llm()

    # Chạy 3 cấu hình
    modes = [
        ("llm_only", "Chỉ dùng duy nhất LLM (LLM-only)"),
        ("z3_1iter", "Tích hợp Z3 Solver (1 Iteration)"),
        ("z3_2iter", "Tích hợp Z3 Solver (2 Iterations)"),
    ]

    all_results: dict[str, list[dict]] = {}
    all_metrics: dict[str, dict] = {}

    output_path = Path("/app/evaluate_layer3_results.json")

    for mode_key, mode_label in modes:
        logger.info("\n" + "━" * 60)
        logger.info("▶ Cấu hình: %s", mode_label)
        logger.info("━" * 60)

        results = []
        for i, tc in enumerate(TEST_CASES):
            logger.info(
                "[%d/%d] %s — %s (GT: %s)",
                i + 1, len(TEST_CASES), tc["node_id"],
                tc["description"], tc["ground_truth"]
            )

            start_time = time.time()
            result = run_layer3_single(
                node_id=tc["node_id"],
                evidence=tc["evidence"],
                cwe_dict_str=cwe_dict_str,
                agent_llm=agent_llm,
                mode=mode_key,
            )
            elapsed = time.time() - start_time
            result["elapsed_seconds"] = round(elapsed, 1)
            result["ground_truth"] = tc["ground_truth"]
            result["description"] = tc["description"]
            results.append(result)

            verdict = "🔴 VULNERABLE" if result["is_flagged_vulnerable"] else "🟢 SAFE"
            correct = (
                (tc["ground_truth"] == "TRUE_POSITIVE" and result["is_flagged_vulnerable"]) or
                (tc["ground_truth"] == "FALSE_POSITIVE" and not result["is_flagged_vulnerable"])
            )
            marker = "✅" if correct else "❌"
            logger.info(
                "  → %s %s (CWE: %s, Sev: %s, Str: %s) [%.1fs] %s",
                verdict, marker,
                result["selected_cwe"], result["severity"],
                result["evidence_strength"], elapsed,
                "CORRECT" if correct else "WRONG"
            )

        all_results[mode_key] = results
        metrics = compute_metrics(results, TEST_CASES)
        all_metrics[mode_label] = metrics

        logger.info(
            "📊 %s: Precision=%.1f%%, Recall=%.1f%%, FP=%d, F1=%.2f",
            mode_label, metrics["Precision"], metrics["Recall"],
            metrics["FP_count"], metrics["F1"]
        )

    # In bảng tổng hợp
    print_table(all_metrics)

    # Lưu kết quả chi tiết ra file
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "repo": REPO_NAME,
        "total_test_cases": len(TEST_CASES),
        "metrics": all_metrics,
        "detailed_results": all_results,
    }
    output_path.write_text(json.dumps(output_data, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Kết quả chi tiết đã lưu tại: %s", output_path)


if __name__ == "__main__":
    main()
