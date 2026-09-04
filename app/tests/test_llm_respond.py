from __future__ import annotations

import sys
from pathlib import Path

# ── sys.path fix ───────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parents[2]   # .../ai-pctp/
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
# ──────────────────────────────────────────────────────────────────────────────

import argparse
import json
import logging
import os
import re
import textwrap
from typing import Optional

from app.service.ScanLayer3 import (
    AffectedChild,
    ExplainInput,
    NodeInfo,
    OtherBug,
    QwenLLMClient,
    ScanLayer3,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# Fix UnicodeEncodeError trên Windows terminal (cp1252 không hỗ trợ tiếng Việt)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ── API Configuration ─────────────────────────────────────────────────────────

os.environ.setdefault("OPENAI_BASE_URL", "https://ckey.vn/v1")
os.environ.setdefault("OPENAI_MODEL",    "qwen3-coder-next")


# ── Mock Data ─────────────────────────────────────────────────────────────────

CWE_ID = "CWE-89"
CWE_NAME = "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
CWE_DESCRIPTION = (
    "The application constructs an SQL query using externally-influenced input "
    "from an upstream component without properly neutralizing special elements "
    "that could modify the intended SQL command. In this TypeScript/Node.js "
    "Express API, user-controlled query parameters are concatenated directly "
    "into a raw SQL string, allowing an attacker to manipulate the query "
    "structure, bypass authentication, and exfiltrate or modify database data."
)

SQL_INJECT_CODE = """\
import { Request, Response } from 'express';
import { db } from '../db/database';

// ⚠️  CWE-89: SQL Injection — user input không được sanitize
async function getUserProfile(req: Request, res: Response): Promise<void> {
  const userId = req.query.id;                              // attacker-controlled
  const query = `SELECT * FROM users WHERE id = '${userId}'`;  // string concat!
  const result = await db.query(query);                    // raw SQL execution
  res.json(result.rows[0]);                                // full row exposed
}

export { getUserProfile };
"""

OTHER_BUGS = [
    OtherBug(
        cwe_id="CWE-20",
        cwe_name="Improper Input Validation",
        cwe_description=(
            "The `id` parameter from `req.query.id` is never validated for type, "
            "format, or length before being embedded into the SQL query. "
            "An attacker can supply arbitrary strings including SQL metacharacters "
            "(`'`, `--`, `;`, `UNION`, `OR 1=1`) without any rejection."
        ),
        affected_node_id=None,
        affected_node_name=None,
        severity="High",
    ),
    OtherBug(
        cwe_id="CWE-200",
        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
        cwe_description=(
            "The endpoint returns the full database row (`result.rows[0]`) "
            "directly to the client without field filtering. Combined with SQL "
            "Injection, an attacker can issue a `UNION SELECT` to read from "
            "arbitrary tables (passwords, tokens) and receive sensitive data "
            "verbatim in the HTTP response."
        ),
        affected_node_id="Component:src/models/User.ts",
        affected_node_name="User",
        severity="High",
    ),
]


# ── LLM Client (ckey.vn API) ──────────────────────────────────────────────────

class CKeyLLMClient(QwenLLMClient):
    """
    LLM client gọi API ckey.vn qua OpenAI-compatible endpoint.

    Endpoint : https://ckey.vn/v1
    Model    : qwen3-coder-next
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 180,
    ) -> None:
        super().__init__(
            api_key=api_key or os.getenv("OPENAI_API_KEY"),
            base_url=base_url or os.getenv("OPENAI_BASE_URL"),
            model=model or os.getenv("OPENAI_MODEL"),
            timeout=timeout,
        )
        logger.info(
            "CKeyLLMClient — base_url=%s  model=%s  timeout=%ds",
            self.base_url, self.model, self.timeout,
        )


# ── Input Builder (từ mock data) ──────────────────────────────────────────────

def build_explain_input() -> ExplainInput:
    """Xây dựng ExplainInput trực tiếp từ mock data định nghĩa trong file."""
    root_node_info = NodeInfo(
        node_id="Function:src/controllers/userController.ts:getUserProfile",
        label="Function",
        name="getUserProfile",
        start_line=5,
        end_line=11,
        description=(
            "Express REST handler truy vấn thông tin người dùng theo ID từ query string. "
            "Không sanitize hoặc parameterize input trước khi nhúng vào câu lệnh SQL."
        ),
        is_exported=True,
    )

    affected_children: list[AffectedChild] = [
        AffectedChild(
            node_id="Component:src/db/database.ts",
            name="database",
            label="Component",
            relation_type="IMPORTS",
            file_path="src/db/database.ts",
            start_line=1,
            end_line=None,
        ),
        AffectedChild(
            node_id="Component:src/models/User.ts",
            name="User",
            label="Component",
            relation_type="IMPORTS",
            file_path="src/models/User.ts",
            start_line=1,
            end_line=None,
        ),
    ]

    return ExplainInput(
        cwe_id=CWE_ID,
        cwe_name=CWE_NAME,
        cwe_description=CWE_DESCRIPTION,
        node_info=root_node_info,
        file_path="src/controllers/userController.ts",
        line_code=SQL_INJECT_CODE,
        other_bugs=OTHER_BUGS,
        affected_children=affected_children,
    )


# ── Output Printer ────────────────────────────────────────────────────────────

def extract_json_from_text(text: str) -> Optional[dict]:
    cleaned = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", cleaned, flags=re.DOTALL)
    if fenced:
        cleaned = fenced.group(1).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError:
        return None


def print_result(result) -> None:
    print("\n" + "=" * 72)
    print("MODEL RESPONSE RESULT")
    print("=" * 72)

    print(f"Node       : {result.node_id}")
    print(f"File       : {result.file_path}")
    print(f"CWE        : {result.cwe_id} - {result.cwe_name}")
    print(f"Severity   : {result.severity}")
    print(f"CVSS       : {result.cvss_estimate}")

    print("\nROOT CAUSE")
    print("-" * 72)
    print(textwrap.fill(result.root_cause or "", width=88))

    print("\nEXPLOIT SCENARIO")
    print("-" * 72)
    print(textwrap.fill(result.exploit_scenario or "", width=88))

    print("\nDIRECT IMPACT")
    print("-" * 72)
    print(textwrap.fill(result.direct_impact or "", width=88))

    print("\nCHILD IMPACT")
    print("-" * 72)
    for item in result.child_impact:
        node_name = item.get("node_name") or item.get("node_id")
        relation_type = item.get("relation_type", "UNKNOWN")
        impact = item.get("impact", "")
        print(f"\n[{relation_type}] {node_name}")
        print(textwrap.fill(impact, width=88, initial_indent="  ", subsequent_indent="  "))

    print("\nCOMPOUNDING RISKS")
    print("-" * 72)
    for index, risk in enumerate(result.compounding_risks, start=1):
        print(f"{index}. {textwrap.fill(risk, width=84)}")

    print("\nREMEDIATION STEPS")
    print("-" * 72)
    for step in result.remediation_steps:
        print(f"- {textwrap.fill(step, width=84)}")

    if result.secure_code_example:
        print("\nSECURE CODE EXAMPLE")
        print("-" * 72)
        print(result.secure_code_example.replace("\\n", "\n").replace('\\"', '"'))

    print("\nREFERENCES")
    print("-" * 72)
    for ref in result.references:
        print(f"- {ref}")


# ── Runner ────────────────────────────────────────────────────────────────────

def run(timeout: int, preview_prompt: bool) -> None:
    explain_input = build_explain_input()

    llm = CKeyLLMClient(timeout=timeout)
    service = ScanLayer3(repo_name="mock", llm_client=llm)

    print("\n" + "=" * 72)
    print("LLM VULNERABILITY REASONING  —  ckey.vn API")
    print("=" * 72)
    print("Data      : (mock data, no file)")
    print(f"Model     : {llm.model}")
    print(f"Endpoint  : {llm.base_url}")
    print(f"Timeout   : {llm.timeout}s")
    print(f"Nodes     : {len(explain_input.affected_children) + 1}")
    print("=" * 72)

    if preview_prompt:
        print("\nPROMPT PREVIEW")
        print("-" * 72)
        print(json.dumps(service.preview_messages(explain_input), ensure_ascii=False, indent=2))

    result = service.explain_one(explain_input)
    print_result(result)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run LLM Vulnerability Reasoning via ckey.vn API (qwen3-coder-next)."
    )

    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Override model name. Mặc định lấy từ OPENAI_MODEL env var (qwen3-coder-next).",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Timeout HTTP tính bằng giây. Mặc định: 180.",
    )

    parser.add_argument(
        "--preview-prompt",
        action="store_true",
        help="In prompt trước khi gọi API.",
    )

    args = parser.parse_args()

    if args.model:
        os.environ["OPENAI_MODEL"] = args.model

    run(
        timeout=args.timeout,
        preview_prompt=args.preview_prompt,
    )


if __name__ == "__main__":
    main()
