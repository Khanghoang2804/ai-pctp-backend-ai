from pathlib import Path
import argparse
import json

from app.service.ScanLayer1 import ScanLayer1, UPLOADS_DIR
from app.service.ScanLayer2 import ScanLayer2
from app.service.ScanLayer3 import ScanLayer3


class ScanLayers:
    def __init__(
        self,
        repo_name: str,
        model_path: Path,
        root: Path | None = None,
        codeql_root: Path | None = None,
        cwe_dictionary_path: str | Path | None = None,
        prompt_dump_dir: str | Path | None = None,
    ):
        resolved_root = root or (
            UPLOADS_DIR / repo_name if (UPLOADS_DIR / repo_name).exists() else Path(".")
        )
        self.scan_layer1 = ScanLayer1(repo_name, resolved_root, codeql_root=codeql_root)
        self.scan_layer2 = ScanLayer2(resolved_root, model_path, repo_name)
        self.scan_layer3 = ScanLayer3(
            repo_name,
            cwe_dictionary_path=cwe_dictionary_path,
            prompt_dump_dir=prompt_dump_dir,
            repo_root=resolved_root,
        )
        self.scan_results: list[dict] = []
        self.layer3_results: list[dict] = []

    def scan(self):
        layer1 = self.scan_layer1.run_scan()
        layer2 = self.scan_layer2.scan()
        self.scan_results = layer1 + layer2
        return self.scan_results

    def scan_with_layer3(
        self,
        limit: int | None = None,
        depth: int = 2,
        debug_prompt: bool = False,
        repository: bool = False,
    ):
        self.scan()
        if repository:
            repo_result = self.scan_layer3.scan_repository_findings(
                self.scan_results,
                depth=depth,
                debug_prompt=debug_prompt,
            )
            return {
                "scan_results": self.scan_results,
                "layer3_repository": repo_result,
            }

        self.layer3_results = self.scan_layer3.scan_layer_results(
            self.scan_results,
            limit=limit,
            depth=depth,
            debug_prompt=debug_prompt,
        )

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
            "SEC295": "CWE-295"
        }

        flat_layer1 = []
        for file_item in self.scan_results:
            file_path = file_item.get("file_path", "")
            for finding in file_item.get("findings", []):
                for rule in finding.get("rules", []):
                    # Map the category to a standard CWE ID, fallback to rule_id (SECXXX)
                    cwe_id = CWE_MAP.get(rule.get("category", ""), rule.get("rule_id", "UNKNOWN"))
                    
                    flat_layer1.append({
                        "node_id": f"File:{file_path}",
                        "file_path": file_path,
                        "selected_cwe_id": cwe_id,
                        "selected_cwe_name": rule.get("name", "Vulnerability"),
                        "severity": str(rule.get("severity", "High")).capitalize(),
                        "selected_cwe_reason": f"Dòng {finding.get('line')}: {rule.get('description', '')}\nCode: {finding.get('line_content', '').strip()}",
                        "root_cause": f"Phát hiện bởi Layer 1 (Hard Rule): Dữ liệu hoặc cấu hình không an toàn tại dòng {finding.get('line')} của file {file_path}. {rule.get('description', '')}",
                        "attack_path": "Lỗ hổng này có thể bị khai thác trực tiếp nếu điểm yếu nằm trên luồng dữ liệu mà người dùng có thể can thiệp, hoặc bị dùng làm bước đệm cho một cuộc tấn công chuỗi.",
                        "impact": f"Nguy cơ rò rỉ dữ liệu, chiếm quyền điều khiển hoặc lỗi hệ thống tùy thuộc vào bối cảnh (Mức độ: {str(rule.get('severity', 'High')).capitalize()}).",
                        "remediation": rule.get("recommendation", "Tuân thủ các nguyên tắc mã hóa an toàn và kiểm tra kỹ đầu vào dữ liệu."),
                        "secure_code_example": f"// Hãy thay thế mã lỗi tại dòng {finding.get('line')} bằng các hàm an toàn hơn.\n// Tham khảo: {rule.get('recommendation', 'Kiểm tra kỹ lưỡng các tham số đầu vào và tránh hardcode dữ liệu nhạy cảm.')}",
                        "layer1_raw": True
                    })

        combined_results = self.layer3_results + flat_layer1

        return {
            "scan_results": self.scan_results,
            "layer3_results": combined_results,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run ScanLayer1, ScanLayer2, and ScanLayer3 (full pipeline).")
    parser.add_argument("--repo-name", default="aicaller")
    parser.add_argument("--repo-root", default=".", help="Repository root path for layer 1 file reads.")
    parser.add_argument("--codeql-root", default=None, help="Thư mục CodeQL scan (mặc định dùng --repo-root). Vd: app/")
    parser.add_argument("--model-path", default=str(Path(__file__).parent / "codebert-binary-final_v69_"))
    parser.add_argument("--cwe-dictionary", default=None)
    parser.add_argument(
        "--layer3-limit",
        type=int,
        default=0,
        help="Số item trong scan_results xử lý tuần tự (per-file graph). 0 = tất cả.",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=2,
        help="BFS depth cho db_node_graph (Layer 3). GitNexus clamp 1–3. Mặc định 2 để thấy CALLS/IMPORTS cross-file.",
    )
    parser.add_argument("--debug-prompt", action="store_true", help="In toàn bộ prompt gửi cho LLM trước khi call API.")
    parser.add_argument(
        "--prompt-dump-dir",
        default=None,
        help="Thư mục ghi JSON prompt trước khi gọi LLM (mặc định: scan_layer3_prompts/ hoặc SCAN_LAYER3_PROMPT_DIR).",
    )
    parser.add_argument("--output", default=None, help="Ghi kết quả ra file JSON (vd: output.json). Mặc định chỉ in ra stdout.")
    args = parser.parse_args()

    model_path = Path(args.model_path) if args.model_path else Path(__file__).parent / "codebert-binary-final_v69_"

    scan_layers = ScanLayers(
        repo_name=args.repo_name,
        root=Path(args.repo_root),
        codeql_root=Path(args.codeql_root) if args.codeql_root else None,
        model_path=model_path,
        cwe_dictionary_path=args.cwe_dictionary,
        prompt_dump_dir=args.prompt_dump_dir,
    )

    limit = None if args.layer3_limit == 0 else args.layer3_limit
    output = scan_layers.scan_with_layer3(
        limit=limit,
        depth=args.depth,
        debug_prompt=args.debug_prompt,
        repository=False,
    )

    output_text = json.dumps(output, indent=2, ensure_ascii=False)
    print(output_text)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_text, encoding="utf-8")
        print(f"\nSaved to: {out_path}", flush=True)
