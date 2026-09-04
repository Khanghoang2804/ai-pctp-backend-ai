from __future__ import annotations
from pathlib import Path
from typing import Any, Optional, Protocol, cast
from app.service.queryNodeAndRel import db_nodes
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import json
import torch
import torch.nn.functional as F

# Xác suất lớp vulnerable (label_id == 1 trong model binary hiện tại) phải vượt ngưỡng mới đưa vào kết quả scan.
_LAYER2_VULNERABILITY_PROB_THRESHOLD = 0.8
_LAYER2_VULNERABLE_CLASS_ID = 1

class TokenizerLike(Protocol):
    def __call__(self, text: str | list[str], *, return_tensors: str, truncation: bool, padding: str, max_length: int) -> dict[str, torch.Tensor]: ...

class ModelConfigLike(Protocol):
    id2label: dict[int | str, str]

class ModelOutputLike(Protocol):
    logits: torch.Tensor

class SequenceClassifierLike(Protocol):
    config: ModelConfigLike
    def __call__(self, **inputs: torch.Tensor) -> ModelOutputLike: ...
    def to(self, device: torch.device) -> Any: ...
    def eval(self) -> Any: ...

class ScanLayer2:
    def __init__(self, path: Path, model_path: Path, repo_name: str):
        self.path = path
        self.model_path = Path(model_path)
        self.repo_name = repo_name
        self.scan_results_repo = []
        self.scan_results_file = []
        self._tokenizer: Optional[TokenizerLike] = None
        self._model: Optional[SequenceClassifierLike] = None
        self._device = self._get_device()

    def _get_device(self):
        if torch.cuda.is_available(): return torch.device("cuda")
        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available(): return torch.device("mps")
        return torch.device("cpu")

    def _get_model(self) -> Optional[tuple[TokenizerLike, SequenceClassifierLike]]:
        if self._tokenizer is not None and self._model is not None:
            return self._tokenizer, self._model
        try:
            mp = str(self.model_path)
            self._tokenizer = cast(TokenizerLike, AutoTokenizer.from_pretrained("microsoft/codebert-base", use_fast=False))
            self._model = cast(SequenceClassifierLike, AutoModelForSequenceClassification.from_pretrained(mp))
            self._model.to(self._device)
            self._model.eval()
            print(f"Model loaded from: {mp}")
            print(f"Device: {self._device}")
            print(f"Labels: {self._model.config.id2label}")
            return self._tokenizer, self._model
        except Exception as e:
            print(f"Error warming up model: {e}")
            return None
        
    def get_all_functions_from_db(self) -> list[dict]:
        return db_nodes(repo_name=self.repo_name, label="Function", limit=10000)

    def predict_function_code_batch(self, function_codes: list[str], max_length: int = 512, batch_size: int = 16) -> list[dict]:
        loaded = self._get_model()
        if loaded is None:
            return [{"ok": False, "error": "Model/tokenizer could not be loaded"} for _ in function_codes]
        
        tokenizer, model = loaded
        id2label = model.config.id2label
        
        results = []
        for i in range(0, len(function_codes), batch_size):
            batch_codes = function_codes[i:i + batch_size]
            batch_codes_str = [str(code).strip() if code else "" for code in batch_codes]
            
            # Replace empty strings with a dummy string so tokenizer doesn't crash
            valid_batch_codes_str = [code if code else "pass" for code in batch_codes_str]

            try:
                inputs = tokenizer(
                    valid_batch_codes_str,
                    return_tensors="pt",
                    truncation=True,
                    padding="max_length",
                    max_length=max_length
                )
            except Exception as e:
                for _ in batch_codes:
                    results.append({"ok": False, "error": f"Tokenizer failed: {e}"})
                continue

            inputs = {key: value.to(self._device) for key, value in inputs.items()}

            with torch.no_grad():
                outputs = model(**inputs)
                probs = F.softmax(outputs.logits, dim=-1)

            for j, prob_row in enumerate(probs):
                if not batch_codes_str[j]:
                    results.append({"ok": False, "error": "Empty or null function code"})
                    continue
                
                pred_id = int(torch.argmax(prob_row).item())
                confidence = float(prob_row[pred_id].item())
                
                label = id2label.get(pred_id) or id2label.get(str(pred_id)) or str(pred_id)
                all_scores = {}
                prob_by_label_id = {}
                for idx, score in enumerate(prob_row):
                    label_i = id2label.get(idx) or id2label.get(str(idx)) or str(idx)
                    score_val = float(score.item())
                    all_scores[label_i] = score_val
                    prob_by_label_id[idx] = score_val

                results.append({
                    "ok": True,
                    "label": label,
                    "label_id": pred_id,
                    "confidence": confidence,
                    "scores": all_scores,
                    "prob_by_label_id": prob_by_label_id,
                })
                
        return results

    def predict_function_code(self, function_code: str, max_length: int = 512):
        res = self.predict_function_code_batch([function_code], max_length=max_length)
        return res[0]

    def scan(self) -> list[dict]:
        self.scan_results_file = []
        functions = self.get_all_functions_from_db()
        
        valid_functions = [f for f in functions if f.get("content")]
        contents = [f["content"] for f in valid_functions]
        
        if not valid_functions:
            return []
            
        batch_results = self.predict_function_code_batch(contents, batch_size=16)
        
        for function, result in zip(valid_functions, batch_results):
            if not result.get("ok"):
                continue
            vul_p = result.get("prob_by_label_id", {}).get(_LAYER2_VULNERABLE_CLASS_ID)
            if vul_p is None or vul_p <= _LAYER2_VULNERABILITY_PROB_THRESHOLD:
                continue
            
            self.scan_results_file.append({
                "file_path": function["file_path"],
                "function_name": function["name"],
                "start_line": function["start_line"],
                "end_line": function["end_line"],
                "result": result
            })
            
        return self.scan_results_file
