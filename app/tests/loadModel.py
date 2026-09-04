from pathlib import Path
from typing import Optional, Tuple
from app.service.queryNodeAndRel import db_nodes
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import torch.nn.functional as F
import json


class ScanLayer2:
    def __init__(self, path: Path, model_path: Path):
        self.path = path
        self.scan_results_cwe = []
        self.model_path = Path(model_path)
        self.repo_name = None
        self.scan_results_repo = []
        self.scan_results_file = []
        self._tokenizer: Optional[object] = None
        self._model: Optional[object] = None
        self._device = self._get_device()

    def _get_device(self):
        if torch.cuda.is_available():
            return torch.device("cuda")

        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            return torch.device("mps")

        return torch.device("cpu")

    def _get_model(self) -> Optional[Tuple[object, object]]:
        if self._tokenizer is not None and self._model is not None:
            return self._tokenizer, self._model

        try:
            mp = str(self.model_path)

            # Ưu tiên load tokenizer gốc để tránh lỗi tokenizer.json version mismatch
            self._tokenizer = AutoTokenizer.from_pretrained(
                "microsoft/codebert-base",
                use_fast=False
            )

            # Load model fine-tuned local
            self._model = AutoModelForSequenceClassification.from_pretrained(mp)
            self._model.to(self._device)
            self._model.eval()

            print(f"Model loaded from: {mp}")
            print(f"Device: {self._device}")
            print(f"Labels: {self._model.config.id2label}")

            return self._tokenizer, self._model

        except Exception as e:
            print(f"Error warming up model: {e}")
            return None

    def predict_function_code(self, function_code: str, max_length: int = 512):
        loaded = self._get_model()

        if loaded is None:
            return {
                "ok": False,
                "error": "Model/tokenizer could not be loaded"
            }

        tokenizer, model = loaded

        inputs = tokenizer(
            function_code,
            return_tensors="pt",
            truncation=True,
            padding="max_length",
            max_length=max_length
        )

        inputs = {
            key: value.to(self._device)
            for key, value in inputs.items()
        }

        with torch.no_grad():
            outputs = model(**inputs)
            probs = F.softmax(outputs.logits, dim=-1)[0]
            pred_id = int(torch.argmax(probs).item())
            confidence = float(probs[pred_id].item())

        id2label = model.config.id2label

        # config id2label đôi khi key là int, đôi khi là string
        label = id2label.get(pred_id) or id2label.get(str(pred_id)) or str(pred_id)

        all_scores = {}
        for i, score in enumerate(probs):
            label_i = id2label.get(i) or id2label.get(str(i)) or str(i)
            all_scores[label_i] = float(score.item())

        return {
            "ok": True,
            "label": label,
            "label_id": pred_id,
            "confidence": confidence,
            "scores": all_scores
        }

    def predict_mock_function(self):
        mock_function = """
def add(a, b):
    return a + b

"""

        result = self.predict_function_code(mock_function)

        print("Mock function prediction:")
        print(json.dumps(result, indent=2))

        return result


if __name__ == "__main__":
    model_path = Path(__file__).parent.parent / "service" / "codebert-binary-final_v69_"

    scanner = ScanLayer2(Path("."), model_path)

    scanner._get_model()
    cmd_mock = """
    import os

    def run_command(user_input):
        os.system(user_input)
    """
    result = scanner.predict_function_code(cmd_mock)
    print(f'cmd_mock 1: {cmd_mock}')
    print(json.dumps( result, indent=2))
    cmd_mock = """
import os
from flask import request

def run_command():
    user_input = request.args.get("cmd")
    os.system(user_input)
"""
    print(f'cmd_mock 2: {cmd_mock}')
    result = scanner.predict_function_code(cmd_mock)
    print(json.dumps(result, indent=2))