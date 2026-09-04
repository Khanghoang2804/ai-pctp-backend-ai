import os

# ── Cấu hình API ckey.vn ──────────────────────────────────────────────────────
# Có thể override bằng biến môi trường shell trước khi chạy script.
os.environ.setdefault("OPENAI_BASE_URL", "https://ckey.vn/v1")
os.environ.setdefault("OPENAI_MODEL",    "qwen3-coder-next")

import json
import urllib.request

BASE_URL = os.environ["OPENAI_BASE_URL"].rstrip("/")
MODEL    = os.environ["OPENAI_MODEL"]
API_KEY  = os.environ["OPENAI_API_KEY"]

messages = [
    {"role": "user", "content": "Who are you?"},
]

payload = json.dumps({
    "model":      MODEL,
    "messages":   messages,
    "max_tokens": 40,
    "temperature": 0.1,
}).encode("utf-8")

req = urllib.request.Request(
    f"{BASE_URL}/chat/completions",
    data=payload,
    headers={
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {API_KEY}",
    },
    method="POST",
)

with urllib.request.urlopen(req, timeout=120) as resp:
    data = json.loads(resp.read().decode("utf-8"))

print(data["choices"][0]["message"]["content"])
