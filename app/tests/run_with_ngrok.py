
from __future__ import annotations

import os
import socket
import sys
import threading
import time
from pathlib import Path

# ai-pctp repo root (parent of package `app/`)
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _wait_port(host: str, port: int, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main() -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv(_PROJECT_ROOT / "app" / ".env")
    except ImportError:
        pass

    port = int(os.environ.get("PORT", "8000"))
    token = os.environ.get("NGROK_AUTHTOKEN", "").strip()
    if not token:
        sys.exit(
            "Thiếu NGROK_AUTHTOKEN.\n"
            "  Lấy token: https://dashboard.ngrok.com/get-started/your-authtoken\n"
            "  export NGROK_AUTHTOKEN='<token>'"
        )

    from pyngrok import conf, ngrok
    import uvicorn

    conf.get_default().auth_token = token

    def run_server() -> None:
        uvicorn.run(
            "app.main:app",
            host="127.0.0.1",
            port=port,
        )

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()

    if not _wait_port("127.0.0.1", port):
        sys.exit(f"API không lắng nghe được trên 127.0.0.1:{port} sau khi khởi động.")

    tunnel = ngrok.connect(port, proto="http")
    print("Ngrok public URL:", tunnel.public_url)
    print(f"Local API: http://127.0.0.1:{port}")

    try:
        thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        ngrok.kill()


if __name__ == "__main__":
    main()
