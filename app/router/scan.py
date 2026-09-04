from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

from app.schema.scan import ScanLayersRequest, ScanLayersResponse
from app.service.ScanLayers import ScanLayers


router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("/layers", response_model=ScanLayersResponse)
def scan_layers(payload: ScanLayersRequest) -> dict[str, Any]:
    repo_root = Path(payload.repo_root).expanduser().resolve()
    if not repo_root.exists():
        raise HTTPException(status_code=404, detail=f"repo_root not found: {repo_root}")
    if not repo_root.is_dir():
        raise HTTPException(status_code=422, detail=f"repo_root is not a directory: {repo_root}")

    codeql_root_env = os.getenv("SCAN_CODEQL_ROOT", "").strip()
    codeql_root = Path(codeql_root_env).expanduser().resolve() if codeql_root_env else repo_root
    if codeql_root is not None and not codeql_root.is_dir():
        raise HTTPException(status_code=422, detail=f"codeql_root is not a directory: {codeql_root}")

    model_path_env = os.getenv("SCAN_MODEL_PATH", "").strip()
    model_path = Path(model_path_env).expanduser().resolve() if model_path_env else (
        Path(__file__).resolve().parents[1] / "service" / "codebert-binary-final_v69_"
    )
    if not model_path.exists():
        raise HTTPException(status_code=404, detail=f"model_path not found: {model_path}")

    prompt_dump_dir = (
        Path(payload.prompt_dump_dir).expanduser().resolve()
        if payload.prompt_dump_dir
        else None
    )

    try:
        scanner = ScanLayers(
            repo_name=payload.repo_name,
            root=repo_root,
            codeql_root=codeql_root,
            model_path=model_path,
            prompt_dump_dir=prompt_dump_dir,
        )
        limit = None if payload.layer3_limit == 0 else payload.layer3_limit
        return scanner.scan_with_layer3(
            limit=limit,
            depth=payload.depth,
            debug_prompt=payload.debug_prompt,
            repository=False,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
