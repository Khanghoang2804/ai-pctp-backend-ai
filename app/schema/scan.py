from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScanLayersRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    repo_name: str = Field(..., min_length=1)
    repo_root: str = Field(..., min_length=1)
    prompt_dump_dir: Optional[str] = None
    layer3_limit: int = Field(default=0, ge=0)
    depth: int = Field(default=2, ge=1, le=3)
    debug_prompt: bool = False

    @field_validator("repo_root", "prompt_dump_dir")
    @classmethod
    def expand_user_path(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return str(Path(value).expanduser())


class ScanLayersResponse(BaseModel):
    scan_results: list[dict[str, Any]]
    layer3_results: list[dict[str, Any]]
