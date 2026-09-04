from dataclasses import dataclass
import os


def _int_from_env(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    parsed = int(raw)
    if parsed < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {parsed}")
    return parsed


@dataclass(frozen=True)
class GitNexusSettings:
    package: str = "gitnexus@latest"
    use_npx: bool = True
    local_cli_path: str = ""
    analyze_timeout_seconds: int = 3600
    medium_timeout_seconds: int = 300
    short_timeout_seconds: int = 120
    serve_base_url: str = "http://localhost:4747"

    @classmethod
    def from_env(cls) -> "GitNexusSettings":
        def env(name: str, default: str) -> str:
            return os.getenv(name, default)

        use_npx = env("GITNEXUS_USE_NPX", "1").strip().lower() not in {"0", "false", "no"}

        return cls(
            package=env("GITNEXUS_PACKAGE", "gitnexus@latest"),
            use_npx=use_npx,
            local_cli_path=env("GITNEXUS_LOCAL_CLI_PATH", ""),
            analyze_timeout_seconds=_int_from_env("GITNEXUS_ANALYZE_TIMEOUT_SECONDS", 3600),
            medium_timeout_seconds=_int_from_env("GITNEXUS_MEDIUM_TIMEOUT_SECONDS", 300),
            short_timeout_seconds=_int_from_env("GITNEXUS_SHORT_TIMEOUT_SECONDS", 120),
            serve_base_url=env("GITNEXUS_SERVE_BASE_URL", "http://localhost:4747"),
        )
