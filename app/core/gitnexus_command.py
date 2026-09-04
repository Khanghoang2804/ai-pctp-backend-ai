import os
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from enum import Enum
from shutil import which
from typing import Callable, Optional, TextIO


class CommandErrorCode(str, Enum):
    INVALID_WORKDIR = "invalid_workdir"
    INVALID_REPO = "invalid_repo"
    BINARY_NOT_FOUND = "binary_not_found"
    TIMEOUT = "timeout"
    NON_ZERO_EXIT = "non_zero_exit"
    EXECUTION_ERROR = "execution_error"


class CommandRunError(Exception):
    def __init__(
        self,
        message: str,
        code: CommandErrorCode,
        *,
        command: Optional[list[str]] = None,
        cwd: Optional[str] = None,
        stdout: str = "",
        stderr: str = "",
        returncode: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.command = command or []
        self.cwd = cwd
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


@dataclass
class CommandResult:
    command: list[str]
    cwd: str
    stdout: str
    stderr: str
    returncode: int


def _raise_error(
    message: str,
    code: CommandErrorCode,
    *,
    command: Optional[list[str]] = None,
    cwd: Optional[str] = None,
    stdout: str = "",
    stderr: str = "",
    returncode: Optional[int] = None,
) -> None:
    raise CommandRunError(
        message,
        code,
        command=command,
        cwd=cwd,
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
    )


def _validate_working_directory(cwd: str, require_git_repo: bool) -> Path:
    working_dir = Path(cwd).resolve()
    if not working_dir.exists() or not working_dir.is_dir():
        _raise_error(
            f"Working directory does not exist: {working_dir}",
            CommandErrorCode.INVALID_WORKDIR,
            cwd=str(working_dir),
        )
    if require_git_repo and not (working_dir / ".git").exists():
        _raise_error(
            f"Not a git repository (missing .git): {working_dir}",
            CommandErrorCode.INVALID_REPO,
            cwd=str(working_dir),
        )
    return working_dir


def _validate_command_binary(command: list[str]) -> None:
    if not command:
        _raise_error("Empty command received", CommandErrorCode.EXECUTION_ERROR)
    executable = command[0]
    if which(executable) is None:
        _raise_error(
            f"Required executable was not found in PATH: {executable}",
            CommandErrorCode.BINARY_NOT_FOUND,
            command=command,
        )


def run_command(
    command: list[str],
    cwd: str,
    timeout_seconds: int = 600,
    env: Optional[dict[str, str]] = None,
    require_git_repo: bool = False,
) -> CommandResult:
    working_dir = _validate_working_directory(cwd, require_git_repo)
    _validate_command_binary(command)

    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    try:
        result = subprocess.run(
            command,
            cwd=str(working_dir),
            env=full_env,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        _raise_error(
            f"Command timeout after {timeout_seconds}s: {' '.join(command)}",
            CommandErrorCode.TIMEOUT,
            command=command,
            cwd=str(working_dir),
            stdout=(exc.stdout or ""),
            stderr=(exc.stderr or ""),
        )
    except OSError as exc:
        _raise_error(
            f"Failed to execute command: {' '.join(command)} ({exc})",
            CommandErrorCode.EXECUTION_ERROR,
            command=command,
            cwd=str(working_dir),
        )

    output = CommandResult(
        command=command,
        cwd=str(working_dir),
        stdout=result.stdout,
        stderr=result.stderr,
        returncode=result.returncode,
    )

    if result.returncode != 0:
        _raise_error(
            "Command failed\n"
            f"Command: {' '.join(command)}\n"
            f"CWD: {working_dir}\n"
            f"Return code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}",
            CommandErrorCode.NON_ZERO_EXIT,
            command=command,
            cwd=str(working_dir),
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )

    return output

