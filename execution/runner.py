import os
import subprocess
import sys
import time
from typing import Optional

# Set MCP_DEBUG=1 (or pass --debug to server_http.py) to get full command
# tracing: the exact command run, elapsed time, return code, and stdout/stderr.
_DEBUG = os.environ.get("MCP_DEBUG", "0").strip() in ("1", "true", "yes")

# Max chars of stdout/stderr printed in debug mode (keeps console readable)
_DEBUG_OUTPUT_LIMIT = int(os.environ.get("MCP_DEBUG_OUTPUT_LIMIT", "2000"))


def _dbg(msg: str) -> None:
    """Print a debug message with a [MCP-DBG] prefix to stdout."""
    print(f"[MCP-DBG] {msg}", flush=True)


def run_command(cmd: list[str], timeout: int = 120, stdin_input: Optional[str] = None):
    """
    Centralized subprocess runner.

    Args:
        cmd: Command and arguments list.
        timeout: Subprocess timeout in seconds.
        stdin_input: If provided, pipe this string to the process stdin
                     (e.g., for tools like waybackurls that read from stdin).

    When MCP_DEBUG=1 is set, prints the full command, elapsed time, return
    code, and truncated stdout/stderr to stdout so you can see what tools
    are actually doing in real time.
    """
    kwargs: dict = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "shell": False,
    }

    if stdin_input is not None:
        kwargs["input"] = stdin_input
    else:
        kwargs["stdin"] = subprocess.DEVNULL  # Prevent hanging on input

    # On Windows, prevent subprocess from inheriting console
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    if _DEBUG:
        cmd_str = " ".join(str(c) for c in cmd)
        _dbg(f"CMD  : {cmd_str}")
        _dbg(f"TIMEOUT: {timeout}s")

    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired as e:
        elapsed = time.monotonic() - t0
        if _DEBUG:
            _dbg(f"TIMEOUT after {elapsed:.1f}s")
        raise
    elapsed = time.monotonic() - t0

    if _DEBUG:
        _dbg(f"DONE : exit={proc.returncode}  elapsed={elapsed:.2f}s")
        if proc.stdout and proc.stdout.strip():
            preview = proc.stdout[:_DEBUG_OUTPUT_LIMIT]
            truncated = len(proc.stdout) > _DEBUG_OUTPUT_LIMIT
            _dbg(f"STDOUT ({len(proc.stdout)} chars{', truncated' if truncated else ''}):\n{preview}")
        else:
            _dbg("STDOUT: (empty)")
        if proc.stderr and proc.stderr.strip():
            preview = proc.stderr[:_DEBUG_OUTPUT_LIMIT]
            truncated = len(proc.stderr) > _DEBUG_OUTPUT_LIMIT
            _dbg(f"STDERR ({len(proc.stderr)} chars{', truncated' if truncated else ''}):\n{preview}")
        else:
            _dbg("STDERR: (empty)")

    return proc.returncode, proc.stdout, proc.stderr


'''
def run_command(
    cmd: list[str],
    timeout: int = 120,
) -> tuple[int, str, str]:
    """
    Centralized subprocess runner.
    """

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    return proc.returncode, proc.stdout, proc.stderr
'''