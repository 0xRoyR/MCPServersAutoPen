import os
import subprocess
import sys
import threading
import time
from typing import Optional

# Set MCP_LIVE_OUTPUT=0 to suppress live terminal streaming (default: on)
_LIVE = os.environ.get("MCP_LIVE_OUTPUT", "1").strip() not in ("0", "false", "no")

# ANSI color codes
_C_CMD    = "\033[96m"   # cyan   — command line
_C_STDOUT = "\033[0m"    # reset  — stdout (normal)
_C_STDERR = "\033[33m"   # yellow — stderr
_C_META   = "\033[90m"   # grey   — exit/elapsed
_C_WARN   = "\033[31m"   # red    — timeout/error
_C_RESET  = "\033[0m"


def _print(msg: str) -> None:
    print(msg, flush=True)


def run_command(cmd: list[str], timeout: int = 120, stdin_input: Optional[str] = None):
    """
    Centralized subprocess runner with live terminal output.

    Prints every line of stdout/stderr to the MCP server terminal in real time
    as the tool runs — exactly as if you had typed the command yourself.

    Disable live output with: MCP_LIVE_OUTPUT=0
    """
    cmd_str = " ".join(str(c) for c in cmd)

    if _LIVE:
        _print(f"\n{_C_CMD}$ {cmd_str}{_C_RESET}")

    kwargs: dict = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "shell": False,
    }

    if stdin_input is not None:
        kwargs["stdin"] = subprocess.PIPE
    else:
        kwargs["stdin"] = subprocess.DEVNULL

    # On Windows, prevent subprocess from opening its own console window
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    def _read_stream(stream, lines: list[str], color: str) -> None:
        """Read a stream line-by-line, print live, and accumulate."""
        for raw_line in stream:
            line = raw_line.rstrip("\n")
            lines.append(line)
            if _LIVE:
                _print(f"{color}{line}{_C_RESET}")

    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(cmd, **kwargs)

        t_out = threading.Thread(target=_read_stream,
                                 args=(proc.stdout, stdout_lines, _C_STDOUT),
                                 daemon=True)
        t_err = threading.Thread(target=_read_stream,
                                 args=(proc.stderr, stderr_lines, _C_STDERR),
                                 daemon=True)
        t_out.start()
        t_err.start()

        if stdin_input is not None:
            try:
                proc.stdin.write(stdin_input)
                proc.stdin.close()
            except BrokenPipeError:
                pass

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            t_out.join(timeout=5)
            t_err.join(timeout=5)
            elapsed = time.monotonic() - t0
            if _LIVE:
                _print(f"{_C_WARN}[TIMEOUT after {elapsed:.1f}s — process killed]{_C_RESET}")
            raise

        t_out.join()
        t_err.join()

    except subprocess.TimeoutExpired:
        raise
    except Exception as exc:
        elapsed = time.monotonic() - t0
        if _LIVE:
            _print(f"{_C_WARN}[ERROR after {elapsed:.1f}s]: {exc}{_C_RESET}")
        raise

    elapsed = time.monotonic() - t0
    if _LIVE:
        _print(f"{_C_META}[exit={proc.returncode}  elapsed={elapsed:.2f}s]{_C_RESET}")

    return proc.returncode, "\n".join(stdout_lines), "\n".join(stderr_lines)
