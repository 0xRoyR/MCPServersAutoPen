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

    Non-UTF-8 bytes are replaced with '?' rather than crashing.
    If a stream reader thread hits any error it logs the problem and returns
    whatever output it accumulated up to that point — the process keeps running
    and the other stream keeps being read.

    Disable live output with: MCP_LIVE_OUTPUT=0
    """
    cmd_str = " ".join(str(c) for c in cmd)

    if _LIVE:
        if stdin_input is not None:
            # Show piped input inline so the full invocation is visible in the terminal,
            # e.g. `$ echo 'example.com' | waybackurls` instead of just `$ waybackurls`
            stdin_preview = stdin_input.strip()[:120].replace("\n", " ")
            _print(f"\n{_C_CMD}$ echo '{stdin_preview}' | {cmd_str}{_C_RESET}")
        else:
            _print(f"\n{_C_CMD}$ {cmd_str}{_C_RESET}")

    kwargs: dict = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        # Binary mode — we decode manually with errors='replace' so bad bytes
        # (e.g. from gobuster scanning paths with non-UTF-8 chars) never crash us.
        "text": False,
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

    def _read_stream(stream, lines: list[str], color: str, label: str) -> None:
        """
        Read a binary stream line-by-line, decode with replacement for bad bytes,
        print live, and accumulate. Any exception is caught so the thread always
        exits cleanly — partial output accumulated so far is preserved in `lines`.
        """
        try:
            for raw_bytes in stream:
                line = raw_bytes.rstrip(b"\n").decode("utf-8", errors="replace")
                lines.append(line)
                if _LIVE:
                    _print(f"{color}{line}{_C_RESET}")
        except Exception as exc:
            # Log the error but don't re-raise — preserves everything read so far
            err_msg = f"[{label} reader error: {exc}]"
            lines.append(err_msg)
            if _LIVE:
                _print(f"{_C_WARN}{err_msg}{_C_RESET}")

    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(cmd, **kwargs)

        t_out = threading.Thread(target=_read_stream,
                                 args=(proc.stdout, stdout_lines, _C_STDOUT, "stdout"),
                                 daemon=True)
        t_err = threading.Thread(target=_read_stream,
                                 args=(proc.stderr, stderr_lines, _C_STDERR, "stderr"),
                                 daemon=True)
        t_out.start()
        t_err.start()

        if stdin_input is not None:
            try:
                proc.stdin.write(stdin_input.encode("utf-8", errors="replace"))
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
