import subprocess
import sys
from typing import Optional


def run_command(cmd: list[str], timeout: int = 120, stdin_input: Optional[str] = None):
    """
    Centralized subprocess runner.

    Args:
        cmd: Command and arguments list.
        timeout: Subprocess timeout in seconds.
        stdin_input: If provided, pipe this string to the process stdin
                     (e.g., for tools like waybackurls that read from stdin).
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

    proc = subprocess.run(cmd, **kwargs)
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