import subprocess
import sys


def run_command(cmd: list[str], timeout: int = 120):
    # Build kwargs for subprocess
    kwargs = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "shell": False,
        "stdin": subprocess.DEVNULL,  # Prevent waiting for input
    }

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