import subprocess


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
