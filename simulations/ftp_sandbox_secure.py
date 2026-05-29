"""
Local sandbox FTP server with anonymous login DISABLED — the "fixed" counterpart
to ftp_sandbox_vulnerable.py. Use it to test the recheck agent's FIXED verdict.

The server is fully up and serving (it answers the 220 banner and accepts a real
user), but it has NO anonymous account — so an anonymous login attempt is met with
an FTP 530 rejection. That maps to:

    run_ftp_anon_check  → anonymous_allowed=False, login_refused=True
    recheck agent       → verdict "fixed"  (server reachable, anon explicitly refused)

Contrast with the three FTP states the recheck agent distinguishes:
    ftp_sandbox_vulnerable.py running → anonymous_allowed=True  → "vulnerable"
    ftp_sandbox_secure.py running     → login_refused=True      → "fixed"      (this file)
    nothing listening on :21        → connection refused       → "inconclusive"

Install:
    pip install pyftpdlib

Run (port 21 needs root/admin):
    sudo python simulations/ftp_sandbox_secure.py
    python simulations/ftp_sandbox_secure.py --port 2121     # high port, no sudo

A real user is configured (default ftpuser/ftppass) so the service behaves like a
genuine, functioning FTP server that simply has anonymous access turned off.
"""

import argparse
import os
import tempfile

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


def main():
    ap = argparse.ArgumentParser(description="Sandbox FTP server with anonymous login DISABLED")
    ap.add_argument("--port", type=int, default=21, help="Listen port (default 21; needs root)")
    ap.add_argument("--host", default="0.0.0.0", help="Bind address (default all interfaces)")
    ap.add_argument("--root", default=None, help="Directory to serve (default: a temp sandbox dir)")
    ap.add_argument("--user", default="ftpuser", help="Real (non-anonymous) username")
    ap.add_argument("--password", default="ftppass", help="Real user's password")
    args = ap.parse_args()

    root = args.root or os.path.join(tempfile.gettempdir(), "autopen_ftp_secure")
    os.makedirs(root, exist_ok=True)
    sample = os.path.join(root, "README.txt")
    if not os.path.exists(sample):
        with open(sample, "w") as f:
            f.write("AutoPen secure FTP sandbox — anonymous login is DISABLED.\n")

    authorizer = DummyAuthorizer()
    # A real user only — NO add_anonymous(...). An anonymous login attempt will
    # therefore fail authentication and the server replies 530.
    authorizer.add_user(args.user, args.password, root, perm="elr")

    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = "AutoPen Secure FTP ready (anonymous login disabled)."
    handler.passive_ports = range(60000, 60050)

    print(f"[ftp-secure] serving {root}")
    print(f"[ftp-secure] anonymous login DISABLED on {args.host}:{args.port}")
    print(f"[ftp-secure] real user available: {args.user} / {args.password}")
    print(f"[ftp-secure] passive ports: 60000-60049")
    if args.port < 1024:
        print("[ftp-secure] NOTE: port < 1024 — run with sudo/admin if bind fails.")

    server = FTPServer((args.host, args.port), handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
