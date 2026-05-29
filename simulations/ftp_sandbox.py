"""
Local sandbox FTP server for testing AutoPen's FTP agent (SENTINEL-FTP) and the
recheck agent's verdicts. One file, two modes:

    (default)   anonymous login ENABLED   → recheck verdict "vulnerable"
    --secure    anonymous login DISABLED   → recheck verdict "fixed" (server up, anon 530)

The third recheck state — "inconclusive" — is simply this server NOT running
(connection refused / unreachable), so no separate mode is needed for it.

What the agent's `run_ftp_anon_check` tool sees:
    default        → anonymous_allowed=True                 → "vulnerable"
    --secure       → anonymous_allowed=False, login_refused=True → "fixed"
    not running    → connection refused                     → "inconclusive"

Install:
    pip install pyftpdlib

Run (port 21 needs root/admin):
    sudo python ftp_sandbox.py                 # vulnerable: anonymous read-only
    sudo python ftp_sandbox.py --writable      # vulnerable: writable anon dir (higher severity)
    sudo python ftp_sandbox.py --secure        # fixed: anonymous disabled (530)
    python ftp_sandbox.py --port 2121          # high port, no sudo (direct tool test only)

Notes:
  * The AutoPen FTP agent hardcodes port 21, so a FULL-PIPELINE test must use
    port 21. The --port override is only useful for a direct tool test where you
    pass the port explicitly.
  * Python's ftplib (used by the tool) defaults to PASSIVE mode, so the server
    advertises a passive port range below — open those ports in the firewall if
    the client is on another host.
  * Run this on a host reachable from wherever the MCP server runs (the MCP
    server is what actually opens the FTP connection). Easiest: run it on the
    Ubuntu MCP host itself and scan that host's IP.
"""

import argparse
import os
import tempfile

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


def main():
    ap = argparse.ArgumentParser(
        description="Sandbox FTP server — vulnerable (anonymous enabled) by default; --secure disables it"
    )
    ap.add_argument("--secure", action="store_true",
                    help="Disable anonymous login (real user only → FTP 530). Tests the recheck 'fixed' verdict.")
    ap.add_argument("--writable", action="store_true",
                    help="(default/vulnerable mode) grant the anonymous user WRITE access (higher-severity case)")
    ap.add_argument("--port", type=int, default=21, help="Listen port (default 21; needs root)")
    ap.add_argument("--host", default="0.0.0.0", help="Bind address (default all interfaces)")
    ap.add_argument("--root", default=None, help="Directory to serve (default: a temp sandbox dir)")
    ap.add_argument("--user", default="ftpuser", help="(secure mode) real username")
    ap.add_argument("--password", default="ftppass", help="(secure mode) real user's password")
    args = ap.parse_args()

    # Sandbox directory with a sample file so a successful LIST returns evidence.
    root = args.root or os.path.join(
        tempfile.gettempdir(),
        "autopen_ftp_secure" if args.secure else "autopen_ftp_sandbox",
    )
    os.makedirs(root, exist_ok=True)
    sample = os.path.join(root, "README.txt")
    if not os.path.exists(sample):
        with open(sample, "w") as f:
            state = "DISABLED" if args.secure else "enabled"
            f.write(f"AutoPen FTP sandbox — anonymous login is {state}.\n")
    if not args.secure:
        os.makedirs(os.path.join(root, "pub"), exist_ok=True)

    authorizer = DummyAuthorizer()
    if args.secure:
        # Real user only — NO anonymous account. An anonymous login attempt
        # therefore fails authentication and the server replies FTP 530.
        authorizer.add_user(args.user, args.password, root, perm="elr")
    else:
        # Anonymous enabled. Permission letters:
        #   read-only : e=cd  l=list  r=download
        #   write     : a=append d=delete f=rename m=mkdir w=upload
        perm = "elradfmw" if args.writable else "elr"
        authorizer.add_anonymous(root, perm=perm)

    handler = FTPHandler
    handler.authorizer = authorizer
    # Passive data-connection port range — open these in the firewall if the
    # FTP client (MCP server) is on a different host than this sandbox.
    handler.passive_ports = range(60000, 60050)

    if args.secure:
        handler.banner = "AutoPen Secure FTP ready (anonymous login disabled)."
        print("[ftp-sandbox] MODE: SECURE — anonymous login DISABLED (expect recheck 'fixed')")
        print(f"[ftp-sandbox] real user available: {args.user} / {args.password}")
    else:
        handler.banner = "AutoPen Sandbox FTP ready (anonymous login enabled)."
        mode = "READ-WRITE" if args.writable else "read-only"
        print(f"[ftp-sandbox] MODE: VULNERABLE — anonymous login ENABLED ({mode}) (expect recheck 'vulnerable')")

    print(f"[ftp-sandbox] serving {root} on {args.host}:{args.port}")
    print("[ftp-sandbox] passive ports: 60000-60049")
    if args.port < 1024:
        print("[ftp-sandbox] NOTE: port < 1024 — run with sudo/admin if bind fails.")

    server = FTPServer((args.host, args.port), handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
