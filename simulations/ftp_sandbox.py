"""
Local sandbox FTP server with ANONYMOUS LOGIN enabled — for testing AutoPen's
FTP agent (SENTINEL-FTP) against a known-vulnerable target.

Anonymous FTP login is exactly what the agent's `run_ftp_anon_check` tool probes:
it connects to port 21, logs in as 'anonymous', and (on success) lists the root.

Install:
    pip install pyftpdlib

Run (port 21 needs root/admin):
    sudo python ftp_sandbox.py                 # read-only anonymous (medium finding)
    sudo python ftp_sandbox.py --writable      # writable anon dir (higher severity)
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
    ap = argparse.ArgumentParser(description="Sandbox anonymous-login FTP server")
    ap.add_argument("--port", type=int, default=21, help="Listen port (default 21; needs root)")
    ap.add_argument("--host", default="0.0.0.0", help="Bind address (default all interfaces)")
    ap.add_argument("--root", default=None, help="Directory to serve (default: a temp sandbox dir)")
    ap.add_argument("--writable", action="store_true",
                    help="Grant the anonymous user WRITE access (tests the higher-severity case)")
    args = ap.parse_args()

    # Prepare a sandbox directory with a sample file so LIST returns evidence.
    root = args.root or os.path.join(tempfile.gettempdir(), "autopen_ftp_sandbox")
    os.makedirs(root, exist_ok=True)
    sample = os.path.join(root, "README.txt")
    if not os.path.exists(sample):
        with open(sample, "w") as f:
            f.write("AutoPen FTP sandbox — anonymous read access works.\n")
    os.makedirs(os.path.join(root, "pub"), exist_ok=True)

    authorizer = DummyAuthorizer()
    # Permission letters:
    #   read-only : e=cd  l=list  r=download
    #   write     : a=append d=delete f=rename m=mkdir w=upload
    perm = "elradfmw" if args.writable else "elr"
    authorizer.add_anonymous(root, perm=perm)

    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = "AutoPen Sandbox FTP ready (anonymous login enabled)."
    # Passive data-connection port range — open these in the firewall if the
    # FTP client (MCP server) is on a different host than this sandbox.
    handler.passive_ports = range(60000, 60050)

    mode = "READ-WRITE" if args.writable else "read-only"
    print(f"[ftp-sandbox] serving {root}")
    print(f"[ftp-sandbox] anonymous login ENABLED ({mode}) on {args.host}:{args.port}")
    print(f"[ftp-sandbox] passive ports: 60000-60049")
    if args.port < 1024:
        print("[ftp-sandbox] NOTE: port < 1024 — run with sudo/admin if bind fails.")

    server = FTPServer((args.host, args.port), handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
