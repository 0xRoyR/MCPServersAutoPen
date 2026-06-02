from tools.nmap import NmapTool
from tools.whois import WhoisTool
from tools.subfinder import SubfinderTool
from tools.httpx import HttpxTool
from tools.gobuster import GobusterTool
from tools.curl import CurlTool
from tools.verify_ssrf import VerifySSRFTool
from tools.ftp_anon import FtpAnonTool
from tools.sqlmap import SqlmapTool
from tools.waybackurls import WaybackurlsTool
from tools.katana import KatanaTool
from tools.paramspider import ParamSpiderTool
from tools.arjun import ArjunTool
from tools.dalfox import DalfoxTool
from tools.ffuf import FfufTool
from tools.commix import CommixTool
from tools.nuclei import NucleiTool
from tools.retirejs import RetireJsTool
from tools.browser import BrowserTool
from tools.query_recon import (
    GetAttackSurfaceTool,
    GetEndpointsTool,
    GetHttpServicesTool,
    GetSubdomainsTool,
)

TOOLS = [
    NmapTool(),
    WhoisTool(),
    SubfinderTool(),
    HttpxTool(),
    GobusterTool(),
    CurlTool(),
    VerifySSRFTool(),
    FtpAnonTool(),
    SqlmapTool(),
    WaybackurlsTool(),
    KatanaTool(),
    ParamSpiderTool(),
    ArjunTool(),
    DalfoxTool(),
    FfufTool(),
    CommixTool(),
    NucleiTool(),
    RetireJsTool(),
    BrowserTool(),
    GetAttackSurfaceTool(),
    GetEndpointsTool(),
    GetHttpServicesTool(),
    GetSubdomainsTool(),
]
