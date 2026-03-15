from tools.nmap import NmapTool
from tools.whois import WhoisTool
from tools.subfinder import SubfinderTool
from tools.httpx import HttpxTool
from tools.gobuster import GobusterTool
from tools.curl import CurlTool
from tools.sqlmap import SqlmapTool
from tools.waybackurls import WaybackurlsTool
from tools.katana import KatanaTool
from tools.paramspider import ParamSpiderTool
from tools.arjun import ArjunTool
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
    SqlmapTool(),
    WaybackurlsTool(),
    KatanaTool(),
    ParamSpiderTool(),
    ArjunTool(),
    GetAttackSurfaceTool(),
    GetEndpointsTool(),
    GetHttpServicesTool(),
    GetSubdomainsTool(),
]
