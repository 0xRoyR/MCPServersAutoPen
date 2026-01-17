from tools.nmap import NmapTool
from tools.whois import WhoisTool
from tools.subfinder import SubfinderTool
from tools.httpx import HttpxTool
from tools.gobuster import GobusterTool

TOOLS = [
    NmapTool(),
    WhoisTool(),
    SubfinderTool(),
    HttpxTool(),
    GobusterTool(),
]
