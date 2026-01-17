from mcp.server import Server
from mcp.server.stdio import stdio_server

from registry import TOOLS

server = Server(
    name="sec-tools-mcp",
    version="1.0.0",
)


for tool in TOOLS:
    server.tool(
        tool.name,
        input_model=tool.input_model,
    )(tool.run)


if __name__ == "__main__":
    stdio_server(server)
