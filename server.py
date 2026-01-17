import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from registry import TOOLS

server = Server(
    name="sec-tools-mcp",
    version="1.0.0",
)

# Build a lookup dict for tools by name
TOOLS_BY_NAME = {tool.name: tool for tool in TOOLS}


@server.list_tools()
async def list_tools() -> list[Tool]:
    """Return the list of available tools."""
    return [
        Tool(
            name=tool.name,
            description=tool.description,
            inputSchema=tool.input_model.model_json_schema(),
        )
        for tool in TOOLS
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute a tool by name with the given arguments."""
    tool = TOOLS_BY_NAME.get(name)
    if not tool:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    # Parse and validate input
    data = tool.input_model(**arguments)
    result = tool.run(data)

    return [TextContent(type="text", text=result.output)]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
