"""
Test client for the MCP security tools server.
This script spawns the server as a subprocess and communicates via JSON-RPC over stdio.
"""

import asyncio
import json
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def test_server():
    """Connect to the MCP server and test the available tools."""

    # Define server parameters - runs server.py as a subprocess
    server_params = StdioServerParameters(
        command=sys.executable,  # Use the same Python interpreter
        args=["server.py"],
        cwd=".",  # Run from current directory
    )

    print("=" * 60)
    print("MCP Security Tools - Test Client")
    print("=" * 60)
    print("\nConnecting to server...")

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the session
            await session.initialize()
            print("Connected!\n")

            # List available tools
            print("-" * 40)
            print("Available Tools:")
            print("-" * 40)
            tools_result = await session.list_tools()

            for tool in tools_result.tools:
                print(f"\n  Name: {tool.name}")
                print(f"  Description: {tool.description}")
                print(f"  Input Schema: {json.dumps(tool.inputSchema, indent=4)}")

            print("\n" + "=" * 60)
            print("Running Test Calls")
            print("=" * 60)

            # Test 1: Whois lookup (usually works without special tools installed)
            print("\n[Test 1] WHOIS lookup for 'uber.com'")
            print("-" * 40)
            try:
                result = await session.call_tool("run_whois", {"target": "uber.com"})
                print(f"Result:\n{result.content[0].text[:500]}...")  # Truncate output
            except Exception as e:
                print(f"Error: {e}")

            # Test 2: Nmap quick scan (requires nmap installed)
            print("\n[Test 2] Nmap quick scan on 'localhost'")
            print("-" * 40)
            try:
                result = await session.call_tool("run_nmap", {
                    "target": "localhost",
                    "scan_type": "quick"
                })
                print(f"Result:\n{result.content[0].text[:500]}...")
            except Exception as e:
                print(f"Error: {e}")

            # Test 3: Subfinder (requires subfinder installed)
            print("\n[Test 3] Subfinder on 'uber.com'")
            print("-" * 40)
            try:
                result = await session.call_tool("run_subfinder", {
                    "domain": "uber.com",
                    "silent": True,
                    "timeout": 60,
                    "max_time": 120
                })
                output = result.content[0].text
                if output:
                    print(f"Result:\n{output[:500]}")
                else:
                    print("No subdomains found (or subfinder not installed)")
            except Exception as e:
                print(f"Error: {e}")

            print("\n" + "=" * 60)
            print("Test Complete")
            print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_server())
