"""A small simulated filesystem MCP server - used only as a demo/test
fixture for AgentWarden. No real file I/O happens; every tool returns a
plausible-looking simulated result. Never point a real credential at this.

Run standalone for a manual demo over stdio:
    python fixtures/fs_server.py
"""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

server = MCPServer("fs-fixture")


@server.tool()
def write_file(path: str, content: str) -> str:
    """Writes content to a file at the given path."""
    return f"(simulated) wrote {len(content)} byte(s) to {path}"


@server.tool()
def read_file(path: str) -> str:
    """Reads the content of a file at the given path."""
    return f"(simulated) contents of {path}: hello from AgentWarden's fs fixture"


if __name__ == "__main__":
    server.run()
