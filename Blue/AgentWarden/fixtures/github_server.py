"""A small simulated GitHub MCP server - used only as a demo/test fixture
for AgentWarden. No real GitHub API calls happen. Never point a real
credential at this.

Run standalone for a manual demo over stdio:
    python fixtures/github_server.py
"""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

server = MCPServer("github-fixture")


@server.tool()
def create_pr(repo: str, title: str, body: str) -> str:
    """Opens a pull request on the given repository."""
    return f"(simulated) opened PR '{title}' on {repo}"


@server.tool()
def merge_pr(repo: str, pr_number: int) -> str:
    """Merges an existing pull request."""
    return f"(simulated) merged PR #{pr_number} on {repo}"


if __name__ == "__main__":
    server.run()
