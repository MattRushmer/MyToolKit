"""A small simulated payments MCP server - used only as a demo/test fixture
for AgentWarden. No real payment happens. Never point a real credential at
this. Deliberately the highest-risk fixture upstream, and denied entirely
by demo_policy.yaml's coding-agent identity - this is what
BLAST_RADIUS_EXCEEDED/POLICY_DENIED are meant to catch a task reaching for.

Run standalone for a manual demo over stdio:
    python fixtures/payments_server.py
"""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

server = MCPServer("payments-fixture")


@server.tool()
def issue_refund(order_id: str, amount: float) -> str:
    """Issues a refund for the given order."""
    return f"(simulated) refunded {amount} for order {order_id}"


if __name__ == "__main__":
    server.run()
