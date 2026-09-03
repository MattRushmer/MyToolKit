"""A scripted multi-step "agent task" that drives AgentWarden's proxy
exactly like a real MCP client would, over the in-memory transport (no
subprocess, no network port - see mcp.client._memory.InMemoryTransport).

Plants one clean instance of every outcome AgentWarden is built to catch:
allowed calls, an explicit policy denial, an argument-scope violation, a
blast-radius-exceeded denial from a delegated sub-agent reaching a
never-should-touch upstream, and a rate-limit trip shared across a task's
whole delegation subtree. Used both by `agentwarden demo` (README
walkthrough) and by tests/test_demo_scenario.py (the integration-test
target) - see that test for the assertion that every planted outcome
actually fires.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mcp.client import Client
from mcp.client._memory import InMemoryTransport
from mcp.server.mcpserver import MCPServer

from agentwarden.clock import Clock, SystemClock
from agentwarden.ids import new_id
from agentwarden.policy.schema import load_enforcement_modes, load_policy_file
from agentwarden.proxy.server import AgentWardenProxy
from agentwarden.proxy.upstream import UpstreamConfig, UpstreamPool
from agentwarden.store.connection import Store

DEMO_POLICY_PATH = Path(__file__).parent / "demo_policy.yaml"
DEMO_IDENTITY_ID = "coding-agent"
DEMO_BLAST_RADIUS_CEILING = 2

ROOT_SESSION_ID = "demo-root-session"
ROOT_TASK_ID = ROOT_SESSION_ID  # a root session's task_id defaults to its own session_id
SUB_SESSION_ID = "demo-sub-agent-session"


def build_fixture_servers() -> dict[str, MCPServer]:
    fs_server = MCPServer("fs-fixture")

    @fs_server.tool()
    def write_file(path: str, content: str) -> str:
        return f"(simulated) wrote {len(content)} byte(s) to {path}"

    github_server = MCPServer("github-fixture")

    @github_server.tool()
    def create_pr(repo: str, title: str, body: str) -> str:
        return f"(simulated) opened PR '{title}' on {repo}"

    @github_server.tool()
    def merge_pr(repo: str, pr_number: int) -> str:
        return f"(simulated) merged PR #{pr_number} on {repo}"

    payments_server = MCPServer("payments-fixture")

    @payments_server.tool()
    def issue_refund(order_id: str, amount: float) -> str:
        return f"(simulated) refunded {amount} for order {order_id}"

    return {"fs-mcp": fs_server, "github-mcp": github_server, "payments-mcp": payments_server}


@dataclass
class DemoStep:
    description: str
    session: str
    tool_name: str
    upstream: str
    is_error: bool
    result_text: str


@dataclass
class DemoResult:
    root_session_id: str
    task_id: str
    steps: list[DemoStep] = field(default_factory=list)


def _result_text(result) -> str:
    return "; ".join(c.text for c in result.content if hasattr(c, "text"))


async def build_demo_proxy(store: Store, *, clock: Clock | None = None, instance_id: str = "demo-instance") -> tuple[AgentWardenProxy, UpstreamPool]:
    """Returns (proxy, pool) - the caller owns the pool's lifetime and must
    `await pool.stop()` when done (see cli/main.py's `demo` command), or the
    still-open in-memory upstream connections leak past process/event-loop
    shutdown and Python logs a noisy (harmless, but ugly) asyncgen warning."""
    clock = clock or SystemClock()
    servers = build_fixture_servers()
    pool = UpstreamPool([
        UpstreamConfig(upstream_id=upstream_id, transport="memory", memory_server=server)
        for upstream_id, server in servers.items()
    ])
    await pool.start()

    policy_rules = load_policy_file(DEMO_POLICY_PATH)
    enforcement_modes = load_enforcement_modes(DEMO_POLICY_PATH)

    proxy = AgentWardenProxy(
        identity_id=DEMO_IDENTITY_ID, identity_label="Demo Coding Agent", listener_source="fixtures/demo_scenario.py",
        transport_label="memory", policy_rules_by_identity=policy_rules, enforcement_modes=enforcement_modes,
        upstream_pool=pool, store=store, clock=clock, new_id=new_id, instance_id=instance_id,
        blast_radius_ceiling=DEMO_BLAST_RADIUS_CEILING,
    )
    await proxy.start()
    return proxy, pool


async def run_demo_scenario(proxy: AgentWardenProxy) -> DemoResult:
    """Opens exactly two connections - one per session - and makes every
    call for that session over it, the way a real MCP client actually
    behaves (one connection, many calls), rather than one connection per
    call."""
    result = DemoResult(root_session_id=ROOT_SESSION_ID, task_id=ROOT_TASK_ID)

    async def step(client: Client, description: str, session: str, tool_name: str, upstream: str, arguments: dict, meta: dict) -> None:
        call_result = await client.call_tool(tool_name, arguments, meta=meta)
        result.steps.append(DemoStep(
            description=description, session=session, tool_name=tool_name, upstream=upstream,
            is_error=call_result.is_error, result_text=_result_text(call_result),
        ))

    root_meta = {"dev.agentwarden/sessionId": ROOT_SESSION_ID}
    async with Client(server=InMemoryTransport(proxy.mcp_server)) as root_client:
        await step(root_client, "1. Root agent writes a file inside its allowed workspace", ROOT_SESSION_ID,
                    "write_file", "fs-mcp", {"path": "/workspace/notes.md", "content": "hello from the demo"}, root_meta)

        await step(root_client, "2. Root agent opens a PR on its allowed repo", ROOT_SESSION_ID,
                    "create_pr", "github-mcp", {"repo": "my-org/allowed-repo", "title": "demo change", "body": "..."}, root_meta)

        await step(root_client, "3. Root agent tries to merge a PR (explicitly denied tool)", ROOT_SESSION_ID,
                    "merge_pr", "github-mcp", {"repo": "my-org/allowed-repo", "pr_number": 1}, root_meta)

        await step(root_client, "4. Root agent tries to write outside its workspace (scope violation)", ROOT_SESSION_ID,
                    "write_file", "fs-mcp", {"path": "/etc/passwd", "content": "pwned"}, root_meta)

    sub_meta = {"dev.agentwarden/sessionId": SUB_SESSION_ID, "dev.agentwarden/parentSessionId": ROOT_SESSION_ID}
    async with Client(server=InMemoryTransport(proxy.mcp_server)) as sub_client:
        # Rate-limiting first, while the task has only touched fs-mcp/github-mcp
        # (2 upstreams, at the ceiling but not over it) - the payments call below
        # would otherwise trip BLAST_RADIUS_EXCEEDED first and mask every
        # subsequent call on the task behind that same denial, since a task that
        # has already exceeded its ceiling stays over it for every later call too.
        for n in (2, 3, 4):
            await step(sub_client, f"5.{n - 1}. Sub-agent create_pr attempt #{n} against the task's shared budget", SUB_SESSION_ID,
                        "create_pr", "github-mcp", {"repo": "my-org/allowed-repo", "title": f"pr {n}", "body": "..."}, sub_meta)

        await step(sub_client, "6. A delegated sub-agent reaches for the payments upstream (blast-radius exceeded)", SUB_SESSION_ID,
                    "issue_refund", "payments-mcp", {"order_id": "order-1", "amount": 99999}, sub_meta)

    return result
