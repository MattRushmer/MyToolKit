"""Outbound connections to the real upstream MCP server(s) AgentWarden
mediates access to.

AgentWarden owns these credentials (env vars / auth headers), read once from
its own launch config - the agent host connecting to AgentWarden's
host-facing listener never sees them (see proxy/server.py).

Every upstream `Client` is opened once, at pool startup, and held open for
the pool's whole lifetime via one `AsyncExitStack` - not inside a per-request
coroutine. That distinction matters under cancellation: if a client Client
context were entered per-request, a cancelled inbound call could tear the
connection down for every other in-flight session sharing it. Concurrent
`call_tool`/`list_tools` calls against the same upstream Client are expected
to be safe - MCP is JSON-RPC over one persistent connection with per-request
ids, which is exactly the shape built for request pipelining - so no
additional per-upstream lock is added here.
"""
from __future__ import annotations

from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp.client import Client
from mcp.client._memory import InMemoryTransport
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client


@dataclass(frozen=True)
class UpstreamConfig:
    upstream_id: str
    transport: str  # "stdio" | "http" | "sse" | "memory"
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 15.0
    memory_server: Any | None = None  # an in-process MCPServer/Server instance - "memory" transport only, demo/tests


def build_transport(cfg: UpstreamConfig) -> Any:
    if cfg.transport == "memory":
        if cfg.memory_server is None:
            raise ValueError(f"upstream '{cfg.upstream_id}' is configured for the memory transport but has no memory_server")
        return InMemoryTransport(cfg.memory_server)

    if cfg.transport == "stdio":
        if not cfg.command:
            raise ValueError(f"upstream '{cfg.upstream_id}' is configured for stdio but has no command")
        return StdioServerParameters(command=cfg.command, args=list(cfg.args), env=cfg.env or None)

    if cfg.transport == "http":
        if not cfg.url:
            raise ValueError(f"upstream '{cfg.upstream_id}' is configured for http but has no url")
        if cfg.headers:
            import httpx2

            return streamable_http_client(cfg.url, http_client=httpx2.AsyncClient(headers=cfg.headers, timeout=cfg.timeout_seconds))
        return cfg.url

    if cfg.transport == "sse":
        if not cfg.url:
            raise ValueError(f"upstream '{cfg.upstream_id}' is configured for sse but has no url")
        return sse_client(cfg.url, headers=cfg.headers or None, timeout=cfg.timeout_seconds)

    raise ValueError(f"unsupported transport: {cfg.transport}")


class UpstreamPool:
    """Owns one live `Client` per configured upstream, all opened together
    at `start()` and closed together at `stop()`."""

    def __init__(self, configs: list[UpstreamConfig]) -> None:
        self._configs = {c.upstream_id: c for c in configs}
        self._clients: dict[str, Client] = {}
        self._exit_stack = AsyncExitStack()

    @property
    def upstream_ids(self) -> list[str]:
        return list(self._configs)

    async def start(self) -> None:
        for upstream_id, cfg in self._configs.items():
            transport = build_transport(cfg)
            client = await self._exit_stack.enter_async_context(Client(server=transport, read_timeout_seconds=cfg.timeout_seconds))
            self._clients[upstream_id] = client

    async def stop(self) -> None:
        await self._exit_stack.aclose()
        self._clients.clear()

    def client(self, upstream_id: str) -> Client:
        try:
            return self._clients[upstream_id]
        except KeyError:
            raise ValueError(f"unknown or not-yet-started upstream '{upstream_id}'") from None

    async def list_all_tools(self, upstream_id: str) -> list[Any]:
        client = self.client(upstream_id)
        tools: list[Any] = []
        cursor: str | None = None
        while True:
            result = await client.list_tools(cursor=cursor)
            tools.extend(result.tools)
            if not result.next_cursor:
                break
            cursor = result.next_cursor
        return tools

    async def call_tool(self, upstream_id: str, tool_name: str, arguments: dict[str, Any]) -> Any:
        return await self.client(upstream_id).call_tool(tool_name, arguments)


class ToolNameCollisionError(ValueError):
    pass


async def build_tool_registry(pool: UpstreamPool) -> dict[str, tuple[str, Any]]:
    """{tool_name: (upstream_id, Tool)} across every configured upstream.

    Raises ToolNameCollisionError if two upstreams expose the same tool
    name. The underlying SDK's own `ToolManager.add_tool` silently keeps the
    first registration on a duplicate name rather than raising - fine for a
    single app assembling its own tools, but AgentWarden is routing *other
    people's* upstream servers, where a same-named tool on two upstreams
    would route a call to the wrong one's credential and policy scope. v1's
    answer is to fail closed at startup rather than silently misroute; see
    README's Known limitations for the one-tool-namespace-per-name
    constraint this implies."""
    registry: dict[str, tuple[str, Any]] = {}
    for upstream_id in pool.upstream_ids:
        for tool in await pool.list_all_tools(upstream_id):
            if tool.name in registry:
                other_upstream, _ = registry[tool.name]
                raise ToolNameCollisionError(
                    f"tool '{tool.name}' is exposed by both '{other_upstream}' and '{upstream_id}' - "
                    "AgentWarden requires unique tool names across all configured upstreams (see README)"
                )
            registry[tool.name] = (upstream_id, tool)
    return registry
