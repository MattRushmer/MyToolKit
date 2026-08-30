"""Live MCP protocol client: connects to one configured server and introspects
its tools/resources/prompts. Read-only by design - this module never calls a
tool; invoking a tool (for injection probing) is probes/active.py's job,
gated behind an explicit opt-in flag.

Credential handling: `headers`/`env` here are the real, live values (read
transiently from the host's config file by the caller) needed to actually
authenticate the connection. They are used only to open the transport and are
never attached to the returned ServerInventory or copied into any field that
ends up in a ScanReport or baseline file - see discovery/parser.py's
`extract_raw_entries` docstring for the split this depends on.
"""
from __future__ import annotations

import logging
from typing import Any

import anyio
import httpx2
from mcp.client import Client
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

from mcp_sentinel.models import (
    MCPServerConfig,
    PromptInfo,
    ResourceInfo,
    ServerInventory,
    ToolAnnotations,
    ToolInfo,
    TransportType,
)

logger = logging.getLogger(__name__)


def _build_transport(config: MCPServerConfig, headers: dict[str, str] | None, env: dict[str, str] | None) -> Any:
    if config.transport == TransportType.STDIO:
        if not config.command:
            raise ValueError(f"server '{config.server_id}' is configured for stdio but has no command")
        return StdioServerParameters(command=config.command, args=list(config.args), env=env or None)

    if not config.url:
        raise ValueError(f"server '{config.server_id}' is configured for {config.transport.value} but has no url")

    if config.transport == TransportType.HTTP:
        if headers:
            return streamable_http_client(config.url, http_client=httpx2.AsyncClient(headers=headers))
        return config.url  # Client(server=<str>) opens a plain streamable_http_client itself

    if config.transport == TransportType.SSE:
        return sse_client(config.url, headers=headers or None)

    raise ValueError(f"unsupported transport: {config.transport}")


def _map_annotations(raw: Any) -> ToolAnnotations:
    if raw is None:
        return ToolAnnotations()
    return ToolAnnotations(
        title=raw.title,
        read_only_hint=raw.read_only_hint,
        destructive_hint=raw.destructive_hint,
        idempotent_hint=raw.idempotent_hint,
        open_world_hint=raw.open_world_hint,
    )


async def _list_all_tools(client: Client) -> list[ToolInfo]:
    tools: list[ToolInfo] = []
    cursor: str | None = None
    while True:
        result = await client.list_tools(cursor=cursor)
        for t in result.tools:
            tools.append(
                ToolInfo(
                    name=t.name,
                    description=t.description or "",
                    input_schema=t.input_schema or {},
                    annotations=_map_annotations(t.annotations),
                )
            )
        if not result.next_cursor:
            break
        cursor = result.next_cursor
    return tools


async def _list_all_resources(client: Client) -> list[ResourceInfo]:
    resources: list[ResourceInfo] = []
    cursor: str | None = None
    try:
        while True:
            result = await client.list_resources(cursor=cursor)
            for r in result.resources:
                resources.append(
                    ResourceInfo(uri=str(r.uri), name=r.name or "", description=r.description or "", mime_type=r.mime_type or "")
                )
            if not result.next_cursor:
                break
            cursor = result.next_cursor
    except Exception:  # noqa: BLE001 - resources capability is optional; absence isn't a scan failure
        logger.debug("server does not support resources/list or the call failed", exc_info=True)
    return resources


async def _list_all_prompts(client: Client) -> list[PromptInfo]:
    prompts: list[PromptInfo] = []
    cursor: str | None = None
    try:
        while True:
            result = await client.list_prompts(cursor=cursor)
            for p in result.prompts:
                arg_names = tuple(a.name for a in (p.arguments or []))
                prompts.append(PromptInfo(name=p.name, description=p.description or "", arguments=arg_names))
            if not result.next_cursor:
                break
            cursor = result.next_cursor
    except Exception:  # noqa: BLE001 - prompts capability is optional; absence isn't a scan failure
        logger.debug("server does not support prompts/list or the call failed", exc_info=True)
    return prompts


async def introspect_server(
    config: MCPServerConfig,
    *,
    headers: dict[str, str] | None = None,
    env: dict[str, str] | None = None,
    timeout_seconds: float = 15.0,
) -> ServerInventory:
    """Connect to `config` and enumerate its tools/resources/prompts.

    Never raises: any transport, protocol, or timeout failure is captured on
    the returned ServerInventory (reachable=False, connection_error=...) so
    one unreachable server can't abort a fleet-wide scan.
    """
    inventory = ServerInventory(config=config)

    try:
        transport = _build_transport(config, headers, env)
    except ValueError as exc:
        inventory.connection_error = str(exc)
        return inventory

    try:
        with anyio.fail_after(timeout_seconds):
            async with Client(server=transport, read_timeout_seconds=timeout_seconds) as client:
                inventory.reachable = True
                info = client.server_info
                if info is not None:
                    inventory.server_name = info.name
                    inventory.server_version = info.version
                inventory.tools = await _list_all_tools(client)
                inventory.resources = await _list_all_resources(client)
                inventory.prompts = await _list_all_prompts(client)
    except TimeoutError:
        inventory.connection_error = f"timed out after {timeout_seconds}s"
    except Exception as exc:  # noqa: BLE001 - any connector/protocol failure degrades to a finding, never crashes the scan
        inventory.connection_error = f"{type(exc).__name__}: {exc}"

    return inventory
