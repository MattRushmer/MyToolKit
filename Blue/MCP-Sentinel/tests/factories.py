"""Shared test-data builders. Not a test module itself (no test_ functions)."""
from __future__ import annotations

from mcp_sentinel.models import MCPServerConfig, ToolAnnotations, ToolInfo, TransportType


def make_config(
    name: str = "demo",
    host_app: str = "claude-desktop",
    transport: TransportType = TransportType.STDIO,
    command: str | None = "python",
    args: tuple[str, ...] = (),
    url: str | None = None,
    has_auth_header: bool = False,
    auto_approved_tools: tuple[str, ...] = (),
    env_var_names: tuple[str, ...] = (),
) -> MCPServerConfig:
    return MCPServerConfig(
        server_id=f"{host_app}:{name}",
        config_name=name,
        host_app=host_app,
        source_config_path=f"/fake/{host_app}.json",
        transport=transport,
        command=command,
        args=args,
        url=url,
        has_auth_header=has_auth_header,
        auto_approved_tools=auto_approved_tools,
        env_var_names=env_var_names,
    )


def make_tool(
    name: str = "demo_tool",
    description: str = "",
    input_schema: dict | None = None,
    read_only_hint: bool | None = None,
    destructive_hint: bool | None = None,
    idempotent_hint: bool | None = None,
    open_world_hint: bool | None = None,
) -> ToolInfo:
    return ToolInfo(
        name=name,
        description=description,
        input_schema=input_schema or {},
        annotations=ToolAnnotations(
            read_only_hint=read_only_hint,
            destructive_hint=destructive_hint,
            idempotent_hint=idempotent_hint,
            open_world_hint=open_world_hint,
        ),
    )
