"""Normalize every supported agent host's MCP config shape into MCPServerConfig.

Two shapes are supported:
  - "mcpServers": {name: {command, args, env}} or {name: {url, headers, type}}
    - used by Claude Desktop, Claude Code, Cursor, Windsurf, Cline.
  - "servers": {name: {type, command, args, env, url, headers}}
    - VS Code's native MCP support.

Cline additionally exposes "autoApprove" (list[str] or bool) and "disabled"
at the per-server level; both are privilege-relevant signals we carry through
rather than discard.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_sentinel.discovery.config_locations import ConfigLocation
from mcp_sentinel.models import MCPServerConfig, TransportType

_AUTH_HEADER_NAMES = {"authorization", "x-api-key", "api-key", "x-auth-token"}


def _looks_like_auth_header(headers: dict[str, Any] | None) -> bool:
    if not headers:
        return False
    return any(str(k).lower() in _AUTH_HEADER_NAMES for k in headers)


def _transport_for(entry: dict[str, Any]) -> TransportType:
    declared = str(entry.get("type", "")).lower()
    if declared in ("sse",):
        return TransportType.SSE
    if declared in ("http", "streamable-http", "streamable_http"):
        return TransportType.HTTP
    if declared == "stdio":
        return TransportType.STDIO
    # No explicit type: infer from shape.
    if entry.get("url"):
        url = str(entry["url"]).lower()
        return TransportType.SSE if "sse" in url else TransportType.HTTP
    return TransportType.STDIO


def _auto_approved(entry: dict[str, Any]) -> tuple[str, ...]:
    raw = entry.get("autoApprove")
    if raw is True:
        return ("*",)
    if isinstance(raw, list):
        return tuple(str(x) for x in raw)
    return ()


def parse_server_entry(host_app: str, config_name: str, entry: dict[str, Any], source_path: str) -> MCPServerConfig:
    transport = _transport_for(entry)
    headers = entry.get("headers") if isinstance(entry.get("headers"), dict) else None
    env = entry.get("env") if isinstance(entry.get("env"), dict) else {}
    args = entry.get("args") if isinstance(entry.get("args"), list) else []

    return MCPServerConfig(
        server_id=f"{host_app}:{config_name}",
        config_name=config_name,
        host_app=host_app,
        source_config_path=source_path,
        transport=transport,
        command=entry.get("command"),
        args=tuple(str(a) for a in args),
        env_var_names=tuple(sorted(str(k) for k in env)),
        url=entry.get("url"),
        has_auth_header=_looks_like_auth_header(headers),
        auto_approved_tools=_auto_approved(entry),
    )


def _iter_raw_entries(schema: str, data: dict[str, Any], source_path: str) -> tuple[list[tuple[str, Any]], list[str]]:
    """Yields (config_name, raw_entry) pairs for every schema shape we know
    about. Shared by parse_config_dict (builds MCPServerConfig) and
    extract_raw_entries (returns the raw dict verbatim, secrets included) so
    the two can never disagree about which servers a config file declares.

    A top-level "projects" dict (Claude Code's user-scoped ~/.claude.json:
    {"projects": {"<abs project path>": {"mcpServers": {...}}}}) is detected
    from the data itself, not from `schema` - a location built for a known
    host app (see discovery/config_locations.py) can supply the right
    `schema` up front, but `--config <arbitrary path>` cannot, so this can't
    depend on the caller having already guessed the file's shape.
    """
    warnings: list[str] = []
    pairs: list[tuple[str, Any]] = []

    projects = data.get("projects")
    if isinstance(projects, dict):
        for project_path, project_data in projects.items():
            if not isinstance(project_data, dict):
                continue
            raw_servers = project_data.get("mcpServers")
            if raw_servers is None:
                continue
            if not isinstance(raw_servers, dict):
                warnings.append(f"{source_path}: project '{project_path}' mcpServers is not an object, skipping")
                continue
            for name, entry in raw_servers.items():
                pairs.append((f"{project_path}::{name}", entry))

    top_level_key = "servers" if schema == "servers" else "mcpServers"
    raw_servers = data.get(top_level_key)
    if isinstance(raw_servers, dict):
        for name, entry in raw_servers.items():
            pairs.append((str(name), entry))
    elif raw_servers is not None:
        warnings.append(f"{source_path}: '{top_level_key}' is not an object, skipping")

    return pairs, warnings


def parse_config_dict(host_app: str, schema: str, data: dict[str, Any], source_path: str) -> tuple[list[MCPServerConfig], list[str]]:
    """Returns (servers, warnings). Never raises on malformed per-entry data -
    one bad server entry in a host's config shouldn't blind the scan to every
    other server declared alongside it."""

    servers: list[MCPServerConfig] = []
    pairs, warnings = _iter_raw_entries(schema, data, source_path)

    for config_name, entry in pairs:
        if not isinstance(entry, dict):
            warnings.append(f"{source_path}: server '{config_name}' entry is not an object, skipping")
            continue
        if entry.get("disabled") is True:
            continue
        try:
            servers.append(parse_server_entry(host_app, config_name, entry, source_path))
        except Exception as exc:  # noqa: BLE001 - one malformed entry must not abort the scan
            warnings.append(f"{source_path}: failed to parse server '{config_name}': {exc}")

    return servers, warnings


def load_config_file(location: ConfigLocation) -> tuple[list[MCPServerConfig], list[str]]:
    try:
        raw_text = location.path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], [f"{location.path}: could not read file: {exc}"]

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        return [], [f"{location.path}: invalid JSON: {exc}"]

    if not isinstance(data, dict):
        return [], [f"{location.path}: top-level JSON is not an object, skipping"]

    return parse_config_dict(location.host_app, location.schema, data, str(location.path))


def extract_raw_entries(location: ConfigLocation) -> dict[str, dict[str, Any]]:
    """Re-read a config file's per-server entries verbatim (including secret
    values), keyed by config_name. Used only transiently, by the live client
    connector, to authenticate a real introspection connection - callers must
    not persist the return value. MCPServerConfig (from load_config_file)
    never carries these values, only their names/presence, so a ScanReport
    or baseline file can never leak a credential even if serialized to disk.
    """
    try:
        data = json.loads(location.path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    pairs, _ = _iter_raw_entries(location.schema, data, str(location.path))
    return {name: entry for name, entry in pairs if isinstance(entry, dict)}


def load_config_files(locations: list[ConfigLocation]) -> tuple[list[MCPServerConfig], list[str]]:
    all_servers: list[MCPServerConfig] = []
    all_warnings: list[str] = []
    for location in locations:
        if not location.path.is_file():
            continue
        servers, warnings = load_config_file(location)
        all_servers.extend(servers)
        all_warnings.extend(warnings)
    return all_servers, all_warnings
