"""Known on-disk locations of MCP client (agent host) config files.

This is the "inventory the org's agent tool-grants" half of the scanner: most
MCP security write-ups analyze one server at a time given its URL/command.
Real orgs instead have N developer machines, each running M agent hosts
(Claude Desktop, Claude Code, Cursor, Windsurf, Cline/VS Code, ...), each with
its own MCP server grants. Walking every known host's config location is how
you build the "who has access to what" picture before scoring any one tool.
"""
from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ConfigLocation:
    host_app: str
    path: Path
    # "mcpServers" (Claude Desktop/Code, Cursor, Windsurf, Cline) or
    # "servers" (VS Code's native MCP support) - selects the parser shape.
    schema: str = "mcpServers"


def _home() -> Path:
    return Path.home()


def _appdata() -> Path:
    return Path(os.environ.get("APPDATA", _home() / "AppData" / "Roaming"))


def known_config_locations(cwd: Path | None = None) -> list[ConfigLocation]:
    """Every location a supported agent host is known to keep its MCP server
    config, across Windows/macOS/Linux plus the current project directory.
    A missing file is not an error here - callers filter to existing paths."""

    cwd = cwd or Path.cwd()
    system = platform.system()
    locations: list[ConfigLocation] = []

    # Claude Desktop
    if system == "Windows":
        locations.append(ConfigLocation("claude-desktop", _appdata() / "Claude" / "claude_desktop_config.json"))
    elif system == "Darwin":
        locations.append(ConfigLocation("claude-desktop", _home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"))
    else:
        locations.append(ConfigLocation("claude-desktop", _home() / ".config" / "Claude" / "claude_desktop_config.json"))

    # Claude Code: user-scoped (~/.claude.json) and project-scoped (.mcp.json).
    # The user-scoped file nests servers per project - {"projects": {"<abs
    # path>": {"mcpServers": {...}}}} - not a top-level "mcpServers" key, so
    # it gets its own schema (see parser.py's claude_code_projects handling).
    locations.append(ConfigLocation("claude-code-user", _home() / ".claude.json", schema="claude_code_projects"))
    locations.append(ConfigLocation("claude-code-project", cwd / ".mcp.json"))

    # Cursor: user-scoped and project-scoped
    locations.append(ConfigLocation("cursor-user", _home() / ".cursor" / "mcp.json"))
    locations.append(ConfigLocation("cursor-project", cwd / ".cursor" / "mcp.json"))

    # Windsurf
    locations.append(ConfigLocation("windsurf", _home() / ".codeium" / "windsurf" / "mcp_config.json"))

    # Cline (VS Code extension) - globalStorage path differs by OS
    if system == "Windows":
        cline_root = _appdata() / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings"
    elif system == "Darwin":
        cline_root = _home() / "Library" / "Application Support" / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings"
    else:
        cline_root = _home() / ".config" / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings"
    locations.append(ConfigLocation("cline", cline_root / "cline_mcp_settings.json"))

    # VS Code's own native MCP support uses a different top-level key ("servers")
    locations.append(ConfigLocation("vscode-project", cwd / ".vscode" / "mcp.json", schema="servers"))

    # Generic fallback some hosts/tools use
    locations.append(ConfigLocation("generic-project", cwd / "mcp.json"))

    return locations


def existing_config_locations(cwd: Path | None = None) -> list[ConfigLocation]:
    return [loc for loc in known_config_locations(cwd) if loc.path.is_file()]
