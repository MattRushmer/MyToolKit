import json

import pytest

from mcp_sentinel.discovery.config_locations import ConfigLocation
from mcp_sentinel.discovery.parser import load_config_file, parse_config_dict
from mcp_sentinel.models import TransportType


def test_parses_stdio_mcpservers_shape():
    data = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                "env": {"SOME_TOKEN": "secret-value"},
            }
        }
    }
    servers, warnings = parse_config_dict("claude-desktop", "mcpServers", data, "/fake/path.json")
    assert warnings == []
    assert len(servers) == 1
    s = servers[0]
    assert s.server_id == "claude-desktop:filesystem"
    assert s.transport == TransportType.STDIO
    assert s.command == "npx"
    assert s.args == ("-y", "@modelcontextprotocol/server-filesystem", "/tmp")
    # Only the env var *name* is captured, never the value.
    assert s.env_var_names == ("SOME_TOKEN",)
    assert "secret-value" not in repr(s)


def test_parses_remote_http_shape_with_auth_header():
    data = {
        "mcpServers": {
            "billing-api": {
                "url": "https://mcp.example.com/sse",
                "type": "sse",
                "headers": {"Authorization": "Bearer xyz"},
            }
        }
    }
    servers, warnings = parse_config_dict("cursor-user", "mcpServers", data, "/fake/cursor.json")
    assert warnings == []
    s = servers[0]
    assert s.transport == TransportType.SSE
    assert s.url == "https://mcp.example.com/sse"
    assert s.has_auth_header is True


def test_remote_shape_without_auth_header_flagged_false():
    data = {"mcpServers": {"open": {"url": "https://mcp.example.com/mcp", "type": "http"}}}
    servers, _ = parse_config_dict("windsurf", "mcpServers", data, "/fake/windsurf.json")
    assert servers[0].has_auth_header is False


def test_vscode_servers_shape():
    data = {"servers": {"github": {"type": "http", "url": "https://api.githubcopilot.com/mcp/"}}}
    servers, warnings = parse_config_dict("vscode-project", "servers", data, "/fake/.vscode/mcp.json")
    assert warnings == []
    assert servers[0].server_id == "vscode-project:github"
    assert servers[0].transport == TransportType.HTTP


def test_disabled_server_is_skipped():
    data = {"mcpServers": {"off": {"command": "python", "disabled": True}}}
    servers, warnings = parse_config_dict("cline", "mcpServers", data, "/fake/cline.json")
    assert servers == []
    assert warnings == []


def test_auto_approve_list_is_captured():
    data = {"mcpServers": {"risky": {"command": "python", "autoApprove": ["delete_file", "run_shell"]}}}
    servers, _ = parse_config_dict("cline", "mcpServers", data, "/fake/cline.json")
    assert servers[0].auto_approved_tools == ("delete_file", "run_shell")


def test_auto_approve_true_means_wildcard():
    data = {"mcpServers": {"risky": {"command": "python", "autoApprove": True}}}
    servers, _ = parse_config_dict("cline", "mcpServers", data, "/fake/cline.json")
    assert servers[0].auto_approved_tools == ("*",)


def test_missing_top_level_key_returns_empty_without_warning():
    servers, warnings = parse_config_dict("generic-project", "mcpServers", {"unrelated": {}}, "/fake/mcp.json")
    assert servers == []
    assert warnings == []


def test_non_dict_top_level_value_warns():
    servers, warnings = parse_config_dict("generic-project", "mcpServers", {"mcpServers": "oops"}, "/fake/mcp.json")
    assert servers == []
    assert len(warnings) == 1


def test_non_dict_entry_warns_but_continues():
    data = {"mcpServers": {"bad": "not-an-object", "good": {"command": "python"}}}
    servers, warnings = parse_config_dict("generic-project", "mcpServers", data, "/fake/mcp.json")
    assert len(servers) == 1
    assert servers[0].config_name == "good"
    assert len(warnings) == 1


def test_load_config_file_missing_file_returns_error(tmp_path):
    location = ConfigLocation("claude-desktop", tmp_path / "nope.json")
    servers, warnings = load_config_file(location)
    assert servers == []
    assert len(warnings) == 1
    assert "could not read" in warnings[0]


def test_load_config_file_invalid_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not valid json", encoding="utf-8")
    servers, warnings = load_config_file(ConfigLocation("claude-desktop", path))
    assert servers == []
    assert "invalid JSON" in warnings[0]


def test_load_config_file_valid(tmp_path):
    path = tmp_path / "good.json"
    path.write_text(json.dumps({"mcpServers": {"a": {"command": "python"}}}), encoding="utf-8")
    servers, warnings = load_config_file(ConfigLocation("claude-desktop", path))
    assert warnings == []
    assert len(servers) == 1
