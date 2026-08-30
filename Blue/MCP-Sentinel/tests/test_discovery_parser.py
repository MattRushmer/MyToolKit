import json

import pytest

from mcp_sentinel.discovery.config_locations import ConfigLocation
from mcp_sentinel.discovery.parser import extract_raw_entries, load_config_file, parse_config_dict
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


def test_secret_flag_and_following_value_are_redacted_in_args():
    data = {"mcpServers": {"crm": {"command": "python", "args": ["sync.py", "--api-key", "sk_live_51H8x9zK2example"]}}}
    servers, _ = parse_config_dict("cline", "mcpServers", data, "/fake/cline.json")
    s = servers[0]
    assert s.args == ("sync.py", "--api-key", "<redacted-by-mcp-sentinel>")
    assert s.secret_like_arg_flags == ("--api-key",)
    assert "sk_live_51H8x9zK2example" not in repr(s)


def test_bearer_flag_is_recognized_as_secret_like():
    data = {"mcpServers": {"x": {"command": "python", "args": ["--bearer", "REALVALUE1234567890ABCDEF"]}}}
    servers, _ = parse_config_dict("cline", "mcpServers", data, "/fake/cline.json")
    s = servers[0]
    assert s.secret_like_arg_flags == ("--bearer",)
    assert "REALVALUE1234567890ABCDEF" not in repr(s)


def test_inline_flag_equals_value_form_is_redacted():
    # Regression test: --flag=value (one array entry) is a common alternate
    # CLI convention to --flag value (two entries). A round-2 security review
    # found the original fix only handled the two-entry form - .match()
    # against "--api-key=<secret>" succeeded on just the "--api-key=" prefix,
    # so the code took the "it's a flag name" branch and appended the WHOLE
    # "--api-key=<secret>" string (secret included) as the "flag name",
    # leaving the actual secret value untouched in `args` too.
    data = {"mcpServers": {"crm": {"command": "python", "args": ["sync.py", "--api-key=sk_live_51H8x9zK2example"]}}}
    servers, _ = parse_config_dict("cline", "mcpServers", data, "/fake/cline.json")
    s = servers[0]
    assert s.args == ("sync.py", "--api-key=<redacted-by-mcp-sentinel>")
    assert s.secret_like_arg_flags == ("--api-key",)
    assert "sk_live_51H8x9zK2example" not in repr(s)


def test_bare_opaque_looking_value_is_redacted_even_without_a_flag():
    data = {"mcpServers": {"srv": {"command": "python", "args": ["server.py", "AKIAIOSFODNN7EXAMPLEAKIA1234567890"]}}}
    servers, _ = parse_config_dict("cline", "mcpServers", data, "/fake/cline.json")
    s = servers[0]
    assert s.args == ("server.py", "<redacted-by-mcp-sentinel>")
    assert "AKIAIOSFODNN7EXAMPLEAKIA1234567890" not in repr(s)


def test_short_benign_args_are_not_redacted():
    data = {"mcpServers": {"srv": {"command": "python", "args": ["-y", "server.py", "/tmp/data"]}}}
    servers, _ = parse_config_dict("cline", "mcpServers", data, "/fake/cline.json")
    assert servers[0].args == ("-y", "server.py", "/tmp/data")
    assert servers[0].secret_like_arg_flags == ()


def test_secret_query_param_redacted_in_url():
    data = {"mcpServers": {"billing": {"url": "https://mcp.example.com/mcp?token=abc123secretvalue&region=us", "type": "http"}}}
    servers, _ = parse_config_dict("cursor-user", "mcpServers", data, "/fake/cursor.json")
    s = servers[0]
    assert "abc123secretvalue" not in s.url
    assert "token=%3Credacted-by-mcp-sentinel%3E" in s.url
    assert "region=us" in s.url


def test_url_without_secret_query_param_is_unchanged():
    data = {"mcpServers": {"billing": {"url": "https://mcp.example.com/mcp?region=us", "type": "http"}}}
    servers, _ = parse_config_dict("cursor-user", "mcpServers", data, "/fake/cursor.json")
    assert servers[0].url == "https://mcp.example.com/mcp?region=us"


def test_extract_raw_entries_still_returns_unredacted_secret_for_live_connection(tmp_path):
    path = tmp_path / "secret.json"
    path.write_text(
        json.dumps({"mcpServers": {"crm": {"command": "python", "args": ["sync.py", "--api-key", "sk_live_real_secret_value"]}}}),
        encoding="utf-8",
    )
    raw = extract_raw_entries(ConfigLocation("cline", path))
    assert raw["crm"]["args"] == ["sync.py", "--api-key", "sk_live_real_secret_value"]


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


def test_claude_code_projects_shape_finds_nested_servers():
    data = {
        "projects": {
            "/home/dev/project-a": {"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "server-fs"]}}},
            "/home/dev/project-b": {"mcpServers": {"billing": {"url": "https://mcp.example.com/mcp", "type": "http"}}},
        }
    }
    servers, warnings = parse_config_dict("claude-code-user", "claude_code_projects", data, "/fake/.claude.json")
    assert warnings == []
    assert len(servers) == 2
    names = {s.config_name for s in servers}
    assert names == {"/home/dev/project-a::filesystem", "/home/dev/project-b::billing"}


def test_claude_code_projects_shape_ignores_projects_without_mcp_servers():
    data = {"projects": {"/home/dev/no-mcp": {"allowedTools": []}}}
    servers, warnings = parse_config_dict("claude-code-user", "claude_code_projects", data, "/fake/.claude.json")
    assert servers == []
    assert warnings == []


def test_claude_code_projects_shape_missing_projects_key_returns_empty():
    servers, warnings = parse_config_dict("claude-code-user", "claude_code_projects", {}, "/fake/.claude.json")
    assert servers == []
    assert warnings == []


def test_claude_code_projects_shape_non_dict_mcp_servers_warns():
    data = {"projects": {"/home/dev/x": {"mcpServers": "oops"}}}
    servers, warnings = parse_config_dict("claude-code-user", "claude_code_projects", data, "/fake/.claude.json")
    assert servers == []
    assert len(warnings) == 1


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


def test_extract_raw_entries_returns_verbatim_secrets(tmp_path):
    path = tmp_path / "secret.json"
    path.write_text(
        json.dumps({"mcpServers": {"billing": {"url": "https://x", "headers": {"Authorization": "Bearer real-secret-value"}}}}),
        encoding="utf-8",
    )
    raw = extract_raw_entries(ConfigLocation("cursor-user", path))
    assert raw["billing"]["headers"]["Authorization"] == "Bearer real-secret-value"


def test_extract_raw_entries_handles_claude_code_projects_shape(tmp_path):
    path = tmp_path / ".claude.json"
    path.write_text(
        json.dumps({"projects": {"/home/dev/x": {"mcpServers": {"billing": {"env": {"TOKEN": "real-secret-value"}}}}}}),
        encoding="utf-8",
    )
    raw = extract_raw_entries(ConfigLocation("claude-code-user", path, schema="claude_code_projects"))
    assert raw["/home/dev/x::billing"]["env"]["TOKEN"] == "real-secret-value"


def test_extract_raw_entries_missing_file_returns_empty(tmp_path):
    assert extract_raw_entries(ConfigLocation("claude-desktop", tmp_path / "nope.json")) == {}


def test_extract_raw_entries_invalid_json_returns_empty(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    assert extract_raw_entries(ConfigLocation("claude-desktop", path)) == {}
