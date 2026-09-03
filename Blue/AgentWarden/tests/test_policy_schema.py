from __future__ import annotations

from pathlib import Path

import pytest

from agentwarden.policy.schema import PolicyValidationError, load_enforcement_modes, load_policy_file


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_loads_valid_policy_with_catch_all_appended(tmp_path: Path):
    path = _write(tmp_path, """
version: 1
identities:
  - identity: coding-agent
    default: deny
    rules:
      - tool: write_file
        upstream: fs-mcp
        ttl_seconds: 60
""")
    policies = load_policy_file(path)
    rules = policies["coding-agent"]
    assert rules[-1].tool_name == "*" and rules[-1].deny is True


def test_rejects_missing_version(tmp_path: Path):
    path = _write(tmp_path, "identities:\n  - identity: x\n    rules: []\n")
    with pytest.raises(PolicyValidationError):
        load_policy_file(path)


def test_rejects_ttl_over_ceiling(tmp_path: Path):
    path = _write(tmp_path, """
version: 1
identities:
  - identity: x
    rules:
      - tool: t
        upstream: u
        ttl_seconds: 999999
""")
    with pytest.raises(PolicyValidationError):
        load_policy_file(path)


def test_deny_rules_ordered_before_allow_rules(tmp_path: Path):
    path = _write(tmp_path, """
version: 1
identities:
  - identity: x
    rules:
      - tool: t
        upstream: u
        ttl_seconds: 10
      - tool: t
        upstream: u
        deny: true
""")
    rules = load_policy_file(path)["x"]
    assert rules[0].deny is True
    assert rules[1].deny is False


def test_rejects_prefix_constraint_on_path_like_field(tmp_path: Path):
    """H1: 'prefix' is a raw, un-normalized startswith() with no '../'
    handling - using it on a path-shaped field is a directory-traversal hole
    ('/workspace/../../etc/passwd' satisfies prefix: '/workspace/' outright).
    'path_within' is the only constraint that normalizes and blocks
    traversal, so a path-like field name must be rejected at load time."""
    path = _write(tmp_path, """
version: 1
identities:
  - identity: x
    rules:
      - tool: write_file
        upstream: fs-mcp
        argument_constraints:
          path: {prefix: "/workspace/"}
""")
    with pytest.raises(PolicyValidationError, match="path_within"):
        load_policy_file(path)


def test_prefix_constraint_still_allowed_on_non_path_field(tmp_path: Path):
    path = _write(tmp_path, """
version: 1
identities:
  - identity: x
    rules:
      - tool: create_pr
        upstream: github-mcp
        argument_constraints:
          repo: {prefix: "my-org/"}
""")
    rules = load_policy_file(path)["x"]
    assert rules[0].argument_constraints["repo"].prefix == "my-org/"


def test_ttl_seconds_falls_back_to_configured_default(tmp_path: Path, monkeypatch):
    """M8: AGENTWARDEN_DEFAULT_TTL_SECONDS used to be read and displayed by
    `check-setup` but never actually consulted anywhere - a rule that omits
    ttl_seconds always got a separate hardcoded literal (60) instead. It must
    fall back to the configured setting, not a second independent constant."""
    from agentwarden.config import Settings
    from agentwarden.policy import schema as schema_module

    monkeypatch.setattr(schema_module, "settings", Settings(default_ttl_seconds=123))
    path = _write(tmp_path, """
version: 1
identities:
  - identity: x
    rules:
      - tool: t
        upstream: u
""")
    rules = load_policy_file(path)["x"]
    assert rules[0].ttl_seconds == 123


def test_strict_flag_parsed_from_policy(tmp_path: Path):
    path = _write(tmp_path, """
version: 1
identities:
  - identity: x
    rules:
      - tool: write_file
        upstream: fs-mcp
        strict: true
        argument_constraints:
          path: {path_within: "/workspace/"}
""")
    rules = load_policy_file(path)["x"]
    assert rules[0].strict is True


def test_strict_defaults_to_false(tmp_path: Path):
    path = _write(tmp_path, """
version: 1
identities:
  - identity: x
    rules:
      - tool: t
        upstream: u
""")
    rules = load_policy_file(path)["x"]
    assert rules[0].strict is False


def test_enforcement_modes(tmp_path: Path):
    path = _write(tmp_path, """
version: 1
identities:
  - identity: x
    enforcement: monitor
    rules: []
  - identity: y
    rules: []
""")
    modes = load_enforcement_modes(path)
    assert modes == {"x": "monitor", "y": "enforce"}
