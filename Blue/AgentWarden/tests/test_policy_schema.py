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
