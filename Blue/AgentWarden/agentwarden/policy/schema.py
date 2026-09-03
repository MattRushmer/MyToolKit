"""Load and validate a policy YAML file into PolicyRule objects.

    version: 1
    identities:
      - identity: "coding-agent"
        enforcement: enforce   # "enforce" (default) | "monitor" - monitor logs
                                # what WOULD have been blocked but allows it through,
                                # for a dry-run rollout
        default: deny           # "deny" (default) | "allow" - fallthrough for any
                                 # (tool, upstream) pair with no matching rule below
        rules:
          - tool: "write_file"
            upstream: "fs-mcp"
            ttl_seconds: 60
            argument_constraints:
              path: {path_within: "/workspace/"}
          - tool: "create_pr"
            upstream: "github-mcp"
            max_uses_per_task: 3
            ttl_seconds: 300
            argument_constraints:
              repo: {in: ["my-org/allowed-repo"]}
          - tool: "*"
            upstream: "payments-mcp"
            deny: true

Rule-matching order (resolved once at load time, not re-derived per call):
deny rules are tried first (in declaration order), then allow rules (in
declaration order); the first match wins. A synthetic catch-all rule
(`tool="*", upstream="*"`) is appended last per identity, carrying that
identity's `default` - so an unmatched call always matches *some* rule, and
policy/engine.py never needs "no rule matched" as a separate case. An
explicit `deny: true` rule is attributable (its `rule_id` names exactly which
rule fired); the catch-all's `source` is `"default-catch-all"` so an audit
event can tell the two apart even though both deny.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agentwarden.models import ArgumentConstraint, PolicyRule

_CONSTRAINT_KEYS = ("prefix", "path_within", "in", "lt", "gt", "eq")
_MAX_TTL_SECONDS = 3600  # a security tool that can itself mint a day-long credential defeats its own purpose


class PolicyValidationError(ValueError):
    pass


def _parse_constraint(field_name: str, raw: dict[str, Any]) -> ArgumentConstraint:
    unknown = set(raw) - set(_CONSTRAINT_KEYS)
    if unknown:
        raise PolicyValidationError(f"argument_constraints.{field_name} has unknown key(s): {sorted(unknown)}")
    present = [k for k in _CONSTRAINT_KEYS if k in raw]
    if len(present) != 1:
        raise PolicyValidationError(f"argument_constraints.{field_name} must set exactly one of {_CONSTRAINT_KEYS}, got {present}")
    kwargs: dict[str, Any] = {}
    if "prefix" in raw:
        kwargs["prefix"] = str(raw["prefix"])
    if "path_within" in raw:
        kwargs["path_within"] = str(raw["path_within"])
    if "in" in raw:
        kwargs["in_"] = tuple(raw["in"])
    if "lt" in raw:
        kwargs["lt"] = float(raw["lt"])
    if "gt" in raw:
        kwargs["gt"] = float(raw["gt"])
    if "eq" in raw:
        kwargs["eq"] = raw["eq"]
    return ArgumentConstraint(**kwargs)


def _parse_rule(identity_id: str, index: int, raw: dict[str, Any]) -> PolicyRule:
    if "tool" not in raw or "upstream" not in raw:
        raise PolicyValidationError(f"rule for identity '{identity_id}' is missing required 'tool'/'upstream': {raw}")

    constraints_raw = raw.get("argument_constraints", {})
    if not isinstance(constraints_raw, dict):
        raise PolicyValidationError(f"argument_constraints for identity '{identity_id}' must be a mapping")
    constraints = {field_name: _parse_constraint(field_name, spec) for field_name, spec in constraints_raw.items()}

    ttl_seconds = int(raw.get("ttl_seconds", 60))
    if not (0 < ttl_seconds <= _MAX_TTL_SECONDS):
        raise PolicyValidationError(f"identity '{identity_id}' rule #{index}: ttl_seconds must be in (0, {_MAX_TTL_SECONDS}], got {ttl_seconds}")

    max_uses = raw.get("max_uses_per_task")
    if max_uses is not None and int(max_uses) < 1:
        raise PolicyValidationError(f"identity '{identity_id}' rule #{index}: max_uses_per_task must be >= 1, got {max_uses}")

    return PolicyRule(
        rule_id=f"{identity_id}:{index}:{raw['tool']}@{raw['upstream']}",
        identity_id=identity_id,
        tool_name=str(raw["tool"]),
        upstream_server_id=str(raw["upstream"]),
        source="explicit",
        deny=bool(raw.get("deny", False)),
        max_uses_per_task=int(max_uses) if max_uses is not None else None,
        ttl_seconds=ttl_seconds,
        argument_constraints=constraints,
    )


def load_policy_file(path: Path) -> dict[str, list[PolicyRule]]:
    """Returns {identity_id: [PolicyRule, ...]}, deny rules first (declaration
    order), then allow rules (declaration order), then the identity's
    catch-all - the exact order policy/engine.py's evaluate() tries them in."""
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyValidationError(f"could not read policy file {path}: {exc}") from exc

    try:
        document = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError as exc:
        raise PolicyValidationError(f"invalid YAML in {path}: {exc}") from exc

    version = document.get("version")
    if version != 1:
        raise PolicyValidationError(f"{path}: 'version: 1' is required at the top level, got {version!r}")

    identity_blocks = document.get("identities")
    if not isinstance(identity_blocks, list) or not identity_blocks:
        raise PolicyValidationError(f"{path} must have a non-empty top-level 'identities' list")

    policies: dict[str, list[PolicyRule]] = {}
    for block in identity_blocks:
        if "identity" not in block:
            raise PolicyValidationError(f"identity block missing 'identity' key: {block}")
        identity_id = str(block["identity"])
        if identity_id in policies:
            raise PolicyValidationError(f"identity '{identity_id}' is declared more than once in {path}")

        default = str(block.get("default", "deny")).lower()
        if default not in ("deny", "allow"):
            raise PolicyValidationError(f"identity '{identity_id}': default must be 'deny' or 'allow', got {default!r}")

        enforcement = str(block.get("enforcement", "enforce")).lower()
        if enforcement not in ("enforce", "monitor"):
            raise PolicyValidationError(f"identity '{identity_id}': enforcement must be 'enforce' or 'monitor', got {enforcement!r}")

        rules_raw = block.get("rules", [])
        if not isinstance(rules_raw, list):
            raise PolicyValidationError(f"identity '{identity_id}': 'rules' must be a list")

        parsed = [_parse_rule(identity_id, i, r) for i, r in enumerate(rules_raw)]
        deny_rules = [r for r in parsed if r.deny]
        allow_rules = [r for r in parsed if not r.deny]
        catch_all = PolicyRule(
            rule_id=f"{identity_id}:catch-all",
            identity_id=identity_id,
            tool_name="*",
            upstream_server_id="*",
            source="default-catch-all",
            deny=(default == "deny"),
        )
        # `enforcement` isn't a PolicyRule field - engine.py reads it via
        # load_enforcement_modes() below, keyed by identity_id, so a monitor-mode
        # identity's Decision can still be built from the exact rule that would
        # have fired under enforce mode.
        policies[identity_id] = [*deny_rules, *allow_rules, catch_all]

    return policies


def load_enforcement_modes(path: Path) -> dict[str, str]:
    """Companion to load_policy_file: {identity_id: "enforce"|"monitor"}.
    Kept separate rather than smuggled onto PolicyRule so a rule's identity
    doesn't have to carry a mode that's actually a property of the whole
    identity block, duplicated onto every one of its rules."""
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    modes: dict[str, str] = {}
    for block in document.get("identities", []):
        identity_id = str(block.get("identity", ""))
        if identity_id:
            modes[identity_id] = str(block.get("enforcement", "enforce")).lower()
    return modes
