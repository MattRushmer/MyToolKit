"""Loads the combined `agentwarden serve` config: identity, upstream server
definitions, and where the policy file lives - kept separate from
policy/schema.py's PolicyRule loading since this is CLI/deployment wiring,
not the policy model itself.

    identity_id: coding-agent
    identity_label: "Coding Agent"
    policy_file: policy.yaml
    blast_radius_ceiling: 2
    upstreams:
      - id: fs-mcp
        transport: stdio
        command: python
        args: ["fixtures/fs_server.py"]
        env:
          FS_ROOT: /workspace
      - id: github-mcp
        transport: http
        url: https://internal-github-mcp.example/mcp
        headers:
          Authorization: "Bearer ${GITHUB_MCP_TOKEN}"

`${VAR}` in any string value is expanded from the environment at load time -
this is how a real deployment keeps upstream credentials (the whole point of
this tool) out of the config file itself; only the *names* of the env vars a
credential comes from ever appear in `agentwarden serve`'s config, never the
values, mirroring MCP-Sentinel's real-vs-redacted split for MCPServerConfig.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from agentwarden.proxy.upstream import UpstreamConfig

_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ServeConfigError(ValueError):
    pass


def _expand_env(value: object) -> object:
    if isinstance(value, str):
        return _ENV_VAR_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


@dataclass(frozen=True)
class ServeConfig:
    identity_id: str
    identity_label: str
    policy_file: Path
    blast_radius_ceiling: int
    upstreams: list[UpstreamConfig]


def load_serve_config(path: Path) -> ServeConfig:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise ServeConfigError(f"could not read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ServeConfigError(f"invalid YAML in {path}: {exc}") from exc

    raw = _expand_env(raw)

    for required in ("identity_id", "policy_file", "upstreams"):
        if required not in raw:
            raise ServeConfigError(f"{path} is missing required key '{required}'")

    upstreams = []
    for entry in raw["upstreams"]:
        if "id" not in entry or "transport" not in entry:
            raise ServeConfigError(f"upstream entry missing 'id'/'transport': {entry}")
        upstreams.append(UpstreamConfig(
            upstream_id=str(entry["id"]),
            transport=str(entry["transport"]),
            command=entry.get("command"),
            args=tuple(entry.get("args", [])),
            env=dict(entry.get("env", {})),
            url=entry.get("url"),
            headers=dict(entry.get("headers", {})),
            timeout_seconds=float(entry.get("timeout_seconds", 15.0)),
        ))

    policy_file = Path(raw["policy_file"])
    if not policy_file.is_absolute():
        policy_file = path.parent / policy_file

    return ServeConfig(
        identity_id=str(raw["identity_id"]),
        identity_label=str(raw.get("identity_label", raw["identity_id"])),
        policy_file=policy_file,
        blast_radius_ceiling=int(raw.get("blast_radius_ceiling", 3)),
        upstreams=upstreams,
    )
