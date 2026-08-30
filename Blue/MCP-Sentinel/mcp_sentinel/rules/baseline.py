"""Rug-pull / config-drift detection: a tool that looked safe on a previous
scan can silently change its description or schema later - the classic
"rug pull" where a server earns trust with a benign tool, then swaps in
malicious behavior after it's already been granted. We can't see intent, but
we can see when the on-disk facts changed since the last scan.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from mcp_sentinel.models import Finding, RiskCategory, ServerInventory, Severity, ToolInfo
from mcp_sentinel.rules.catalog import OWASP_SHADOW_SERVERS, OWASP_TOOL_POISONING

BASELINE_FILENAME = "baseline.json"


def _tool_fingerprint(tool: ToolInfo) -> str:
    payload = {
        "description": tool.description,
        "input_schema": tool.input_schema,
        "annotations": asdict(tool.annotations),
    }
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def build_baseline(inventories: list[ServerInventory]) -> dict[str, Any]:
    baseline: dict[str, Any] = {}
    for inv in inventories:
        if not inv.reachable:
            continue
        baseline[inv.config.server_id] = {
            "server_name": inv.server_name,
            "server_version": inv.server_version,
            "tools": {tool.name: _tool_fingerprint(tool) for tool in inv.tools},
        }
    return baseline


def load_baseline(state_dir: Path) -> dict[str, Any]:
    path = state_dir / BASELINE_FILENAME
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_baseline(state_dir: Path, baseline: dict[str, Any]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / BASELINE_FILENAME).write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")


def check_drift(inventory: ServerInventory, previous_baseline: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    server_id = inventory.config.server_id
    prev_server = previous_baseline.get(server_id)
    if prev_server is None:
        return findings  # first time we've seen this server - nothing to diff against yet

    prev_tools: dict[str, str] = prev_server.get("tools", {})
    current_names = {tool.name for tool in inventory.tools}

    for tool in inventory.tools:
        prev_hash = prev_tools.get(tool.name)
        if prev_hash is None:
            continue  # newly added tool, not drift of an existing grant
        if prev_hash != _tool_fingerprint(tool):
            findings.append(
                Finding(
                    finding_id=f"drift-tool-changed:{server_id}:{tool.name}",
                    severity=Severity.HIGH,
                    category=RiskCategory.CONFIG_DRIFT,
                    title=f"Tool '{tool.name}' on server '{server_id}' changed since the last scan",
                    description=(
                        f"The description, input schema, or annotations of tool '{tool.name}' differ from the "
                        "previously recorded baseline. A previously-trusted tool changing behavior after the "
                        "fact is the defining pattern of a rug-pull attack."
                    ),
                    server_id=server_id,
                    tool_name=tool.name,
                    evidence={"previous_hash": prev_hash, "current_hash": _tool_fingerprint(tool)},
                    recommendation="Diff the tool definition against the previous scan's report and re-review before continuing to trust this grant.",
                    references=(OWASP_TOOL_POISONING, OWASP_SHADOW_SERVERS),
                )
            )

    removed = set(prev_tools) - current_names
    for name in sorted(removed):
        findings.append(
            Finding(
                finding_id=f"drift-tool-removed:{server_id}:{name}",
                severity=Severity.INFO,
                category=RiskCategory.CONFIG_DRIFT,
                title=f"Tool '{name}' on server '{server_id}' is no longer advertised",
                description="A previously-seen tool is absent from this scan. Confirm this is an intentional removal, not a server serving a different tool set to different callers.",
                server_id=server_id,
                tool_name=name,
                evidence={},
                recommendation="Confirm the removal was intentional.",
                references=(OWASP_SHADOW_SERVERS,),
            )
        )

    return findings
