"""Shared data contracts used across discovery, introspection, rules, probes, and reporting."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Ordering used to sort findings worst-first without a custom comparator.
_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


def severity_rank(severity: Severity) -> int:
    return _SEVERITY_RANK[severity]


class RiskCategory(str, Enum):
    OVER_PRIVILEGED_TOOL = "over_privileged_tool"
    UNAUTHENTICATED_TRANSPORT = "unauthenticated_transport"
    TOOL_POISONING = "tool_poisoning"
    PROMPT_INJECTION = "prompt_injection"
    CONFIG_DRIFT = "config_drift"
    UNREACHABLE_SERVER = "unreachable_server"


class TransportType(str, Enum):
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"


@dataclass(frozen=True)
class ToolAnnotations:
    """Mirrors the MCP spec's optional tool annotations. `None` means the server
    didn't declare the hint at all - distinct from declaring it `False` - because
    an undeclared destructive/read-only hint is itself a finding (see rules/privilege.py)."""

    title: str | None = None
    read_only_hint: bool | None = None
    destructive_hint: bool | None = None
    idempotent_hint: bool | None = None
    open_world_hint: bool | None = None


@dataclass(frozen=True)
class ToolInfo:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: ToolAnnotations = field(default_factory=ToolAnnotations)


@dataclass(frozen=True)
class ResourceInfo:
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str = ""


@dataclass(frozen=True)
class PromptInfo:
    name: str
    description: str = ""
    arguments: tuple[str, ...] = ()


@dataclass(frozen=True)
class MCPServerConfig:
    """One MCP server entry as declared in an agent host's config file (Claude
    Desktop, Claude Code, Cursor, Windsurf, Cline/VS Code, or a generic .mcp.json)."""

    server_id: str  # stable id: f"{host_app}:{config_name}"
    config_name: str  # the key this server was registered under in its config file
    host_app: str  # which agent host declared it, e.g. "claude-desktop", "cursor"
    source_config_path: str
    transport: TransportType
    command: str | None = None
    # Redacted at parse time (see discovery/parser.py's _redact_args): any
    # value that looks like a credential is replaced with a placeholder
    # before it ever reaches this field, since this is what gets serialized
    # into every JSON/Markdown report. The real values needed to actually
    # launch the server are re-read separately and transiently at connect
    # time - see discovery/parser.py's extract_raw_entries.
    args: tuple[str, ...] = ()
    # Flag names only (e.g. "--api-key") - never the value - for launch args
    # that looked like they carried a credential. Safe to persist, same
    # principle as env_var_names below.
    secret_like_arg_flags: tuple[str, ...] = ()
    env_var_names: tuple[str, ...] = ()  # names only - never the values, to avoid persisting secrets
    # Redacted at parse time (see discovery/parser.py's _redact_url): any
    # query-string parameter that looks like a credential is replaced with a
    # placeholder. Same real-vs-persisted split as `args` above.
    url: str | None = None
    has_auth_header: bool = False
    # Some hosts (e.g. Cline) let a server auto-approve tool calls without a
    # human prompt. "*" means "all tools on this server auto-approve".
    auto_approved_tools: tuple[str, ...] = ()


@dataclass
class ServerInventory:
    """Live introspection result for one configured server."""

    config: MCPServerConfig
    reachable: bool = False
    connection_error: str | None = None
    server_name: str | None = None
    server_version: str | None = None
    tools: list[ToolInfo] = field(default_factory=list)
    resources: list[ResourceInfo] = field(default_factory=list)
    prompts: list[PromptInfo] = field(default_factory=list)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: Severity
    category: RiskCategory
    title: str
    description: str
    server_id: str
    tool_name: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    references: tuple[str, ...] = ()  # e.g. ("OWASP-MCP-01", "CSA-MCP-TOOL-POISONING")


@dataclass
class ScanReport:
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    inventories: list[ServerInventory] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    active_probes_run: bool = False

    @property
    def counts_by_severity(self) -> dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def total_servers(self) -> int:
        return len(self.inventories)

    @property
    def total_tools(self) -> int:
        return sum(len(inv.tools) for inv in self.inventories)

    def findings_sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (severity_rank(f.severity), f.server_id, f.tool_name or ""))
