"""Unauthenticated-transport detection for network-reachable MCP servers, and
secret-in-plaintext detection for stdio server launch args.
"""
from __future__ import annotations

from urllib.parse import urlparse

from mcp_sentinel.models import Finding, MCPServerConfig, RiskCategory, Severity, TransportType
from mcp_sentinel.rules.catalog import OWASP_INSUFFICIENT_AUTH, OWASP_TOKEN_MISMANAGEMENT

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}  # noqa: S104 - detection target, not a bind address here


def _is_local_url(url: str) -> bool:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return False
    return (host or "").lower() in _LOCAL_HOSTS


def check_transport_auth(config: MCPServerConfig) -> list[Finding]:
    findings: list[Finding] = []

    if config.transport in (TransportType.HTTP, TransportType.SSE) and config.url:
        remote = not _is_local_url(config.url)
        if not config.has_auth_header:
            findings.append(
                Finding(
                    finding_id=f"auth-missing:{config.server_id}",
                    severity=Severity.CRITICAL if remote else Severity.LOW,
                    category=RiskCategory.UNAUTHENTICATED_TRANSPORT,
                    title=f"{'Remote' if remote else 'Local'} MCP server '{config.config_name}' has no auth header configured",
                    description=(
                        f"Server '{config.server_id}' is configured over {config.transport.value} to "
                        f"{config.url} without an Authorization/API-key header in its client config. "
                        + ("Anyone who can reach this network endpoint can invoke its tools." if remote else
                           "It is loopback-only, but any other local process/user can still reach it.")
                    ),
                    server_id=config.server_id,
                    evidence={"url": config.url, "transport": config.transport.value},
                    recommendation="Require an auth header (bearer token, API key, mTLS) on the server, and configure it in every host that connects.",
                    references=(OWASP_INSUFFICIENT_AUTH,),
                )
            )

    if config.transport == TransportType.STDIO:
        # Detection (and the one place the real value is ever seen) happens
        # at parse time in discovery/parser.py's _redact_args - only the
        # matched flag *name* survives onto config, so there's nothing here
        # that could re-leak a credential into this Finding's evidence.
        for flag in config.secret_like_arg_flags:
            findings.append(_stdio_secret_finding(config, flag))

    return findings


def _stdio_secret_finding(config: MCPServerConfig, matched_flag: str) -> Finding:
    return Finding(
        finding_id=f"auth-secret-in-args:{config.server_id}:{matched_flag}",
        severity=Severity.MEDIUM,
        category=RiskCategory.UNAUTHENTICATED_TRANSPORT,
        title=f"Server '{config.config_name}' may pass a credential via plaintext command-line arguments",
        description=(
            f"Server '{config.server_id}' launch args include '{matched_flag}', whose name suggests a "
            "credential follows it. Command-line arguments are visible to any other process on the same "
            "host (process listings, /proc, task manager) and are persisted in plaintext in the host's "
            "config file. The value itself is not shown here or anywhere in this report."
        ),
        server_id=config.server_id,
        evidence={"redacted_args": list(config.args)},
        recommendation="Pass credentials via the server's `env` block (or a secret manager) instead of CLI arguments.",
        references=(OWASP_TOKEN_MISMANAGEMENT,),
    )
