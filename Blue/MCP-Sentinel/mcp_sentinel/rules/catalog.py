"""OWASP MCP Top 10 (2025) reference IDs, shared across rule modules so every
finding cites a real, checkable external reference instead of an invented one.

Source: https://owasp.org/www-project-mcp-top-10/
"""
from __future__ import annotations

OWASP_TOKEN_MISMANAGEMENT = "MCP01:2025 Token Mismanagement & Secret Exposure"
OWASP_PRIVILEGE_ESCALATION = "MCP02:2025 Privilege Escalation via Scope Creep"
OWASP_TOOL_POISONING = "MCP03:2025 Tool Poisoning"
OWASP_SUPPLY_CHAIN = "MCP04:2025 Software Supply Chain Attacks & Dependency Tampering"
OWASP_COMMAND_INJECTION = "MCP05:2025 Command Injection & Execution"
OWASP_INTENT_FLOW_SUBVERSION = "MCP06:2025 Intent Flow Subversion"
OWASP_INSUFFICIENT_AUTH = "MCP07:2025 Insufficient Authentication & Authorization"
OWASP_LACK_OF_AUDIT = "MCP08:2025 Lack of Audit and Telemetry"
OWASP_SHADOW_SERVERS = "MCP09:2025 Shadow MCP Servers"
OWASP_CONTEXT_INJECTION = "MCP10:2025 Context Injection & Over-Sharing"
