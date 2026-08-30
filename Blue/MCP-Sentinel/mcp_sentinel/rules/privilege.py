"""Over-privileged tool detection: dangerous capabilities, missing/mismatched
annotations, overly broad schemas, and auto-approval of risky tools.
"""
from __future__ import annotations

import re
from typing import Any

from mcp_sentinel.models import Finding, RiskCategory, ServerInventory, Severity, ToolInfo
from mcp_sentinel.rules.catalog import OWASP_COMMAND_INJECTION, OWASP_PRIVILEGE_ESCALATION

# Verb stems (matched with a trailing \w* so "delete"/"deletes"/"deleting"
# all hit, and against text pre-normalized to turn "run_shell_command" /
# "run-shell-command" / "runShellCommand" into "run shell command" first - a
# bare \b...\b would never isolate "shell" inside an underscore-joined
# identifier, since regex treats "_" as a word character with no boundary on
# either side of it, and camelCase has no separator character at all).
#
# eval(?!uat) rather than a bare eval\w*: the bare stem also matches
# "evaluate"/"evaluation" - ordinary English words for "assess", not a
# code-execution primitive - which produced false CRITICAL/HIGH findings on
# perfectly benign tools like evaluate_expression/get_evaluation_report.
_EXEC_PATTERN = re.compile(
    r"\b(exec\w*|eval(?!uat)\w*|shell|bash|powershell|subprocess\w*|os\.system|"
    r"run\s?command|arbitrary\s?(code|command)|run\s?script)\b",
    re.IGNORECASE,
)

# Verbs that indicate the tool mutates or destroys state - relevant for
# checking whether destructive_hint was honestly declared.
#
# drop(?!down) excludes "dropdown"; "wip\w*" was replaced with "wipe\w*" since
# bare "wip" (as in "work in progress") is a common benign abbreviation, not
# a destructive verb; bare "format\w*" was dropped entirely - "format_date"/
# "format_currency" utility tools are far more common in the wild than a
# literal disk-format tool, and the ambiguity made this stem net-negative.
_DESTRUCTIVE_PATTERN = re.compile(
    r"\b(delete\w*|remov\w*|drop(?!down)\w*|truncat\w*|destroy\w*|wipe\w*|purg\w*|overwrit\w*)\b", re.IGNORECASE
)

_WRITE_PATTERN = re.compile(r"\b(writ\w*|creat\w*|updat\w*|modif\w*|edit\w*|insert\w*|sav\w*|upload\w*|send\w*)\b", re.IGNORECASE)

# Parameter names that commonly carry attacker-reachable arbitrary paths/URLs/commands.
_BROAD_PARAM_NAMES = {"path", "file_path", "filepath", "cwd", "command", "cmd", "url", "uri", "query", "code", "script"}

_WORD_JOINER_PATTERN = re.compile(r"[_\-]+")
# Two boundary rules, the standard pair for splitting identifiers that mix
# acronyms and words: lower/digit -> upper ("runShell" -> "run Shell") and
# upper -> upper-then-lower ("OSExec" -> "OS Exec", "HTTPDropTable" ->
# "HTTP Drop Table"). A round-2 review found the first rule alone still
# fused an acronym straight into the following verb ("HTTPDrop" never
# isolated "Drop"), letting an acronym-prefixed exec/destructive tool name
# evade every keyword rule below.
_CAMEL_CASE_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _tool_text(tool: ToolInfo) -> str:
    # Normalize identifier joiners AND camelCase boundaries to spaces, purely
    # for keyword matching, so "run_shell_command"/"run-shell-command"/
    # "runShellCommand" all read as "run shell command" - see the comment
    # above _EXEC_PATTERN for why this matters.
    text = _WORD_JOINER_PATTERN.sub(" ", f"{tool.name} {tool.description}")
    return _CAMEL_CASE_BOUNDARY.sub(" ", text)


def _schema_properties(tool: ToolInfo) -> dict[str, Any]:
    props = tool.input_schema.get("properties") if isinstance(tool.input_schema, dict) else None
    return props if isinstance(props, dict) else {}


def _is_unconstrained_string(prop_schema: Any) -> bool:
    if not isinstance(prop_schema, dict):
        return False
    return prop_schema.get("type") == "string" and not any(k in prop_schema for k in ("enum", "pattern", "format", "maxLength"))


def has_exec_indicators(tool: ToolInfo) -> bool:
    """True if the tool's name/description matches shell/subprocess/code-exec
    language. Exposed for probes/active.py's safety gate: a tool shouldn't be
    actively invoked just because it *claims* readOnlyHint=true if it also
    reads as an execution primitive - an annotation can lie."""
    return bool(_EXEC_PATTERN.search(_tool_text(tool)))


def check_tool_privileges(server_id: str, tool: ToolInfo, auto_approved_tools: tuple[str, ...] = ()) -> list[Finding]:
    findings: list[Finding] = []
    text = _tool_text(tool)
    ann = tool.annotations
    is_auto_approved = "*" in auto_approved_tools or tool.name in auto_approved_tools

    if _EXEC_PATTERN.search(text):
        findings.append(
            Finding(
                finding_id=f"priv-exec:{server_id}:{tool.name}",
                severity=Severity.CRITICAL if is_auto_approved else Severity.HIGH,
                category=RiskCategory.OVER_PRIVILEGED_TOOL,
                title=f"Tool '{tool.name}' appears to grant arbitrary command/code execution",
                description=(
                    f"The name/description of tool '{tool.name}' on server '{server_id}' matches "
                    "patterns associated with shell, subprocess, or code-execution capability. "
                    "An agent with this tool grant can act far beyond a narrow, auditable task."
                ),
                server_id=server_id,
                tool_name=tool.name,
                evidence={"matched_text": text[:300], "auto_approved": is_auto_approved},
                recommendation=(
                    "Confirm this tool is intentional and scoped (e.g. an allow-listed command set, "
                    "not a raw shell). Require human confirmation before invocation and never auto-approve it."
                ),
                references=(OWASP_COMMAND_INJECTION, OWASP_PRIVILEGE_ESCALATION),
            )
        )

    destructive_language = bool(_DESTRUCTIVE_PATTERN.search(text))
    if destructive_language and ann.destructive_hint is False:
        findings.append(
            Finding(
                finding_id=f"priv-mismatch:{server_id}:{tool.name}",
                severity=Severity.HIGH,
                category=RiskCategory.OVER_PRIVILEGED_TOOL,
                title=f"Tool '{tool.name}' declares destructiveHint=false but reads as destructive",
                description=(
                    f"Tool '{tool.name}' contains destructive language (delete/remove/drop/wipe/...) in its "
                    "name or description, but its annotations claim it is non-destructive. Agents and "
                    "human reviewers both rely on this annotation to decide whether to prompt for confirmation."
                ),
                server_id=server_id,
                tool_name=tool.name,
                evidence={"matched_text": text[:300]},
                recommendation="Correct the annotation, or if the mismatch is deliberate, treat this as tool poisoning.",
                references=(OWASP_PRIVILEGE_ESCALATION,),
            )
        )
    elif (destructive_language or _WRITE_PATTERN.search(text)) and ann.destructive_hint is None and ann.read_only_hint is None:
        findings.append(
            Finding(
                finding_id=f"priv-undeclared:{server_id}:{tool.name}",
                severity=Severity.MEDIUM,
                category=RiskCategory.OVER_PRIVILEGED_TOOL,
                title=f"Tool '{tool.name}' has state-changing language but no read-only/destructive annotation",
                description=(
                    f"Tool '{tool.name}' looks like it writes or mutates state, but declares neither "
                    "readOnlyHint nor destructiveHint. Undeclared risk cannot be safely defaulted by a host "
                    "or an agent."
                ),
                server_id=server_id,
                tool_name=tool.name,
                evidence={"matched_text": text[:300]},
                recommendation="Ask the server maintainer to declare tool annotations, or manually classify this tool before granting it.",
                references=(OWASP_PRIVILEGE_ESCALATION,),
            )
        )

    broad_params = [name for name, schema in _schema_properties(tool).items() if name.lower() in _BROAD_PARAM_NAMES and _is_unconstrained_string(schema)]
    if broad_params and ann.open_world_hint is not False:
        findings.append(
            Finding(
                finding_id=f"priv-broad-schema:{server_id}:{tool.name}",
                severity=Severity.MEDIUM,
                category=RiskCategory.OVER_PRIVILEGED_TOOL,
                title=f"Tool '{tool.name}' accepts unconstrained {', '.join(broad_params)} parameter(s)",
                description=(
                    f"Tool '{tool.name}' takes free-form string input for {', '.join(broad_params)} with no "
                    "enum, pattern, or format constraint, and does not declare openWorldHint=false. This is "
                    "consistent with the tool reaching arbitrary filesystem paths, URLs, or commands rather "
                    "than a bounded resource set."
                ),
                server_id=server_id,
                tool_name=tool.name,
                evidence={"unconstrained_params": broad_params},
                recommendation="Constrain the parameter (allow-list, path prefix, URL scheme/host allow-list) or scope the grant to a sandboxed environment.",
                references=(OWASP_PRIVILEGE_ESCALATION,),
            )
        )

    if is_auto_approved and (ann.destructive_hint is True or destructive_language):
        findings.append(
            Finding(
                finding_id=f"priv-auto-approve-destructive:{server_id}:{tool.name}",
                severity=Severity.HIGH,
                category=RiskCategory.OVER_PRIVILEGED_TOOL,
                title=f"Destructive tool '{tool.name}' is auto-approved, bypassing human confirmation",
                description=(
                    f"The agent host's config auto-approves '{tool.name}' on server '{server_id}', which "
                    "appears destructive. A prompt-injected or hallucinating agent can invoke it with no "
                    "human in the loop."
                ),
                server_id=server_id,
                tool_name=tool.name,
                evidence={"auto_approved_tools": list(auto_approved_tools)},
                recommendation="Remove this tool from the auto-approve list; require explicit confirmation for destructive actions.",
                references=(OWASP_PRIVILEGE_ESCALATION,),
            )
        )

    return findings


def check_server_privileges(inventory: ServerInventory) -> list[Finding]:
    findings: list[Finding] = []
    for tool in inventory.tools:
        findings.extend(check_tool_privileges(inventory.config.server_id, tool, inventory.config.auto_approved_tools))
    return findings
