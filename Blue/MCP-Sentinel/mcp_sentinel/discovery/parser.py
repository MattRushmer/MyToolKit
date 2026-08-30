"""Normalize every supported agent host's MCP config shape into MCPServerConfig.

Two shapes are supported:
  - "mcpServers": {name: {command, args, env}} or {name: {url, headers, type}}
    - used by Claude Desktop, Claude Code, Cursor, Windsurf, Cline.
  - "servers": {name: {type, command, args, env, url, headers}}
    - VS Code's native MCP support.

Cline additionally exposes "autoApprove" (list[str] or bool) and "disabled"
at the per-server level; both are privilege-relevant signals we carry through
rather than discard.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from mcp_sentinel.discovery.config_locations import ConfigLocation
from mcp_sentinel.models import MCPServerConfig, TransportType

_AUTH_HEADER_NAMES = {"authorization", "x-api-key", "api-key", "x-auth-token"}

REDACTED_PLACEHOLDER = "<redacted-by-mcp-sentinel>"

# Matched with .search() (anywhere in the identifier, not just as an exact
# name or an immediate suffix) against BOTH a CLI flag name and a URL query
# param / fragment key. A round-2 security review found the original
# exact-prefix-match version missed "--client-secret", "refresh_token",
# "id_token", etc. Substring matching over-redacts occasionally (e.g. a
# "--keyword" flag) - that's the intended, accepted tradeoff for a mechanism
# whose failure mode must be "redacts too much," never "leaks a credential."
_SECRET_KEYWORDS = re.compile(r"(api[-_]?key|token|passwd|password|secret|credential|auth)", re.IGNORECASE)
# A bare value that looks like an opaque credential regardless of context
# (long run of token-safe characters) - redacted defensively even without a
# preceding flag name, since some servers take a credential as a positional arg.
_LOOKS_LIKE_SECRET_VALUE = re.compile(r"^[A-Za-z0-9_\-\.+]{16,}$")


def _is_secret_flag_name(candidate: str) -> bool:
    return candidate.startswith("-") and bool(_SECRET_KEYWORDS.search(candidate))


def _looks_like_auth_header(headers: dict[str, Any] | None) -> bool:
    if not headers:
        return False
    return any(str(k).lower() in _AUTH_HEADER_NAMES for k in headers)


def _redact_args(args: list[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Returns (redacted_args, secret_like_flags) from the RAW arg list. Only
    the return value here is ever persisted to MCPServerConfig - the caller
    (engine.py, via extract_raw_entries) is responsible for getting the real
    args back to the connector at connect time.

    Handles both CLI conventions for passing a flag's value: space-separated
    ("--api-key" "<value>", two array entries) and inline ("--api-key=<value>",
    one entry) - each arg is split on its own "=" first so the inline form's
    value never ends up copied into `flags` (which only ever holds a flag
    *name*) or left un-redacted in `redacted`.
    """
    redacted = list(args)
    flags: list[str] = []
    for i, arg in enumerate(args):
        flag_part, sep, _value_part = arg.partition("=")
        if sep and _is_secret_flag_name(flag_part):
            flags.append(flag_part)
            redacted[i] = f"{flag_part}={REDACTED_PLACEHOLDER}"
            continue
        if _is_secret_flag_name(arg):
            flags.append(arg)
            if i + 1 < len(args):
                redacted[i + 1] = REDACTED_PLACEHOLDER
            continue
        if _LOOKS_LIKE_SECRET_VALUE.match(arg):
            redacted[i] = REDACTED_PLACEHOLDER
    return tuple(redacted), tuple(flags)


def _redact_query_like(raw: str) -> tuple[str, bool]:
    """Redacts secret-looking key=value pairs in a query string or fragment,
    or the whole thing if it's a bare opaque value with no "=" at all (e.g. a
    fragment that's just "#<access_token>" with no "key=value" framing - a
    real shape for OAuth implicit-flow redirects). Returns (result, changed).

    The no-"=" check must come first: parse_qsl(..., keep_blank_values=True)
    on a string with no "=" treats the WHOLE string as a key with an empty
    value, so if that string happens to contain a keyword substring (a bare
    fragment token literally containing "token" is common), the naive
    key=value path would redact the fabricated empty *value* and leave the
    actual secret sitting untouched in the "key" position - the opposite of
    what's intended.
    """
    if "=" not in raw:
        return (REDACTED_PLACEHOLDER, True) if _LOOKS_LIKE_SECRET_VALUE.match(raw) else (raw, False)
    pairs = parse_qsl(raw, keep_blank_values=True)
    if not pairs or not any(_SECRET_KEYWORDS.search(k) for k, _ in pairs):
        return raw, False
    redacted_pairs = [(k, REDACTED_PLACEHOLDER if _SECRET_KEYWORDS.search(k) else v) for k, v in pairs]
    return urlencode(redacted_pairs), True


def _redact_url(url: str | None) -> str | None:
    """Redacts credentials embedded in a URL: HTTP Basic-auth-style
    userinfo (user:password@host), secret-looking query params, and a
    secret-looking fragment (common in OAuth implicit-flow redirects, e.g.
    "#access_token=..." or a bare opaque token with no "key=value" framing)."""
    if not url:
        return url
    parsed = urlsplit(url)
    changed = False

    netloc = parsed.netloc
    if parsed.username or parsed.password:
        changed = True
        host_part = parsed.hostname or ""
        if parsed.port:
            host_part = f"{host_part}:{parsed.port}"
        netloc = f"{REDACTED_PLACEHOLDER}@{host_part}"

    query = parsed.query
    if query:
        query, query_changed = _redact_query_like(query)
        changed = changed or query_changed

    fragment = parsed.fragment
    if fragment:
        fragment, frag_changed = _redact_query_like(fragment)
        changed = changed or frag_changed

    if not changed:
        return url
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment))


def _transport_for(entry: dict[str, Any]) -> TransportType:
    declared = str(entry.get("type", "")).lower()
    if declared in ("sse",):
        return TransportType.SSE
    if declared in ("http", "streamable-http", "streamable_http"):
        return TransportType.HTTP
    if declared == "stdio":
        return TransportType.STDIO
    # No explicit type: infer from shape.
    if entry.get("url"):
        url = str(entry["url"]).lower()
        return TransportType.SSE if "sse" in url else TransportType.HTTP
    return TransportType.STDIO


def _auto_approved(entry: dict[str, Any]) -> tuple[str, ...]:
    raw = entry.get("autoApprove")
    if raw is True:
        return ("*",)
    if isinstance(raw, list):
        return tuple(str(x) for x in raw)
    return ()


def parse_server_entry(host_app: str, config_name: str, entry: dict[str, Any], source_path: str) -> MCPServerConfig:
    transport = _transport_for(entry)
    headers = entry.get("headers") if isinstance(entry.get("headers"), dict) else None
    env = entry.get("env") if isinstance(entry.get("env"), dict) else {}
    raw_args = entry.get("args") if isinstance(entry.get("args"), list) else []
    redacted_args, secret_flags = _redact_args([str(a) for a in raw_args])

    return MCPServerConfig(
        server_id=f"{host_app}:{config_name}",
        config_name=config_name,
        host_app=host_app,
        source_config_path=source_path,
        transport=transport,
        command=entry.get("command"),
        args=redacted_args,
        secret_like_arg_flags=secret_flags,
        env_var_names=tuple(sorted(str(k) for k in env)),
        url=_redact_url(entry.get("url")),
        has_auth_header=_looks_like_auth_header(headers),
        auto_approved_tools=_auto_approved(entry),
    )


def _iter_raw_entries(schema: str, data: dict[str, Any], source_path: str) -> tuple[list[tuple[str, Any]], list[str]]:
    """Yields (config_name, raw_entry) pairs for every schema shape we know
    about. Shared by parse_config_dict (builds MCPServerConfig) and
    extract_raw_entries (returns the raw dict verbatim, secrets included) so
    the two can never disagree about which servers a config file declares.

    A top-level "projects" dict (Claude Code's user-scoped ~/.claude.json:
    {"projects": {"<abs project path>": {"mcpServers": {...}}}}) is detected
    from the data itself, not from `schema` - a location built for a known
    host app (see discovery/config_locations.py) can supply the right
    `schema` up front, but `--config <arbitrary path>` cannot, so this can't
    depend on the caller having already guessed the file's shape.
    """
    warnings: list[str] = []
    pairs: list[tuple[str, Any]] = []

    projects = data.get("projects")
    if isinstance(projects, dict):
        for project_path, project_data in projects.items():
            if not isinstance(project_data, dict):
                continue
            raw_servers = project_data.get("mcpServers")
            if raw_servers is None:
                continue
            if not isinstance(raw_servers, dict):
                warnings.append(f"{source_path}: project '{project_path}' mcpServers is not an object, skipping")
                continue
            for name, entry in raw_servers.items():
                pairs.append((f"{project_path}::{name}", entry))
    elif projects is not None:
        warnings.append(f"{source_path}: 'projects' is not an object, skipping")

    top_level_key = "servers" if schema == "servers" else "mcpServers"
    raw_servers = data.get(top_level_key)
    if isinstance(raw_servers, dict):
        for name, entry in raw_servers.items():
            pairs.append((str(name), entry))
    elif raw_servers is not None:
        warnings.append(f"{source_path}: '{top_level_key}' is not an object, skipping")

    return pairs, warnings


def parse_config_dict(host_app: str, schema: str, data: dict[str, Any], source_path: str) -> tuple[list[MCPServerConfig], list[str]]:
    """Returns (servers, warnings). Never raises on malformed per-entry data -
    one bad server entry in a host's config shouldn't blind the scan to every
    other server declared alongside it."""

    servers: list[MCPServerConfig] = []
    pairs, warnings = _iter_raw_entries(schema, data, source_path)

    for config_name, entry in pairs:
        if not isinstance(entry, dict):
            warnings.append(f"{source_path}: server '{config_name}' entry is not an object, skipping")
            continue
        if entry.get("disabled") is True:
            continue
        try:
            servers.append(parse_server_entry(host_app, config_name, entry, source_path))
        except Exception as exc:  # noqa: BLE001 - one malformed entry must not abort the scan
            warnings.append(f"{source_path}: failed to parse server '{config_name}': {exc}")

    return servers, warnings


def load_config_file(location: ConfigLocation) -> tuple[list[MCPServerConfig], list[str]]:
    try:
        raw_text = location.path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], [f"{location.path}: could not read file: {exc}"]

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        return [], [f"{location.path}: invalid JSON: {exc}"]

    if not isinstance(data, dict):
        return [], [f"{location.path}: top-level JSON is not an object, skipping"]

    return parse_config_dict(location.host_app, location.schema, data, str(location.path))


def extract_raw_entries(location: ConfigLocation) -> dict[str, dict[str, Any]]:
    """Re-read a config file's per-server entries verbatim (including secret
    values), keyed by config_name. Used only transiently, by the live client
    connector, to authenticate a real introspection connection - callers must
    not persist the return value. MCPServerConfig (from load_config_file)
    never carries these values, only their names/presence, so a ScanReport
    or baseline file can never leak a credential even if serialized to disk.
    """
    try:
        data = json.loads(location.path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    pairs, _ = _iter_raw_entries(location.schema, data, str(location.path))
    return {name: entry for name, entry in pairs if isinstance(entry, dict)}


def load_config_files(locations: list[ConfigLocation]) -> tuple[list[MCPServerConfig], list[str]]:
    all_servers: list[MCPServerConfig] = []
    all_warnings: list[str] = []
    for location in locations:
        if not location.path.is_file():
            continue
        servers, warnings = load_config_file(location)
        all_servers.extend(servers)
        all_warnings.extend(warnings)
    return all_servers, all_warnings
