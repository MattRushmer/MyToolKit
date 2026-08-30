"""Benign argument construction for active tool probing.

The goal of active probing (see probes/active.py) is NOT to inject anything
into the tool - it's to safely trigger a real invocation of a read-only tool
so we can inspect its *actual response* for injected content (a compromised
upstream API, a poisoned backend, a hostile third-party data source). The
values below are deliberately mundane; any "attacker" content the scanner
finds afterward came from the tool, not from us.
"""
from __future__ import annotations

from typing import Any

_NAME_HINTS: dict[str, str] = {
    "url": "https://example.com/mcp-sentinel-probe",
    "uri": "https://example.com/mcp-sentinel-probe",
    "link": "https://example.com/mcp-sentinel-probe",
    "query": "mcp sentinel connectivity probe",
    "q": "mcp sentinel connectivity probe",
    "search": "mcp sentinel connectivity probe",
    "text": "mcp sentinel connectivity probe",
    "message": "mcp sentinel connectivity probe",
    "path": ".",
    "file_path": ".",
    "filepath": ".",
    "city": "London",
    "location": "London",
    "id": "1",
    "name": "probe",
}

# Types we refuse to guess a value for - safer to skip the whole tool than to
# fabricate a value for something we can't reason about (an object/array
# could hold anything; guessing wrong can trigger unintended tool behavior).
_UNSUPPORTED_TYPES = {"object", "array", "null"}


def _value_for_property(name: str, schema: dict[str, Any]) -> Any | None:
    """Returns a benign value for one schema property, or None if we can't
    confidently construct one (caller should then skip the whole tool)."""
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]

    prop_type = schema.get("type")
    if isinstance(prop_type, list):  # JSON Schema allows a type union; take the first concrete one
        prop_type = next((t for t in prop_type if t != "null"), None)

    if prop_type in _UNSUPPORTED_TYPES:
        return None
    if prop_type == "boolean":
        return False
    if prop_type == "integer":
        return schema.get("minimum", 0)
    if prop_type == "number":
        return float(schema.get("minimum", 0))
    if prop_type == "string" or prop_type is None:
        return _NAME_HINTS.get(name.lower(), "mcp sentinel connectivity probe")
    return None


def build_probe_arguments(input_schema: dict[str, Any]) -> dict[str, Any] | None:
    """Returns a full set of arguments for every *required* property, or None
    if any required property can't be safely filled - the caller must then
    skip probing this tool rather than guess."""
    if not isinstance(input_schema, dict):
        return {}
    properties = input_schema.get("properties")
    if not isinstance(properties, dict):
        return {}

    required = input_schema.get("required")
    required_names = set(required) if isinstance(required, list) else set()

    args: dict[str, Any] = {}
    for name in required_names:
        schema = properties.get(name)
        if not isinstance(schema, dict):
            return None
        value = _value_for_property(name, schema)
        if value is None:
            return None
        args[name] = value
    return args
