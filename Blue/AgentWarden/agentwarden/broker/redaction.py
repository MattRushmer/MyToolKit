"""A ToolCallRecord persists a sha256 digest of the *full* call arguments
plus only the fields the matched rule actually constrains (policy/engine.py's
`_check_constraints` already returns that subset) - this is a credential
tool; tool-call arguments routinely carry file contents, PR bodies, or other
sensitive payloads that must never land in the audit DB/report verbatim,
mirroring MCP-Sentinel's real-vs-redacted split for MCPServerConfig."""
from __future__ import annotations

import hashlib
import json


def digest_arguments(arguments: dict[str, object]) -> str:
    canonical = json.dumps(arguments, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
