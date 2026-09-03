"""v1 identity binding: one Identity per AgentWarden listener, fixed in its
launch config - not cryptographically authenticated (see README's Known
limitations). A real deployment would tie this to the agent host's own
proven identity (client cert, signed JWT); nothing about MCP itself carries
an authenticated caller identity today, so this is the same trust boundary
every MCP proxy has to accept for now."""
from __future__ import annotations

from agentwarden.models import Identity


def bind_listener_identity(identity_id: str, label: str, listener_source: str, clock) -> Identity:
    return Identity(identity_id=identity_id, label=label, source=listener_source, bound_at=clock.now())
