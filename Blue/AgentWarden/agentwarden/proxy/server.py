"""The host-facing MCP server: the agent host connects to *this*, believing
it's talking to the real upstream server(s).

Built on `mcp.server.mcpserver.MCPServer` with a single `ServerMiddleware`
that intercepts every request before the SDK's own tool/resource handlers
ever run - no tool is ever registered via `add_tool()` (an architect-review
finding: the high-level API derives a tool's published JSON schema from a
Python function signature, which cannot carry an arbitrary upstream schema
losslessly). `tools/list` and `tools/call` are answered entirely from the
middleware; every other method is denied by default (see `_middleware`) -
`MCPServer` still advertises the `tools` capability correctly regardless,
since capability advertisement is derived from whether the `on_list_tools`/
`on_call_tool` *callbacks* are wired at construction (always true for
`MCPServer`), not from whether the ToolManager holds any tools - confirmed
by reading `mcp.server.lowlevel.server.Server.get_capabilities`.

Per-connection identity - a real finding from runtime testing, not just
docs: `ServerRequestContext.session` (and even `.session`'s own internal
`_connection`) is a **freshly constructed object on every inbound request**
in this SDK version, confirmed by logging `id(ctx.session)` across multiple
calls on one still-open connection and seeing a different id every time.
There is therefore no per-connection Python object identity available to
middleware to hang session state on at all - the "one MCP connection = one
AgentSession, zero cooperation needed" hard signal from the original design
doesn't exist in this SDK version. AgentWarden falls back to a caller-scoped
soft signal for session continuity too: `_meta["dev.agentwarden/sessionId"]`
on a `tools/call`. Given, a session is created fresh per call and behaves
like a one-call session with full policy enforcement and audit, just no
cross-call continuity - see README's Known limitations, which states this
more strongly than the original plan did.
"""
from __future__ import annotations

from typing import Any

from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import MCPServer
from mcp_types import ListToolsResult

from agentwarden.broker.delegation import resolve_delegation
from agentwarden.broker.identity import bind_listener_identity
from agentwarden.models import (
    AgentSession,
    EventType,
    PolicyRule,
    SessionStatus,
    Severity,
    Task,
    TaskStatus,
)
from agentwarden.proxy import errors
from agentwarden.proxy.mediator import MediatorDeps, mediate_tool_call
from agentwarden.proxy.upstream import UpstreamPool, build_tool_registry
from agentwarden.store import sessions as sessions_store
from agentwarden.store.audit import EventBuilder, append_event
from agentwarden.store.connection import Store

# Reserved `_meta` keys a cooperating agent framework sets on a `tools/call`
# request to get session continuity and delegation-chain tracking. Flat
# string keys, not a nested path: `RequestParamsMeta` is an open TypedDict on
# the wire, and `io.modelcontextprotocol/*` is reserved for the spec itself.
META_SESSION_KEY = "dev.agentwarden/sessionId"
META_PARENT_SESSION_KEY = "dev.agentwarden/parentSessionId"
META_TASK_KEY = "dev.agentwarden/taskId"

_ALWAYS_PASSTHROUGH_METHODS = frozenset({
    "initialize", "server/discover",  # handshake - a client may use either depending on negotiated protocol version
    "notifications/initialized", "ping", "notifications/cancelled",
})


class AgentWardenProxy:
    def __init__(
        self, *, identity_id: str, identity_label: str, listener_source: str, transport_label: str,
        policy_rules_by_identity: dict[str, list[PolicyRule]], enforcement_modes: dict[str, str],
        upstream_pool: UpstreamPool, store: Store, clock, new_id, instance_id: str, blast_radius_ceiling: int,
        name: str = "agentwarden",
    ) -> None:
        self._identity = bind_listener_identity(identity_id, identity_label, listener_source, clock)
        self._policy_rules_by_identity = policy_rules_by_identity
        self._enforcement_modes = enforcement_modes
        self._upstream_pool = upstream_pool
        self._store = store
        self._clock = clock
        self._new_id = new_id
        self._instance_id = instance_id
        self._blast_radius_ceiling = blast_radius_ceiling
        self._transport_label = transport_label
        self._tool_registry: dict[str, tuple[str, Any]] = {}
        self._mediator_deps: MediatorDeps | None = None
        self.mcp_server: MCPServer = MCPServer(name, middleware=[self._middleware])

    async def start(self) -> None:
        self._tool_registry = await build_tool_registry(self._upstream_pool)
        self._mediator_deps = MediatorDeps(
            store=self._store, upstream_pool=self._upstream_pool, tool_registry=self._tool_registry,
            policy_rules_by_identity=self._policy_rules_by_identity, enforcement_modes=self._enforcement_modes,
            blast_radius_ceiling=self._blast_radius_ceiling, clock=self._clock, new_id=self._new_id,
        )
        await sessions_store.upsert_identity(self._store, self._identity)
        await sessions_store.reconcile_stale_sessions(self._store, self._instance_id, self._clock.now().isoformat())

    def _explicit_rule_for(self, rules: list[PolicyRule], tool_name: str, upstream_id: str) -> PolicyRule | None:
        for rule in rules:
            if rule.source != "explicit":
                continue
            if (rule.tool_name in ("*", tool_name)) and (rule.upstream_server_id in ("*", upstream_id)):
                return rule
        return None

    async def _handle_list_tools(self) -> ListToolsResult:
        rules = self._policy_rules_by_identity.get(self._identity.identity_id, [])
        visible = [
            tool for tool_name, (upstream_id, tool) in self._tool_registry.items()
            # P0-5 fix: hide only tools with NO explicit rule at all (they'd only ever
            # reach the identity's default-deny catch-all); an *explicitly* denied tool
            # stays visible-but-blocked, so a caller sees AgentWarden's own denial rather
            # than "Unknown tool" as if it didn't exist.
            if self._explicit_rule_for(rules, tool_name, upstream_id) is not None
        ]
        return ListToolsResult(tools=visible)

    async def _resolve_or_create_session(self, meta: dict[str, Any]) -> AgentSession:
        claimed_session_id = meta.get(META_SESSION_KEY)
        if claimed_session_id:
            existing = await sessions_store.get_session(self._store, claimed_session_id)
            if existing is not None and existing.status is SessionStatus.ACTIVE:
                await sessions_store.touch_session(self._store, existing.session_id, self._clock.now().isoformat())
                return existing
            # Given (missing, or no longer active): fall through and mint a
            # fresh session under this same claimed id - reusing the caller's
            # chosen id keeps their own bookkeeping simple, and there's no
            # live row to collide with a fresh INSERT.

        session_id = claimed_session_id or self._new_id("sess")
        claimed_parent = meta.get(META_PARENT_SESSION_KEY)
        claimed_task = meta.get(META_TASK_KEY)

        resolution = await resolve_delegation(
            self._store, new_session_id=session_id, identity_id=self._identity.identity_id,
            claimed_parent_session_id=claimed_parent, claimed_task_id=claimed_task, clock=self._clock,
        )

        if resolution.is_new_task:
            root_session_id = session_id
            await sessions_store.create_task(self._store, Task(
                task_id=resolution.task_id, root_session_id=root_session_id, identity_id=self._identity.identity_id,
                status=TaskStatus.OPEN, opened_at=self._clock.now(),
            ))
        else:
            task = await sessions_store.get_task(self._store, resolution.task_id)
            root_session_id = task.root_session_id if task else session_id

        session = AgentSession(
            session_id=session_id, identity_id=self._identity.identity_id, transport=self._transport_label,
            task_id=resolution.task_id, root_session_id=root_session_id, instance_id=self._instance_id,
            parent_session_id=resolution.accepted_parent_session_id, started_at=self._clock.now(),
            last_activity_at=self._clock.now(),
        )
        await sessions_store.create_session(self._store, session)
        if resolution.edge is not None:
            await sessions_store.record_session_edge(self._store, resolution.edge)

        builder = EventBuilder(self._new_id, self._clock)
        detail = {"claimed_session_id": claimed_session_id, "claimed_parent_session_id": claimed_parent, "claimed_task_id": claimed_task}
        if resolution.rejection_reason is not None:
            event_type = EventType.CONCURRENT_SESSION_ANOMALY if resolution.is_concurrent_anomaly else EventType.DELEGATION_REJECTED
            severity = Severity.HIGH
            detail["rejection_reason"] = resolution.rejection_reason
        elif resolution.accepted_parent_session_id is not None:
            event_type, severity = EventType.DELEGATION_ACCEPTED, Severity.INFO
        else:
            event_type, severity = EventType.SESSION_OPENED, Severity.INFO
        event = builder.build(
            session_id=session_id, task_id=resolution.task_id, identity_id=self._identity.identity_id,
            event_type=event_type, severity=severity, detail=detail,
        )
        await append_event(self._store, event)
        return session

    async def _handle_call_tool(self, ctx: ServerRequestContext) -> Any:
        if self._mediator_deps is None:
            return errors.deny_result("AgentWarden proxy has not been started")
        params = ctx.params or {}
        tool_name = str(params.get("name", ""))
        arguments = dict(params.get("arguments") or {})
        meta = dict(ctx.meta or {})
        session = await self._resolve_or_create_session(meta)
        return await mediate_tool_call(self._mediator_deps, session=session, task_id=session.task_id, tool_name=tool_name, arguments=arguments)

    async def _middleware(self, ctx: ServerRequestContext, call_next):
        if ctx.method in _ALWAYS_PASSTHROUGH_METHODS:
            return await call_next(ctx)
        if ctx.method == "tools/list":
            return await self._handle_list_tools()
        if ctx.method == "tools/call":
            return await self._handle_call_tool(ctx)

        # P0-5 fix: default-deny every other method (resources/read,
        # prompts/get, ...) rather than silently falling through - v1 only
        # mediates tools/call; see README's Known limitations. This is an
        # explicit AgentWarden-authored refusal, not the SDK's generic
        # "not supported" response, so the boundary is auditable rather than
        # an accident of nothing being registered.
        return {"error": {"code": -32601, "message": f"AgentWarden does not mediate method '{ctx.method}' in v1"}}
