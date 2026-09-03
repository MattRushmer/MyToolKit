"""Shared data contracts for AgentWarden's session/grant/policy/audit model.

Revised after an architect review of the initial plan (see git history) that
caught a security hole (unauthenticated delegation-parent spoofing) and
several modeling gaps (no Task/ToolCallRecord entity, boolean grant use
where policy allows N-use). This shape reflects those fixes:

- `AgentSession.parent_session_id` is the *accepted* parent only (validated -
  see broker/delegation.py); `SessionEdge` is the full audit trail of every
  asserted link, accepted or rejected.
- `Task` is a first-class entity (not inferred) so "task closed" is a real
  state a POST_TASK_ACTIVITY check can read, and so `max_uses_per_task`
  counts across a task's whole session subtree, not one session.
- `ToolCallRecord` exists for every attempted call, allowed or denied, so
  blast-radius can be computed from "everything a task reached or attempted"
  (see analysis/blast_radius.py) - a denied call is still evidence of
  exposure, which a grant-only view would miss.
- `CredentialGrant.use_count`/`max_uses` replace a boolean - policy allows
  more than one use per grant.
"""
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


_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


def severity_rank(severity: Severity) -> int:
    return _SEVERITY_RANK[severity]


class SessionStatus(str, Enum):
    ACTIVE = "active"
    CLOSED = "closed"


class TaskStatus(str, Enum):
    OPEN = "open"
    CLOSED = "closed"


class GrantStatus(str, Enum):
    ACTIVE = "active"      # minted, may still be used up to max_uses
    IN_FLIGHT = "in_flight"  # CAS'd for one dispatch - see broker/lifecycle.py
    CONSUMED = "consumed"   # use_count has reached max_uses
    EXPIRED = "expired"     # past expires_at - only the sweeper writes this
    REVOKED = "revoked"


class CallOutcome(str, Enum):
    ALLOWED = "allowed"
    POLICY_DENIED = "policy_denied"     # the (tool, upstream) itself is forbidden for this identity
    SCOPE_VIOLATION = "scope_violation"  # a real rule matched but the call's arguments failed its constraints
    RATE_EXCEEDED = "rate_exceeded"
    BLAST_RADIUS_EXCEEDED = "blast_radius_exceeded"
    POST_TASK_ACTIVITY = "post_task_activity"
    ERROR = "error"  # upstream call itself failed after being allowed


class EventType(str, Enum):
    SESSION_OPENED = "session_opened"
    SESSION_CLOSED = "session_closed"
    TASK_CLOSED = "task_closed"
    DELEGATION_ACCEPTED = "delegation_accepted"
    DELEGATION_REJECTED = "delegation_rejected"
    GRANT_ISSUED = "grant_issued"
    TOOL_CALL_ALLOWED = "tool_call_allowed"
    TOOL_CALL_ERROR = "tool_call_error"  # call was allowed by policy but the upstream dispatch itself failed
    POLICY_DENIED = "policy_denied"
    SCOPE_VIOLATION = "scope_violation"
    RATE_EXCEEDED = "rate_exceeded"
    EXPIRED_GRANT_REUSE = "expired_grant_reuse"
    CONCURRENT_SESSION_ANOMALY = "concurrent_session_anomaly"
    BLAST_RADIUS_EXCEEDED = "blast_radius_exceeded"
    POST_TASK_ACTIVITY = "post_task_activity"
    GRANT_REVOKED = "grant_revoked"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Identity:
    identity_id: str
    label: str
    source: str  # e.g. "launch-config:listener-1" - v1's (documented, non-cryptographic) binding
    bound_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True)
class Task:
    task_id: str
    root_session_id: str
    identity_id: str
    status: TaskStatus = TaskStatus.OPEN
    opened_at: datetime = field(default_factory=utcnow)
    closed_at: datetime | None = None
    # The blast-radius ceiling actually enforced for this task's whole
    # lifetime, captured once at task creation - a later CLI invocation of
    # `blast-radius`/`review-task` reads this back instead of falling through
    # to whatever AGENTWARDEN_BLAST_RADIUS_CEILING happens to be set to at
    # report time, which has no relationship to what ran the task.
    blast_radius_ceiling: int = 0


@dataclass(frozen=True)
class AgentSession:
    session_id: str
    identity_id: str
    transport: str  # "stdio" | "http" | "sse" | "memory"
    task_id: str  # own task by default; equals an ancestor's task_id once a delegation is accepted
    root_session_id: str  # denormalized: this session's own id if root, else the root ancestor's id
    instance_id: str  # the AgentWarden process instance that owns this session - see store reconciliation
    parent_session_id: str | None = None  # the ACCEPTED parent only, see SessionEdge for the full assertion trail
    started_at: datetime = field(default_factory=utcnow)
    last_activity_at: datetime = field(default_factory=utcnow)
    ended_at: datetime | None = None
    closed_reason: str | None = None
    status: SessionStatus = SessionStatus.ACTIVE


@dataclass(frozen=True)
class SessionEdge:
    """Every delegation link a connection ever asserted, accepted or not -
    the audit trail P0-3 requires: an attacker forging a parent link is
    itself a signal worth keeping even when rejected."""

    child_session_id: str
    parent_session_id: str
    declared_at: datetime
    accepted: bool
    rejection_reason: str | None = None


@dataclass(frozen=True)
class ArgumentConstraint:
    """One field's constraint within a PolicyRule.argument_constraints block.
    Exactly one predicate field is set - see policy/engine.py's
    _evaluate_constraint for the small predicate language this supports.
    `path_within` is `prefix` but path-normalized first (blocks `../` traversal
    past the prefix), which is why it exists as a distinct predicate rather
    than being folded into `prefix`."""

    prefix: str | None = None
    path_within: str | None = None
    in_: tuple[str, ...] | None = None
    lt: float | None = None
    gt: float | None = None
    eq: Any | None = None


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    identity_id: str
    tool_name: str  # "*" matches any tool name on the given upstream
    upstream_server_id: str
    source: str  # "explicit" | "default-catch-all" - provenance for AuditEvent.detail
    deny: bool = False
    max_uses_per_task: int | None = None
    ttl_seconds: int = 60
    argument_constraints: dict[str, ArgumentConstraint] = field(default_factory=dict)
    # If True, any call argument not named in argument_constraints is a
    # SCOPE_VIOLATION - closes the "unnamed field sails through untouched"
    # gap the allow-list shape otherwise has. Shallow only: this checks
    # top-level argument names, not the contents of a nested dict/list value,
    # so an allowed top-level key whose value is itself an object with an
    # unconstrained sensitive subkey is not caught by strict mode alone.
    strict: bool = False


@dataclass(frozen=True)
class CredentialGrant:
    grant_id: str
    session_id: str
    task_id: str
    tool_name: str
    upstream_server_id: str
    rule_id: str
    scope: dict[str, Any]
    issued_at: datetime
    expires_at: datetime
    max_uses: int
    use_count: int = 0
    status: GrantStatus = GrantStatus.ACTIVE


@dataclass(frozen=True)
class ToolCallRecord:
    """One attempted `tools/call`, allowed or denied - the record that lets
    blast-radius and rate-limiting reason about *attempts*, not just
    successfully-minted grants (a denied call is still exposure evidence)."""

    call_id: str
    session_id: str
    task_id: str
    upstream_server_id: str
    tool_name: str
    arguments_digest: str  # sha256 of the full argument object - see broker/redaction.py
    redacted_arguments: dict[str, Any]  # only the fields the matched rule's constraints reference
    outcome: CallOutcome
    matched_rule_id: str | None
    grant_id: str | None
    started_at: datetime
    completed_at: datetime | None = None
    latency_ms: float | None = None


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    seq: int  # monotonic, assigned by the store - timestamps alone aren't a reliable order under asyncio
    timestamp: datetime
    session_id: str
    task_id: str
    identity_id: str
    event_type: EventType
    severity: Severity
    call_id: str | None = None
    grant_id: str | None = None
    tool_name: str | None = None
    upstream_server_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    event_hash: str = ""  # sha256(prev_hash + canonical event fields) - see store/audit.py; not a legal guarantee, just tamper-evidence


@dataclass(frozen=True)
class Decision:
    """The policy engine's verdict for one candidate tool call."""

    outcome: CallOutcome
    matched_rule: PolicyRule | None
    reason: str
    redacted_arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class BlastRadiusReport:
    root_session_id: str
    task_id: str
    computed_at: datetime
    ceiling: int
    reachable: set[tuple[str, str]] = field(default_factory=set)  # {(upstream_server_id, tool_name)}
    path_by_pair: dict[tuple[str, str], list[str]] = field(default_factory=dict)  # pair -> session_id path from root
    sessions_visited: int = 0

    @property
    def distinct_upstreams(self) -> set[str]:
        return {upstream for upstream, _tool in self.reachable}

    @property
    def exceeded(self) -> bool:
        return len(self.distinct_upstreams) > self.ceiling
