# AgentWarden

A runtime credential broker and policy engine purpose-built for AI-agent-held
credentials over MCP (Model Context Protocol). It sits as a local MCP proxy
between an agent host and its real upstream MCP servers, mediating every
`tools/call`: mints a short-lived, scoped authorization per call, tracks the
agent's delegation chain (root session → sub-agent → task), and flags scope
violations, rate-limit abuse, and blast-radius escalation — instead of
governing static, long-lived service-account keys the way the rest of the
non-human-identity (NHI) space does.

## The gap this fills

The NHI space is crowded (GitGuardian, Astrix, Oasis, Akeyless all expanded
in 2026), but nearly all of it targets classic service accounts and API
keys. None of it is purpose-built for the credentials an AI agent holds and
dynamically re-uses across a *chain* of tool calls — a distinct blast-radius
problem once an agent autonomously chains MCP tool calls and spawns
sub-agents that inherit partial access mid-task. AgentWarden is the runtime
governance counterpart to this repo's `Blue/MCP-Sentinel` (which finds the
static attack surface — over-privileged grants, unauthenticated transports);
AgentWarden governs what actually happens once that surface is exercised for
real.

## What it does

1. **Proxies MCP, doesn't extend it.** The agent host connects to
   AgentWarden believing it's the real server; AgentWarden holds one
   already-authenticated connection per real upstream (opened once at
   startup with the credential it owns) and mediates every `tools/list`/
   `tools/call` through a single SDK middleware hook — no tool is ever
   re-registered with a hand-built schema (see Known limitations for why).
2. **Mints a scoped authorization per call, not a new secret per call.**
   A `CredentialGrant` records *this call, this scope, this TTL* — see the
   honesty note in `agentwarden/proxy/mediator.py`'s docstring on why this
   is a different (still legitimate) claim than "a fresh secret every call".
3. **Tracks delegation chains via a caller-declared session id.** MCP has no
   native session concept a proxy can observe (confirmed by direct testing
   against the SDK, not assumed from docs — see `proxy/server.py`). A
   cooperating agent framework sets `_meta["dev.agentwarden/sessionId"]`
   (and, for a sub-agent, `parentSessionId`) on its calls; a claimed parent
   is only trusted after it's validated (exists, still active, same
   identity, no cycle — see `broker/delegation.py`), closing an
   unauthenticated-claim privilege-escalation gap an earlier design pass
   missed.
4. **Enforces policy** (YAML, least-privilege-by-default) with a small
   argument-constraint predicate language (`prefix`, `path_within`, `in`,
   `lt`, `gt`, `eq`), `max_uses_per_task` rate limiting shared across a
   task's whole delegation subtree, and a `monitor`/`enforce` mode per
   identity for a dry-run rollout.
5. **Flags six anomaly signals**: `POLICY_DENIED`, `SCOPE_VIOLATION`,
   `RATE_EXCEEDED`, `BLAST_RADIUS_EXCEEDED` (a task touching more distinct
   upstreams than its ceiling — computed from every *attempted* call, not
   just granted ones), `CONCURRENT_SESSION_ANOMALY` (a phantom task-join
   claim), and `EXPIRED_GRANT_REUSE` (an internal-consistency check on a
   narrow mint-vs-dispatch race).
6. **Computes blast radius** for a task: every `(upstream, tool)` pair its
   whole delegation subtree reached or attempted, with the session path each
   was reached through.
7. **Tamper-evident audit log**: every event is sha256 hash-chained to the
   previous one (`agentwarden audit`, `store/audit.py`'s `verify_chain`).
8. **Optional Claude second opinion** (`agentwarden review-task`) on a
   task's whole audit narrative — not per-anomaly-event, since each anomaly
   is already a deterministic rule firing; what an LLM adds is judging
   whether the *sequence* reads as a deliberate escalation attempt.

## Setup

```bash
python -m venv .venv
./.venv/Scripts/pip install -r requirements.txt   # Windows
# .venv/bin/pip install -r requirements.txt       # macOS/Linux

./.venv/Scripts/pip install -e .                  # registers the `agentwarden` CLI command

cp env.example .env
# ANTHROPIC_API_KEY is optional - only used by `review-task`.
```

## Try it without a real MCP server

```bash
agentwarden demo
```

Runs a scripted six-step task against three in-memory demo MCP servers
(`fixtures/fs_server.py`, `github_server.py`, `payments_server.py`) with
`fixtures/demo_policy.yaml`: an allowed file write, an allowed PR, an
explicitly-denied merge, a path-traversal scope violation, a shared-budget
rate-limit trip, and a delegated sub-agent reaching for the payments upstream
(blast-radius exceeded) — every outcome category AgentWarden is built to
catch, in one run. `tests/test_demo_scenario.py` asserts all six fire.

## CLI usage

```bash
agentwarden check-setup
agentwarden demo
agentwarden audit --db .agentwarden_state/demo.db
agentwarden blast-radius --db .agentwarden_state/demo.db --task demo-root-session
agentwarden list-sessions --db .agentwarden_state/demo.db
agentwarden grants --db .agentwarden_state/demo.db --session demo-root-session
agentwarden revoke --db .agentwarden_state/demo.db --session demo-root-session
agentwarden review-task --db .agentwarden_state/demo.db --task demo-root-session   # needs ANTHROPIC_API_KEY
agentwarden serve my-serve-config.yaml --port 8642                                 # real deployment, see below
```

`serve` config shape (`identity_id`, `policy_file`, `upstreams: [{id,
transport, command/url, env/headers}]`) — see `agentwarden/serve_config.py`'s
docstring for the full schema, including `${ENV_VAR}` expansion so real
upstream credentials never sit in the config file itself.

## Known limitations

- **No per-connection session anchor in this SDK version.** Confirmed by
  direct testing (not assumed): `ServerRequestContext.session` — and even
  its own internal `_connection` — is a freshly constructed object on
  *every* inbound request, even within one still-open connection. AgentWarden
  falls back to a caller-declared `_meta["dev.agentwarden/sessionId"]` for
  all session continuity; without a cooperating framework setting it, every
  call is its own one-call session with full policy enforcement and audit,
  but no cross-call continuity.
- **Identity binding is launch-time/config, one identity per listener
  process** — not cryptographically authenticated. A real deployment needs
  the agent host to prove identity (client cert, signed JWT); MCP itself
  carries no authenticated caller identity today.
- **Session close is idle-timeout-based, not exact-disconnect-based** — same
  root cause as above (no stable per-connection hook to detect a clean
  close). `broker/sweeper.py` closes sessions idle past a configurable
  timeout and revokes their outstanding grants; a crashed process's sessions
  are reconciled (closed) the next time an AgentWarden instance starts.
- **Only `tools/call` is mediated.** `resources/read`/`prompts/get`/every
  other method is explicitly denied by default in v1 (a real refusal, not an
  accidental side effect) rather than proxied — see `proxy/server.py`'s
  `_middleware`.
- **Unique tool names required across all configured upstreams.** Two
  upstreams exposing the same tool name fail startup (`ToolNameCollisionError`)
  rather than silently routing to whichever registered first, which the
  underlying SDK's own tool manager would otherwise do.
- **The tamper-evident audit chain is evidence, not proof.** The SQLite file
  is still filesystem-editable; `verify_chain()` detects a rewrite, it
  doesn't prevent one, and there's no external anchor for the chain head.
- **Single-process, SQLite-backed state.** Fine for a demo/single-host
  deployment; not HA/multi-tenant. `store/connection.py`'s single
  process-wide lock is what makes the mint-vs-rate-check TOCTOU safe, and
  that same lock is the ceiling on concurrent throughput.
- **`path_within`/`prefix` constraints are lexical, not filesystem-aware** —
  no symlink resolution; the real containment guarantee is still the
  upstream tool's own.
- **No renew-in-place for a call that outlives its grant's TTL** (e.g. a
  slow/streaming tool call) — the grant simply expires; a retry mints a new one.

## Project layout

```
agentwarden/
  models.py, clock.py, ids.py, config.py
  store/          schema.py, connection.py, sessions.py, grants.py, calls.py, audit.py
  policy/         schema.py (YAML -> PolicyRule), engine.py (pure evaluate())
  broker/         identity.py, delegation.py, lifecycle.py (rate-check+mint), redaction.py, sweeper.py
  proxy/          upstream.py (outbound pool), mediator.py (the call pipeline), server.py (host-facing MCPServer+middleware), errors.py
  analysis/       detectors.py (inline signals), blast_radius.py
  llm/            client.py, prompts.py - optional Claude second opinion
  report/         json_report.py, markdown_report.py
cli/              Typer CLI
fixtures/         3 in-memory demo MCP servers + demo_policy.yaml + demo_scenario.py
tests/            pytest suite (policy engine, delegation, lifecycle/redaction, full demo-scenario integration)
```
