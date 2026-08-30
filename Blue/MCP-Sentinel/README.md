# MCP Sentinel

An attack-surface scanner for MCP (Model Context Protocol) servers and agent
tool-grants. It inventories every MCP server an org's agent hosts are wired
up to, flags over-privileged and unauthenticated tools, detects tool
poisoning, and actively probes tool responses for prompt injection.

## The gap this fills

Every org that wired an LLM up to MCP servers this year created an attack
surface that didn't exist eighteen months ago - tool poisoning, over-scoped
tool permissions, prompt injection via tool output. OWASP's [MCP Top
10](https://owasp.org/www-project-mcp-top-10/) and CSA's research notes are
cataloguing the risk faster than defensive tooling is catching up. A couple
of real scanners now exist (Cisco's YARA-based mcp-scanner, Invariant Labs'
mcp-scan), but they work the way a vulnerability scanner works for one
server at a time, given its URL or launch command, and they check the
server's *advertised metadata* - tool descriptions and schemas - for known-bad
patterns.

MCP Sentinel adds two things neither of those does:

1. **Org-wide agent tool-grant inventory.** Most orgs don't have one server -
   they have N developer machines, each running M agent hosts (Claude
   Desktop, Claude Code, Cursor, Windsurf, Cline/VS Code), each with its own
   MCP server grants. This walks every known host's config location and
   builds the "who has access to what" picture first, before scoring any one
   tool.
2. **Active response probing.** Static scanning only sees what a tool
   *claims* about itself. A compromised upstream API, or a backend that
   injects instructions into the data it returns, is invisible to a
   description-only scan. MCP Sentinel safely calls a server's read-only
   tools and scans their *actual responses* for injected content - this is
   the literal "test for injection via tool responses" gap the tool exists
   to close.

## What it does

1. **Discover** - walk every known agent-host config location (Claude
   Desktop, Claude Code's user- and project-scoped configs, Cursor,
   Windsurf, Cline, VS Code's native MCP support, or a generic `mcp.json`)
   and normalize every server grant into one shape, capturing
   privilege-relevant signals (auth-header presence, auto-approved tools,
   env var *names* - never values) without ever persisting a credential.
2. **Introspect** - connect to each server for real, over stdio/HTTP/SSE via
   the official `mcp` SDK, and enumerate its tools, resources, and prompts
   (with pagination). One unreachable server never aborts the rest of the
   scan.
3. **Flag static risk** - rules covering:
   - **Over-privileged tools**: exec/shell/subprocess capability language,
     annotations that contradict the tool's own description (declares
     `destructiveHint=false` but reads as destructive), undeclared risk on a
     state-changing tool, unconstrained path/url/command parameters, and
     destructive tools an agent host will auto-approve without asking a human.
   - **Unauthenticated transports**: a remote HTTP/SSE server with no auth
     header configured, and credentials passed as plaintext stdio launch
     arguments (visible in process listings and shell history) instead of
     the `env` block.
   - **Tool poisoning**: instruction-injection phrasing, hidden HTML
     comments/`display:none` spans, zero-width Unicode characters, oversized
     or base64-blob descriptions - planted in a tool/resource/prompt's own
     metadata.
   - **Rug-pull / config drift**: a tool's description or schema silently
     changing since the last scan, the classic pattern of earning trust with
     a benign tool then swapping in malicious behavior later.
4. **Actively probe (opt-in, `--active`)** - safely invoke tools that
   declare `readOnlyHint=true` with mundane, hardcoded arguments, and run
   the same injection detection against the *real response text*. Heuristic
   pattern matching always runs; an optional Claude-backed LLM judge adds a
   second opinion when `ANTHROPIC_API_KEY` is set, and degrades silently
   without one.
5. **Report** - a Rich terminal summary, plus `--out-json`/`--out-markdown`
   for a full report, and `--fail-on <severity>` to gate CI on findings.

## Safety model

Active probing is the one part of this tool that touches a live server with
a real call, not just reads its metadata, so it's deliberately conservative
and has **no override flag**:

- Only tools declaring `readOnlyHint=true` are ever invoked. No annotation,
  or `destructiveHint=true`, means skipped - full stop.
- Even a `readOnlyHint=true` tool is skipped if its own name/description
  still matches exec/shell/subprocess language - an annotation can lie, and
  this is a second, independent gate.
- A tool is skipped entirely (not guessed at) if any required argument can't
  be confidently constructed from its schema (e.g. a required `object` or
  `array` parameter).
- A tool call that errors on the synthetic input is not itself a finding -
  only successful responses are analyzed.

Credential handling: `MCPServerConfig` - the type that ends up in every
report and baseline file - never carries a real credential value. `env`
values become `env_var_names` (names only); `headers` presence becomes a
bool (`has_auth_header`); and anything in `args`/`url` that looks like a
credential (a recognized flag name, a query param, HTTP Basic-auth
userinfo, an OAuth-style fragment, or a long opaque bare value) is replaced
with a placeholder at parse time (`discovery/parser.py`'s `_redact_args`/
`_redact_url`), with just the matched flag *name* kept as a signal
(`secret_like_arg_flags`). The real, unredacted values needed to actually
open a live connection are re-read separately and transiently
(`extract_raw_entries`) and threaded straight through to the connector -
never through `MCPServerConfig`, and never attached to anything that gets
serialized to disk. This is pattern-based, not a hard guarantee - see Known
limitations below.

## Setup

```bash
python -m venv .venv
./.venv/Scripts/pip install -r requirements.txt   # Windows
# .venv/bin/pip install -r requirements.txt       # macOS/Linux

./.venv/Scripts/pip install -e .                  # registers the `mcp-sentinel` CLI command

cp env.example .env
# ANTHROPIC_API_KEY is optional - only used for the active-probe LLM judge.
```

## CLI usage

```bash
mcp-sentinel check-setup           # confirm config, and how many agent-host configs were found
mcp-sentinel list-configs          # show every known config location and whether it exists

mcp-sentinel scan                                    # auto-discover this machine's configs
mcp-sentinel scan --config path/to/mcp.json           # scan one specific file instead
mcp-sentinel scan --active                            # also run live injection probing
mcp-sentinel scan --out-json report.json --out-markdown report.md
mcp-sentinel scan --fail-on high                      # exit 2 if any HIGH+ finding exists (for CI)
mcp-sentinel scan --no-drift                          # skip rug-pull/baseline comparison
```

## Try it without touching a real server

`fixtures/vulnerable_mcp_server/server.py` is a real MCP server with five
tools, each planting exactly one issue the scanner is built to catch: an
over-privileged exec tool, a mismatched destructive annotation, a poisoned
description, an injected live response, and one clean baseline tool. Point
a scan at it directly:

```bash
mcp-sentinel scan --config fixtures/vulnerable_mcp_server/demo.mcp.json --active --no-drift
```

(`fixtures/vulnerable_mcp_server/demo.mcp.json` launches the fixture server
over stdio with `python`.) Never grant this server to a real agent host - it
exists purely to demonstrate and test detection.

## Known limitations

- **OAuth-authenticated remote servers will false-positive on the
  unauthenticated-transport check.** The auth rule only sees a static
  `Authorization`/API-key header declared in the client config; a server
  that authenticates via a dynamic OAuth flow (no static header needed) will
  still be flagged as missing auth. Treat that finding as "confirm how this
  server actually authenticates," not an automatic verdict.
- **Active probing only covers tools that declare `readOnlyHint=true`.** A
  poisoned or compromised tool that doesn't declare itself read-only (most
  don't) is invisible to the active probe, though its static description is
  still scanned for poisoning.
- **Heuristic injection detection is pattern-based**, not a full semantic
  understanding of intent - it will miss novel phrasing and can occasionally
  flag legitimate content that happens to match (e.g. a security blog post
  a documentation tool legitimately returns, quoting the phrase "ignore
  previous instructions" as an example). The optional LLM judge narrows this
  gap but doesn't close it.
- **Resources and prompts are scanned for poisoning but never actively
  probed** - only tools are invoked.
- **No override for probing non-read-only tools.** This is deliberate (see
  Safety model above), but it means a destructive or unannotated tool's live
  behavior can only be assessed manually.
- **Credential redaction is pattern-based, not a guarantee.** `args`/`url`
  values that look like a credential (a recognized flag name like
  `--api-key`/`--bearer`, a query param like `token=`/`client_secret=`, HTTP
  Basic-auth userinfo, or a long opaque bare value) are redacted before
  anything is persisted to a report or baseline - see the Safety model
  section above. This substantially reduces but cannot guarantee zero
  leakage for every possible credential shape: a secret shorter than 16
  characters with no recognized flag name preceding it, or passed via a
  flag name this tool doesn't recognize as credential-shaped, can still
  appear in a report's `args`/`url` fields. Treat `--out-json`/`--out-markdown`
  reports as sensitive by default, the same as you would the config files
  they were generated from.

## Project layout

```
mcp_sentinel/
  discovery/    config_locations.py, parser.py   - find & normalize agent-host configs
  client/       connector.py                     - live MCP protocol introspection
  rules/        privilege.py, auth.py, poisoning.py, baseline.py, text_patterns.py, catalog.py
  probes/       payloads.py, active.py, analyzer.py - active injection probing
  llm/          client.py, prompts.py             - optional Anthropic-backed judge
  report/       json_report.py, markdown_report.py
  engine.py     - ties discovery -> introspection -> rules -> probes -> ScanReport
cli/            Typer CLI (scan, list-configs, check-setup)
fixtures/vulnerable_mcp_server/   real demo/test-fixture MCP server
samples/        illustrative (non-live) config files - discovery/parsing examples only, not scan targets
tests/          pytest suite (unit + real-stdio integration tests, no mocks against the wire protocol)
```

Every finding cites a real [OWASP MCP Top 10 (2025)](https://owasp.org/www-project-mcp-top-10/)
reference ID - see `mcp_sentinel/rules/catalog.py`.
