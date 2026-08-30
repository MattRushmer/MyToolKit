# API keys in this project

Short version: **MCP Sentinel doesn't need any API key to run.** There is
exactly one *optional* real key it ever uses (`ANTHROPIC_API_KEY`), and
everything that looks like a key anywhere else in this repo is a
deliberately fake test fixture. This doc explains both halves.

## The one real key: `ANTHROPIC_API_KEY` (optional)

What it's for: the active-probe injection analysis (`mcp-sentinel scan --active`)
always runs a heuristic pattern-matcher against a tool's live response with
no key required. If `ANTHROPIC_API_KEY` is set, it *also* sends that
response to Claude for a second opinion (`mcp_sentinel/llm/client.py`,
`llm/prompts.py`) - catching phrasing the heuristics miss. Without a key,
this step is skipped silently; nothing else in the tool is affected.

### How to add it

1. Get a key from the [Anthropic Console](https://console.anthropic.com/settings/keys).
2. In `Blue/MCP-Sentinel/`, copy the template and fill it in:
   ```bash
   cp env.example .env
   ```
   Then edit `.env`:
   ```
   ANTHROPIC_API_KEY=sk-ant-...your real key...
   ```
3. That's it - `mcp_sentinel/config.py` loads `.env` automatically on
   startup (no `python-dotenv` dependency needed). Run `mcp-sentinel
   check-setup` to confirm it picked up the key.

`.env` is already in `.gitignore` - it will never be committed. `env.example`
(committed) only ever contains an empty placeholder, never a real value.

## Scanning a server that itself needs a credential

This is a different thing from the key above, and doesn't involve editing
this project at all. If you want to scan an MCP server that requires its
own API key to run (e.g. a real Notion, Firecrawl, or internal API server),
that credential lives in **your agent host's own config file** - Claude
Desktop's `claude_desktop_config.json`, Claude Code's `~/.claude.json`,
Cursor's `mcp.json`, etc. - in that server's `env` or `headers` block,
exactly the way you'd configure it for the agent host to use the server
normally. MCP Sentinel reads whatever's already there; you never add a key
"to MCP Sentinel" for this.

Two safety notes for that credential once it's in a config file MCP
Sentinel scans:

- It's read transiently, purely to open the connection MCP Sentinel needs
  to inventory the server. It's never written to a report or the baseline
  file - see README.md's "Safety model" section for the redaction mechanism
  that enforces this, and "Known limitations" for its honest limits (it's
  pattern-based, not a hard guarantee for every possible credential shape).
- If you want to double-check that for yourself before pointing this at
  something sensitive, run `pytest tests/test_credential_redaction_e2e.py -v`
  - it's an end-to-end test that plants a fake secret in a config, runs a
  real scan, and asserts the secret never appears in the JSON output.

## The fake keys you'll see in `samples/` and `tests/`

Several files contain strings that *look* like API keys at a glance:

```
samples/sample-cline-mcp-settings.json
tests/test_discovery_parser.py
tests/test_client_connector.py
tests/test_credential_redaction_e2e.py
```

**None of these are real.** They exist because MCP Sentinel's whole job
includes detecting and redacting credentials in MCP server configs - the
test suite has to plant something that looks like a credential to prove the
detection/redaction rules actually fire. Every one of these fixture values
now uses a consistent, obviously-fake format:

```
NOT-A-REAL-KEY-mcp-sentinel-<context>-fixture
```

They deliberately avoid any real vendor's key format (no `sk_live_`, `AKIA`,
`ghp_`, etc.) for two reasons: so nobody mistakes one for a real credential
skimming a diff, and so an automated secret scanner (GitHub secret
scanning, TruffleHog, etc.) never mistakes one for a real Stripe/AWS/GitHub
token and fires a false alert - a couple of the original fixture values
used exactly those vendor-shaped prefixes and would have risked exactly
that. If you add a new test that needs a fake-secret-shaped string, follow
the same `NOT-A-REAL-KEY-...` convention rather than inventing something
that happens to resemble a real provider's format.

## Summary checklist

- [ ] Want the LLM judge for active probing? Add your own `ANTHROPIC_API_KEY`
      to a local `.env` (never committed).
- [ ] Want to scan a server that needs its own credential? Put that
      credential in your agent host's config, not in this repo.
- [ ] Seeing a key-looking string in `samples/` or `tests/`? It's fake -
      check for the `NOT-A-REAL-KEY-` prefix.
