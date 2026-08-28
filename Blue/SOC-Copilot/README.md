# SOC Copilot

A lean AI SOC triage copilot for MSPs and small security teams who don't have
a shared SIEM - just a dozen browser tabs (M365 Defender, CrowdStrike,
Huntress, whatever the client's got) and no time to correlate them by hand.

## The gap this fills

The AI SOC platforms reviewed everywhere this year - Prophet Security,
Dropzone AI, Conifers, Intezer - are built and priced for enterprises that
already have a SIEM ingesting everything into one place and a security team
to supervise the agent. An MSP running twenty small-business clients on a
shoestring has no SIEM to plug an agent into and no budget for an
enterprise-tier seat license. They're triaging alerts by hand, tab by tab,
client by client.

This tool does the same core loop - **correlate, triage, recommend** - but
skips the SIEM requirement entirely: point it at whatever CSV/JSON export
each dashboard already produces, and it does the correlation itself. It's
priced and packaged for the MSP doing this by hand today, not for a Fortune
500 SOC (see [PRICING.md](PRICING.md)).

## What it does

1. **Ingest** - normalize alert exports from Microsoft Defender, CrowdStrike,
   Huntress, or any other tool's generic CSV/JSON export into one common
   shape. No SIEM, no log forwarder, no agent installed anywhere - just the
   export button each dashboard already has.
2. **Correlate** - alerts on the same client + host (or user) within a
   rolling time window become one **incident**, not three disconnected tickets.
   This is the actual manual work an MSP tech does today, done mechanically.
3. **Triage** - an LLM (Claude) reads the whole incident and returns a
   verdict (true positive / false positive / benign / needs investigation),
   a confidence score, severity, a PSA-ready ticket priority, and MITRE
   ATT&CK technique tags - written for a generalist tech, not a specialist.
   **No API key configured?** It still runs, using a transparent
   keyword/severity heuristic that flags for review and never auto-clears an
   alert - see [Known limitations](#known-limitations).
4. **Recommend** - a category-matched remediation playbook (ransomware,
   credential access, phishing, suspicious login, persistence, discovery,
   malware execution, data exfiltration) merged with the LLM's incident-
   specific guidance.
5. **Report** - a Markdown ticket note per incident, ready to paste into
   ConnectWise/Autotask/Halo/whatever PSA the MSP uses, plus a client-facing
   digest summarizing the period's incidents for a QBR or status email.
6. **Track cost** - every triage call's real token usage is recorded, so an
   MSP owner can see exactly what running this costs per incident, per
   client, per month - see `soc_copilot/economics/`.

## Setup

```bash
python -m venv .venv
./.venv/Scripts/pip install -r requirements.txt   # Windows
# .venv/bin/pip install -r requirements.txt       # macOS/Linux

./.venv/Scripts/pip install -e .                  # registers the `soc-copilot` CLI command

cp env.example .env
# edit .env and set ANTHROPIC_API_KEY=sk-ant-...
```

Run `soc-copilot check-setup` (or `python -m cli check-setup`) any time to
confirm your API key, model, and correlation window are what you expect.

## CLI usage

```bash
# Correlate + triage two exports for one client
soc-copilot run \
  --client-id acme-dental --client-name "Acme Dental Group" --tier standard \
  --alerts samples/acme-dental_defender_alerts.csv:defender \
  --alerts samples/acme-dental_huntress_alerts.csv:huntress \
  --out-dir output

# Every dashboard's export goes on its own --alerts flag, as path[:source].
# source is one of: generic, defender, crowdstrike, huntress (default generic
# if omitted - works for anything with common column names).

# First-run diagnostics
soc-copilot check-setup

# Illustrative MSP-scaled pricing suggestion for N endpoints
soc-copilot pricing --endpoints 500
```

This writes one ticket note per incident to `{out-dir}/tickets/{incident_id}.md`
and a client digest to `{out-dir}/digest.md`.

## Web app

```bash
./.venv/Scripts/python -m uvicorn webapp.main:app --reload
```

Then open http://127.0.0.1:8000 - fill in the client, upload one or more
alert export files (pick the matching source per file), and submit. You get
back a sortable incident queue, a full ticket note per incident with a "copy"
button, and the client digest, all in one page.

## Try it without an API key

The whole ingest -> correlate -> heuristic-triage -> playbook -> ticket note
pipeline works with **no LLM call at all**, using the bundled sample data
(two clients, three alert sources, a deliberately-crafted multi-alert
ransomware precursor and a multi-alert credential-dumping incident so you can
see correlation actually merge alerts, not just pass them through 1:1):

```bash
soc-copilot run --client-id acme-dental --client-name "Acme Dental Group" \
  --alerts samples/acme-dental_defender_alerts.csv:defender \
  --alerts samples/acme-dental_huntress_alerts.csv:huntress

soc-copilot run --client-id globex-logistics --client-name "Globex Logistics" --tier high \
  --alerts samples/globex-logistics_crowdstrike_detections.json:crowdstrike
```

Without an API key, every verdict is `needs_investigation` at a fixed, low
confidence (35%) - the heuristic is a fail-safe queue-ordering tool, not a
triage replacement. Set `ANTHROPIC_API_KEY` and re-run the same command to
see real verdicts, confidence scores, and tailored recommendations.

## Adding a new alert source

Most MSP dashboards aren't in `soc_copilot/ingest/adapters.py` yet. Two ways
to handle a new one:

- **Fastest:** use `--alerts yourfile.csv:generic` (or leave off `:source`
  entirely). The generic adapter recognizes common column names (`host`,
  `hostname`, `device`, `severity`, `timestamp`, `created_at`, ...) across a
  wide range of exports without any code changes.
- **For a recurring source:** add an `AdapterSpec` to `adapters.py` with that
  vendor's real column names, following the `DEFENDER`/`CROWDSTRIKE`/
  `HUNTRESS` examples. This is a five-minute edit, not a new module.

## Project layout

```
soc_copilot/
  ingest/       CSV/JSON parsing + per-vendor column-name adapters
  correlate/    time-window clustering of alerts into incidents
  llm/          Anthropic prompt + structured tool-call triage
  triage/       LLM triage engine + no-API-key heuristic fallback + ATT&CK reference
  recommend/    category-classified remediation playbooks
  report/       PSA ticket note + client-facing digest rendering
  economics/    real LLM cost tracking + illustrative MSP pricing calculator
  pipeline.py   the one function the CLI and web app both call
cli/            Typer CLI
webapp/         FastAPI web app (Jinja2 templates, no JS build step)
tests/          pytest suite (38 tests: ingest, correlation, playbooks, economics, tickets, end-to-end)
samples/        two clients' worth of realistic multi-source sample alert exports
```

## Known limitations

- **The heuristic fallback is deliberately conservative, not smart.** With no
  API key it never returns `false_positive` or `benign_positive` - only
  `needs_investigation` at a fixed low confidence. It exists so the tool is
  still useful (correlation + queue ordering + playbook matching) without an
  API key, not as a substitute for real triage.
- **ATT&CK tagging is a curated ~60-technique reference list**
  (`triage/attack_reference.py`), not the full offline STIX dataset Detection
  Forge (this suite's sibling tool) bundles for rule validation. An
  unrecognized technique ID is flagged "verify manually," not rejected - this
  tool tags for analyst benefit, it doesn't ship anything that needs hard
  validation.
- **Correlation is time-window + host/user clustering only.** It does not
  attempt cross-host attack-chain reconstruction (e.g. linking a phishing
  click on one host to lateral movement on another three hours later) - that
  needs a human, or a much larger context window than one incident.
- **Pricing numbers in `economics/pricing.py` are illustrative defaults**,
  not a market survey - see [PRICING.md](PRICING.md). Edit them for your own
  LLM spend (tracked for real in `economics/cost.py`) and labor overhead.
- **The web app's upload-size guard has one gap.** `webapp/main.py` rejects
  a request by its declared `Content-Length` before the body is parsed, and
  separately bounds each file to 25MB while streaming it into the app's own
  temp directory - but a client using chunked transfer-encoding (no
  `Content-Length` header) skips the first check, so Starlette's own
  multipart parser still buffers that request before either guard runs. If
  you deploy this somewhere reachable by untrusted clients rather than
  running it locally/internally, also set a body-size limit at the reverse
  proxy (nginx `client_max_body_size`, Caddy `request_body`, etc.), which
  doesn't have this blind spot.
