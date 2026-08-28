# Pricing & packaging notes

This is a product-positioning note, not a market survey. Nothing here is
scraped competitor pricing - it's the reasoning behind why SOC Copilot is
built the way it is, and a starting-point calculator for an MSP to edit with
their own real numbers.

## Why "enterprise AI SOC" pricing doesn't fit an MSP

The current wave of AI SOC platforms (Prophet Security, Dropzone AI,
Conifers, Intezer, and similar) share two assumptions baked into their
architecture and pricing:

1. **You already have a SIEM.** The agent sits on top of Splunk/Sentinel/
   Elastic and reads from one normalized event stream. An MSP running twenty
   SMB clients almost never has this - each client has whatever endpoint
   tool they could afford, reporting to that vendor's own dashboard, and no
   shared log pipeline tying them together.
2. **You have a security team to supervise the agent.** Enterprise AI SOC
   pricing assumes a human SOC still exists and the agent is triaging a
   queue *for* them at scale. An MSP's "security team" for a given client is
   often one generalist tech splitting time across many other clients too.

Both assumptions make the per-seat/per-integration enterprise pricing model
(often five to six figures a year, scoped to one SIEM) a non-starter for a
shop billing SMB clients a few hundred dollars a month for "security
monitoring" as one line item among many.

## What SOC Copilot does differently

- **No SIEM requirement.** It reads the export button every dashboard
  already has (CSV/JSON), not a log pipeline. Onboarding a new client's alert
  source is adding one `--alerts file:source` flag, not a SIEM integration
  project.
- **Priced by endpoint, scaled down, not by seat.** MSPs already think and
  bill in per-endpoint terms (that's how RMM/AV/EDR is priced to their
  clients). `soc_copilot/economics/pricing.py` mirrors that shape instead of
  a flat enterprise seat price.
- **Cost is measured, not estimated.** `soc_copilot/economics/cost.py`
  records real input/output token counts from every triage call, so "what
  does this actually cost us to run" is a number you can pull, not a guess
  from a vendor's sales deck.

## Using the calculator

```bash
soc-copilot pricing --endpoints 500
```

This returns a suggested monthly price band for that endpoint count, based on
the illustrative tiers in `soc_copilot/economics/pricing.py`:

| Tier | Endpoints | $/endpoint/month (illustrative) |
|---|---|---|
| Starter | up to 250 | $1.25 - $2.00 |
| Growth | up to 1,000 | $0.90 - $1.50 |
| Scale | up to 5,000 | $0.60 - $1.10 |
| Enterprise MSP | 5,000+ | $0.40 - $0.85 |

A $149/month floor applies so a handful of endpoints doesn't get priced
below what it costs to support. **These numbers are defaults meant to be
edited**, not a claim about what the market charges - the file has a comment
block explaining exactly what to change and why. Combine this with your
actual measured LLM spend (`economics/cost.py`) and your own labor/overhead
per client to set a real number.
