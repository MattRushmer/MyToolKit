# Detection Forge

Turns a CTI report or CVE writeup into a **validated, backtested, noise-scored**
Sigma detection rule, mapped to real MITRE ATT&CK techniques, exportable to
Splunk / Elasticsearch / Wazuh / native Sigma - as both a CLI and a web app.

Closes the loop that's normally manual: LLM-drafted Sigma rules are common,
but nothing tests them against real logs, estimates false-positive noise, or
catches hallucinated ATT&CK tags before they ship. This does all three.

## What it does

1. **Ingest** - paste/upload a CTI report or CVE writeup; IOCs (hashes, IPs,
   domains, CVEs, file paths) are auto-extracted for the generator.
2. **Generate** - an LLM (Claude) drafts a Sigma rule, grounded with real
   example rules and required to justify every choice.
3. **Validate** - the rule is parsed with [pySigma](https://github.com/SigmaHQ/pySigma)
   (real structural validation, not a guess), and every `attack.txxxx` tag is
   checked against a locally bundled, offline MITRE ATT&CK dataset - **hallucinated
   technique IDs are caught and flagged, not shipped.**
4. **Backtest** - run the rule against sample log files you supply (JSON/NDJSON)
   to see exactly what would have fired, using pySigma's own field-matching
   semantics (wildcards, `|contains`, `|endswith`, `|re`, etc.), not a
   re-implementation of Sigma's matching rules.
5. **Score noise** - a transparent, explained 0-100 heuristic score (match
   rate, structural specificity, wildcard density, falsepositives quality)
   estimates how noisy the rule would be in production.
6. **Export** - Splunk SPL and Elasticsearch/Lucene via pySigma's official
   backends; native Sigma YAML; and a best-effort Wazuh XML rule (no official
   Sigma-to-Wazuh converter exists, so this one is hand-built and always
   comes with a warning to review the field mappings before deploying).

## Setup

```bash
python -m venv .venv
./.venv/Scripts/pip install -r requirements.txt   # Windows
# .venv/bin/pip install -r requirements.txt       # macOS/Linux

./.venv/Scripts/pip install -e .                  # registers the `detection-forge` CLI command

cp env.example .env
# edit .env and set ANTHROPIC_API_KEY=sk-ant-...

python scripts/download_attack_data.py            # only needed if data/enterprise-attack.json is missing
```

Run `detection-forge check-setup` (or `python -m cli check-setup`) any time to
confirm your API key, the ATT&CK dataset, and both SIEM export backends are
all in place.

## CLI usage

```bash
# Full pipeline: generate, validate, backtest, score, export
detection-forge run \
  --cti-file samples/sample_cti_report.txt \
  --logs samples/sample_logs.ndjson \
  --export sigma --export splunk --export elasticsearch --export wazuh \
  --out-dir output

# Validate a hand-written rule (no LLM call, no API key needed)
detection-forge validate --rule-file path/to/rule.yml

# First-run diagnostics
detection-forge check-setup
```

`--logs` accepts files or directories (globs `*.json`/`*.ndjson`/`*.jsonl`
inside a directory). CTI text can also be piped via stdin instead of `--cti-file`.

Exported rules are written to `{out_dir}/{target}/{filename}`.

## Web app

```bash
./.venv/Scripts/python -m uvicorn webapp.main:app --reload
```

Then open http://127.0.0.1:8000 - paste or upload a CTI report, optionally
upload sample log files and pick export targets, and submit. Results show the
rule YAML, per-tag ATT&CK validation, backtest matches, the noise score
breakdown, and each requested export with copy buttons.

## Try it without an API key

`detection-forge validate --rule-file` and the whole backtest/scoring/export
engine work with **no LLM call at all** - try it against the bundled example
rules and sample log file, which are hand-crafted so you can see real matches,
a real filtered-out benign event, and a real noise score:

```bash
detection-forge validate --rule-file detection_forge/rules/examples/mshta_suspicious_execution.yml
```

To see backtesting/scoring/export end-to-end without the LLM, use the Python
API directly (see `detection_forge/pipeline.py` - `run_pipeline()` is the one
function both the CLI and web app call; the LLM step is only one part of it).

## Project layout

```
detection_forge/
  ingest/       CTI text loading + regex IOC extraction
  llm/          Anthropic prompt + structured tool-call generation
  attack/       offline MITRE ATT&CK tag validation (data/enterprise-attack.json)
  rules/        pySigma structural validation, generation orchestration, example rules
  backtest/     log loading/flattening + pySigma-object-model rule matcher
  scoring/      heuristic noise/false-positive scoring
  export/       Sigma / Splunk / Elasticsearch (via pySigma) / Wazuh (custom) exporters
  pipeline.py   the one function the CLI and web app both call
cli/            Typer CLI
webapp/         FastAPI web app (Jinja2 templates, no JS build step)
tests/          pytest suite (backtest, scoring, export, ingest, ATT&CK validation)
samples/        a hand-crafted CTI report + matching sample log file for testing
```

## Known limitations

- **Wazuh export is best-effort.** There's no official pySigma-Wazuh backend
  (verified - not published on PyPI). The exporter translates simple field
  conditions into Wazuh `<field>` matches but does **not** translate
  `and not filter_*` exclusion logic, and the `<if_sid>` base rule is a
  placeholder you must set yourself. Every Wazuh export includes an explicit
  warning; always review it before deploying.
- **Backtest condition parsing** covers the common Sigma condition grammar
  (`and`/`or`/`not`, parens, `1 of <pattern>`, `all of <pattern>`, `them`) but
  does not flatten deeply nested list-of-maps selections (a rarer Sigma
  construct). Field-level value matching (wildcards, modifiers) is delegated
  to pySigma's own object model, not re-implemented.
- **Noise scoring is a heuristic**, not a calibrated statistical model - it's
  meant to focus analyst attention, not replace judgment. It's most reliable
  when you supply a representative sample log set; without one, it falls back
  to structural signals only.
