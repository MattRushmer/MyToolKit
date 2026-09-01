# VibeCheck

A security reviewer purpose-built for AI-generated ("vibe-coded") code. It
scans a Python/JS/TS codebase for the specific failure modes that show up in
LLM-written code far more than in human-written code, on top of baseline SAST
coverage for the vulnerability classes an LLM still reaches for out of habit.

## The gap this fills

Generic SAST tools were trained on (and tuned against) human-written
vulnerable code. As more production code ships from Copilot/Claude/Cursor
with light review, the failure signature is different enough to justify a
purpose-built rule set:

1. **Hallucinated auth checks.** An LLM writes code that reads as an
   authorization check because that's the statistically expected shape for a
   protected route - without it actually being wired up to deny access. A
   guard decorator referencing a name that's never defined anywhere in the
   project (would NameError the first time the route is actually hit), an
   auth check inside a try/except that swallows the error and falls through,
   a tautological condition, an auth helper that's defined but never called,
   or one route silently missing the guard all its siblings carry.
2. **Copy-pasted insecure patterns repeated across a whole codebase.** Ask an
   LLM to "add an endpoint like the others" and it will often copy-paste the
   *same* vulnerable snippet into every new handler. Fixing only the first
   occurrence found leaves every copy exploitable - this needs to be reported
   as one systemic cluster, not N disconnected one-off findings.
3. **Hallucinated / invented dependencies ("slopsquatting").** LLMs
   sometimes declare a package that sounds plausible but was never published.
   Today that's just an install error - but an attacker who notices the same
   hallucinated name (from this codebase or anyone else's) can publish
   malware under it, and every future install becomes a live supply-chain
   attack.

## What it does

1. **Walk** the target directory for Python/JS/TS source, skipping
   `.venv`/`node_modules`/`dist`/build output/vendored code.
2. **Baseline SAST rules** (`vibecheck/rules/`): hardcoded secrets (vendor
   key patterns + a suspiciously-named-variable + entropy heuristic),
   eval/exec, shell command injection (`os.system`/`subprocess(shell=True)`/
   `child_process.exec`), unsafe deserialization (`pickle`, unsafe
   `yaml.load`), SQL injection (query built via f-string/concat/%-format/
   `.format()`, including the common "build the string on one line, execute
   it a few lines later" shape), disabled TLS verification, permissive CORS,
   debug mode left on, and weak password hashing (md5/sha1).
3. **Auth-hallucination analysis** (`vibecheck/auth/`): extracts every
   Flask/FastAPI/Django-style and Express-style route, cross-references its
   guard decorators/middleware against everything actually defined/imported
   in the project, and separately scans for fail-open try/except auth checks,
   tautological auth conditions, unused auth-looking helper functions, and
   sibling routes missing a guard their neighbors have.
4. **Duplicate-pattern clustering** (`vibecheck/duplication/`): groups every
   baseline-SAST finding by (rule, normalized snippet) and collapses 2+
   occurrences of the same insecure pattern into one higher-severity cluster
   finding listing every location.
5. **Dependency hallucination check** (`--check-deps`, opt-in, needs network):
   parses `requirements.txt`/`pyproject.toml`/`package.json` and checks every
   declared package against the real PyPI/npm registry, caching results
   locally with a 24h TTL and degrading to "unknown" (never a false
   "hallucinated") on any network failure.
6. **Optional LLM second opinion** (`--llm-judge`, needs `ANTHROPIC_API_KEY`):
   sends each hallucinated-auth finding plus its surrounding source to Claude
   for a real/false-positive verdict, downgrading confidently-false-positive
   findings instead of silently deleting them.
7. **Report**: a Rich terminal summary, plus `--out-json`/`--out-markdown` for
   a full report, and `--fail-on <severity>` to gate CI on findings.

## Setup

```bash
python -m venv .venv
./.venv/Scripts/pip install -r requirements.txt   # Windows
# .venv/bin/pip install -r requirements.txt       # macOS/Linux

./.venv/Scripts/pip install -e .                  # registers the `vibecheck` CLI command

cp env.example .env
# ANTHROPIC_API_KEY is optional - only used by --llm-judge.
```

## CLI usage

```bash
vibecheck check-setup                                 # confirm config

vibecheck scan .                                       # baseline + auth + duplication rules
vibecheck scan . --check-deps                          # also check declared deps against PyPI/npm
vibecheck scan . --llm-judge                            # also get a Claude second opinion on auth findings
vibecheck scan . --out-json report.json --out-markdown report.md
vibecheck scan . --fail-on high                         # exit 2 if any HIGH+ finding exists (for CI)
```

## Try it without a real target

`fixtures/vibe_demo_app/` is a small deliberately-vulnerable Flask app that
plants one clean instance of every rule category (including a copy-pasted
SQL injection pattern across two handlers and a hallucinated PyPI package in
its `requirements.txt`). Point a scan at it directly:

```bash
vibecheck scan fixtures/vibe_demo_app --check-deps
```

Never deploy this fixture app - it exists purely to demonstrate and test
detection, and `tests/test_engine_fixture.py` asserts every planted rule
category actually fires.

## Known limitations

- **JS/TS analysis is regex/heuristic-based, not a real parser.** Python
  rules run on the stdlib `ast` module for precision; there's no JS/TS AST
  dependency, so the JS-side rules (route extraction, dangerous calls,
  injection, undefined-guard/sibling-gap) are line-oriented heuristics and
  will miss unusual formatting or multi-line call signatures.
- **Fail-open auth, tautological auth, and unused-auth-helper detection are
  Python-only.** These need real control-flow/whole-project symbol
  resolution that the JS heuristics don't attempt - documented rather than
  guessed at.
- **The undefined-guard check only flags a *bare* decorator/middleware name**
  (`@require_admin`), never an attribute/method reference (`@auth.login_required`,
  `mw.checkAuth`) - those resolve through an object this tool has no
  visibility into, so flagging them would produce far more false positives
  than true ones.
- **Dependency hallucination checking works off declared manifests, not
  `import`/`require` statements.** A package that's imported but never
  declared (or declared but never imported) is invisible to `--check-deps`.
- **Duplicate-pattern clustering normalizes string literals and identifiers
  to shared placeholders**, so two *structurally* identical insecure calls
  with entirely different SQL/commands inside an f-string can cluster
  together. This is intentional (the pattern being repeated is "build the
  query dynamically and execute it", not the specific query text) but means
  a cluster's member list should always be read as "same pattern," not
  "same query."
- **The registry check has no rate-limit backoff** - a very large manifest
  scanned repeatedly in a short window may get throttled by PyPI/npm, at
  which point those packages degrade to "unknown" rather than blocking the
  scan.
- **Secret detection is pattern-based**, not a full entropy/ML classifier -
  it will miss a low-entropy real secret and can flag a high-entropy
  non-secret string assigned to a suspiciously-named variable.

## Project layout

```
vibecheck/
  scanner/      walker.py                          - file discovery, language detection
  rules/        secrets.py, dangerous_calls.py, injection.py, crypto_and_config.py, catalog.py
  auth/         route_extractor.py, symbol_index.py, hallucination_rules.py
  duplication/  duplication.py                       - cross-codebase insecure-pattern clustering
  dependencies/ extractor.py, registry.py, findings.py - PyPI/npm hallucination check
  llm/          client.py, prompts.py                 - optional Claude second-opinion judge
  report/       json_report.py, markdown_report.py
  engine.py     - ties everything together into one ScanReport
cli/            Typer CLI (scan, check-setup)
fixtures/vibe_demo_app/   deliberately-vulnerable demo/test-fixture target
tests/          pytest suite (unit tests per rule + an end-to-end fixture scan)
```

Every finding cites a CWE and/or OWASP Top 10 (2021) reference where one
exists - see `vibecheck/rules/catalog.py` for the VIBE-* rule taxonomy.
