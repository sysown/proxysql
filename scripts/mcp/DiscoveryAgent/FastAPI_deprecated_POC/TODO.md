# TODO — Next Steps (Detailed)

This document describes the next steps for evolving the current prototype into a robust discovery agent.
Each section includes **what**, **why**, and **how** (implementation guidance).

---

## 0) Stabilize the prototype

### 0.1 Normalize MCP tool responses

**What**
Create a single normalization helper for list-like responses (schemas, tables, catalog search).

**Why**
MCP backends often return different top-level keys (`items`, `schemas`, `tables`, `result`). Normalizing early removes brittleness.

**How**
Add a function like:

- `normalize_list(res, keys=("items","schemas","tables","result")) -> list`

Use it for:
- `list_schemas`
- `list_tables`
- `catalog_search`

Also log unknown shapes (for quick debugging when MCP changes).

---

### 0.2 Harden LLM output validation

**What**
Enforce strict JSON schema for all LLM outputs (planner + experts).

**Why**
Even with “JSON-only” prompts, models sometimes emit invalid JSON or fields that don’t match your contract.

**How**
- Keep one “JSON repair” attempt.
- Add server-side constraints:
  - max tool calls per ACT (e.g. 6)
  - max bytes for tool args (prevent giant payloads)
  - reject tools not in allow-list (already implemented)

Optional upgrade:
- Add per-tool argument schema validation (Pydantic models per tool).

---

### 0.3 Improve stopping conditions (still simple)

**What**
Make stop logic deterministic and transparent.

**Why**
Avoid infinite loops and token waste when the planner repeats itself.

**How**
Track per iteration:
- number of catalog writes (new/updated)
- number of distinct new insights
- repeated tasks

Stop if:
- 2 consecutive iterations with zero catalog writes
- or planner repeats the same task set N times (e.g. 3)

---

## 1) Make catalog entries consistent

### 1.1 Adopt a canonical JSON envelope for catalog documents

**What**
Standardize the shape of `catalog_upsert.document` (store JSON as a string, but always the same structure).

**Why**
Without a standard envelope, later reasoning (semantic synthesis, confidence scoring, reporting) becomes messy.

**How**
Require experts to output documents like:

```json
{
  "version": 1,
  "run_id": "…",
  "expert": "structural|statistical|semantic|query",
  "created_at": "ISO8601",
  "confidence": 0.0,
  "provenance": {
    "tools": [{"name":"describe_table","args":{}}],
    "sampling": {"method":"sample_rows","limit":50}
  },
  "payload": { "…": "…" }
}
```

Enforce server-side:
- `document` must parse as JSON
- must include `run_id`, `expert`, `payload`

---

### 1.2 Enforce key naming conventions

**What**
Make keys predictable and merge-friendly.

**Why**
It becomes trivial to find and update knowledge, and easier to build reports/UI.

**How**
Adopt these conventions:

- `structure/table/<schema>.<table>`
- `stats/table/<schema>.<table>`
- `stats/col/<schema>.<table>.<col>`
- `semantic/entity/<schema>.<table>`
- `semantic/hypothesis/<id>`
- `intent/<run_id>`
- `question/<run_id>/<question_id>`
- `report/<run_id>`

Update expert REFLECT prompt to follow them.

---

## 2) Make experts behave like specialists

Right now experts are LLM-driven, but still generic. Next: give each expert a clear strategy.

### 2.1 Structural expert: relationship graph

**What**
Turn structure entries into a connected schema graph.

**Why**
Knowing tables without relationships is not “understanding”.

**How**
In ACT phase, encourage:

- `describe_table`
- `get_constraints` (always pass schema + table)
- then either:
  - `suggest_joins`
  - or `find_reference_candidates`

In REFLECT phase, write:
- table structure entry
- relationship candidate entries, e.g. `relationship/<a>↔<b>`

---

### 2.2 Statistical expert: prioritize columns + data quality flags

**What**
Profile “important” columns first and produce data quality findings.

**Why**
Profiling everything is expensive and rarely needed.

**How**
Teach the expert to prioritize:
- id-like columns (`id`, `*_id`)
- timestamps (`created_at`, `updated_at`, etc.)
- categorical status columns (`status`, `type`, `state`)
- numeric measure columns (`amount`, `total`, `price`)

Emit flags in catalog:
- high null % columns
- suspicious min/max ranges
- very low/high cardinality anomalies

---

### 2.3 Semantic expert: domain inference + user checkpoints

**What**
Infer domain meaning and ask the user only when it matters.

**Why**
Semantic inference is the #1 hallucination risk and also the #1 value driver.

**How**
Semantic expert should:
- read structure/stats entries from catalog
- `sample_rows` from 1–3 informative tables
- propose:
  - one or more domain hypotheses (with confidence)
  - entity definitions (what tables represent)
  - key processes (e.g. “order lifecycle”)

Add a checkpoint trigger in the orchestrator:
- if 2+ plausible domains within close confidence
- or domain confidence < 0.6
- or intent is missing and choices would change exploration

Then store a `question/<run_id>/<id>` entry.

---

### 2.4 Query expert: safe access guidance

**What**
Recommend safe, efficient query patterns.

**Why**
Exploration can unintentionally generate heavy queries.

**How**
Default policy:
- only `explain_sql`

Allow `run_sql_readonly` only if:
- user intent says it’s okay
- constraints allow some load

Enforce guardrails:
- require `LIMIT`
- forbid unbounded `SELECT *`
- prefer indexed predicates where known

---

## 3) Add lightweight coverage and confidence scoring

### 3.1 Coverage

**What**
Track exploration completeness.

**How**
Maintain a `run_state/<run_id>` entry with counts:
- total tables discovered
- tables with structure stored
- tables with stats stored
- columns profiled

Use coverage to guide planner prompts and stopping.

---

### 3.2 Confidence

**What**
Compute simple confidence values.

**How**
Start with heuristics:
- Structural confidence increases with constraints + join candidates
- Statistical confidence increases with key column profiles
- Semantic confidence increases with multiple independent signals (names + samples + relationships)

Store confidence per claim in the document envelope.

---

## 4) Add a CLI (practical, fast win)

**What**
A small terminal client to start a run and tail SSE events.

**Why**
Gives you a usable experience without needing a browser.

**How**
Implement `cli.py` with `httpx`:
- `start` command: POST /runs
- `tail` command: GET /runs/{id}/events (stream)
- `intent` command: POST /runs/{id}/intent
- `questions` command: GET /runs/{id}/questions

---

## 5) Reporting: generate a human-readable summary

**What**
Create a final report from catalog entries.

**Why**
Demos and real usage depend on readable output.

**How**
Add an endpoint:
- `GET /runs/{run_id}/report`

Implementation:
- `catalog_search` all entries tagged with `run:<run_id>`
- call the LLM with a “report writer” prompt
- store as `report/<run_id>` via `catalog_upsert`

---

## 6) Parallelism (do last)

**What**
Run multiple tasks concurrently.

**Why**
Big databases need speed, but concurrency adds complexity.

**How**
- Add an `asyncio.Semaphore` for tool calls (e.g. 2 concurrent)
- Add per-table locks to avoid duplicate work
- Keep catalog writes atomic per key (upsert is fine, but avoid racing updates)

---

## 7) Testing & reproducibility

### 7.1 Replay mode

**What**
Record tool call transcripts and allow replay without hitting the DB.

**How**
Store tool call + result in:
- `trace/<run_id>/<seq>`

Then add a run mode that reads traces instead of calling MCP.

### 7.2 Unit tests

Cover:
- JSON schema validation
- allow-list enforcement
- response normalization
- stop conditions

---

## Suggested implementation order

1. Normalize MCP responses and harden LLM output validation
2. Enforce catalog envelope + key conventions
3. Improve Structural + Statistical expert strategies
4. Semantic expert + user checkpoints
5. Report synthesis endpoint
6. CLI
7. Coverage/confidence scoring
8. Controlled concurrency
9. Replay mode + tests
10. MCP enhancements only when justified by real runs
