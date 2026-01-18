# Two-Phase Database Discovery - User Prompt

Perform LLM-driven discovery using the MCP catalog and persist your findings back to the catalog.

## Context

- A deterministic harvest has already been populated in the SQLite catalog (objects/columns/indexes/FKs/profiles and fts_objects) via `discovery.run_static`
- You must NOT connect to MySQL directly
- The database size is unknown; work in stages and persist progress frequently

## Inputs

- **run_id**: `<RUN_ID_HERE>` - The discovery run ID from the static harvest
- **model_name**: `<MODEL_NAME_HERE>` - e.g., "claude-3.5-sonnet" or your local model
- **desired coverage**:
  - summarize at least 50 high-value objects (tables/views/routines)
  - create 3–10 domains with membership + roles
  - create 10–30 metrics and 15–50 question templates

## Required Outputs (persisted via MCP)

### 1) Agent Run Tracking
- Start an agent run bound to `run_id` via `agent.run_start`
- Record discovery plan and budgets via `agent.event_append`
- Finish the run via `agent.run_finish`

### 2) Per-Object Summaries
- `llm.summary_upsert` for each processed object with:
  - Structured `summary_json` (hypothesis, grain, keys, dims/measures, joins, example questions)
  - `confidence` score (0.0-1.0)
  - `status` (draft/validated/stable)
  - `sources_json` (what evidence was used)

### 3) Inferred Joins
- `llm.relationship_upsert` where useful, with:
  - `child_object_id`, `child_column`, `parent_object_id`, `parent_column`
  - `rel_type` (fk_like/bridge/polymorphic/etc)
  - `confidence` and `evidence_json`

### 4) Domain Model
- `llm.domain_upsert` for each domain (billing, sales, auth, etc.)
- `llm.domain_set_members` with object_ids and roles (entity/fact/dimension/log/bridge/lookup)
- `llm.note_add` with domain descriptions

### 5) Answerability
- `llm.metric_upsert` for each metric (orders.count, revenue.gross, etc.)
- `llm.question_template_add` for each question template

### 6) Final Global Note
- `llm.note_add(scope="global")` summarizing:
  - What this database is about
  - The key entities
  - Typical joins
  - The top questions it can answer

## Discovery Procedure

### Step 1: Trigger Static Harvest & Start Agent Run

```python
# Phase 1: Static Discovery
call discovery.run_static(schema_filter="<SCHEMA_FILTER>", notes="<NOTES>")
# → returns run_id, started_at, mysql_version, objects_count, columns_count

# Phase 2: LLM Agent Discovery
call agent.run_start(run_id=<run_id>, model_name="<MODEL_NAME>")
# → returns agent_run_id
```

### Step 2: Scope Discovery

```python
# Understand what was harvested
call catalog.list_objects(run_id=<run_id>, order_by="name", page_size=100)
call catalog.search(run_id=<run_id>, query="<KEYWORD>", limit=25)
```

### Step 3: Execute Staged Discovery

```python
# Stage 0: Plan
call agent.event_append(agent_run_id, "decision", {"plan": "...", "budgets": {...}})

# Stage 1: Triage - build prioritized backlog
# Identify top 20 high-value objects by:
# - FK relationships
# - Business names (orders, customers, products, etc.)
# - Time columns
# - Views

# Stage 2: Summarize objects in batches
for each batch:
    call catalog.get_object(run_id, object_id, include_profiles=true)
    call catalog.get_relationships(run_id, object_id)
    call llm.summary_upsert(agent_run_id, run_id, object_id, summary={...}, confidence=0.8, sources={...})

# Stage 3: Enhance relationships
for each missing or unclear join:
    call llm.relationship_upsert(..., confidence=0.7, evidence={...})

# Stage 4: Build domains
for each domain (billing, sales, auth, etc.):
    call llm.domain_upsert(agent_run_id, run_id, domain_key, title, description, confidence=0.8)
    call llm.domain_set_members(agent_run_id, run_id, domain_key, members=[...])

# Stage 5: Create answerability artifacts
for each metric:
    call llm.metric_upsert(agent_run_id, run_id, metric_key, title, description, sql_template, depends, confidence=0.7)

for each question template:
    call llm.question_template_add(agent_run_id, run_id, title, question_nl, template, example_sql, confidence=0.7)

# Final summary
call llm.note_add(agent_run_id, run_id, "global", title="Database Summary", body="...", tags=["final"])

# Cleanup
call agent.event_append(agent_run_id, "decision", {"status": "complete", "summaries": 50, "domains": 5, "metrics": 15, "templates": 25})
call agent.run_finish(agent_run_id, "success")
```

## Important Constraint

- **DO NOT write any files**
- **DO NOT create artifacts on disk**
- All progress and final outputs MUST be stored ONLY through MCP tool calls
- Use `agent_events` and `llm_notes` as your scratchpad

---

## Begin Now

Start with Stage 0:
1. Call `discovery.run_static` to trigger ProxySQL's static harvest
2. Receive `run_id` from the response
3. Call `agent.run_start` with the returned `run_id`

Then proceed with the discovery stages.
