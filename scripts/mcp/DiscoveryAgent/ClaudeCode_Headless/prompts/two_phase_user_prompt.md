# Two-Phase Database Discovery - User Prompt

Perform LLM-driven discovery using the MCP catalog and persist your findings back to the catalog.

## Context

- **Phase 1 (Static Harvest) is ALREADY COMPLETE** - DO NOT call `discovery.run_static`
- The catalog is already populated with objects/columns/indexes/FKs/profiles
- You must ONLY use catalog/LLM/agent tools - NO MySQL query tools
- The database size is unknown; work in stages and persist progress frequently

## Inputs

- **target_id**: `<TARGET_ID>` (required for all catalog/agent/llm tool calls)
- **run_id**: **use the provided run_id from the static harvest**
- **model_name**: `<MODEL_NAME_HERE>` - e.g., "claude-3.5-sonnet"
- **desired coverage**:
  - summarize at least 50 high-value objects (tables/views/routines)
  - create 3–10 domains with membership + roles
  - create 10–30 metrics and 15–50 question templates

## Required Outputs (persisted via MCP)

### 1) Agent Run Tracking
- Start an agent run bound to the provided target/run via `agent.run_start`
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

### Step 1: Start Agent Run (NOT discovery.run_static - already done!)

```python
# Phase 1: ALREADY DONE - DO NOT CALL
# discovery.run_static(schema_filter="<SCHEMA_FILTER>", notes="<NOTES>")

# Phase 2: LLM Agent Discovery - Start here
run_id = <USE_THE_PROVIDED_RUN_ID>
target_id = "<TARGET_ID>"
call agent.run_start(target_id=target_id, run_id=run_id, model_name="<MODEL_NAME_HERE>")
# → returns agent_run_id
```

### Step 2: Scope Discovery

```python
# Understand what was harvested
call catalog.list_objects(target_id=target_id, run_id=run_id, order_by="name", page_size=100)
call catalog.search(target_id=target_id, run_id=run_id, query="<KEYWORD>", limit=25)
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
    call catalog.get_object(target_id, run_id, object_id, include_profiles=true)
    call catalog.get_relationships(target_id, run_id, object_id)
    call llm.summary_upsert(target_id, agent_run_id, run_id, object_id, summary={...}, confidence=0.8, sources={...})

# Stage 3: Enhance relationships
for each missing or unclear join:
    call llm.relationship_upsert(..., confidence=0.7, evidence={...})

# Stage 4: Build domains
for each domain (billing, sales, auth, etc.):
    call llm.domain_upsert(target_id, agent_run_id, run_id, domain_key, title, description, confidence=0.8)
    call llm.domain_set_members(target_id, agent_run_id, run_id, domain_key, members=[...])

# Stage 5: Create answerability artifacts
for each metric:
    call llm.metric_upsert(target_id, agent_run_id, run_id, metric_key, title, description, sql_template, depends, confidence=0.7)

for each question template:
    # Extract table/view names from example_sql or template_json
    related_objects = ["Customer", "Invoice", "InvoiceLine"]  # JSON array of object names
    call llm.question_template_add(target_id, run_id, title, question_nl, template, agent_run_id, example_sql, related_objects, confidence=0.7)

# Final summary
call llm.note_add(target_id, agent_run_id, run_id, "global", title="Database Summary", body="...", tags=["final"])

# Cleanup
call agent.event_append(agent_run_id, "decision", {"status": "complete", "summaries": 50, "domains": 5, "metrics": 15, "templates": 25})
call agent.run_finish(agent_run_id, "success")
```

## Important Constraints

- **DO NOT call `discovery.run_static`** - Phase 1 is already complete
- **DO NOT use MySQL query tools** - Use ONLY catalog/LLM/agent tools
- **DO NOT write any files**
- **DO NOT create artifacts on disk**
- All progress and final outputs MUST be stored ONLY through MCP tool calls
- Use `agent_events` and `llm_notes` as your scratchpad

---

## Begin Now

Start with Stage 0:
1. Use the provided target_id and run_id from the static harvest (DO NOT call discovery.run_static)
2. Call `agent.run_start` with target_id + run_id
3. Proceed with the discovery stages
