# Database Discovery Agent (Prototype)

This repository contains a **fully functional prototype** of a database discovery agent that:

- uses an **LLM** to plan work and to drive multiple expert “subagents”
- interacts with a database **only through an MCP Query endpoint**
- writes discoveries into the **MCP catalog** (shared memory)
- streams progress/events to clients using **SSE** (Server‑Sent Events)

The prototype is intentionally simple (sequential execution, bounded iterations) but already demonstrates the core architecture:

**Planner LLM → Expert LLMs → MCP tools → Catalog memory**

---

## What’s implemented

### Multi-agent / Experts

The agent runs multiple experts, each using the LLM with a different role/prompt and a restricted tool set:

- **Planner**: chooses the next tasks (bounded list) based on schema/tables and existing catalog state
- **Structural Expert**: focuses on table structure and relationships
- **Statistical Expert**: profiles tables/columns and samples data
- **Semantic Expert**: infers domain/business meaning and can ask clarifying questions
- **Query Expert**: runs `EXPLAIN` and (optionally) safe read-only SQL to validate access patterns

Experts collaborate indirectly via the **MCP catalog**.

### MCP integration

The agent talks to MCP via JSON‑RPC calls to the MCP Query endpoint. Tool names used by the prototype correspond to your MCP tools list (e.g. `list_schemas`, `list_tables`, `describe_table`, `table_profile`, `catalog_upsert`, etc.).

### Catalog (shared memory)

The agent stores:

- table structure summaries
- statistics profiles
- semantic hypotheses
- questions for the user
- run intent (user‑provided steering data)

The catalog is the “long‑term memory” and enables cross‑expert collaboration.

### FastAPI service

The FastAPI service supports:

- starting a run
- streaming events as SSE
- setting user intent mid‑run
- listing questions created by experts

---

## Quickstart

### 1) Create environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Configure environment variables

#### MCP

```bash
export MCP_ENDPOINT="http://localhost:6071/mcp/query"
# export MCP_AUTH_TOKEN="..."   # if your MCP requires auth
```

#### LLM

The LLM client expects an **OpenAI‑compatible** `/v1/chat/completions` endpoint.

For OpenAI:

```bash
export LLM_BASE_URL="https://api.openai.com"
export LLM_API_KEY="YOUR_KEY"
export LLM_MODEL="gpt-4o-mini"
```

For Z.ai:

```bash
export LLM_BASE_URL="https://api.z.ai/api/coding/paas/v4"
export LLM_API_KEY="YOUR_KEY"
export LLM_MODEL="GLM-4.7"
```

For a local OpenAI‑compatible server (vLLM / llama.cpp / etc.):

```bash
export LLM_BASE_URL="http://localhost:8001"   # example
export LLM_API_KEY=""                         # often unused locally
export LLM_MODEL="your-model-name"
```

### 3) Run the API server

```bash
uvicorn agent_app:app --reload --port 8000
```

---

## How to use

### Start a run

```bash
curl -s -X POST http://localhost:8000/runs \
  -H 'content-type: application/json' \
  -d '{"max_iterations":6,"tasks_per_iter":3}'
```

Response:

```json
{"run_id":"<uuid>"}
```

### Stream run events (SSE)

```bash
curl -N http://localhost:8000/runs/<RUN_ID>/events
```

You will see events like:

- selected schema
- planned tasks
- tool calls (MCP calls)
- catalog writes
- questions raised by experts
- stop reason

### Provide user intent mid‑run

User intent is stored in the MCP catalog and immediately influences planning.

```bash
curl -s -X POST http://localhost:8000/runs/<RUN_ID>/intent \
  -H 'content-type: application/json' \
  -d '{"audience":"support","goals":["qna","documentation"],"constraints":{"max_db_load":"low"}}'
```

### List questions the agent asked

```bash
curl -s http://localhost:8000/runs/<RUN_ID>/questions
```

---

## API reference

### POST /runs

Starts a discovery run.

Body:

```json
{
  "schema": "optional_schema_name",
  "max_iterations": 8,
  "tasks_per_iter": 3
}
```

### GET /runs/{run_id}/events

Streams events over SSE.

### POST /runs/{run_id}/intent

Stores user intent into the catalog under `kind=intent`, `key=intent/<run_id>`.

Body:

```json
{
  "audience": "support|analytics|dev|end_user|mixed",
  "goals": ["qna","documentation","analytics","performance"],
  "constraints": {"max_db_load":"low"}
}
```

### GET /runs/{run_id}/questions

Lists question entries stored in the catalog.

---

## How the agent works (high‑level)

Each iteration:

1. Orchestrator reads schema and table list (bootstrap).
2. Orchestrator calls the **Planner LLM** to get up to 6 tasks.
3. For each task (bounded by `tasks_per_iter`):
   1. Call the corresponding **Expert LLM** (ACT phase) to request MCP tool calls
   2. Execute MCP tool calls
   3. Call the Expert LLM (REFLECT phase) to synthesize catalog writes and (optionally) questions
   4. Write entries via `catalog_upsert`
4. Stop on:
   - diminishing returns
   - max iterations

This is “real” agentic behavior: experts decide what to call next rather than running a fixed script.

---

## Tool restrictions / safety

Each expert can only request tools in its allow‑list. This is enforced server‑side:

- prevents a semantic expert from unexpectedly running SQL
- keeps profiling lightweight by default
- makes behavior predictable

You can tighten or relax allow‑lists in `ALLOWED_TOOLS`.

---

## Notes on MCP responses

MCP tools may return different shapes (`items`, `tables`, `schemas`, `result`). The prototype tries to normalize common variants. If your MCP returns different fields, update the normalization logic in the orchestrator.

---

## Current limitations (prototype choices)

- tasks run **sequentially** (no parallelism yet)
- confidence/coverage scoring is intentionally minimal
- catalog document structure is not yet strictly standardized (it stores JSON strings, but without a single shared envelope)
- no authentication/authorization layer is implemented for the FastAPI server
- no UI included (SSE works with curl or a tiny CLI)

---

## License

Prototype / internal use. Add your preferred license later.
