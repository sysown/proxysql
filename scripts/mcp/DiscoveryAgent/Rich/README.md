# Database Discovery Agent (Async CLI Prototype)

This prototype is a **single-file Python CLI** that runs an **LLM-driven database discovery agent** against an existing **MCP Query endpoint**.

It is designed to be:

- **Simple to run** (no web server, no SSE, no background services)
- **Asynchronous** (uses `asyncio` + async HTTP clients)
- **Easy to troubleshoot**
  - `--trace trace.jsonl` records every LLM request/response and every MCP tool call/result
  - `--debug` shows stack traces

The UI is rendered in the terminal using **Rich** (live dashboard + status).

---

## What the script does

The CLI (`discover_cli.py`) implements a minimal but real “multi-expert” agent:

- A **Planner** (LLM) decides what to do next (bounded list of tasks).
- Multiple **Experts** (LLM) execute tasks:
  - **Structural**: table shapes, constraints, relationship candidates
  - **Statistical**: table/column profiling, sampling
  - **Semantic**: domain inference, entity meaning, asks questions when needed
  - **Query**: explain plans and safe read-only validation (optional)

Experts do not talk to the database directly. They only request **MCP tools**.
Discoveries can be stored in the MCP **catalog** (if your MCP provides catalog tools).

### Core loop

1. **Bootstrap**
   - `list_schemas`
   - choose schema (`--schema` or first returned)
   - `list_tables(schema)`

2. **Iterate** (up to `--max-iterations`)
   - Planner LLM produces up to 1–6 tasks (bounded)
   - Orchestrator executes up to `--tasks-per-iter` tasks:
     - Expert ACT: choose MCP tool calls
     - MCP tool calls executed
     - Expert REFLECT: synthesize insights + catalog writes + optional questions
     - Catalog writes applied via `catalog_upsert` (if present)

3. **Stop**
   - when max iterations reached, or
   - when the run shows diminishing returns (simple heuristic)

---

## Install

Create a venv and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Configuration

The script needs **two endpoints**:

1) **MCP Query endpoint** (JSON-RPC)  
2) **LLM endpoint** (OpenAI-compatible `/v1/chat/completions`)

You can configure via environment variables or CLI flags.

### MCP configuration

```bash
export MCP_ENDPOINT="https://127.0.0.1:6071/mcp/query"
export MCP_AUTH_TOKEN="YOUR_TOKEN"
export MCP_INSECURE_TLS="1"
# export MCP_AUTH_TOKEN="..."     # if your MCP needs auth
```

CLI flags override env vars:
- `--mcp-endpoint`
- `--mcp-auth-token`
- `--mcp-insecure-tls`

### LLM configuration

The LLM client expects an **OpenAI‑compatible** `/chat/completions` endpoint.

For OpenAI:

```bash
export LLM_BASE_URL="https://api.openai.com/v1" # must include `v1`
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

CLI flags override env vars:
- `--llm-base-url`
- `--llm-api-key`
- `--llm-model`

---

## Run

### Start a discovery run

```bash
python discover_cli.py run --max-iterations 6 --tasks-per-iter 3
```

### Focus on a specific schema

```bash
python discover_cli.py run --schema public
```

### Debugging mode (stack traces)

```bash
python discover_cli.py run --debug
```

### Trace everything to a file (recommended)

```bash
python discover_cli.py run --trace trace.jsonl
```

The trace is JSONL and includes:
- `llm.request`, `llm.raw`, and optional `llm.repair.*`
- `mcp.call` and `mcp.result`
- `error` and `error.traceback` (when `--debug`)

---

## Provide user intent (optional)

Store intent in the MCP catalog so it influences planning:

```bash
python discover_cli.py intent --run-id <RUN_ID> --audience support --goals qna documentation
python discover_cli.py intent --run-id <RUN_ID> --constraint max_db_load=low --constraint max_seconds=120
```

The agent reads intent from:
- `kind=intent`
- `key=intent/<run_id>`

---

## Troubleshooting

If it errors and you don’t know where:

1. re-run with `--trace trace.jsonl --debug`
2. open the trace and find the last `llm.request` / `mcp.call`

Common issues:
- invalid JSON from the LLM (see `llm.raw`)
- disallowed tool calls (allow-lists)
- MCP tool failure (see last `mcp.call`)

---

## Safety notes

The Query expert can call `run_sql_readonly` if the planner chooses it.
To disable SQL execution, remove `run_sql_readonly` from the Query expert allow-list.

---

## License

Prototype / internal use.

