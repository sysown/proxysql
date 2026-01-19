import asyncio
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, AsyncGenerator, Literal, Tuple

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, ValidationError


# ============================================================
# MCP client (JSON-RPC)
# ============================================================

class MCPError(RuntimeError):
    pass

class MCPClient:
    def __init__(self, endpoint: str, auth_token: Optional[str] = None, timeout_sec: float = 120.0):
        self.endpoint = endpoint
        self.auth_token = auth_token
        self._client = httpx.AsyncClient(timeout=timeout_sec)

    async def call(self, method: str, params: Dict[str, Any]) -> Any:
        req_id = str(uuid.uuid4())
        payload = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        r = await self._client.post(self.endpoint, json=payload, headers=headers)
        if r.status_code != 200:
            raise MCPError(f"MCP HTTP {r.status_code}: {r.text}")
        data = r.json()
        if "error" in data:
            raise MCPError(f"MCP error: {data['error']}")
        return data.get("result")

    async def close(self):
        await self._client.aclose()


# ============================================================
# OpenAI-compatible LLM client (works with OpenAI or local servers that mimic it)
# ============================================================

class LLMError(RuntimeError):
    pass

class LLMClient:
    """
    Calls an OpenAI-compatible /v1/chat/completions endpoint.
    Configure via env:
      LLM_BASE_URL  (default: https://api.openai.com)
      LLM_API_KEY
      LLM_MODEL     (default: gpt-4o-mini)  # change as needed
    For local llama.cpp or vLLM OpenAI-compatible server: set LLM_BASE_URL accordingly.
    """
    def __init__(self, base_url: str, api_key: str, model: str, timeout_sec: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self._client = httpx.AsyncClient(timeout=timeout_sec)

    async def chat_json(self, system: str, user: str, max_tokens: int = 1200) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "temperature": 0.2,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }

        r = await self._client.post(url, json=payload, headers=headers)
        if r.status_code != 200:
            raise LLMError(f"LLM HTTP {r.status_code}: {r.text}")

        data = r.json()
        try:
            content = data["choices"][0]["message"]["content"]
        except Exception:
            raise LLMError(f"Unexpected LLM response: {data}")

        # Strict JSON-only contract
        try:
            return json.loads(content)
        except Exception:
            # one repair attempt
            repair_system = "You are a JSON repair tool. Return ONLY valid JSON, no prose."
            repair_user = f"Fix this into valid JSON only:\n\n{content}"
            r2 = await self._client.post(url, json={
                "model": self.model,
                "temperature": 0.0,
                "max_tokens": 1200,
                "messages": [
                    {"role":"system","content":repair_system},
                    {"role":"user","content":repair_user},
                ],
            }, headers=headers)
            if r2.status_code != 200:
                raise LLMError(f"LLM repair HTTP {r2.status_code}: {r2.text}")
            data2 = r2.json()
            content2 = data2["choices"][0]["message"]["content"]
            try:
                return json.loads(content2)
            except Exception as e:
                raise LLMError(f"LLM returned non-JSON (even after repair): {content2}") from e

    async def close(self):
        await self._client.aclose()


# ============================================================
# Shared schemas (LLM contracts)
# ============================================================

ExpertName = Literal["planner", "structural", "statistical", "semantic", "query"]

class ToolCall(BaseModel):
    name: str
    args: Dict[str, Any] = Field(default_factory=dict)

class CatalogWrite(BaseModel):
    kind: str
    key: str
    document: str
    tags: Optional[str] = None
    links: Optional[str] = None

class QuestionForUser(BaseModel):
    question_id: str
    title: str
    prompt: str
    options: Optional[List[str]] = None

class ExpertAct(BaseModel):
    tool_calls: List[ToolCall] = Field(default_factory=list)
    notes: Optional[str] = None

class ExpertReflect(BaseModel):
    catalog_writes: List[CatalogWrite] = Field(default_factory=list)
    insights: List[Dict[str, Any]] = Field(default_factory=list)
    questions_for_user: List[QuestionForUser] = Field(default_factory=list)

class PlannedTask(BaseModel):
    expert: ExpertName
    goal: str
    schema: str
    table: Optional[str] = None
    priority: float = 0.5


# ============================================================
# Tool allow-lists per expert (from your MCP tools/list) :contentReference[oaicite:1]{index=1}
# ============================================================

TOOLS = {
    "list_schemas","list_tables","describe_table","get_constraints",
    "table_profile","column_profile","sample_rows","sample_distinct",
    "run_sql_readonly","explain_sql","suggest_joins","find_reference_candidates",
    "catalog_upsert","catalog_get","catalog_search","catalog_list","catalog_merge","catalog_delete"
}

ALLOWED_TOOLS: Dict[ExpertName, set] = {
    "planner": {"catalog_search","catalog_list","catalog_get"},  # planner reads state only
    "structural": {"describe_table","get_constraints","suggest_joins","find_reference_candidates","catalog_search","catalog_get","catalog_list"},
    "statistical": {"table_profile","column_profile","sample_rows","sample_distinct","catalog_search","catalog_get","catalog_list"},
    "semantic": {"sample_rows","catalog_search","catalog_get","catalog_list"},
    "query": {"explain_sql","run_sql_readonly","catalog_search","catalog_get","catalog_list"},
}

# ============================================================
# Prompts
# ============================================================

PLANNER_SYSTEM = """You are the Planner agent for a database discovery system.
You plan a small set of next tasks for specialist experts. Output ONLY JSON.

Rules:
- Produce 1 to 6 tasks maximum.
- Prefer high value tasks: relationship mapping, profiling key tables, domain inference.
- Use schema/table names provided.
- If user intent exists in catalog, prioritize accordingly.
- Each task must include: expert, goal, schema, table(optional), priority (0..1).

Output schema:
{ "tasks": [ { "expert": "...", "goal":"...", "schema":"...", "table":"optional", "priority":0.0 } ] }
"""

EXPERT_ACT_SYSTEM_TEMPLATE = """You are the {expert} expert agent in a database discovery system.
You can request MCP tools by returning JSON.

Return ONLY JSON in this schema:
{{
  "tool_calls": [{{"name":"tool_name","args":{{...}}}}, ...],
  "notes": "optional brief note"
}}

Rules:
- Only call tools from this allowed set: {allowed_tools}
- Keep tool calls minimal and targeted.
- Prefer sampling/profiling to full scans.
- If unsure, request small samples (sample_rows) and/or lightweight profiles.
"""

EXPERT_REFLECT_SYSTEM_TEMPLATE = """You are the {expert} expert agent. You are given results of tool calls.
Synthesize them into durable catalog entries and (optionally) questions for the user.

Return ONLY JSON in this schema:
{{
  "catalog_writes": [{{"kind":"...","key":"...","document":"...","tags":"optional","links":"optional"}}, ...],
  "insights": [{{"claim":"...","confidence":0.0,"evidence":[...]}}, ...],
  "questions_for_user": [{{"question_id":"...","title":"...","prompt":"...","options":["..."]}}, ...]
}}

Rules:
- catalog_writes.document MUST be a JSON string (i.e., json.dumps payload).
- Use stable keys so entries can be updated: e.g. table/<schema>.<table>, col/<schema>.<table>.<col>, hypothesis/<id>, intent/<run_id>
- If you detect ambiguity about goal/audience, ask ONE focused question.
"""


# ============================================================
# Expert implementations
# ============================================================

@dataclass
class ExpertContext:
    run_id: str
    schema: str
    table: Optional[str]
    user_intent: Optional[Dict[str, Any]]
    catalog_snippets: List[Dict[str, Any]]

class Expert:
    def __init__(self, name: ExpertName, llm: LLMClient, mcp: MCPClient, emit):
        self.name = name
        self.llm = llm
        self.mcp = mcp
        self.emit = emit

    async def act(self, ctx: ExpertContext) -> ExpertAct:
        system = EXPERT_ACT_SYSTEM_TEMPLATE.format(
            expert=self.name,
            allowed_tools=sorted(ALLOWED_TOOLS[self.name])
        )
        user = {
            "run_id": ctx.run_id,
            "schema": ctx.schema,
            "table": ctx.table,
            "user_intent": ctx.user_intent,
            "catalog_snippets": ctx.catalog_snippets[:10],
            "request": f"Choose the best MCP tool calls for your expert role ({self.name}) to advance discovery."
        }
        raw = await self.llm.chat_json(system, json.dumps(user, ensure_ascii=False), max_tokens=900)
        try:
            return ExpertAct.model_validate(raw)
        except ValidationError as e:
            raise LLMError(f"{self.name} act schema invalid: {e}\nraw={raw}")

    async def reflect(self, ctx: ExpertContext, tool_results: List[Dict[str, Any]]) -> ExpertReflect:
        system = EXPERT_REFLECT_SYSTEM_TEMPLATE.format(expert=self.name)
        user = {
            "run_id": ctx.run_id,
            "schema": ctx.schema,
            "table": ctx.table,
            "user_intent": ctx.user_intent,
            "catalog_snippets": ctx.catalog_snippets[:10],
            "tool_results": tool_results,
            "instruction": "Write catalog entries that capture durable discoveries."
        }
        raw = await self.llm.chat_json(system, json.dumps(user, ensure_ascii=False), max_tokens=1200)
        try:
            return ExpertReflect.model_validate(raw)
        except ValidationError as e:
            raise LLMError(f"{self.name} reflect schema invalid: {e}\nraw={raw}")


# ============================================================
# Orchestrator
# ============================================================

class Orchestrator:
    def __init__(self, run_id: str, mcp: MCPClient, llm: LLMClient, emit):
        self.run_id = run_id
        self.mcp = mcp
        self.llm = llm
        self.emit = emit

        self.experts: Dict[ExpertName, Expert] = {
            "structural": Expert("structural", llm, mcp, emit),
            "statistical": Expert("statistical", llm, mcp, emit),
            "semantic": Expert("semantic", llm, mcp, emit),
            "query": Expert("query", llm, mcp, emit),
            "planner": Expert("planner", llm, mcp, emit),  # not used as Expert; planner has special prompt
        }

    async def _catalog_search(self, query: str, kind: Optional[str] = None, tags: Optional[str] = None, limit: int = 10):
        params = {"query": query, "limit": limit, "offset": 0}
        if kind:
            params["kind"] = kind
        if tags:
            params["tags"] = tags
        return await self.mcp.call("catalog_search", params)

    async def _get_user_intent(self) -> Optional[Dict[str, Any]]:
        # Convention: kind="intent", key="intent/<run_id>"
        try:
            res = await self.mcp.call("catalog_get", {"kind": "intent", "key": f"intent/{self.run_id}"})
            if not res:
                return None
            doc = res.get("document")
            if not doc:
                return None
            return json.loads(doc)
        except Exception:
            return None

    async def _upsert_question(self, q: QuestionForUser):
        payload = {
            "run_id": self.run_id,
            "question_id": q.question_id,
            "title": q.title,
            "prompt": q.prompt,
            "options": q.options,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        await self.mcp.call("catalog_upsert", {
            "kind": "question",
            "key": f"question/{self.run_id}/{q.question_id}",
            "document": json.dumps(payload, ensure_ascii=False),
            "tags": f"run:{self.run_id}"
        })

    async def _execute_tool_calls(self, expert: ExpertName, calls: List[ToolCall]) -> List[Dict[str, Any]]:
        results = []
        for c in calls:
            if c.name not in TOOLS:
                raise MCPError(f"Unknown tool: {c.name}")
            if c.name not in ALLOWED_TOOLS[expert]:
                raise MCPError(f"Tool not allowed for {expert}: {c.name}")
            await self.emit("tool", "call", {"expert": expert, "name": c.name, "args": c.args})
            res = await self.mcp.call(c.name, c.args)
            results.append({"tool": c.name, "args": c.args, "result": res})
        return results

    async def _apply_catalog_writes(self, expert: ExpertName, writes: List[CatalogWrite]):
        for w in writes:
            await self.emit("catalog", "upsert", {"expert": expert, "kind": w.kind, "key": w.key})
            await self.mcp.call("catalog_upsert", {
                "kind": w.kind,
                "key": w.key,
                "document": w.document,
                "tags": w.tags or f"run:{self.run_id},expert:{expert}",
                "links": w.links,
            })

    async def _planner(self, schema: str, tables: List[str], user_intent: Optional[Dict[str, Any]]) -> List[PlannedTask]:
        # Pull a small slice of catalog state to inform planning
        snippets = []
        try:
            sres = await self._catalog_search(query=f"run:{self.run_id}", limit=10)
            items = sres.get("items") or sres.get("results") or []
            snippets = items[:10]
        except Exception:
            snippets = []

        user = {
            "run_id": self.run_id,
            "schema": schema,
            "tables": tables[:200],
            "user_intent": user_intent,
            "catalog_snippets": snippets,
            "instruction": "Plan next tasks."
        }
        raw = await self.llm.chat_json(PLANNER_SYSTEM, json.dumps(user, ensure_ascii=False), max_tokens=900)
        try:
            tasks_raw = raw.get("tasks", [])
            tasks = [PlannedTask.model_validate(t) for t in tasks_raw]
            # enforce allowed experts
            tasks = [t for t in tasks if t.expert in ("structural","statistical","semantic","query")]
            tasks.sort(key=lambda x: x.priority, reverse=True)
            return tasks[:6]
        except ValidationError as e:
            raise LLMError(f"Planner schema invalid: {e}\nraw={raw}")

    async def run(self, schema: Optional[str], max_iterations: int, tasks_per_iter: int):
        await self.emit("run", "starting", {"run_id": self.run_id})

        schemas_res = await self.mcp.call("list_schemas", {"page_size": 50})
        schemas = schemas_res.get("schemas") or schemas_res.get("items") or schemas_res.get("result") or []
        if not schemas:
            raise MCPError("No schemas returned by list_schemas")

        chosen_schema = schema or (schemas[0]["name"] if isinstance(schemas[0], dict) else schemas[0])
        await self.emit("run", "schema_selected", {"schema": chosen_schema})

        tables_res = await self.mcp.call("list_tables", {"schema": chosen_schema, "page_size": 500})
        tables = tables_res.get("tables") or tables_res.get("items") or tables_res.get("result") or []
        table_names = [(t["name"] if isinstance(t, dict) else t) for t in tables]
        if not table_names:
            raise MCPError(f"No tables returned by list_tables(schema={chosen_schema})")

        await self.emit("run", "tables_listed", {"count": len(table_names)})

        # Track simple diminishing returns
        last_insight_hashes: List[str] = []

        for it in range(1, max_iterations + 1):
            user_intent = await self._get_user_intent()

            tasks = await self._planner(chosen_schema, table_names, user_intent)
            await self.emit("run", "tasks_planned", {"iteration": it, "tasks": [t.model_dump() for t in tasks]})

            if not tasks:
                await self.emit("run", "finished", {"run_id": self.run_id, "reason": "planner returned no tasks"})
                return

            # Execute a bounded number per iteration
            executed = 0
            new_insights = 0

            for task in tasks:
                if executed >= tasks_per_iter:
                    break
                executed += 1

                expert_name: ExpertName = task.expert
                expert = self.experts[expert_name]

                # Collect small relevant context from catalog
                cat_snips = []
                try:
                    # Pull table-specific snippets if possible
                    q = task.table or ""
                    sres = await self._catalog_search(query=q, limit=10)
                    cat_snips = (sres.get("items") or sres.get("results") or [])[:10]
                except Exception:
                    cat_snips = []

                ctx = ExpertContext(
                    run_id=self.run_id,
                    schema=task.schema,
                    table=task.table,
                    user_intent=user_intent,
                    catalog_snippets=cat_snips,
                )

                await self.emit("run", "task_start", {"iteration": it, "task": task.model_dump()})

                # 1) Expert ACT: request tools
                act = await expert.act(ctx)
                tool_results = await self._execute_tool_calls(expert_name, act.tool_calls)

                # 2) Expert REFLECT: write catalog entries
                ref = await expert.reflect(ctx, tool_results)
                await self._apply_catalog_writes(expert_name, ref.catalog_writes)

                # store questions (if any)
                for q in ref.questions_for_user:
                    await self._upsert_question(q)

                # crude diminishing return tracking via insight hashes
                for ins in ref.insights:
                    h = json.dumps(ins, sort_keys=True)
                    if h not in last_insight_hashes:
                        last_insight_hashes.append(h)
                        new_insights += 1
                last_insight_hashes = last_insight_hashes[-50:]

                await self.emit("run", "task_done", {"iteration": it, "expert": expert_name, "new_insights": new_insights})

            await self.emit("run", "iteration_done", {"iteration": it, "executed": executed, "new_insights": new_insights})

            # Simple stop: if 2 iterations in a row produced no new insights
            if it >= 2 and new_insights == 0:
                await self.emit("run", "finished", {"run_id": self.run_id, "reason": "diminishing returns"})
                return

        await self.emit("run", "finished", {"run_id": self.run_id, "reason": "max_iterations reached"})


# ============================================================
# FastAPI + SSE
# ============================================================

app = FastAPI(title="Database Discovery Agent (LLM + Multi-Expert)")

RUNS: Dict[str, Dict[str, Any]] = {}

class RunCreate(BaseModel):
    schema: Optional[str] = None
    max_iterations: int = 8
    tasks_per_iter: int = 3

def sse_format(event: Dict[str, Any]) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

async def event_emitter(q: asyncio.Queue) -> AsyncGenerator[bytes, None]:
    while True:
        ev = await q.get()
        yield sse_format(ev).encode("utf-8")
        if ev.get("type") == "run" and ev.get("message") in ("finished", "error"):
            return

@app.post("/runs")
async def create_run(req: RunCreate):
    # LLM env
    llm_base = os.getenv("LLM_BASE_URL", "https://api.openai.com")
    llm_key = os.getenv("LLM_API_KEY", "")
    llm_model = os.getenv("LLM_MODEL", "gpt-4o-mini")

    if not llm_key and "openai.com" in llm_base:
        raise HTTPException(status_code=400, detail="Set LLM_API_KEY (or use a local OpenAI-compatible server).")

    # MCP env
    mcp_endpoint = os.getenv("MCP_ENDPOINT", "http://localhost:6071/mcp/query")
    mcp_token = os.getenv("MCP_AUTH_TOKEN")

    run_id = str(uuid.uuid4())
    q: asyncio.Queue = asyncio.Queue()

    async def emit(ev_type: str, message: str, data: Optional[Dict[str, Any]] = None):
        await q.put({
            "ts": time.time(),
            "run_id": run_id,
            "type": ev_type,
            "message": message,
            "data": data or {}
        })

    mcp = MCPClient(mcp_endpoint, auth_token=mcp_token)
    llm = LLMClient(llm_base, llm_key, llm_model)

    async def runner():
        try:
            orch = Orchestrator(run_id, mcp, llm, emit)
            await orch.run(schema=req.schema, max_iterations=req.max_iterations, tasks_per_iter=req.tasks_per_iter)
        except Exception as e:
            await emit("run", "error", {"error": str(e)})
        finally:
            await mcp.close()
            await llm.close()

    task = asyncio.create_task(runner())
    RUNS[run_id] = {"queue": q, "task": task}
    return {"run_id": run_id}

@app.get("/runs/{run_id}/events")
async def stream_events(run_id: str):
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run_id not found")
    return StreamingResponse(event_emitter(run["queue"]), media_type="text/event-stream")

class IntentUpsert(BaseModel):
    audience: Optional[str] = None     # "dev"|"support"|"analytics"|"end_user"|...
    goals: Optional[List[str]] = None  # e.g. ["qna","documentation","analytics"]
    constraints: Optional[Dict[str, Any]] = None

@app.post("/runs/{run_id}/intent")
async def upsert_intent(run_id: str, intent: IntentUpsert):
    # Writes to MCP catalog so experts can read it immediately
    mcp_endpoint = os.getenv("MCP_ENDPOINT", "http://localhost:6071/mcp/query")
    mcp_token = os.getenv("MCP_AUTH_TOKEN")
    mcp = MCPClient(mcp_endpoint, auth_token=mcp_token)
    try:
        payload = intent.model_dump(exclude_none=True)
        payload["run_id"] = run_id
        payload["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        await mcp.call("catalog_upsert", {
            "kind": "intent",
            "key": f"intent/{run_id}",
            "document": json.dumps(payload, ensure_ascii=False),
            "tags": f"run:{run_id}"
        })
        return {"ok": True}
    finally:
        await mcp.close()

@app.get("/runs/{run_id}/questions")
async def list_questions(run_id: str):
    mcp_endpoint = os.getenv("MCP_ENDPOINT", "http://localhost:6071/mcp/query")
    mcp_token = os.getenv("MCP_AUTH_TOKEN")
    mcp = MCPClient(mcp_endpoint, auth_token=mcp_token)
    try:
        res = await mcp.call("catalog_search", {"query": f"question/{run_id}/", "limit": 50, "offset": 0})
        return res
    finally:
        await mcp.close()

