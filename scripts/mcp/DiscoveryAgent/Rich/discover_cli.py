#!/usr/bin/env python3
"""
Database Discovery Agent (Async CLI, Rich UI)

Key fixes vs earlier version:
- MCP tools are invoked via JSON-RPC method **tools/call** (NOT by calling tool name as method).
- Supports HTTPS + Bearer token + optional insecure TLS (self-signed certs).

Environment variables (or CLI flags):
- MCP_ENDPOINT (e.g. https://127.0.0.1:6071/mcp/query)
- MCP_AUTH_TOKEN (Bearer token, if required)
- MCP_INSECURE_TLS=1 to disable TLS verification (like curl -k)

- LLM_BASE_URL (OpenAI-compatible base, e.g. https://api.openai.com)
- LLM_API_KEY
- LLM_MODEL
"""

import argparse
import asyncio
import json
import os
import sys
import time
import uuid
import traceback
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Literal, Tuple

import httpx
from pydantic import BaseModel, Field, ValidationError

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.layout import Layout


ExpertName = Literal["planner", "structural", "statistical", "semantic", "query"]

KNOWN_MCP_TOOLS = {
    "list_schemas", "list_tables", "describe_table", "get_constraints",
    "table_profile", "column_profile", "sample_rows", "sample_distinct",
    "run_sql_readonly", "explain_sql", "suggest_joins", "find_reference_candidates",
    "catalog_upsert", "catalog_get", "catalog_search", "catalog_list", "catalog_merge", "catalog_delete"
}

ALLOWED_TOOLS: Dict[ExpertName, set] = {
    "planner": {"catalog_search", "catalog_list", "catalog_get"},
    "structural": {"describe_table", "get_constraints", "suggest_joins", "find_reference_candidates", "catalog_search", "catalog_get", "catalog_list"},
    "statistical": {"table_profile", "column_profile", "sample_rows", "sample_distinct", "catalog_search", "catalog_get", "catalog_list"},
    "semantic": {"sample_rows", "catalog_search", "catalog_get", "catalog_list"},
    "query": {"explain_sql", "run_sql_readonly", "catalog_search", "catalog_get", "catalog_list"},
}


class ToolCall(BaseModel):
    name: str
    args: Dict[str, Any] = Field(default_factory=dict)

class PlannedTask(BaseModel):
    expert: ExpertName
    goal: str
    schema: str
    table: Optional[str] = None
    priority: float = 0.5

class PlannerOut(BaseModel):
    tasks: List[PlannedTask] = Field(default_factory=list)

class ExpertAct(BaseModel):
    tool_calls: List[ToolCall] = Field(default_factory=list)
    notes: Optional[str] = None

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

class ExpertReflect(BaseModel):
    catalog_writes: List[CatalogWrite] = Field(default_factory=list)
    insights: List[Dict[str, Any]] = Field(default_factory=list)
    questions_for_user: List[QuestionForUser] = Field(default_factory=list)


class TraceLogger:
    def __init__(self, path: Optional[str]):
        self.path = path

    def write(self, record: Dict[str, Any]):
        if not self.path:
            return
        rec = dict(record)
        rec["ts"] = time.time()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


class MCPError(RuntimeError):
    pass

class MCPClient:
    def __init__(self, endpoint: str, auth_token: Optional[str], trace: TraceLogger, insecure_tls: bool = False):
        self.endpoint = endpoint
        self.auth_token = auth_token
        self.trace = trace
        self.client = httpx.AsyncClient(timeout=120.0, verify=(not insecure_tls))

    async def rpc(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        req_id = str(uuid.uuid4())
        payload = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            payload["params"] = params

        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        self.trace.write({"type": "mcp.rpc", "method": method, "params": params})
        r = await self.client.post(self.endpoint, json=payload, headers=headers)
        if r.status_code != 200:
            raise MCPError(f"MCP HTTP {r.status_code}: {r.text}")
        data = r.json()
        if "error" in data:
            raise MCPError(f"MCP error: {data['error']}")
        return data.get("result")

    async def call_tool(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        if tool_name not in KNOWN_MCP_TOOLS:
            raise MCPError(f"Unknown tool: {tool_name}")
        args = arguments or {}
        self.trace.write({"type": "mcp.call", "tool": tool_name, "arguments": args})

        result = await self.rpc("tools/call", {"name": tool_name, "arguments": args})
        self.trace.write({"type": "mcp.result", "tool": tool_name, "result": result})

        # Expected: {"success": true, "result": ...}
        if isinstance(result, dict) and "success" in result:
            if not result.get("success", False):
                raise MCPError(f"MCP tool failed: {tool_name}: {result}")
            return result.get("result")
        return result

    async def close(self):
        await self.client.aclose()


class LLMError(RuntimeError):
    pass

class LLMClient:
    def __init__(self, base_url: str, api_key: str, model: str, trace: TraceLogger, insecure_tls: bool = False):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.trace = trace
        self.client = httpx.AsyncClient(timeout=120.0, verify=(not insecure_tls))

    async def chat_json(self, system: str, user: str, *, max_tokens: int = 1200) -> Dict[str, Any]:
        url = f"{self.base_url}/chat/completions"
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

        self.trace.write({"type": "llm.request", "model": self.model, "system": system[:4000], "user": user[:8000]})
        r = await self.client.post(url, json=payload, headers=headers)
        if r.status_code != 200:
            raise LLMError(f"LLM HTTP {r.status_code}: {r.text}")
        data = r.json()
        try:
            content = data["choices"][0]["message"]["content"]
        except Exception:
            raise LLMError(f"Unexpected LLM response: {data}")
        self.trace.write({"type": "llm.raw", "content": content})

        try:
            return json.loads(content)
        except Exception:
            repair_payload = {
                "model": self.model,
                "temperature": 0.0,
                "max_tokens": 1200,
                "messages": [
                    {"role": "system", "content": "Return ONLY valid JSON, no prose."},
                    {"role": "user", "content": f"Fix into valid JSON:\n\n{content}"},
                ],
            }
            self.trace.write({"type": "llm.repair.request", "bad": content[:8000]})
            r2 = await self.client.post(url, json=repair_payload, headers=headers)
            if r2.status_code != 200:
                raise LLMError(f"LLM repair HTTP {r2.status_code}: {r2.text}")
            data2 = r2.json()
            content2 = data2["choices"][0]["message"]["content"]
            self.trace.write({"type": "llm.repair.raw", "content": content2})
            try:
                return json.loads(content2)
            except Exception as e:
                raise LLMError(f"LLM returned non-JSON after repair: {content2}") from e


PLANNER_SYSTEM = """You are the Planner agent for a database discovery system.
You plan a small set of next tasks for specialist experts. Output ONLY JSON.

Rules:
- Produce 1 to 6 tasks maximum.
- Prefer high-value tasks: mapping structure, finding relationships, profiling key tables, domain inference.
- Consider user intent if provided.
- Each task must include: expert, goal, schema, table(optional), priority (0..1).

Output schema:
{"tasks":[{"expert":"structural|statistical|semantic|query","goal":"...","schema":"...","table":"optional","priority":0.0}]}
"""

EXPERT_ACT_SYSTEM = """You are the {expert} expert agent.
Return ONLY JSON in this schema:
{{"tool_calls":[{{"name":"tool_name","args":{{...}}}}], "notes":"optional"}}

Rules:
- Only call tools from: {allowed_tools}
- Keep tool calls minimal (max 6).
- Prefer sampling/profiling to full scans.
- If unsure: sample_rows + lightweight profile first.
"""

EXPERT_REFLECT_SYSTEM = """You are the {expert} expert agent. You are given results of tool calls.
Synthesize durable catalog entries and (optionally) questions for the user.

Return ONLY JSON in this schema:
{{
  "catalog_writes":[{{"kind":"...","key":"...","document":"JSON_STRING","tags":"optional","links":"optional"}}],
  "insights":[{{"claim":"...","confidence":0.0,"evidence":[...]}}],
  "questions_for_user":[{{"question_id":"...","title":"...","prompt":"...","options":["..."]}}]
}}

Rules:
- catalog_writes.document MUST be a JSON string (i.e. json.dumps of your payload).
- Ask at most ONE question per reflect step, only if it materially changes exploration.
"""


@dataclass
class UIState:
    run_id: str
    phase: str = "init"
    iteration: int = 0
    planned_tasks: List[PlannedTask] = None
    last_event: str = ""
    last_error: str = ""
    tool_calls: int = 0
    catalog_writes: int = 0
    insights: int = 0

    def __post_init__(self):
        if self.planned_tasks is None:
            self.planned_tasks = []


def normalize_list(res: Any, keys: Tuple[str, ...]) -> List[Any]:
    if isinstance(res, list):
        return res
    if isinstance(res, dict):
        for k in keys:
            v = res.get(k)
            if isinstance(v, list):
                return v
    return []

def item_name(x: Any) -> str:
    if isinstance(x, dict) and "name" in x:
        return str(x["name"])
    return str(x)

def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Agent:
    def __init__(self, mcp: MCPClient, llm: LLMClient, trace: TraceLogger, debug: bool):
        self.mcp = mcp
        self.llm = llm
        self.trace = trace
        self.debug = debug

    async def planner(self, schema: str, tables: List[str], user_intent: Optional[Dict[str, Any]]) -> List[PlannedTask]:
        user = json.dumps({
            "schema": schema,
            "tables": tables[:300],
            "user_intent": user_intent,
            "instruction": "Plan next tasks."
        }, ensure_ascii=False)

        raw = await self.llm.chat_json(PLANNER_SYSTEM, user, max_tokens=900)
        try:
            out = PlannerOut.model_validate(raw)
        except ValidationError as e:
            raise LLMError(f"Planner output invalid: {e}\nraw={raw}")

        tasks = [t for t in out.tasks if t.expert in ("structural","statistical","semantic","query")]
        tasks.sort(key=lambda t: t.priority, reverse=True)
        return tasks[:6]

    async def expert_act(self, expert: ExpertName, ctx: Dict[str, Any]) -> ExpertAct:
        system = EXPERT_ACT_SYSTEM.format(expert=expert, allowed_tools=sorted(ALLOWED_TOOLS[expert]))
        raw = await self.llm.chat_json(system, json.dumps(ctx, ensure_ascii=False), max_tokens=900)
        try:
            act = ExpertAct.model_validate(raw)
        except ValidationError as e:
            raise LLMError(f"{expert} ACT invalid: {e}\nraw={raw}")

        act.tool_calls = act.tool_calls[:6]
        for c in act.tool_calls:
            if c.name not in KNOWN_MCP_TOOLS:
                raise MCPError(f"{expert} requested unknown tool: {c.name}")
            if c.name not in ALLOWED_TOOLS[expert]:
                raise MCPError(f"{expert} requested disallowed tool: {c.name}")
        return act

    async def expert_reflect(self, expert: ExpertName, ctx: Dict[str, Any], tool_results: List[Dict[str, Any]]) -> ExpertReflect:
        system = EXPERT_REFLECT_SYSTEM.format(expert=expert)
        user = dict(ctx)
        user["tool_results"] = tool_results
        raw = await self.llm.chat_json(system, json.dumps(user, ensure_ascii=False), max_tokens=1200)
        try:
            ref = ExpertReflect.model_validate(raw)
        except ValidationError as e:
            raise LLMError(f"{expert} REFLECT invalid: {e}\nraw={raw}")
        return ref

    async def apply_catalog_writes(self, writes: List[CatalogWrite]):
        for w in writes:
            await self.mcp.call_tool("catalog_upsert", {
                "kind": w.kind,
                "key": w.key,
                "document": w.document,
                "tags": w.tags,
                "links": w.links
            })

    async def run(self, ui: UIState, schema: Optional[str], max_iterations: int, tasks_per_iter: int):
        ui.phase = "bootstrap"

        schemas_res = await self.mcp.call_tool("list_schemas", {"page_size": 50})
        schemas = schemas_res if isinstance(schemas_res, list) else normalize_list(schemas_res, ("schemas","items","result"))
        if not schemas:
            raise MCPError("No schemas returned by MCP list_schemas")

        chosen_schema = schema or item_name(schemas[0])
        ui.last_event = f"Selected schema: {chosen_schema}"

        tables_res = await self.mcp.call_tool("list_tables", {"schema": chosen_schema, "page_size": 500})
        tables = tables_res if isinstance(tables_res, list) else normalize_list(tables_res, ("tables","items","result"))
        table_names = [item_name(t) for t in tables]
        if not table_names:
            raise MCPError(f"No tables returned by MCP list_tables(schema={chosen_schema})")

        user_intent = None
        try:
            ig = await self.mcp.call_tool("catalog_get", {"kind": "intent", "key": f"intent/{ui.run_id}"})
            if isinstance(ig, dict) and ig.get("document"):
                user_intent = json.loads(ig["document"])
        except Exception:
            user_intent = None

        ui.phase = "running"
        no_progress_streak = 0

        for it in range(1, max_iterations + 1):
            ui.iteration = it
            ui.last_event = "Planning tasks…"
            tasks = await self.planner(chosen_schema, table_names, user_intent)
            ui.planned_tasks = tasks
            ui.last_event = f"Planned {len(tasks)} tasks"

            if not tasks:
                ui.phase = "done"
                ui.last_event = "No tasks from planner"
                return

            executed = 0
            before_insights = ui.insights
            before_writes = ui.catalog_writes

            for task in tasks:
                if executed >= tasks_per_iter:
                    break
                executed += 1

                expert = task.expert
                ctx = {
                    "run_id": ui.run_id,
                    "schema": task.schema,
                    "table": task.table,
                    "goal": task.goal,
                    "user_intent": user_intent,
                    "note": "Choose minimal tool calls to advance discovery."
                }

                ui.last_event = f"{expert} ACT: {task.goal}" + (f" ({task.table})" if task.table else "")
                act = await self.expert_act(expert, ctx)

                tool_results: List[Dict[str, Any]] = []
                for call in act.tool_calls:
                    ui.last_event = f"MCP tool: {call.name}"
                    ui.tool_calls += 1
                    res = await self.mcp.call_tool(call.name, call.args)
                    tool_results.append({"tool": call.name, "args": call.args, "result": res})

                ui.last_event = f"{expert} REFLECT"
                ref = await self.expert_reflect(expert, ctx, tool_results)

                if ref.catalog_writes:
                    await self.apply_catalog_writes(ref.catalog_writes)
                    ui.catalog_writes += len(ref.catalog_writes)

                for q in ref.questions_for_user[:1]:
                    payload = {
                        "run_id": ui.run_id,
                        "question_id": q.question_id,
                        "title": q.title,
                        "prompt": q.prompt,
                        "options": q.options,
                        "created_at": now_iso()
                    }
                    await self.mcp.call_tool("catalog_upsert", {
                        "kind": "question",
                        "key": f"question/{ui.run_id}/{q.question_id}",
                        "document": json.dumps(payload, ensure_ascii=False),
                        "tags": f"run:{ui.run_id}"
                    })
                    ui.catalog_writes += 1

                ui.insights += len(ref.insights)

            gained_insights = ui.insights - before_insights
            gained_writes = ui.catalog_writes - before_writes
            if gained_insights == 0 and gained_writes == 0:
                no_progress_streak += 1
            else:
                no_progress_streak = 0

            if no_progress_streak >= 2:
                ui.phase = "done"
                ui.last_event = "Stopping: diminishing returns"
                return

        ui.phase = "done"
        ui.last_event = "Finished: max_iterations reached"


def render(ui: UIState) -> Layout:
    layout = Layout()

    header = Text()
    header.append("Database Discovery Agent ", style="bold")
    header.append(f"(run_id: {ui.run_id})", style="dim")

    status = Table.grid(expand=True)
    status.add_column(justify="left")
    status.add_column(justify="right")
    status.add_row("Phase", f"[bold]{ui.phase}[/bold]")
    status.add_row("Iteration", str(ui.iteration))
    status.add_row("Tool calls", str(ui.tool_calls))
    status.add_row("Catalog writes", str(ui.catalog_writes))
    status.add_row("Insights", str(ui.insights))

    tasks_table = Table(title="Planned Tasks", expand=True)
    tasks_table.add_column("Prio", justify="right", width=6)
    tasks_table.add_column("Expert", width=11)
    tasks_table.add_column("Goal")
    tasks_table.add_column("Table", style="dim")

    for t in (ui.planned_tasks or [])[:10]:
        tasks_table.add_row(f"{t.priority:.2f}", t.expert, t.goal, t.table or "")

    events = Text()
    if ui.last_event:
        events.append(ui.last_event, style="white")
    if ui.last_error:
        events.append("\n")
        events.append(ui.last_error, style="bold red")

    layout.split_column(
        Layout(Panel(header, border_style="cyan"), size=3),
        Layout(Panel(status, title="Status", border_style="green"), size=8),
        Layout(Panel(tasks_table, border_style="magenta"), ratio=2),
        Layout(Panel(events, title="Last event", border_style="yellow"), size=6),
    )
    return layout


async def cmd_run(args: argparse.Namespace):
    console = Console()
    trace = TraceLogger(args.trace)

    mcp_endpoint = args.mcp_endpoint or os.getenv("MCP_ENDPOINT", "")
    mcp_token = args.mcp_auth_token or os.getenv("MCP_AUTH_TOKEN")
    mcp_insecure = args.mcp_insecure_tls or (os.getenv("MCP_INSECURE_TLS", "0") in ("1","true","TRUE","yes","YES"))

    llm_base = args.llm_base_url or os.getenv("LLM_BASE_URL", "https://api.openai.com")
    llm_key = args.llm_api_key or os.getenv("LLM_API_KEY", "")
    llm_model = args.llm_model or os.getenv("LLM_MODEL", "gpt-4o-mini")
    llm_insecure = args.llm_insecure_tls or (os.getenv("LLM_INSECURE_TLS", "0") in ("1","true","TRUE","yes","YES"))

    if not mcp_endpoint:
        console.print("[bold red]MCP endpoint is required (set MCP_ENDPOINT or --mcp-endpoint)[/bold red]")
        raise SystemExit(2)

    if "openai.com" in llm_base and not llm_key:
        console.print("[bold red]LLM_API_KEY is required for OpenAI[/bold red]")
        raise SystemExit(2)

    run_id = args.run_id or str(uuid.uuid4())
    ui = UIState(run_id=run_id)

    mcp = MCPClient(mcp_endpoint, mcp_token, trace, insecure_tls=mcp_insecure)
    llm = LLMClient(llm_base, llm_key, llm_model, trace, insecure_tls=llm_insecure)
    agent = Agent(mcp, llm, trace, debug=args.debug)

    async def runner():
        try:
            await agent.run(ui, args.schema, args.max_iterations, args.tasks_per_iter)
        except Exception as e:
            ui.phase = "error"
            ui.last_error = f"{type(e).__name__}: {e}"
            trace.write({"type": "error", "error": ui.last_error})
            if args.debug:
                tb = traceback.format_exc()
                trace.write({"type": "error.traceback", "traceback": tb})
                ui.last_error += "\n" + tb
        finally:
            await mcp.close()
            await llm.close()

    task = asyncio.create_task(runner())
    with Live(render(ui), refresh_per_second=8, console=console):
        while not task.done():
            await asyncio.sleep(0.1)

    console.print(render(ui))
    if ui.phase == "error":
        raise SystemExit(1)


async def cmd_intent(args: argparse.Namespace):
    console = Console()
    trace = TraceLogger(args.trace)

    mcp_endpoint = args.mcp_endpoint or os.getenv("MCP_ENDPOINT", "")
    mcp_token = args.mcp_auth_token or os.getenv("MCP_AUTH_TOKEN")
    mcp_insecure = args.mcp_insecure_tls or (os.getenv("MCP_INSECURE_TLS", "0") in ("1","true","TRUE","yes","YES"))

    if not mcp_endpoint:
        console.print("[bold red]MCP endpoint is required[/bold red]")
        raise SystemExit(2)

    payload = {
        "run_id": args.run_id,
        "audience": args.audience,
        "goals": args.goals,
        "constraints": {},
        "updated_at": now_iso()
    }
    for kv in (args.constraint or []):
        if "=" in kv:
            k, v = kv.split("=", 1)
            payload["constraints"][k] = v

    mcp = MCPClient(mcp_endpoint, mcp_token, trace, insecure_tls=mcp_insecure)
    try:
        await mcp.call_tool("catalog_upsert", {
            "kind": "intent",
            "key": f"intent/{args.run_id}",
            "document": json.dumps(payload, ensure_ascii=False),
            "tags": f"run:{args.run_id}"
        })
        console.print("[green]Intent stored[/green]")
    finally:
        await mcp.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="discover_cli", description="Database Discovery Agent (Async CLI)")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--mcp-endpoint", default=None, help="MCP JSON-RPC endpoint (or MCP_ENDPOINT env)")
    common.add_argument("--mcp-auth-token", default=None, help="MCP auth token (or MCP_AUTH_TOKEN env)")
    common.add_argument("--mcp-insecure-tls", action="store_true", help="Disable MCP TLS verification (like curl -k)")
    common.add_argument("--llm-base-url", default=None, help="OpenAI-compatible base URL (or LLM_BASE_URL env)")
    common.add_argument("--llm-api-key", default=None, help="LLM API key (or LLM_API_KEY env)")
    common.add_argument("--llm-model", default=None, help="LLM model (or LLM_MODEL env)")
    common.add_argument("--llm-insecure-tls", action="store_true", help="Disable LLM TLS verification")
    common.add_argument("--trace", default=None, help="Write JSONL trace to this file")
    common.add_argument("--debug", action="store_true", help="Show stack traces")

    prun = sub.add_parser("run", parents=[common], help="Run discovery")
    prun.add_argument("--run-id", default=None, help="Optional run id (uuid). If omitted, generated.")
    prun.add_argument("--schema", default=None, help="Optional schema to focus on")
    prun.add_argument("--max-iterations", type=int, default=6)
    prun.add_argument("--tasks-per-iter", type=int, default=3)
    prun.set_defaults(func=cmd_run)

    pint = sub.add_parser("intent", parents=[common], help="Set user intent for a run (stored in MCP catalog)")
    pint.add_argument("--run-id", required=True)
    pint.add_argument("--audience", default="mixed")
    pint.add_argument("--goals", nargs="*", default=["qna"])
    pint.add_argument("--constraint", action="append", help="constraint as key=value; repeatable")
    pint.set_defaults(func=cmd_intent)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(args.func(args))
    except KeyboardInterrupt:
        Console().print("\n[yellow]Interrupted[/yellow]")
        raise SystemExit(130)


if __name__ == "__main__":
    main()

