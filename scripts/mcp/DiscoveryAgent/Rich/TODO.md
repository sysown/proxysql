# TODO — Future Enhancements

This prototype prioritizes **runnability and debuggability**. Suggested next steps:

---

## 1) Catalog consistency

- Standardize catalog document structure (envelope with provenance + confidence)
- Enforce key naming conventions (structure/table, stats/col, semantic/entity, report, …)

---

## 2) Better expert strategies

- Structural: relationship graph (constraints + join candidates)
- Statistical: prioritize high-signal columns; sampling-first for big tables
- Semantic: evidence-based claims, fewer hallucinations, ask user only when needed
- Query: safe mode (`explain_sql` by default; strict LIMIT for readonly SQL)

---

## 3) Coverage and confidence

- Track coverage: tables discovered vs analyzed vs profiled
- Compute confidence heuristics and use them for stopping/checkpoints

---

## 4) Planning improvements

- Task de-duplication (avoid repeating the same work)
- Heuristics for table prioritization if planner struggles early

---

## 5) Add commands

- `report --run-id <id>`: synthesize a readable report from catalog
- `replay --trace trace.jsonl`: iterate prompts without hitting the DB

---

## 6) Optional UI upgrade

Move from Rich Live to **Textual** for:
- scrolling logs
- interactive question answering
- better filtering and navigation

---

## 7) Controlled concurrency

Once stable:
- run tasks concurrently with a semaphore
- per-table locks to avoid duplication
- keep catalog writes atomic per key

---

## 8) MCP enhancements (later)

After real usage:
- batch table describes / batch column profiles
- explicit row-count estimation tool
- typed catalog documents (native JSON instead of string)

