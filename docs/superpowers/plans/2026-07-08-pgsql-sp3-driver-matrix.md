# PostgreSQL SP-3 — Driver Matrix Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the SP-2 driver-agnostic behavior contract (connect, transactions, prepared statements, session isolation) through three additional real-world driver stacks — **Go/pgx**, **Java/pgjdbc**, **Node.js/node-postgres + Prisma** — each with its own protocol implementation and prepared-statement strategy, orchestrated by the existing pytest harness so the xfail catalogue, junit report, and CI wiring apply unchanged.

**Architecture:** Each language ships ONE self-contained behavior program implementing the 4-behavior contract behind a uniform CLI (`<prog> <behavior-name>` → exit 0/1, diagnostics on stderr). Programs are compiled/installed into the existing runner image via a multi-stage Dockerfile extension (the container is the only place toolchains are guaranteed — Java doesn't exist on the dev host). Thin pytest subprocess wrappers under `tests/` give each (language × behavior) pair a stable nodeid (`tests/test_behaviors_go.py::test_behavior_go[transactions]`) so the exact-nodeid xfail catalogue works as-is. **Scope decision (user-approved 2026-07-08): behaviors only** — the differential engine stays Python/psycopg (its comparison unit is psycopg's decode semantics; per-language differential runners are a possible SP-3b, not this plan).

**Tech Stack:** Go 1.22 + pgx v5, Java 21 (Temurin) + pgjdbc 42.7.x, Node 22 + pg (node-postgres) 8.x + Prisma 5.x, multi-stage Docker on `python:3.11-slim`, pytest subprocess wrappers, existing `run-pg-compat.bash`/CI.

## Global Constraints

- **The behavior contract is FROZEN.** The four behaviors' semantics must match `test/pg-compat/behaviors/*.py` exactly (they are the cross-driver contract): same assertions, same trap adaptations. Do not change the Python behaviors.
- **Trap adaptations every port MUST reproduce** (from the SP-1/SP-2 findings — the Python behaviors' docstrings are the reference):
  - Session-isolation probe = `SET TimeZone = 'Antarctica/Troll'` / `SHOW TimeZone` (NEVER `application_name` — it's in ProxySQL's `ignore_vars`). Close A **before** opening B; assert B ≠ the distinctive value.
  - Transactions: every verification `SELECT count(*) ... AS verify_read` runs inside its own explicit BEGIN/COMMIT (pins to the writer; a bare `^SELECT` routes to a replica → replication-lag flake).
  - Every connection string pins **`client_encoding=UTF8`** (backend DBs are SQL_ASCII; ProxySQL imposes UTF8 — recorded finding in `xfail.toml`). Driver syntax: pgx/node-pg DSN param `client_encoding=UTF8`; pgjdbc URL does NOT accept it directly — use `options=-c%20client_encoding=UTF8` in the JDBC URL (verify empirically; `SET client_encoding` after connect is the fallback).
  - Placeholders are driver-native: pgx `$1,$2` · pgjdbc `?` · node-pg `$1,$2` (Python's `%s` is psycopg-specific).
- **Env contract (read, never invent):** programs read `PGCOMPAT_PROXY_HOST` (default `proxysql`) / `PGCOMPAT_PROXY_PORT` (default `6133`), connect as `testuser`/`testuser`, db `testuser`, sslmode/ssl disabled. No other env vars needed by behavior programs.
- **CLI contract (uniform across languages):** `<program> <behavior>` where `<behavior>` ∈ {connect, transactions, prepared, session_isolation}; exit 0 = pass, exit 1 = behavior assertion failed (human-readable reason on stderr), exit 2 = usage/infra error. No output on stdout needed for pass.
- **Table names are per-language** to be parallel-safe: `behavior_tx_t_go`, `behavior_tx_t_java`, `behavior_tx_t_node`, `behavior_tx_t_prisma` (Python keeps `behavior_tx_t`). Each program drops its table in a finally-equivalent.
- **Nodeid stability:** pytest wrappers use `@pytest.mark.parametrize(..., ids=[...])` with the literal behavior names so xfail.toml keys are stable (`tests/test_behaviors_<lang>.py::test_behavior_<lang>[<behavior>]`).
- **Docker builds need `--network=host` in this environment** (documented in `run-pg-compat.bash`); harmless on GitHub runners. All toolchains live in the IMAGE (multi-stage), not the host — Java does not exist on the dev host at all.
- **Discovery-phase (spec §2.1):** a driver behavior that genuinely fails through ProxySQL is a FINDING — never weaken the program's assertion; add an `[[xfail]]` entry with reason+ref (this is exactly what the catalogue is for; Prisma is the most likely candidate).
- **Verify runs:** `WORKSPACE=$(pwd) INFRA_ID=sdd-sp2 test/pg-compat/run-pg-compat.bash <pytest args>` against the standing `sdd-sp2` infra (`ensure-infras.bash` first if down). Do NOT touch `sdd-pg1`, `dev-rene*`, `iss5883`.
- **Version pins:** pgx `v5.7.x`, pgjdbc `42.7.x` (exact jar version pinned in the Dockerfile), pg (node) `8.x`, Prisma `5.x` — record exact chosen versions in a comment + the README table.

---

## File Structure

**New (this plan):**
- `test/pg-compat/drivers/go/behaviors.go` + `go.mod`/`go.sum` — Go behavior program (pgx v5).
- `test/pg-compat/drivers/java/Behaviors.java` — Java behavior program (single file, pgjdbc on the classpath).
- `test/pg-compat/drivers/node/behaviors.js` + `package.json`/`package-lock.json` — Node behavior program (pg).
- `test/pg-compat/drivers/prisma/` — `behaviors.mjs`, `schema.prisma`, package files — Prisma behavior program.
- `test/pg-compat/tests/test_behaviors_go.py`, `test_behaviors_java.py`, `test_behaviors_node.py`, `test_behaviors_prisma.py` — subprocess wrappers.
- `test/pg-compat/tests/_subproc.py` — the one shared subprocess helper (run program, assert exit 0, surface stderr).

**Modified:**
- `test/pg-compat/Dockerfile` — multi-stage: Go builder (static binary), Java builder (javac) + JRE in final, Node runtime + npm ci; final stage remains `python:3.11-slim`-based.
- `test/pg-compat/README.md` — driver matrix table (language, driver, version, prepared-statement strategy, placeholder syntax).
- `docs/superpowers/specs/2026-07-08-pgsql-protocol-testing-design.md` — §6 SP-3 stub updated to the approved behaviors-only scope (+ SP-3b stub for per-language differential runners).
- `.github/workflows/gh-actions-reusable/ci-pg-compat.yml` — timeout bump only if measured necessary (Task 6 decides on evidence).

**Interfaces produced (consumed by every task):**
- CLI contract as in Global Constraints; binaries land in the image at `/pg-compat/bin/behaviors-go`, `/pg-compat/bin/Behaviors.class`+wrapper `behaviors-java`, `/pg-compat/bin/behaviors-node` (wrapper invoking `node /pg-compat/drivers/node/behaviors.js`), `/pg-compat/bin/behaviors-prisma`.
- `tests/_subproc.py`: `def run_behavior(program: str, behavior: str) -> None` — runs `[program, behavior]`, `pytest.fail` with captured stderr on nonzero exit; `pytest.skip(f"{program} not in image")` if the binary is absent (lets partial images run).

---

## Task 1: Multi-language runner image + CLI/subprocess scaffolding

Extend the Dockerfile with the three toolchains (multi-stage; final image stays lean), add the shared subprocess helper, and prove the wiring with stub programs that only implement `connect`. Real behaviors land per-language in Tasks 2–4 — this task makes the image+harness seam work end to end.

**Files:**
- Modify: `test/pg-compat/Dockerfile`
- Create: `test/pg-compat/tests/_subproc.py`, `test/pg-compat/drivers/go/{behaviors.go,go.mod}`, `test/pg-compat/drivers/java/Behaviors.java`, `test/pg-compat/drivers/node/{behaviors.js,package.json}` (stubs: `connect` only, other behaviors exit 2 "not implemented")
- Create: `test/pg-compat/tests/test_behaviors_go.py` (+ java, node variants) with ONLY the `connect` param active this task (`BEHAVIORS = ["connect"]`; Tasks 2–4 extend the list per language)

**Interfaces:**
- Produces: the Dockerfile stages + `/pg-compat/bin/behaviors-{go,java,node}` layout, `run_behavior()` helper, wrapper test files. Tasks 2–4 only edit their language's program + extend their `BEHAVIORS` list.

- [ ] **Step 1: Extend the Dockerfile (multi-stage)**

Replace `test/pg-compat/Dockerfile` with:

```dockerfile
# ---- Go builder: static behavior binary (no runtime needed in final) ----
FROM golang:1.22-bookworm AS gobuild
WORKDIR /src
COPY drivers/go/ .
RUN CGO_ENABLED=0 go build -o /out/behaviors-go .

# ---- Java builder: compile against a pinned pgjdbc jar ----
FROM eclipse-temurin:21-jdk AS javabuild
WORKDIR /src
# Pin the driver version explicitly; record bumps in README's driver table.
ARG PGJDBC_VERSION=42.7.4
RUN curl -fsSLo /pgjdbc.jar "https://repo1.maven.org/maven2/org/postgresql/postgresql/${PGJDBC_VERSION}/postgresql-${PGJDBC_VERSION}.jar"
COPY drivers/java/Behaviors.java .
RUN javac -cp /pgjdbc.jar Behaviors.java -d /out

# ---- Node deps: install node-postgres against the lockfile ----
FROM node:22-bookworm-slim AS nodebuild
WORKDIR /app
COPY drivers/node/package.json drivers/node/package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev
COPY drivers/node/behaviors.js .

# ---- Final: python base + JRE + node runtime + artifacts ----
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 curl default-jre-headless \
    && rm -rf /var/lib/apt/lists/*
# Node runtime copied from the official image (bookworm-glibc compatible).
COPY --from=nodebuild /usr/local/bin/node /usr/local/bin/node
WORKDIR /pg-compat
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Language artifacts under /pg-compat/bin with uniform CLI wrappers.
COPY --from=gobuild /out/behaviors-go /pg-compat/bin/behaviors-go
COPY --from=javabuild /out/ /pg-compat/bin/java-classes/
COPY --from=javabuild /pgjdbc.jar /pg-compat/bin/pgjdbc.jar
COPY --from=nodebuild /app /pg-compat/node-app
RUN printf '#!/bin/sh\nexec java -cp /pg-compat/bin/java-classes:/pg-compat/bin/pgjdbc.jar Behaviors "$@"\n' > /pg-compat/bin/behaviors-java \
 && printf '#!/bin/sh\nexec node /pg-compat/node-app/behaviors.js "$@"\n' > /pg-compat/bin/behaviors-node \
 && chmod +x /pg-compat/bin/behaviors-*
ENTRYPOINT ["pytest", "-q"]
```

(If `COPY --from=nodebuild /usr/local/bin/node` misses shared libs at runtime, fall back to `apt-get install nodejs` from bookworm — decide empirically, document in the report.)

- [ ] **Step 2: Shared subprocess helper**

`test/pg-compat/tests/_subproc.py`:

```python
"""Run a per-language behavior program and translate its exit code into
pytest semantics. The CLI contract: `<prog> <behavior>` -> exit 0 pass,
exit 1 assertion-failure (reason on stderr), exit 2 usage/infra error."""
import os
import subprocess

import pytest

def run_behavior(program, behavior):
    if not os.path.exists(program):
        pytest.skip(f"{program} not present in this image")
    r = subprocess.run(
        [program, behavior], capture_output=True, text=True, timeout=120,
        env=os.environ.copy(),
    )
    if r.returncode == 0:
        return
    detail = f"{program} {behavior} -> exit {r.returncode}\nstderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    if r.returncode == 2:
        pytest.fail(f"infra/usage error (not a behavior failure): {detail}")
    pytest.fail(detail)
```

- [ ] **Step 3: Stub programs (connect only) + wrapper tests**

Each stub implements `connect` fully (open → `SELECT 1` → assert 1 → close) and exits 2 with "not implemented" for the other names. Wrapper test file pattern (`tests/test_behaviors_go.py`; java/node identical with names swapped):

```python
import pytest
from tests._subproc import run_behavior

PROGRAM = "/pg-compat/bin/behaviors-go"
BEHAVIORS = ["connect"]   # Tasks 2-4 extend per language

@pytest.mark.parametrize("behavior", BEHAVIORS, ids=BEHAVIORS)
def test_behavior_go(behavior):
    run_behavior(PROGRAM, behavior)
```

Stub sources: keep the real connection code (it is Task-common): read `PGCOMPAT_PROXY_HOST`/`PGCOMPAT_PROXY_PORT`, user/pass/db `testuser`, ssl off, `client_encoding=UTF8`. (Full per-language programs land in Tasks 2–4 — write the stubs so extending = filling in function bodies, not restructuring.)

- [ ] **Step 4: Build + run — expect 3 new `connect` passes**

```bash
WORKSPACE=$(pwd) INFRA_ID=sdd-sp2 test/pg-compat/run-pg-compat.bash tests/test_behaviors_go.py tests/test_behaviors_java.py tests/test_behaviors_node.py -v
```
Expected: 3 passed (go/java/node × connect). Full suite still 16+3 passed, 2 skipped.

- [ ] **Step 5: Commit**

```bash
git add test/pg-compat/Dockerfile test/pg-compat/tests/_subproc.py test/pg-compat/tests/test_behaviors_*.py test/pg-compat/drivers/go test/pg-compat/drivers/java test/pg-compat/drivers/node
git commit -m "test(pg-compat): multi-language runner image + behavior CLI scaffolding (connect x3)"
```

---

## Task 2: Go/pgx behavior program (full contract)

**Files:** Modify `test/pg-compat/drivers/go/behaviors.go` (+`go.sum`), extend `BEHAVIORS` in `tests/test_behaviors_go.py` to all four.

**Key driver facts to encode:** pgx v5 (`github.com/jackc/pgx/v5`) prepares statements automatically via its statement cache (`default_query_exec_mode=cache_statement` default) — the 50× parameterized loop (`SELECT $1::int + $2::int`) exercises real extended-protocol prepared statements. DSN: `postgres://testuser:testuser@$HOST:$PORT/testuser?sslmode=disable&client_encoding=UTF8`. Transactions via `conn.Begin(ctx)`/`tx.Commit(ctx)`; verify-reads inside their own tx (`AS verify_read` alias, table `behavior_tx_t_go`). Session isolation: conn A `SET TimeZone='Antarctica/Troll'` → `SHOW TimeZone` == it → `a.Close(ctx)` → conn B `SHOW TimeZone` != it. All four behaviors behind the CLI switch; cleanup via `defer` + explicit final `DROP TABLE IF EXISTS`.

- [ ] **Step 1:** Extend `BEHAVIORS = ["connect", "transactions", "prepared", "session_isolation"]` in the wrapper; run → RED (exit 2 not-implemented for the three new ones).
- [ ] **Step 2:** Implement the three behaviors in `behaviors.go` per the frozen contract (mirror `behaviors/*.py` assertions exactly; the Python files are the spec — read them).
- [ ] **Step 3:** Rebuild image + run `tests/test_behaviors_go.py -v` → 4 passed. Run twice (idempotent). A genuine failure through ProxySQL = finding: keep it failing, add `[[xfail]]` with reason+ref, report it.
- [ ] **Step 4:** Full suite green (± catalogued xfails). Commit: `test(pg-compat): Go/pgx behavior program (full contract)`.

---

## Task 3: Java/pgjdbc behavior program (full contract)

**Files:** Modify `test/pg-compat/drivers/java/Behaviors.java`, extend `tests/test_behaviors_java.py`.

**Key driver facts to encode:** pgjdbc placeholders are `?`; pgjdbc switches a reused `PreparedStatement` to a **server-side named statement after `prepareThreshold` (default 5) executions** — reuse ONE PreparedStatement object for the 50× loop so the back half runs real named statements through ProxySQL's multiplexing (this is the pgjdbc-specific value of the port). URL: `jdbc:postgresql://$HOST:$PORT/testuser?sslmode=disable&options=-c%20client_encoding%3DUTF8` — VERIFY the options form empirically; fallback: execute `SET client_encoding TO 'UTF8'` right after connect and document. Transactions: `setAutoCommit(false)` … `commit()` … `setAutoCommit(true)`; verify-reads in their own autocommit-off/commit pair (`AS verify_read`, table `behavior_tx_t_java`). Session isolation identical structure (close A before B). Exit codes per the CLI contract; single-file `Behaviors.java` with a `main` dispatching on args[0].

- [ ] **Step 1:** Extend BEHAVIORS → RED (exit 2). 
- [ ] **Step 2:** Implement; mirror the Python behaviors exactly.
- [ ] **Step 3:** Rebuild + run → 4 passed ×2 runs. pgjdbc's named-statement path failing through ProxySQL would be a HIGH-VALUE finding (this is the classic pooler breaker): keep failing + xfail-catalogue + report prominently.
- [ ] **Step 4:** Full suite green (± catalogued). Commit: `test(pg-compat): Java/pgjdbc behavior program (full contract)`.

---

## Task 4: Node/node-postgres behavior program (full contract)

**Files:** Modify `test/pg-compat/drivers/node/behaviors.js` (+lockfile), extend `tests/test_behaviors_node.py`.

**Key driver facts to encode:** `pg` 8.x; placeholders `$1,$2`; **named prepared statements** via `client.query({name: 'add', text: 'SELECT $1::int + $2::int AS sum', values: [i, 1]})` — reusing the same `name` for the 50× loop makes node-pg Parse once and Bind/Execute repeatedly (its distinct prepared-statement strategy). Connection config from env (`host`, `port`, user/pass/db `testuser`, `ssl: false`); pin encoding via connection string param `client_encoding=UTF8` (or `options`). Transactions via explicit `BEGIN`/`COMMIT`/`ROLLBACK` queries; verify-reads inside their own BEGIN/COMMIT (`AS verify_read`, table `behavior_tx_t_node`). Session isolation: A sets/asserts TZ, `await a.end()` BEFORE `new Client()` B. Exit codes per CLI; async main with try/finally cleanup.

- [ ] **Step 1:** Extend BEHAVIORS → RED. 
- [ ] **Step 2:** Implement (mirror Python behaviors).
- [ ] **Step 3:** Rebuild + run → 4 passed ×2. Findings → xfail catalogue + report.
- [ ] **Step 4:** Full suite green (± catalogued). Commit: `test(pg-compat): Node/node-postgres behavior program (full contract)`.

---

## Task 5: Prisma behavior program (ORM tier — xfail-tolerant)

Prisma is the notorious pooler-breaker (aggressive prepared statements, its own connection assumptions) — that's exactly why it's in scope. It may legitimately fail through ProxySQL: failures here are FINDINGS for the catalogue, not blockers.

**Files:** Create `test/pg-compat/drivers/prisma/{behaviors.mjs,schema.prisma,package.json,package-lock.json}`, `tests/test_behaviors_prisma.py`; modify the Dockerfile (extend the node stage: `npx prisma generate` at build time against `schema.prisma`; `binaryTargets = ["debian-openssl-3.0.x"]`).

**Key facts:** datasource url from `env("PGCOMPAT_PRISMA_URL")` — construct it in the wrapper test/conftest from the PGCOMPAT proxy vars (`postgresql://testuser:testuser@$HOST:$PORT/testuser?sslmode=disable`). Behaviors via `$queryRaw`/`$executeRaw` + `$transaction` (interactive transactions for the txn-wrapped verify reads): `connect` = `SELECT 1`; `transactions` = table `behavior_tx_t_prisma` with $transaction rollback/commit semantics (rollback = throw inside the interactive txn); `prepared` = 50× `$queryRaw\`SELECT ${i}::int + ${1}::int\`` (Prisma always uses prepared statements — the whole point); `session_isolation` = two PrismaClient instances, `SET TimeZone` via `$executeRawUnsafe`, disconnect A before creating B. Note Prisma pools internally (connection_limit=1 in the URL keeps it deterministic-ish; document).

- [ ] **Step 1:** Dockerfile prisma-generate stage + stub `connect` → wrapper with `BEHAVIORS=["connect"]` → green.
- [ ] **Step 2:** Implement all four; extend BEHAVIORS → run. **Expected outcome is uncertain by design** — record per-behavior results honestly; catalogue genuine ProxySQL-vs-Prisma incompatibilities as `[[xfail]]` entries with precise reasons (these are the deliverable).
- [ ] **Step 3:** Full suite: passes + catalogued xfails only. Run ×2. Commit: `test(pg-compat): Prisma behavior program (ORM tier, findings catalogued)`.

---

## Task 6: Docs, spec sync, CI budget check

**Files:** Modify `test/pg-compat/README.md`, `docs/superpowers/specs/2026-07-08-pgsql-protocol-testing-design.md` (§6), possibly `.github/workflows/gh-actions-reusable/ci-pg-compat.yml` (timeout only).

- [ ] **Step 1:** README driver-matrix table: language | driver+version | placeholder syntax | prepared-statement strategy (psycopg auto-prepare@5 / pgx statement-cache / pgjdbc prepareThreshold@5 named / node-pg named / Prisma always) | wrapper nodeid prefix. Plus how to run one language (`run-pg-compat.bash tests/test_behaviors_go.py`).
- [ ] **Step 2:** Spec §6: replace the SP-3 stub with the as-built scope (behaviors-only, subprocess orchestration, drivers list + versions) and add an **SP-3b** stub (per-language differential runners emitting normalized results for Python's compare — deferred pending nightly stability).
- [ ] **Step 3:** Measure the image-build delta (time the docker build before/after SP-3 stages) and the full-suite wall time; bump the reusable's `timeout-minutes` ONLY if evidence demands (report the numbers either way).
- [ ] **Step 4:** Full suite final run ×2 → record the final pass/skip/xfail tally. Commit: `docs(pg-compat): SP-3 driver matrix docs + spec sync (+ CI budget evidence)`.

---

## Self-Review

**Spec coverage:** SP-3 roadmap items → Java/pgjdbc (Task 3), Go/pgx (Task 2), Node node-postgres + Prisma (Tasks 4–5) — all against the SP-2 `behaviors/` contract (Task 1 seam). Scope deviation from the spec stub's "behaviors + differential cases" is user-approved (2026-07-08, behaviors-only) and gets written back into the spec in Task 6 with an SP-3b stub. CI fan-out from the roadmap ("one matrix job per language") deliberately simplified to the single fat-image job — same coverage, no matrix complexity; revisit at promote-to-gating.

**Placeholder scan:** Tasks 2–5 say "mirror the Python behaviors" instead of embedding ~150 lines × 4 languages — this is deliberate, not a placeholder: the Python behavior modules ARE the frozen executable spec (Global Constraints), each task names the exact driver-specific deltas (placeholders, prepared-statement mechanism, txn API, encoding pin), and implementers must read the Python files first. The Dockerfile, helper, and wrapper code are complete.

**Type consistency:** CLI contract, binary paths (`/pg-compat/bin/behaviors-*`), `run_behavior(program, behavior)`, `BEHAVIORS` list pattern, per-language table names, and nodeid shapes are used identically across Tasks 1–6.

**Risks:** (1) node binary COPY missing shared libs — Task 1 names the fallback; (2) pgjdbc URL encoding-pin syntax — Task 3 mandates empirical verification with a stated fallback; (3) Prisma engine/binaryTarget in slim image — Task 5 pins `debian-openssl-3.0.x`; (4) image size/build time — Task 6 measures and decides the CI budget on evidence.
