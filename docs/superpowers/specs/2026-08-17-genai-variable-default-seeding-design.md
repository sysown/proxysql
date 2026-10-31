# GenAI Plugin Variable Default Seeding Design

**Status:** Approved design; implementation plan available
**Issue:** #6099
**Branch:** `fix/6099-genai-variable-defaults`
**Base:** `v3.0` at `94b3c8260`
**Date:** 2026-08-17

## Problem

The GenAI plugin constructs `MCP_Threads_Handler` and
`GenAI_Threads_Handler` with compiled-in defaults, but plugin startup then
loads `mcp-*` and `genai-*` values from `main.global_variables` without first
seeding those rows. On a fresh installation both queries return no rows.
Subsequent admin statements such as `SET mcp-enabled=true` translate to an
update of a row that does not exist, leaving the handler on its constructor
default and making AI TAP behavior depend on test order.

Before the plugin carve-out, Admin startup wrote handler defaults to both the
persistent config database and the in-memory Admin database with
`INSERT OR IGNORE`, then loaded the in-memory values into the handlers. The
carve-out retained the load path but lost the seeding step.

## Goals

- Restore persistent default seeding for every supported MCP and GenAI
  variable.
- Preserve all operator-provided values during first start, restart, and
  upgrades.
- Add newly introduced variables to an existing installation without
  requiring a manual save command.
- Make plugin startup independent of AI TAP execution order.
- Cover the lifecycle contract with the existing plugin-load unit test.

## Non-goals

- Populating `runtime_global_variables`; issue #6100 owns that projection.
- Changing variable names, defaults, validation, or endpoint authentication.
- Adding a generic variable-registration service to the plugin ABI.
- Modifying `CI-unit-tests-asan-coverage` or AI workflow definitions.

## Considered approaches

### Seed from the plugin during startup — selected

The GenAI plugin enumerates the variables owned by its two handlers and
inserts missing rows into both database layers before loading runtime state.
This restores the previous lifecycle contract within the component that now
owns the variables.

### Add a generic plugin-variable API to the chassis

A new ABI service could register names and defaults before Admin bootstrap.
That may be useful for multiple future plugins, but it expands core and ABI
scope unnecessarily for a defect isolated to the GenAI carve-out.

### Seed variables in AI test setup

The TAP setup could insert the missing rows directly. That would make the
current shards pass while leaving fresh production installations with the
same broken lifecycle, so it is not an acceptable fix.

## Design

### Source of truth

The handlers remain the single source of truth for supported names and
compiled-in defaults:

- `MCP_Threads_Handler::get_variables_list()` and
  `get_variable_string()` expose 14 MCP variables.
- `GenAI_Threads_Handler::get_variables_list()` and `get_variable()` expose
  32 GenAI variables.

Startup must enumerate those APIs instead of maintaining a second defaults
table in plugin glue. Consequently, adding a handler variable automatically
causes it to be seeded on the next start.

### Startup order

`genai_start()` will perform these operations in order:

1. Seed missing `mcp-*` and `genai-*` rows in the persistent config
   database returned by `get_configdb()`.
2. Seed the same missing rows in `main.global_variables` through the Admin
   database returned by `get_admindb()`.
3. Load MCP values from `main.global_variables` into
   `MCP_Threads_Handler`.
4. Load GenAI values from `main.global_variables` into
   `GenAI_Threads_Handler`.
5. Continue the existing runtime-component refresh and listener startup.

Both seeding passes use `INSERT OR IGNORE`. Existing rows always win over
constructor defaults, whether they came from disk, config, or an operator
update. Missing variables are added individually, so a partial variable set
is repaired without resetting the rows that already exist.

### Transaction and failure behavior

Each database is seeded in its own transaction because the plugin receives
separate database handles. A failed prepare, bind, step, or commit rolls back
that database and makes `genai_start()` return false with a specific log
message. If persistent seeding commits and in-memory seeding later fails, the
next start safely retries: `INSERT OR IGNORE` makes every operation
idempotent.

Allocated variable lists and values are released on every success and error
path. No handler write lock is needed because `genai_start()` runs before
plugin worker threads and only reads constructor state.

## Testing

Extend `test/tap/tests/unit/genai_plugin_load_unit-t.cpp`, which already
drives the real shared object through schema registration, initialization,
start, and stop against SQLite databases.

The fixture will create `global_variables` in both the Admin and config
databases. Before plugin startup it will seed distinct non-default values for
one MCP variable and one GenAI variable in both databases, modeling values
loaded from a previous run.

After startup, assertions will verify:

- the persistent and in-memory databases each contain exactly 14 `mcp-*`
  rows and 32 `genai-*` rows;
- representative constructor defaults have been inserted in both databases;
- the pre-existing MCP and GenAI values remain unchanged in both databases;
- every variable name is unique, enforced by the existing
  `global_variables` primary key;
- startup succeeds with a partially populated persistent configuration,
  demonstrating restart and upgrade behavior.

The test fails on the current implementation because neither database is
seeded. It will be run once before the production change to establish the
red phase, then after the minimal implementation and again with the relevant
plugin unit-test suite.

## Compatibility and risk

The change restores behavior that existed before the plugin carve-out. It
does not overwrite configured values, publish runtime rows, alter plugin ABI,
or enable MCP/GenAI features by default. The primary risk is startup failure
on a database error; failing explicitly is preferable to starting with an
incomplete and misleading configuration surface.
