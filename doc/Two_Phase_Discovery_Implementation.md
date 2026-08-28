# Two-Phase Schema Discovery Redesign - Implementation Summary

## Overview

This document summarizes the implementation of the two-phase schema discovery redesign for ProxySQL MCP. The implementation transforms the previous LLM-only auto-discovery into a **two-phase architecture**:

1. **Phase 1: Static/Auto Discovery** - Deterministic harvest from MySQL INFORMATION_SCHEMA
2. **Phase 2: LLM Agent Discovery** - Semantic analysis using MCP tools only (NO file I/O)

## Implementation Date

January 17, 2026

## Files Created

### Core Discovery Components

| File | Purpose |
|------|---------|
| `include/Discovery_Schema.h` | New catalog schema interface with deterministic + LLM layers |
| `lib/Discovery_Schema.cpp` | Schema initialization with 20+ tables (runs, objects, columns, indexes, fks, profiles, FTS, LLM artifacts) |
| `include/Static_Harvester.h` | Static harvester interface for deterministic metadata extraction |
| `lib/Static_Harvester.cpp` | Deterministic metadata harvest from INFORMATION_SCHEMA (mirrors Python PoC) |
| `include/Query_Tool_Handler.h` | **REFACTORED**: Now uses Discovery_Schema directly, includes 17 discovery tools |
| `lib/Query_Tool_Handler.cpp` | **REFACTORED**: All query + discovery tools in unified handler |

### Prompt Files

| File | Purpose |
|------|---------|
| `scripts/mcp/DiscoveryAgent/ClaudeCode_Headless/prompts/two_phase_discovery_prompt.md` | System prompt for LLM agent (staged discovery, MCP-only I/O) |
| `scripts/mcp/DiscoveryAgent/ClaudeCode_Headless/prompts/two_phase_user_prompt.md` | User prompt with discovery procedure |
| `scripts/mcp/DiscoveryAgent/ClaudeCode_Headless/two_phase_discovery.py` | Orchestration script wrapper for Claude Code |

## Files Modified

| File | Changes |
|------|--------|
| `include/Query_Tool_Handler.h` | **COMPLETELY REWRITTEN**: Now uses Discovery_Schema directly, includes MySQL connection pool |
| `lib/Query_Tool_Handler.cpp` | **COMPLETELY REWRITTEN**: 37 tools (20 original + 17 discovery), direct catalog/harvester usage |
| `lib/ProxySQL_MCP_Server.cpp` | Updated Query_Tool_Handler initialization (new constructor signature), removed Discovery_Tool_Handler |
| `include/MCP_Thread.h` | Removed Discovery_Tool_Handler forward declaration and pointer |
| `lib/Makefile` | Added Discovery_Schema.oo, Static_Harvester.oo (removed Discovery_Tool_Handler.oo) |

## Files Deleted

| File | Reason |
|------|--------|
| `include/Discovery_Tool_Handler.h` | Consolidated into Query_Tool_Handler |
| `lib/Discovery_Tool_Handler.cpp` | Consolidated into Query_Tool_Handler |

## Architecture

**IMPORTANT ARCHITECTURAL NOTE:** All discovery tools are now available through the `/mcp/query` endpoint. The separate `/mcp/discovery` endpoint approach was **removed** in favor of consolidation. Query_Tool_Handler now:

1. Uses `Discovery_Schema` directly (instead of wrapping `MySQL_Tool_Handler`)
2. Includes MySQL connection pool for direct queries
3. Provides all 37 tools (20 original + 17 discovery) through a single endpoint

### Phase 1: Static Discovery (C++)

The `Static_Harvester` class performs deterministic metadata extraction:

```
MySQL INFORMATION_SCHEMA → Static_Harvester → Discovery_Schema SQLite
```

**Harvest stages:**
1. Schemas (`information_schema.SCHEMATA`)
2. Objects (`information_schema.TABLES`, `ROUTINES`)
3. Columns (`information_schema.COLUMNS`) with derived hints (is_time, is_id_like)
4. Indexes (`information_schema.STATISTICS`)
5. Foreign Keys (`KEY_COLUMN_USAGE`, `REFERENTIAL_CONSTRAINTS`)
6. View definitions (`information_schema.VIEWS`)
7. Quick profiles (metadata-based analysis)
8. FTS5 index rebuild

**Derived field calculations:**
| Field | Calculation |
|-------|-------------|
| `is_time` | `data_type IN ('date','datetime','timestamp','time','year')` |
| `is_id_like` | `column_name REGEXP '(^id$|_id$)'` |
| `has_primary_key` | `EXISTS (SELECT 1 FROM indexes WHERE is_primary=1)` |
| `has_foreign_keys` | `EXISTS (SELECT 1 FROM foreign_keys WHERE child_object_id=?)` |
| `has_time_column` | `EXISTS (SELECT 1 FROM columns WHERE is_time=1)` |

### Phase 2: LLM Agent Discovery (MCP Tools)

The LLM agent (via Claude Code) performs semantic analysis using 18+ MCP tools:

**Discovery Trigger (1 tool):**
- `discovery.run_static` - Triggers ProxySQL's static harvest

**Catalog Tools (5 tools):**
- `catalog.init` - Initialize/migrate SQLite schema
- `catalog.search` - FTS5 search over objects
- `catalog.get_object` - Get object with columns/indexes/FKs
- `catalog.list_objects` - List objects (paged)
- `catalog.get_relationships` - Get FKs, view deps, inferred relationships

**Agent Tools (3 tools):**
- `agent.run_start` - Create agent run bound to run_id
- `agent.run_finish` - Mark agent run success/failed
- `agent.event_append` - Log tool calls, results, decisions

**LLM Memory Tools (9 tools):**
- `llm.summary_upsert` - Store semantic summary for object
- `llm.summary_get` - Get semantic summary
- `llm.relationship_upsert` - Store inferred relationship
- `llm.domain_upsert` - Create/update domain
- `llm.domain_set_members` - Set domain members
- `llm.metric_upsert` - Store metric definition
- `llm.question_template_add` - Add question template
- `llm.note_add` - Add durable note
- `llm.search` - FTS over LLM artifacts

## Database Schema

### Deterministic Layer Tables

| Table | Purpose |
|-------|---------|
| `runs` | Track each discovery run (run_id, started_at, finished_at, source_dsn, mysql_version) |
| `schemas` | Discovered MySQL schemas (schema_name, charset, collation) |
| `objects` | Tables/views/routines/triggers with metadata (engine, rows_est, has_pk, has_fks, has_time) |
| `columns` | Column details (data_type, is_nullable, is_pk, is_unique, is_indexed, is_time, is_id_like) |
| `indexes` | Index metadata (is_unique, is_primary, index_type, cardinality) |
| `index_columns` | Ordered index columns |
| `foreign_keys` | FK relationships |
| `foreign_key_columns` | Ordered FK columns |
| `profiles` | Profiling results (JSON for extensibility) |
| `fts_objects` | FTS5 index over objects (contentless) |

### LLM Agent Layer Tables

| Table | Purpose |
|-------|---------|
| `agent_runs` | LLM agent runs (bound to deterministic run_id) |
| `agent_events` | Tool calls, results, decisions (traceability) |
| `llm_object_summaries` | Per-object semantic summaries (hypothesis, grain, dims/measures, joins) |
| `llm_relationships` | LLM-inferred relationships with confidence |
| `llm_domains` | Domain clusters (billing, sales, auth, etc.) |
| `llm_domain_members` | Object-to-domain mapping with roles |
| `llm_metrics` | Metric/KPI definitions |
| `llm_question_templates` | NL → structured query plan mappings |
| `llm_notes` | Free-form durable notes |
| `fts_llm` | FTS5 over LLM artifacts |

## Usage

The two-phase discovery provides two ways to discover your database schema:

### Phase 1: Static Harvest (Direct curl)

Phase 1 is a simple HTTP POST to trigger deterministic metadata extraction. No Claude Code required.

```bash
# Option A: Using the convenience script (recommended)
cd scripts/mcp/DiscoveryAgent/ClaudeCode_Headless/
./static_harvest.sh --schema sales --notes "Production sales database discovery"

# Option B: Using curl directly
curl -k -X POST https://localhost:6071/mcp/query \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "discovery.run_static",
      "arguments": {
        "schema_filter": "sales",
        "notes": "Production sales database discovery"
      }
    }
  }'
# Returns: { run_id: 1, started_at: "...", objects_count: 45, columns_count: 380 }
```

### Phase 2: LLM Agent Discovery (via two_phase_discovery.py)

Phase 2 uses Claude Code for semantic analysis. Requires MCP configuration.

```bash
# Step 1: Copy example MCP config and customize
cp scripts/mcp/DiscoveryAgent/ClaudeCode_Headless/mcp_config.example.json mcp_config.json
# Edit mcp_config.json to set your PROXYSQL_MCP_ENDPOINT if needed

# Step 2: Run the two-phase discovery
./scripts/mcp/DiscoveryAgent/ClaudeCode_Headless/two_phase_discovery.py \
    --mcp-config mcp_config.json \
    --schema sales \
    --model claude-3.5-sonnet

# Dry-run mode (preview without executing)
./scripts/mcp/DiscoveryAgent/ClaudeCode_Headless/two_phase_discovery.py \
    --mcp-config mcp_config.json \
    --schema test \
    --dry-run
```

### Direct MCP Tool Calls (via /mcp/query endpoint)

You can also call discovery tools directly via the MCP endpoint:

```bash
# All discovery tools are available via /mcp/query endpoint
curl -k -X POST https://localhost:6071/mcp/query \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "discovery.run_static",
      "arguments": {
        "schema_filter": "sales",
        "notes": "Production sales database discovery"
      }
    }
  }'
# Returns: { run_id: 1, started_at: "...", objects_count: 45, columns_count: 380 }

# Phase 2: LLM agent discovery
curl -k -X POST https://localhost:6071/mcp/query \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "agent.run_start",
      "arguments": {
        "run_id": 1,
        "model_name": "claude-3.5-sonnet"
      }
    }
  }'
# Returns: { agent_run_id: 1 }
```

## Discovery Workflow

```
Stage 0: Start and plan
├─> discovery.run_static() → run_id
├─> agent.run_start(run_id) → agent_run_id
└─> agent.event_append(plan, budgets)

Stage 1: Triage and prioritization
└─> catalog.list_objects() + catalog.search() → build prioritized backlog

Stage 2: Per-object semantic summarization
└─> catalog.get_object() + catalog.get_relationships()
    └─> llm.summary_upsert() (50+ high-value objects)

Stage 3: Relationship enhancement
└─> llm.relationship_upsert() (where FKs missing or unclear)

Stage 4: Domain clustering and synthesis
└─> llm.domain_upsert() + llm.domain_set_members()
    └─> llm.note_add(domain descriptions)

Stage 5: "Answerability" artifacts
├─> llm.metric_upsert() (10-30 metrics)
└─> llm.question_template_add() (15-50 question templates)

Shutdown:
├─> agent.event_append(final_summary)
└─> agent.run_finish(success)
```

## Quality Rules

Confidence scores:
- **0.9–1.0**: supported by schema + constraints or very strong evidence
- **0.6–0.8**: likely, supported by multiple signals but not guaranteed
- **0.3–0.5**: tentative hypothesis; mark warnings and what's needed to confirm

## Critical Constraint: NO FILES

- LLM agent MUST NOT create/read/modify any local files
- All outputs MUST be persisted exclusively via MCP tools
- Use `agent_events` and `llm_notes` as scratchpad

## Verification

To verify the implementation:

```bash
# Build ProxySQL
cd /home/rene/proxysql-vec
make -j$(nproc)

# Verify new discovery components exist
ls -la include/Discovery_Schema.h include/Static_Harvester.h
ls -la lib/Discovery_Schema.cpp lib/Static_Harvester.cpp

# Verify Discovery_Tool_Handler was removed (should return nothing)
ls include/Discovery_Tool_Handler.h 2>&1 # Should fail
ls lib/Discovery_Tool_Handler.cpp 2>&1   # Should fail

# Verify Query_Tool_Handler uses Discovery_Schema
grep -n "Discovery_Schema" include/Query_Tool_Handler.h
grep -n "Static_Harvester" include/Query_Tool_Handler.h

# Verify Query_Tool_Handler has discovery tools
grep -n "discovery.run_static" lib/Query_Tool_Handler.cpp
grep -n "agent.run_start" lib/Query_Tool_Handler.cpp
grep -n "llm.summary_upsert" lib/Query_Tool_Handler.cpp

# Test Phase 1 (curl)
curl -k -X POST https://localhost:6071/mcp/query \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"discovery.run_static","arguments":{"schema_filter":"test"}}}'
# Should return: { run_id: 1, objects_count: X, columns_count: Y }

# Test Phase 2 (two_phase_discovery.py)
cd scripts/mcp/DiscoveryAgent/ClaudeCode_Headless/
cp mcp_config.example.json mcp_config.json
./two_phase_discovery.py --dry-run --mcp-config mcp_config.json --schema test
```

## Next Steps

1. **Build and test**: Compile ProxySQL and test with a small database
2. **Integration testing**: Test with medium database (100+ tables)
3. **Documentation updates**: Update main README and MCP docs
4. **Migration guide**: Document transition from legacy 6-agent to new two-phase system

## References

- Python PoC: `/tmp/mysql_autodiscovery_poc.py`
- Schema specification: `/tmp/schema.sql`
- MCP tools specification: `/tmp/mcp_tools_discovery_catalog.json`
- System prompt reference: `/tmp/system_prompt.md`
- User prompt reference: `/tmp/user_prompt.md`
