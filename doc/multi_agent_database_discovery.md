# Multi-Agent Database Discovery System

## Overview

This document describes a multi-agent database discovery system implemented using Claude Code's autonomous agent capabilities. The system uses 4 specialized subagents that collaborate via the MCP (Model Context Protocol) catalog to perform comprehensive database analysis.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Main Agent (Orchestrator)                       │
│  - Launches 4 specialized subagents in parallel                     │
│  - Coordinates via MCP catalog                                      │
│  - Synthesizes final report                                        │
└────────────────┬────────────────────────────────────────────────────┘
                 │
    ┌────────────┼────────────┬────────────┬────────────┐
    │            │            │            │            │
    ▼            ▼            ▼            ▼            ▼
┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐
│Struct. │  │Statist.│  │Semantic│  │Query   │  │  MCP   │
│ Agent  │  │ Agent  │  │ Agent  │  │ Agent  │  │Catalog │
└────────┘  └────────┘  └────────┘  └────────┘  └────────┘
     │            │            │            │            │
     └────────────┴────────────┴────────────┴────────────┘
                          │
                   ▼              ▼
              ┌─────────┐  ┌─────────────┐
              │ Database│  │   Catalog   │
              │ (testdb)│  │ (Shared Mem)│
              └─────────┘  └─────────────┘
```

## The Four Discovery Agents

### 1. Structural Agent
**Mission**: Map tables, relationships, indexes, and constraints

**Responsibilities**:
- Complete ERD documentation
- Table schema analysis (columns, types, constraints)
- Foreign key relationship mapping
- Index inventory and assessment
- Architectural pattern identification

**Catalog Entries**: `structural_discovery`

**Key Deliverables**:
- Entity Relationship Diagram
- Complete table definitions
- Index inventory with recommendations
- Relationship cardinality mapping

### 2. Statistical Agent
**Mission**: Profile data distributions, patterns, and anomalies

**Responsibilities**:
- Table row counts and cardinality analysis
- Data distribution profiling
- Anomaly detection (duplicates, outliers)
- Statistical summaries (min/max/avg/stddev)
- Business metrics calculation

**Catalog Entries**: `statistical_discovery`

**Key Deliverables**:
- Data quality score
- Duplicate detection reports
- Statistical distributions
- True vs inflated metrics

### 3. Semantic Agent
**Mission**: Infer business domain and entity types

**Responsibilities**:
- Business domain identification
- Entity type classification (master vs transactional)
- Business rule discovery
- Entity lifecycle analysis
- State machine identification

**Catalog Entries**: `semantic_discovery`

**Key Deliverables**:
- Complete domain model
- Business rules documentation
- Entity lifecycle definitions
- Missing capabilities identification

### 4. Query Agent
**Mission**: Analyze access patterns and optimization opportunities

**Responsibilities**:
- Query pattern identification
- Index usage analysis
- Performance bottleneck detection
- N+1 query risk assessment
- Optimization recommendations

**Catalog Entries**: `query_discovery`

**Key Deliverables**:
- Access pattern analysis
- Index recommendations (prioritized)
- Query optimization strategies
- EXPLAIN analysis results

## Discovery Process

### Round Structure

Each agent runs 4 rounds of analysis:

#### Round 1: Blind Exploration
- Initial schema/data analysis
- First observations cataloged
- Initial hypotheses formed

#### Round 2: Pattern Recognition
- Read other agents' findings from catalog
- Identify patterns and anomalies
- Form and test hypotheses

#### Round 3: Hypothesis Testing
- Validate business rules against actual data
- Cross-reference findings with other agents
- Confirm or reject hypotheses

#### Round 4: Final Synthesis
- Compile comprehensive findings
- Generate actionable recommendations
- Create final mission summary

### Catalog-Based Collaboration

```python
# Agent writes findings
catalog_upsert(
    kind="structural_discovery",
    key="table_customers",
    document="...",
    tags="structural,table,schema"
)

# Agent reads other agents' findings
findings = catalog_list(kind="statistical_discovery")
```

## Example Discovery Output

### Database: testdb (E-commerce Order Management)

#### True Statistics (After Deduplication)
| Metric | Current | Actual |
|--------|---------|--------|
| Customers | 15 | 5 |
| Products | 15 | 5 |
| Orders | 15 | 5 |
| Order Items | 27 | 9 |
| Revenue | $10,886.67 | $3,628.85 |

#### Critical Findings
1. **Data Quality**: 5/100 (Catastrophic) - 67% data triplication
2. **Missing Index**: orders.order_date (P0 critical)
3. **Missing Constraints**: No UNIQUE or FK constraints
4. **Business Domain**: E-commerce order management system

## Launching the Discovery System

```python
# In Claude Code, launch 4 agents in parallel:
Task(
    description="Structural Discovery",
    prompt=STRUCTURAL_AGENT_PROMPT,
    subagent_type="general-purpose"
)

Task(
    description="Statistical Discovery",
    prompt=STATISTICAL_AGENT_PROMPT,
    subagent_type="general-purpose"
)

Task(
    description="Semantic Discovery",
    prompt=SEMANTIC_AGENT_PROMPT,
    subagent_type="general-purpose"
)

Task(
    description="Query Discovery",
    prompt=QUERY_AGENT_PROMPT,
    subagent_type="general-purpose"
)
```

## MCP Tools Used

The agents use these MCP tools for database analysis:

- `list_schemas` - List all databases
- `list_tables` - List tables in a schema
- `describe_table` - Get table schema
- `sample_rows` - Get sample data from table
- `column_profile` - Get column statistics
- `run_sql_readonly` - Execute read-only queries
- `catalog_upsert` - Store findings in catalog
- `catalog_list` / `catalog_get` - Retrieve findings from catalog

### Target Scoping Requirement

Discovery and catalog/LLM tools are target-scoped. Always pass `target_id`:

- `discovery.run_static(target_id=..., schema_filter=...)`
- `catalog.*(target_id=..., run_id=...)`
- `agent.run_start(target_id=..., run_id=...)`
- `llm.*(target_id=..., run_id=...)`

`run_id` resolution is no longer global. The same schema name can exist on multiple targets, so `target_id` is required to resolve the correct discovery run.

## Benefits of Multi-Agent Approach

1. **Parallel Execution**: All 4 agents run simultaneously
2. **Specialized Expertise**: Each agent focuses on its domain
3. **Cross-Validation**: Agents validate each other's findings
4. **Comprehensive Coverage**: All aspects of database analyzed
5. **Knowledge Synthesis**: Final report combines all perspectives

## Output Format

The system produces:

1. **40+ Catalog Entries** - Detailed findings organized by agent
2. **Comprehensive Report** - Executive summary with:
   - Structure & Schema (ERD, table definitions)
   - Business Domain (entity model, business rules)
   - Key Insights (data quality, performance)
   - Data Quality Assessment (score, recommendations)

## Future Enhancements

- [ ] Additional specialized agents (Security, Performance, Compliance)
- [ ] Automated remediation scripts
- [ ] Continuous monitoring mode
- [ ] Integration with CI/CD pipelines
- [ ] Web-based dashboard for findings

## Related Files

- `simple_discovery.py` - Simplified demo of multi-agent pattern
- `mcp_catalog.db` - Catalog database for storing findings

## References

- Claude Code Task Tool Documentation
- MCP (Model Context Protocol) Specification
- ProxySQL MCP Server Implementation
