# Headless Database Discovery with Claude Code

Multi-agent database discovery system for comprehensive analysis through MCP (Model Context Protocol).

## Overview

This directory contains scripts for running **6-agent collaborative database discovery** in headless (non-interactive) mode using Claude Code.

**Key Features:**
- **6 Agents (5 Analysis + 1 Meta):** STRUCTURAL, STATISTICAL, SEMANTIC, QUERY, SECURITY, META
- **5-Round Protocol:** Blind exploration → Pattern recognition → Hypothesis testing → Final synthesis → Meta analysis
- **MCP Catalog Collaboration:** Agents share findings via catalog
- **Comprehensive Reports:** Structured markdown with health scores and prioritized recommendations
- **Evidence-Based:** 20+ hypothesis validations with direct database evidence
- **Self-Improving:** META agent analyzes report quality and suggests prompt improvements

## Quick Start

### Using the Python Script (Recommended)

```bash
# Basic discovery - discovers the first available database
python ./headless_db_discovery.py

# Discover a specific database
python ./headless_db_discovery.py --database mydb

# Specify output file
python ./headless_db_discovery.py --output my_report.md

# With verbose output
python ./headless_db_discovery.py --verbose
```

### Using the Bash Script

```bash
# Basic discovery
./headless_db_discovery.sh

# Discover specific database
./headless_db_discovery.sh -d mydb

# With custom timeout
./headless_db_discovery.sh -t 600
```

## Multi-Agent Discovery Architecture

### The 6 Agents

| Agent | Type | Focus | Key MCP Tools |
|-------|------|-------|---------------|
| **STRUCTURAL** | Analysis | Schemas, tables, relationships, indexes, constraints | `list_schemas`, `list_tables`, `describe_table`, `get_constraints`, `suggest_joins` |
| **STATISTICAL** | Analysis | Data distributions, quality, anomalies | `table_profile`, `sample_rows`, `column_profile`, `sample_distinct`, `run_sql_readonly` |
| **SEMANTIC** | Analysis | Business domain, entities, rules, terminology | `sample_rows`, `sample_distinct`, `run_sql_readonly` |
| **QUERY** | Analysis | Index efficiency, query patterns, optimization | `describe_table`, `explain_sql`, `suggest_joins`, `run_sql_readonly` |
| **SECURITY** | Analysis | Sensitive data, access patterns, vulnerabilities | `sample_rows`, `sample_distinct`, `column_profile`, `run_sql_readonly` |
| **META** | Meta | Report quality analysis, prompt improvement suggestions | `catalog_search`, `catalog_get` (reads findings) |

### 5-Round Protocol

1. **Round 1: Blind Exploration** (Parallel)
   - All 5 analysis agents explore independently
   - Each discovers patterns without seeing others' findings
   - Findings written to MCP catalog

2. **Round 2: Pattern Recognition** (Collaborative)
   - All 5 analysis agents read each other's findings via `catalog_search`
   - Identify cross-cutting patterns and anomalies
   - Collaborative analysis documented

3. **Round 3: Hypothesis Testing** (Validation)
   - Each analysis agent validates 3-4 specific hypotheses
   - Results documented with PASS/FAIL/MIXED and evidence
   - 20+ hypothesis validations total

4. **Round 4: Final Synthesis**
   - All 5 analysis agents synthesize findings into comprehensive report
   - Written to MCP catalog and local file

5. **Round 5: Meta Analysis** (META agent only)
   - META agent reads the complete final report
   - Analyzes each section for depth, completeness, quality
   - Identifies gaps and suggests prompt improvements
   - Writes separate meta-analysis document to MCP catalog

## What Gets Discovered

### 1. Structural Analysis
- Complete table schemas (columns, types, constraints)
- Primary keys, foreign keys, unique constraints
- Indexes and their purposes
- Entity Relationship Diagram (ERD)
- Design patterns and anti-patterns

### 2. Statistical Analysis
- Row counts and cardinality
- Data distributions for key columns
- Null value percentages
- Distinct value counts and selectivity
- Statistical summaries (min/max/avg)
- Anomaly detection (duplicates, outliers, skew)

### 3. Semantic Analysis
- Business domain identification (e.g., e-commerce, healthcare)
- Entity type classification (master vs transactional)
- Business rules and constraints
- Entity lifecycles and state machines
- Domain terminology glossary

### 4. Query Analysis
- Index coverage and efficiency
- Missing index identification
- Composite index opportunities
- Join performance analysis
- Query pattern identification
- Optimization recommendations with expected improvements

### 5. Security Analysis
- **Sensitive Data Identification:**
  - PII: names, emails, phone numbers, SSN, addresses
  - Credentials: passwords, API keys, tokens
  - Financial data: credit cards, bank accounts
  - Health data: medical records
- **Access Pattern Analysis:**
  - Overly permissive schemas
  - Missing row-level security
- **Vulnerability Assessment:**
  - SQL injection vectors
  - Weak authentication patterns
  - Missing encryption indicators
- **Compliance Assessment:**
  - GDPR indicators (personal data)
  - PCI-DSS indicators (payment data)
  - Data retention patterns
- **Data Classification:**
  - PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED

### 6. Meta Analysis
- Report quality assessment by section (depth, completeness)
- Gap identification (what was missed)
- Prompt improvement suggestions for future runs
- Evolution history tracking

### 7. Question Catalogs ✨
- **90+ Answerable Questions** across all agents (minimum 15-20 per agent)
- **Executable Answer Plans** for each question using MCP tools
- **Question Templates** with structured answer formats
- **Cross-Domain Questions** requiring multiple agents
- **Complexity Ratings** (LOW/MEDIUM/HIGH) with time estimates

Each agent generates a catalog of questions they can answer about the database, with step-by-step plans for how to answer each question using MCP tools. This creates a reusable knowledge base for future LLM interactions.

## Output Format

The generated report includes:

```markdown
# COMPREHENSIVE DATABASE DISCOVERY REPORT

## Executive Summary
- Database identity (system type, purpose, scale)
- Critical findings (top 5 - one from each agent)
- Health score: current X/10 → potential Y/10
- Top 5 recommendations (prioritized)

## 1. STRUCTURAL ANALYSIS
- Schema inventory
- Relationship diagram
- Design patterns
- Issues & recommendations

## 2. STATISTICAL ANALYSIS
- Table profiles
- Data quality score
- Distribution profiles
- Anomalies detected

## 3. SEMANTIC ANALYSIS
- Business domain identification
- Entity catalog
- Business rules inference
- Domain glossary

## 4. QUERY ANALYSIS
- Index coverage assessment
- Query pattern analysis
- Optimization opportunities
- Expected improvements

## 5. SECURITY ANALYSIS
- Sensitive data identification
- Access pattern analysis
- Vulnerability assessment
- Compliance indicators
- Security recommendations

## 6. CRITICAL FINDINGS
- Each with: description, impact quantification, root cause, remediation

## 7. RECOMMENDATIONS ROADMAP
- URGENT: [actions with impact/effort]
- HIGH: [actions]
- MODERATE: [actions]
- Expected timeline with metrics

## Appendices
- A. Table DDL
- B. Query examples with EXPLAIN
- C. Statistical distributions
- D. Business glossary
- E. Security data classification
```

Additionally, a separate **META ANALYSIS** document is generated with:
- Section quality ratings (depth, completeness)
- Specific prompt improvement suggestions
- Gap identification
- Evolution history

## Question Catalogs

In addition to the analysis reports, each agent generates a **Question Catalog** - a knowledge base of questions the agent can answer about the database, with executable plans for how to answer each question.

### What Are Question Catalogs?

A Question Catalog contains:
- **90+ questions** across all agents (minimum 15-20 per agent)
- **Executable answer plans** using specific MCP tools
- **Answer templates** with structured output formats
- **Complexity ratings** (LOW/MEDIUM/HIGH)
- **Time estimates** for answering each question

### Question Catalog Structure

```markdown
# {AGENT} QUESTION CATALOG

## Metadata
- Agent: {STRUCTURAL|STATISTICAL|SEMANTIC|QUERY|SECURITY}
- Database: {database_name}
- Questions Generated: {count}

## Questions by Category

### Category 1: {Category Name}

#### Q1. {Question Template}
**Question Type:** factual|analytical|comparative|predictive|recommendation

**Example Questions:**
- "What tables exist in the database?"
- "What columns does table X have?"

**Answer Plan:**
1. Step 1: Use `list_tables` to get all tables
2. Step 2: Use `describe_table` to get column details
3. Output: Structured list with table names and column details

**Answer Template:**
Based on the schema analysis:
- Table 1: {columns}
- Table 2: {columns}
```

### Question Catalog Examples

#### STRUCTURAL Agent Questions
- "What tables exist in the database?"
- "How are tables X and Y related?"
- "What indexes exist on table X?"
- "What constraints are defined on table X?"

#### STATISTICAL Agent Questions
- "How many rows does table X have?"
- "What is the distribution of values in column X?"
- "Are there any outliers in column X?"
- "What percentage of values are null in column X?"

#### SEMANTIC Agent Questions
- "What type of system is this database for?"
- "What does table X represent?"
- "What business rules are enforced?"
- "What does term X mean in this domain?"

#### QUERY Agent Questions
- "Why is query X slow?"
- "What indexes would improve query X?"
- "How can I optimize query X?"
- "What is the most efficient join path?"

#### SECURITY Agent Questions
- "What sensitive data exists in table X?"
- "Where is PII stored?"
- "What security vulnerabilities exist?"
- "Does this database comply with GDPR?"

#### Cross-Domain Questions (META Agent)
- "What are the security implications of query performance issues?"
- "How does data quality affect business intelligence?"
- "What is the cost-benefit of proposed optimizations?"

### Using Question Catalogs

Question catalogs enable:
1. **Fast Answers:** Pre-validated plans skip analysis phase
2. **Consistent Quality:** All answers follow proven templates
3. **Tool Reuse:** Efficient MCP tool usage patterns
4. **Comprehensive Coverage:** 90+ questions cover most user needs

Example workflow:
```bash
# User asks: "What sensitive data exists in the customers table?"

# System retrieves from SECURITY question catalog:
# - Question template: "What sensitive data exists in table X?"
# - Answer plan: sample_rows + column_profile on customers
# - Answer template: Structured list with sensitivity classification

# System executes plan and returns formatted answer
```

### Minimum Questions Per Agent

| Agent | Minimum Questions | High-Complexity Target |
|-------|-------------------|----------------------|
| STRUCTURAL | 20 | 5 |
| STATISTICAL | 20 | 5 |
| SEMANTIC | 15 | 3 |
| QUERY | 20 | 5 |
| SECURITY | 15 | 5 |
| **TOTAL** | **90+** | **23+** |

### Stored In Catalog

All question catalogs are stored in the MCP catalog for easy retrieval:
- `kind="question_catalog"`, `key="structural_questions"`
- `kind="question_catalog"`, `key="statistical_questions"`
- `kind="question_catalog"`, `key="semantic_questions"`
- `kind="question_catalog"`, `key="query_questions"`
- `kind="question_catalog"`, `key="security_questions"`
- `kind="question_catalog"`, `key="cross_domain_questions"`

## Command-Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--database` | `-d` | Database name to discover | First available |
| `--schema` | `-s` | Schema name to analyze | All schemas |
| `--output` | `-o` | Output file path | `discovery_YYYYMMDD_HHMMSS.md` |
| `--timeout` | `-t` | Timeout in seconds | 300 |
| `--verbose` | `-v` | Enable verbose output | Disabled |
| `--help` | `-h` | Show help message | - |

## System Prompts

The discovery uses the system prompt in `prompts/multi_agent_discovery_prompt.md`:

- **`prompts/multi_agent_discovery_prompt.md`** - Concise system prompt for actual use
- **`prompts/multi_agent_discovery_reference.md`** - Comprehensive reference documentation

## Examples

### CI/CD Integration

```yaml
# .github/workflows/database-discovery.yml
name: Database Discovery

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
  workflow_dispatch:

jobs:
  discovery:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Claude Code
        run: npm install -g @anthropics/claude-code
      - name: Run Discovery
        env:
          PROXYSQL_MCP_ENDPOINT: ${{ secrets.PROXYSQL_MCP_ENDPOINT }}
          PROXYSQL_MCP_TOKEN: ${{ secrets.PROXYSQL_MCP_TOKEN }}
        run: |
          cd scripts/mcp/DiscoveryAgent/ClaudeCode_Headless
          python ./headless_db_discovery.py \
            --database production \
            --output discovery_$(date +%Y%m%d).md
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: discovery-report
          path: discovery_*.md
```

### Monitoring Automation

```bash
#!/bin/bash
# weekly_discovery.sh - Run weekly and compare results

REPORT_DIR="/var/db-discovery/reports"
mkdir -p "$REPORT_DIR"

# Run discovery
python ./headless_db_discovery.py \
  --database mydb \
  --output "$REPORT_DIR/discovery_$(date +%Y%m%d).md"

# Compare with previous week
PREV=$(ls -t "$REPORT_DIR"/discovery_*.md | head -2 | tail -1)
if [ -f "$PREV" ]; then
  echo "=== Changes since last discovery ==="
  diff "$PREV" "$REPORT_DIR/discovery_$(date +%Y%m%d).md" || true
fi
```

### Custom Discovery Focus

```python
# Modify the prompt in the script for focused discovery
def build_discovery_prompt(database: Optional[str]) -> str:
    prompt = f"""Using the 4-agent discovery protocol, focus on:
    1. Security aspects of {database}
    2. Performance optimization opportunities
    3. Data quality issues

    Follow the standard 4-round protocol but prioritize these areas.
    """
    return prompt
```

## Troubleshooting

### "Claude Code executable not found"

Set the `CLAUDE_PATH` environment variable:

```bash
export CLAUDE_PATH="/path/to/claude"
python ./headless_db_discovery.py
```

Or install Claude Code:

```bash
npm install -g @anthropics/claude-code
```

### "No MCP servers available"

Ensure MCP servers are configured in your Claude Code settings or provide MCP configuration via command line.

### Discovery times out

Increase the timeout:

```bash
python ./headless_db_discovery.py --timeout 600
```

### Output is truncated

The multi-agent prompt is designed for comprehensive output. If truncated:
1. Increase timeout
2. Check MCP server connection stability
3. Review MCP catalog for partial results

## Directory Structure

```
ClaudeCode_Headless/
├── README.md                           # This file
├── prompts/
│   ├── multi_agent_discovery_prompt.md      # Concise system prompt
│   └── multi_agent_discovery_reference.md   # Comprehensive reference
├── headless_db_discovery.py            # Python script
├── headless_db_discovery.sh            # Bash script
└── examples/
    ├── DATABASE_DISCOVERY_REPORT.md        # Example output
    └── DATABASE_QUESTION_CAPABILITIES.md   # Feature documentation
```

## Related Documentation

- [Multi-Agent Database Discovery System](../../doc/multi_agent_database_discovery.md)
- [Claude Code Documentation](https://docs.anthropic.com/claude-code)
- [MCP Specification](https://modelcontextprotocol.io/)

## License

Same license as the proxysql-vec project.
