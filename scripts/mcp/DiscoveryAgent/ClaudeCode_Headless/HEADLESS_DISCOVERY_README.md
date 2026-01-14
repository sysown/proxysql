# Headless Database Discovery with Claude Code

This directory contains scripts for running Claude Code in headless (non-interactive) mode to perform comprehensive database discovery via **ProxySQL Query MCP**.

## Overview

The headless discovery scripts allow you to:

- **Discover any database schema** accessible through ProxySQL Query MCP
- **Automated analysis** - Run without interactive session
- **Comprehensive reports** - Get detailed markdown reports covering structure, data quality, business domain, and performance
- **Scriptable** - Integrate into CI/CD pipelines, cron jobs, or automation workflows

## Files

| File | Description |
|------|-------------|
| `headless_db_discovery.sh` | Bash script for headless discovery |
| `headless_db_discovery.py` | Python script for headless discovery (recommended) |

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

# Discover specific database with schema
./headless_db_discovery.sh -d mydb -s public

# With custom timeout
./headless_db_discovery.sh -t 600
```

## Command-Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--database` | `-d` | Database name to discover | First available |
| `--schema` | `-s` | Schema name to analyze | All schemas |
| `--output` | `-o` | Output file path | `discovery_YYYYMMDD_HHMMSS.md` |
| `--timeout` | `-t` | Timeout in seconds | 300 |
| `--verbose` | `-v` | Enable verbose output | Disabled |
| `--help` | `-h` | Show help message | - |

## ProxySQL Query MCP Configuration

Configure the ProxySQL MCP connection via environment variables:

```bash
# Required: ProxySQL MCP endpoint URL
export PROXYSQL_MCP_ENDPOINT="https://127.0.0.1:6071/mcp/query"

# Optional: Auth token
export PROXYSQL_MCP_TOKEN="your_token"

# Optional: Skip SSL verification
export PROXYSQL_MCP_INSECURE_SSL="1"
```

Then run discovery:

```bash
python ./headless_db_discovery.py --database mydb
```

## What Gets Discovered

The discovery process analyzes four key areas:

### 1. Structural Analysis
- Complete table schemas (columns, types, constraints)
- Primary keys and unique constraints
- Foreign key relationships
- Indexes and their purposes
- Entity Relationship Diagram (ERD)

### 2. Data Profiling
- Row counts and cardinality
- Data distributions for key columns
- Null value percentages
- Statistical summaries (min/max/avg)
- Sample data inspection

### 3. Semantic Analysis
- Business domain identification (e.g., e-commerce, healthcare)
- Entity type classification (master vs transactional)
- Business rules and constraints
- Entity lifecycles and state machines

### 4. Performance Analysis
- Missing index identification
- Composite index opportunities
- N+1 query pattern risks
- Optimization recommendations

## Output Format

The generated report includes:

```markdown
# Database Discovery Report: [database_name]

## Executive Summary
[High-level overview of database purpose, size, and health]

## 1. Database Schema
[Complete table definitions with ERD]

## 2. Data Quality Assessment
Score: X/100
[Data quality issues with severity ratings]

## 3. Business Domain Analysis
[Industry, use cases, entity types]

## 4. Performance Recommendations
[Prioritized list of optimizations]

## 5. Anomalies & Issues
[All problems found with severity ratings]
```

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

Ensure you have configured the ProxySQL MCP environment variables:
- `PROXYSQL_MCP_ENDPOINT` (required)
- `PROXYSQL_MCP_TOKEN` (optional)
- `PROXYSQL_MCP_INSECURE_SSL` (optional)

### Discovery times out

Increase the timeout:

```bash
python ./headless_db_discovery.py --timeout 600
```

### Output is truncated

The prompt is designed for comprehensive output. If you're getting truncated results:
1. Increase timeout
2. Check if Claude Code has context limits
3. Consider breaking into smaller, focused discoveries

## Advanced Usage

### Custom Discovery Prompt

You can modify the prompt in the script to focus on specific aspects:

```python
# In headless_db_discovery.py, modify build_discovery_prompt()

def build_discovery_prompt(database: Optional[str], schema: Optional[str]) -> str:
    # Customize for your needs
    prompt = f"""Focus only on security aspects of {database}:
    1. Identify sensitive data columns
    2. Check for SQL injection vulnerabilities
    3. Review access controls
    """
    return prompt
```

### Multi-Database Discovery

```bash
#!/bin/bash
# discover_all.sh - Discover all databases

for db in db1 db2 db3; do
  python ./headless_db_discovery.py \
    --database "$db" \
    --output "reports/${db}_discovery.md" &
done

wait
echo "All discoveries complete!"
```

## Related Documentation

- [Multi-Agent Database Discovery System](../doc/multi_agent_database_discovery.md)
- [Claude Code Documentation](https://docs.anthropic.com/claude-code)
- [MCP Specification](https://modelcontextprotocol.io/)

## License

Same license as the proxysql-vec project.
