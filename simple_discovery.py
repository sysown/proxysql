#!/usr/bin/env python3
"""
Simple Database Discovery Demo

A minimal example to understand Claude Code subagents:
- 2 expert agents analyze a table in parallel
- Both write findings to a shared catalog
- Main agent synthesizes the results

This demonstrates the core pattern before building the full system.
"""

import json
from datetime import datetime

# Simple in-memory catalog for this demo
class SimpleCatalog:
    def __init__(self):
        self.entries = []

    def upsert(self, kind, key, document, tags=""):
        entry = {
            "kind": kind,
            "key": key,
            "document": document,
            "tags": tags,
            "timestamp": datetime.now().isoformat()
        }
        self.entries.append(entry)
        print(f"📝 Catalog: Wrote {kind}/{key}")

    def get_kind(self, kind):
        return [e for e in self.entries if e["kind"].startswith(kind)]

    def search(self, query):
        results = []
        for e in self.entries:
            if query.lower() in str(e).lower():
                results.append(e)
        return results

    def print_all(self):
        print("\n" + "="*60)
        print("CATALOG CONTENTS")
        print("="*60)
        for e in self.entries:
            print(f"\n[{e['kind']}] {e['key']}")
            print(f"  {json.dumps(e['document'], indent=2)[:200]}...")


# Expert prompts - what each agent is told to do
STRUCTURAL_EXPERT_PROMPT = """
You are the STRUCTURAL EXPERT.

Your job: Analyze the TABLE STRUCTURE.

For the table you're analyzing, determine:
1. What columns exist and their types
2. Primary key(s)
3. Foreign keys (relationships to other tables)
4. Indexes
5. Any constraints

Write your findings to the catalog using kind="structure"
"""

DATA_EXPERT_PROMPT = """
You are the DATA EXPERT.

Your job: Analyze the ACTUAL DATA in the table.

For the table you're analyzing, determine:
1. How many rows it has
2. Data distributions (for key columns)
3. Null value percentages
4. Interesting patterns or outliers
5. Data quality issues

Write your findings to the catalog using kind="data"
"""


def main():
    print("="*60)
    print("SIMPLE DATABASE DISCOVERY DEMO")
    print("="*60)
    print("\nThis demo shows how subagents work:")
    print("1. Two agents analyze a table in parallel")
    print("2. Both write findings to a shared catalog")
    print("3. Main agent synthesizes the results\n")

    # In real Claude Code, you'd use Task tool to launch agents
    # For this demo, we'll simulate what happens

    catalog = SimpleCatalog()

    print("⚡ STEP 1: Launching 2 subagents in parallel...\n")

    # Simulating what Claude Code does with Task tool
    print("   Agent 1 (Structural): Analyzing table structure...")
    # In real usage: await Task("Analyze structure", prompt=STRUCTURAL_EXPERT_PROMPT)
    catalog.upsert("structure", "mysql_users",
        {
            "table": "mysql_users",
            "columns": ["username", "hostname", "password", "select_priv"],
            "primary_key": ["username", "hostname"],
            "row_count_estimate": 5
        },
        tags="mysql,system"
    )

    print("\n   Agent 2 (Data): Profiling actual data...")
    # In real usage: await Task("Profile data", prompt=DATA_EXPERT_PROMPT)
    catalog.upsert("data", "mysql_users.distribution",
        {
            "table": "mysql_users",
            "actual_row_count": 5,
            "username_pattern": "All are system accounts (root, mysql.sys, etc.)",
            "null_percentages": {"password": 0},
            "insight": "This is a system table, not user data"
        },
        tags="mysql,data_profile"
    )

    print("\n⚡ STEP 2: Main agent reads catalog and synthesizes...\n")

    # Main agent reads findings
    structure = catalog.get_kind("structure")
    data = catalog.get_kind("data")

    print("📊 SYNTHESIZED FINDINGS:")
    print("-" * 60)
    print(f"Table: {structure[0]['document']['table']}")
    print(f"\nStructure:")
    print(f"  - Columns: {', '.join(structure[0]['document']['columns'])}")
    print(f"  - Primary Key: {structure[0]['document']['primary_key']}")
    print(f"\nData Insights:")
    print(f"  - {data[0]['document']['actual_row_count']} rows")
    print(f"  - {data[0]['document']['insight']}")
    print(f"\nBusiness Understanding:")
    print(f"  → This is MySQL's own user management table.")
    print(f"  → Contains {data[0]['document']['actual_row_count']} system accounts.")
    print(f"  → Not application user data - this is database admin accounts.")

    print("\n" + "="*60)
    print("DEMO COMPLETE")
    print("="*60)
    print("\nKey Takeaways:")
    print("✓ Two agents worked independently in parallel")
    print("✓ Both wrote to shared catalog")
    print("✓ Main agent combined their insights")
    print("✓ We got understanding greater than sum of parts")

    # Show full catalog
    catalog.print_all()

    print("\n" + "="*60)
    print("HOW THIS WOULD WORK IN CLAUDE CODE:")
    print("="*60)
    print("""
# You would say to Claude:
"Analyze the mysql_users table using two subagents"

# Claude would:
1. Launch Task tool twice (parallel):
   Task("Analyze structure", prompt=STRUCTURAL_EXPERT_PROMPT)
   Task("Profile data", prompt=DATA_EXPERT_PROMPT)

2. Wait for both to complete

3. Read catalog results

4. Synthesize and report to you

# Each subagent has access to:
- All MCP tools (list_tables, sample_rows, column_profile, etc.)
- Catalog operations (catalog_upsert, catalog_get)
- Its own reasoning context
""")


if __name__ == "__main__":
    main()
