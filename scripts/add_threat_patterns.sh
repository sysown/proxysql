#!/bin/bash
#
# @file add_threat_patterns.sh
# @brief Add sample threat patterns to Anomaly Detection database
#
# This script populates the anomaly_patterns table with example
# SQL injection and attack patterns for testing the embedding
# similarity detection feature.
#
# Prerequisites:
# - ProxySQL running on localhost:6032 (admin)
# - GenAI module with llama-server running
#
# Usage:
#   ./add_threat_patterns.sh
#
# @date 2025-01-16

set -e

PROXYSQL_ADMIN_HOST=${PROXYSQL_ADMIN_HOST:-127.0.0.1}
PROXYSQL_ADMIN_PORT=${PROXYSQL_ADMIN_PORT:-6032}
PROXYSQL_ADMIN_USER=${PROXYSQL_ADMIN_USER:-admin}
PROXYSQL_ADMIN_PASS=${PROXYSQL_ADMIN_PASS:-admin}

echo "========================================"
echo "Anomaly Detection - Threat Patterns"
echo "========================================"
echo ""

# Note: We would add patterns via the C++ API (add_threat_pattern)
# For now, this script shows what patterns would be added
# In a real deployment, these would be added via MCP tool or admin command

echo "Sample Threat Patterns to Add:"
echo ""

echo "1. SQL Injection - OR 1=1"
echo "   Pattern: OR tautology attack"
echo "   Example: SELECT * FROM users WHERE username='admin' OR 1=1--'"
echo "   Type: sql_injection"
echo "   Severity: 9"
echo ""

echo "2. SQL Injection - UNION SELECT"
echo "   Pattern: UNION SELECT based data extraction"
echo "   Example: SELECT name FROM products WHERE id=1 UNION SELECT password FROM users"
echo "   Type: sql_injection"
echo "   Severity: 8"
echo ""

echo "3. SQL Injection - Comment Injection"
echo "   Pattern: Comment-based injection"
echo "   Example: SELECT * FROM users WHERE id=1-- AND password='xxx'"
echo "   Type: sql_injection"
echo "   Severity: 7"
echo ""

echo "4. DoS - Sleep-based timing attack"
echo "   Pattern: Sleep-based DoS"
echo "   Example: SELECT * FROM users WHERE id=1 AND sleep(10)"
echo "   Type: dos"
echo "   Severity: 6"
echo ""

echo "5. DoS - Benchmark-based attack"
echo "   Pattern: Benchmark-based DoS"
echo "   Example: SELECT * FROM users WHERE id=1 AND benchmark(10000000, MD5(1))"
echo "   Type: dos"
echo "   Severity: 6"
echo ""

echo "6. Data Exfiltration - INTO OUTFILE"
echo "   Pattern: File write exfiltration"
echo "   Example: SELECT * FROM users INTO OUTFILE '/tmp/users.txt'"
echo "   Type: data_exfiltration"
echo "   Severity: 9"
echo ""

echo "7. Privilege Escalation - DROP TABLE"
echo "   Pattern: Destructive SQL"
echo "   Example: SELECT * FROM users; DROP TABLE users--"
echo "   Type: privilege_escalation"
echo "   Severity: 10"
echo ""

echo "8. Reconnaissance - Schema probing"
echo "   Pattern: Information disclosure"
echo "   Example: SELECT * FROM information_schema.tables"
echo "   Type: reconnaissance"
echo "   Severity: 3"
echo ""

echo "9. Second-Order Injection - CONCAT"
echo "   Pattern: Concatenation-based injection"
echo "   Example: SELECT * FROM users WHERE username=CONCAT(0x61, 0x64, 0x6D, 0x69, 0x6E)"
echo "   Type: sql_injection"
echo "   Severity: 8"
echo ""

echo "10. NoSQL Injection - Hex encoding"
echo "   Pattern: Hex-encoded attack"
echo "   Example: SELECT * FROM users WHERE username=0x61646D696E"
echo "   Type: sql_injection"
echo "   Severity: 7"
echo ""

echo "========================================"
echo "Note: These patterns would be added via:"
echo "  1. MCP tool: ai_add_threat_pattern"
echo "  2. C++ API: Anomaly_Detector::add_threat_pattern()"
echo "  3. Admin command (future)"
echo "========================================"
echo ""

echo "To add patterns programmatically, use the Anomaly_Detector API:"
echo ""
echo "C++ example:"
echo '  detector->add_threat_pattern("OR 1=1 Tautology",'
echo '    "SELECT * FROM users WHERE username='"'"' admin' OR 1=1--'"'",'
echo '    "sql_injection", 9);'
echo ""

echo "Or via future MCP tool:"
echo '  {"jsonrpc": "2.0", "method": "tools/call", "params": {'
echo '    "name": "ai_add_threat_pattern",'
echo '    "arguments": {'
echo '      "pattern_name": "OR 1=1 Tautology",'
echo '      "query_example": "...",'
echo '      "pattern_type": "sql_injection",'
echo '      "severity": 9'
echo '    }'
echo '  }}'
echo ""
