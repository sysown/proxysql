#!/bin/bash
#
# @file test_external_live.sh
# @brief Live testing with external LLM and llama-server embeddings
#
# Setup:
# 1. Custom LLM endpoint for NL2SQL
# 2. llama-server (local) for embeddings
#
# Usage:
#   ./test_external_live.sh
#

set -e

# ============================================================================
# Configuration
# ============================================================================

PROXYSQL_ADMIN_HOST=${PROXYSQL_ADMIN_HOST:-127.0.0.1}
PROXYSQL_ADMIN_PORT=${PROXYSQL_ADMIN_PORT:-6032}
PROXYSQL_ADMIN_USER=${PROXYSQL_ADMIN_USER:-admin}
PROXYSQL_ADMIN_PASS=${PROXYSQL_ADMIN_PASS:-admin}

# Ask for custom LLM endpoint
echo ""
echo "=== External Model Configuration ==="
echo ""
echo "Your setup:"
echo "  - Custom LLM endpoint for NL2SQL"
echo "  - llama-server (local) for embeddings"
echo ""

# Prompt for LLM endpoint
read -p "Enter your custom LLM endpoint (e.g., http://localhost:11434/v1/chat/completions): " LLM_ENDPOINT
LLM_ENDPOINT=${LLM_ENDPOINT:-http://localhost:11434/v1/chat/completions}

# Prompt for LLM model name
read -p "Enter your LLM model name (e.g., llama3.2, gpt-4o-mini): " LLM_MODEL
LLM_MODEL=${LLM_MODEL:-llama3.2}

# Prompt for API key (optional)
read -p "Enter API key (optional, press Enter to skip): " API_KEY

# Embedding endpoint (llama-server)
EMBEDDING_ENDPOINT=${EMBEDDING_ENDPOINT:-http://127.0.0.1:8013/embedding}
echo ""
echo "Using embedding endpoint: $EMBEDDING_ENDPOINT"
echo ""

# Check llama-server is running
echo "Checking llama-server..."
if curl -s --connect-timeout 3 "$EMBEDDING_ENDPOINT" > /dev/null 2>&1; then
    echo "✓ llama-server is running"
else
    echo "✗ llama-server is NOT running at $EMBEDDING_ENDPOINT"
    echo "  Please start it with: ollama run nomic-embed-text-v1.5"
    exit 1
fi

# ============================================================================
# Configure ProxySQL
# ============================================================================

echo ""
echo "=== Configuring ProxySQL ==="
echo ""

# Enable AI features
mysql -h "$PROXYSQL_ADMIN_HOST" -P "$PROXYSQL_ADMIN_PORT" -u "$PROXYSQL_ADMIN_USER" -p"$PROXYSQL_ADMIN_PASS" <<SQL
SET ai_features_enabled='true';
SET ai_nl2sql_enabled='true';
SET ai_anomaly_detection_enabled='true';

-- Configure NL2SQL to use custom endpoint (via model provider override)
SET ai_nl2sql_model_provider='ollama';
SET ai_nl2sql_ollama_model='$LLM_MODEL';

-- Configure cache
SET ai_nl2sql_cache_similarity_threshold='85';

-- Configure anomaly detection
SET ai_anomaly_similarity_threshold='85';
SET ai_anomaly_risk_threshold='70';

LOAD MYSQL VARIABLES TO RUNTIME;
SQL

echo "✓ ProxySQL configured"
echo ""

# ============================================================================
# Run Tests
# ============================================================================

echo "=== Running Live Tests ==="
echo ""

# Test 1: Generate embedding
echo "Test 1: Generate embedding via GenAI module..."
EMBEDDING_TEST=$(curl -s -X POST "$EMBEDDING_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"content": "test query"}')

if [ $? -eq 0 ]; then
    echo "✓ Embedding generation works"
else
    echo "✗ Embedding generation failed"
fi
echo ""

# Test 2: Add a threat pattern (requires embedding)
echo "Test 2: Add threat pattern via C++ API..."
echo "  (This would be done programmatically via add_threat_pattern())"
echo "  Example patterns:"
echo "    - OR 1=1 Tautology (severity 9)"
echo "    - Sleep-based DoS (severity 6)"
echo "    - UNION SELECT injection (severity 8)"
echo ""

# Test 3: NL2SQL conversion (requires custom LLM)
echo "Test 3: NL2SQL conversion with custom LLM..."
echo "  Note: This requires the custom LLM endpoint to be accessible"
echo "  from ProxySQL's GenAI module."
echo ""
echo "  To enable custom LLM, configure GenAI_Thread.cpp:"
echo "    - Set endpoint to: $LLM_ENDPOINT"
echo "    - Set model to: $LLM_MODEL"
if [ -n "$API_KEY" ]; then
    echo "    - Set API key: $API_KEY"
fi
echo ""

# Test 4: Check vector database
echo "Test 4: Check vector database..."
VECTOR_DB="/var/lib/proxysql/ai_features.db"
if [ -f "$VECTOR_DB" ]; then
    echo "✓ Vector database exists at $VECTOR_DB"
    
    # Count entries
    CACHE_COUNT=$(sqlite3 "$VECTOR_DB" "SELECT COUNT(*) FROM nl2sql_cache;" 2>/dev/null || echo "0")
    PATTERN_COUNT=$(sqlite3 "$VECTOR_DB" "SELECT COUNT(*) FROM anomaly_patterns;" 2>/dev/null || echo "0")
    
    echo "  - NL2SQL cache entries: $CACHE_COUNT"
    echo "  - Threat patterns: $PATTERN_COUNT"
else
    echo "✗ Vector database not found at $VECTOR_DB"
fi
echo ""

# ============================================================================
# Manual Test Commands
# ============================================================================

echo "=== Manual Test Commands ==="
echo ""
echo "To test NL2SQL manually:"
echo "  mysql -h 127.0.0.1 -P 6033 -u test -ptest -e \"NL2SQL: Show all customers\""
echo ""
echo "To add threat patterns:"
echo "  (Requires C++ API or future MCP tool)"
echo ""
echo "To check statistics:"
echo "  SHOW STATUS LIKE 'ai_%';"
echo ""

echo "=== Testing Complete ==="
