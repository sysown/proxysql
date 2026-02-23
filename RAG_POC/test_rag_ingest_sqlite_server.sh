#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/.." && pwd)"

MYSQL_BIN="${MYSQL_BIN:-mysql}"

# SQLite Server (MySQL protocol gateway) connection parameters
SQLITE_SERVER_HOST="${SQLITE_SERVER_HOST:-127.0.0.1}"
SQLITE_SERVER_PORT="${SQLITE_SERVER_PORT:-6030}"
SQLITE_SERVER_USER="${SQLITE_SERVER_USER:-root}"
SQLITE_SERVER_PASS="${SQLITE_SERVER_PASS:-root}"
SQLITE_SERVER_DB="${SQLITE_SERVER_DB:-rag_db}"

# MySQL backend connection parameters (for sample data)
MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASS="${MYSQL_PASS:-root}"

# rag_ingest binary
RAG_INGEST="${RAG_INGEST:-${ROOT_DIR}/rag_ingest}"

# Embedding provider configuration (for phase 4/5)
EMBEDDING_PROVIDER="${EMBEDDING_PROVIDER:-stub}"
EMBEDDING_DIM="${EMBEDDING_DIM:-1536}"
OPENAI_API_BASE="${OPENAI_API_BASE:-https://api.synthetic.new/openai/v1}"
OPENAI_API_KEY="${OPENAI_API_KEY:-}"
OPENAI_MODEL="${OPENAI_MODEL:-hf:nomic-ai/nomic-embed-text-v1.5}"
OPENAI_EMBEDDING_DIM="${OPENAI_EMBEDDING_DIM:-}"

if [[ -z "${OPENAI_EMBEDDING_DIM}" ]]; then
  if [[ "${OPENAI_MODEL}" == "hf:nomic-ai/nomic-embed-text-v1.5" ]]; then
    OPENAI_EMBEDDING_DIM=768
  else
    OPENAI_EMBEDDING_DIM="${EMBEDDING_DIM}"
  fi
fi

# Uncomment to test OpenAI-compatible embeddings
# export EMBEDDING_PROVIDER=openai
# export EMBEDDING_DIM=1536
# export OPENAI_API_BASE="https://api.synthetic.new/openai/v1"
# export OPENAI_API_KEY="your_api_key_here"
# export OPENAI_MODEL="hf:nomic-ai/nomic-embed-text-v1.5"

# Helper: Run SQL via SQLite Server (MySQL protocol)
run_sqlite_server() {
  local sql="$1"
  "${MYSQL_BIN}" \
    -h"${SQLITE_SERVER_HOST}" -P"${SQLITE_SERVER_PORT}" \
    -u"${SQLITE_SERVER_USER}" -p"${SQLITE_SERVER_PASS}" \
    -D"${SQLITE_SERVER_DB}" \
    -e "${sql}"
}

# Helper: Get single value from SQLite Server
run_sqlite_server_value() {
  local sql="$1"
  local db="${2:-${SQLITE_SERVER_DB}}"
  "${MYSQL_BIN}" \
    -h"${SQLITE_SERVER_HOST}" -P"${SQLITE_SERVER_PORT}" \
    -u"${SQLITE_SERVER_USER}" -p"${SQLITE_SERVER_PASS}" \
    -D"${db}" \
    -N -s -e "${sql}"
}

# Helper: Run SQL via SQLite Server with custom database
run_sqlite_server_with_db() {
  local db="$1"
  local sql="$2"
  "${MYSQL_BIN}" \
    -h"${SQLITE_SERVER_HOST}" -P"${SQLITE_SERVER_PORT}" \
    -u"${SQLITE_SERVER_USER}" -p"${SQLITE_SERVER_PASS}" \
    -D"${db}" \
    -e "${sql}"
}

# Helper: Initialize schema and insert source configuration
apply_schema_and_source() {
  local where_sql="$1"
  local load_schema="$2"
  local chunking_json_override="${3:-}"
  local embedding_json_override="${4:-}"

  echo "==> SQLite Server: ${SQLITE_SERVER_HOST}:${SQLITE_SERVER_PORT}/${SQLITE_SERVER_DB}"
  echo "==> load_schema: ${load_schema}"
  echo "==> where_sql: ${where_sql:-<empty>}"

  local chunking_json_value='{"enabled":false,"unit":"chars","chunk_size":4000,"overlap":400,"min_chunk_size":800}'
  if [[ -n "${chunking_json_override}" ]]; then
    chunking_json_value="${chunking_json_override}"
  fi
  echo "==> chunking_json: ${chunking_json_value}"

  local embedding_json_value='{"enabled":false}'
  if [[ -n "${embedding_json_override}" ]]; then
    embedding_json_value="${embedding_json_override}"
  fi
  echo "==> embedding_json: ${embedding_json_value}"

  if [[ "${load_schema}" == "true" ]]; then
    # Initialize schema using rag_ingest init
    "${RAG_INGEST}" init \
      -h "${SQLITE_SERVER_HOST}" -P "${SQLITE_SERVER_PORT}" \
      -u "${SQLITE_SERVER_USER}" -p "${SQLITE_SERVER_PASS}" \
      -D "${SQLITE_SERVER_DB}"

    # Insert rag_sources configuration
    run_sqlite_server "
      INSERT INTO rag_sources (
        name, enabled, backend_type, backend_host, backend_port, backend_user, backend_pass, backend_db,
        table_name, pk_column, where_sql, doc_map_json, chunking_json, embedding_json
      ) VALUES (
        'test_posts', 1,
        'mysql', '${MYSQL_HOST}', ${MYSQL_PORT}, '${MYSQL_USER}', '${MYSQL_PASS}', 'rag_test',
        'posts', 'Id', '${where_sql}',
        '{\"doc_id\":{\"format\":\"posts:{Id}\"},\"title\":{\"concat\":[{\"col\":\"Title\"}]},\"body\":{\"concat\":[{\"col\":\"Body\"}]},\"metadata\":{\"pick\":[\"Tags\",\"Score\"],\"rename\":{\"Tags\":\"tags\",\"Score\":\"score\"}}}',
        '${chunking_json_value}',
        '${embedding_json_value}'
      );
    "
  else
    # Update existing source
    run_sqlite_server "
      UPDATE rag_sources
      SET chunking_json='${chunking_json_value}',
          embedding_json='${embedding_json_value}',
          where_sql='${where_sql}',
          backend_host='${MYSQL_HOST}',
          backend_port=${MYSQL_PORT},
          backend_user='${MYSQL_USER}',
          backend_pass='${MYSQL_PASS}'
      WHERE source_id=1;
    "
  fi
}

# Helper: Import sample data to MySQL backend
import_mysql_seed() {
  "${MYSQL_BIN}" \
    -h"${MYSQL_HOST}" -P"${MYSQL_PORT}" \
    -u"${MYSQL_USER}" -p"${MYSQL_PASS}" \
    < "${ROOT_DIR}/sample_mysql.sql"
}

# Helper: Run SQL on MySQL backend
run_mysql_sql() {
  local sql="$1"
  "${MYSQL_BIN}" \
    -h"${MYSQL_HOST}" -P"${MYSQL_PORT}" \
    -u"${MYSQL_USER}" -p"${MYSQL_PASS}" \
    -e "${sql}"
}

# Helper: Assert equality
assert_eq() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  if [[ "${expected}" != "${actual}" ]]; then
    echo "FAIL: ${label} expected ${expected}, got ${actual}" >&2
    exit 1
  fi
  echo "OK: ${label} = ${actual}"
}

# Helper: FTS count via SQLite Server
fts_count() {
  local q="$1"
  run_sqlite_server_value "SELECT COUNT(*) FROM rag_fts_chunks WHERE rag_fts_chunks MATCH '${q}';"
}

# Helper: FTS BM25 top result via SQLite Server
fts_bm25_top() {
  local q="$1"
  run_sqlite_server_value "SELECT chunk_id FROM rag_fts_chunks WHERE rag_fts_chunks MATCH '${q}' ORDER BY bm25(rag_fts_chunks) LIMIT 1;"
}

# Helper: Vector self-match via SQLite Server
vec_self_match() {
  local chunk_id="$1"
  run_sqlite_server_value "SELECT chunk_id FROM rag_vec_chunks WHERE embedding MATCH (SELECT embedding FROM rag_vec_chunks WHERE chunk_id='${chunk_id}') ORDER BY distance LIMIT 1;"
}

# Helper: Print sample data from SQLite Server
print_samples() {
  echo "==> Sample rag_documents"
  run_sqlite_server "
    SELECT doc_id, source_id, substr(title,1,40) AS title, json_extract(metadata_json,'$.Score') AS score
    FROM rag_documents ORDER BY doc_id LIMIT 5;
  "
  echo "==> Sample rag_chunks"
  run_sqlite_server "
    SELECT chunk_id, doc_id, chunk_index, substr(body,1,50) AS body
    FROM rag_chunks ORDER BY chunk_id LIMIT 5;
  "
  echo "==> Sample rag_fts_chunks matches for 'ProxySQL'"
  run_sqlite_server "
    SELECT chunk_id, substr(title,1,40) AS title
    FROM rag_fts_chunks WHERE rag_fts_chunks MATCH 'ProxySQL' ORDER BY chunk_id LIMIT 5;
  "
}

# Helper: Cleanup - drop and recreate database
cleanup_db() {
  # Drop all tables and recreate schema
  run_sqlite_server "
    DROP TABLE IF EXISTS rag_sync_state;
    DROP TABLE IF EXISTS rag_fts_chunks;
    DROP TABLE IF EXISTS rag_vec_chunks;
    DROP VIEW IF EXISTS rag_chunk_view;
    DROP TABLE IF EXISTS rag_chunks;
    DROP TABLE IF EXISTS rag_documents;
    DROP TABLE IF EXISTS rag_sources;
  " 2>/dev/null || true
}

# Cleanup before starting
cleanup_db

# ===========================================================================
# Phase 1: load schema + source, chunking disabled, no where filter
# ===========================================================================
echo "=========================================="
echo "Phase 1: Initial ingestion (no chunking)"
echo "=========================================="
apply_schema_and_source "" "true"

# Seed MySQL backend
import_mysql_seed

# Run rag_ingest
"${RAG_INGEST}" ingest \
  -h "${SQLITE_SERVER_HOST}" -P "${SQLITE_SERVER_PORT}" \
  -u "${SQLITE_SERVER_USER}" -p "${SQLITE_SERVER_PASS}" \
  -D "${SQLITE_SERVER_DB}"

# Validate counts (sample_mysql has 10 rows)
DOCS_COUNT="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_documents;")"
CHUNKS_COUNT="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_chunks;")"
FTS_COUNT="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_fts_chunks;")"
VEC_COUNT="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_vec_chunks;")"

assert_eq "rag_documents" "10" "${DOCS_COUNT}"
assert_eq "rag_chunks (chunking disabled)" "10" "${CHUNKS_COUNT}"
assert_eq "rag_fts_chunks" "10" "${FTS_COUNT}"
assert_eq "rag_vec_chunks (embedding disabled)" "0" "${VEC_COUNT}"

print_samples

# FTS tests (phase 1)
FTS_PHRASE_1="$(fts_count '"ProxySQL adds MCP"')"
FTS_SHORT_1="$(fts_count 'Short')"
FTS_TAG_1="$(fts_count 'Tag')"
FTS_BM25_1="$(fts_bm25_top 'ProxySQL')"

assert_eq "fts phrase (ProxySQL adds MCP)" "1" "${FTS_PHRASE_1}"
assert_eq "fts term (Short)" "1" "${FTS_SHORT_1}"
assert_eq "fts term (Tag)" "1" "${FTS_TAG_1}"
assert_eq "fts bm25 top (ProxySQL)" "posts:3#0" "${FTS_BM25_1}"

# ===========================================================================
# Phase 1a: update skip behavior (existing docs are not updated)
# ===========================================================================
echo "=========================================="
echo "Phase 1a: Verify existing docs are not updated"
echo "=========================================="
run_mysql_sql "USE rag_test; UPDATE posts SET Title='Hello RAG UPDATED' WHERE Id=1;"
"${RAG_INGEST}" ingest \
  -h "${SQLITE_SERVER_HOST}" -P "${SQLITE_SERVER_PORT}" \
  -u "${SQLITE_SERVER_USER}" -p "${SQLITE_SERVER_PASS}" \
  -D "${SQLITE_SERVER_DB}"
TITLE_AFTER_UPDATE="$(run_sqlite_server_value "SELECT title FROM rag_documents WHERE doc_id='posts:1';")"
assert_eq "rag_documents title unchanged on update" "Hello RAG" "${TITLE_AFTER_UPDATE}"

# Reset MySQL data after update test
import_mysql_seed

# ===========================================================================
# Phase 1b: rag_sync_state watermark (incremental ingestion)
# ===========================================================================
echo "=========================================="
echo "Phase 1b: Watermark-based incremental sync"
echo "=========================================="
SYNC_COL_1="$(run_sqlite_server_value "SELECT json_extract(cursor_json,'$.column') FROM rag_sync_state WHERE source_id=1;")"
SYNC_VAL_1="$(run_sqlite_server_value "SELECT json_extract(cursor_json,'$.value') FROM rag_sync_state WHERE source_id=1;")"

assert_eq "rag_sync_state column" "Id" "${SYNC_COL_1}"
assert_eq "rag_sync_state value (initial)" "10" "${SYNC_VAL_1}"

# Delete one doc to verify watermark prevents backfill
run_sqlite_server "DELETE FROM rag_vec_chunks WHERE chunk_id LIKE 'posts:5#%';"
run_sqlite_server "DELETE FROM rag_fts_chunks WHERE chunk_id LIKE 'posts:5#%';"
run_sqlite_server "DELETE FROM rag_chunks WHERE doc_id='posts:5';"
run_sqlite_server "DELETE FROM rag_documents WHERE doc_id='posts:5';"

DOCS_AFTER_DELETE="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_documents;")"
assert_eq "rag_documents after delete" "9" "${DOCS_AFTER_DELETE}"

"${RAG_INGEST}" ingest \
  -h "${SQLITE_SERVER_HOST}" -P "${SQLITE_SERVER_PORT}" \
  -u "${SQLITE_SERVER_USER}" -p "${SQLITE_SERVER_PASS}" \
  -D "${SQLITE_SERVER_DB}"

DOCS_AFTER_REINGEST="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_documents;")"
CHUNKS_AFTER_REINGEST="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_chunks;")"
FTS_AFTER_REINGEST="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_fts_chunks;")"

assert_eq "rag_documents after watermark reingest" "9" "${DOCS_AFTER_REINGEST}"
assert_eq "rag_chunks after watermark reingest" "9" "${CHUNKS_AFTER_REINGEST}"
assert_eq "rag_fts_chunks after watermark reingest" "9" "${FTS_AFTER_REINGEST}"

# Insert a new source row and ensure only it is ingested
run_mysql_sql "USE rag_test; INSERT INTO posts (Id, Title, Body, Tags, Score, CreationDate, UpdatedAt) VALUES (11, 'Watermark New', 'This row should be ingested via watermark.', 'wm,test', 1, '2024-01-14 10:00:00', '2024-01-14 11:00:00');"

"${RAG_INGEST}" ingest \
  -h "${SQLITE_SERVER_HOST}" -P "${SQLITE_SERVER_PORT}" \
  -u "${SQLITE_SERVER_USER}" -p "${SQLITE_SERVER_PASS}" \
  -D "${SQLITE_SERVER_DB}"

DOCS_AFTER_NEW="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_documents;")"
SYNC_VAL_2="$(run_sqlite_server_value "SELECT json_extract(cursor_json,'$.value') FROM rag_sync_state WHERE source_id=1;")"

assert_eq "rag_documents after new row" "10" "${DOCS_AFTER_NEW}"
assert_eq "rag_sync_state value (after new row)" "11" "${SYNC_VAL_2}"

# Reset sync state for subsequent phases
run_sqlite_server "DELETE FROM rag_sync_state;"

# Reset MySQL data after watermark insert
import_mysql_seed

# ===========================================================================
# Phase 1c: UpdatedAt-based watermark filtering
# ===========================================================================
echo "=========================================="
echo "Phase 1c: UpdatedAt-based watermark filtering"
echo "=========================================="
run_sqlite_server "DELETE FROM rag_vec_chunks;"
run_sqlite_server "DELETE FROM rag_fts_chunks;"
run_sqlite_server "DELETE FROM rag_chunks;"
run_sqlite_server "DELETE FROM rag_documents;"
run_sqlite_server "INSERT OR REPLACE INTO rag_sync_state(source_id, mode, cursor_json, last_ok_at, last_error) VALUES (1, 'poll', '{\"column\":\"UpdatedAt\",\"value\":\"2024-01-10 10:00:00\"}', NULL, NULL);"

"${RAG_INGEST}" ingest \
  -h "${SQLITE_SERVER_HOST}" -P "${SQLITE_SERVER_PORT}" \
  -u "${SQLITE_SERVER_USER}" -p "${SQLITE_SERVER_PASS}" \
  -D "${SQLITE_SERVER_DB}"

DOCS_UPDATED_AT="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_documents;")"
SYNC_UPDATED_AT="$(run_sqlite_server_value "SELECT json_extract(cursor_json,'$.value') FROM rag_sync_state WHERE source_id=1;")"

assert_eq "rag_documents (UpdatedAt watermark)" "1" "${DOCS_UPDATED_AT}"
assert_eq "rag_sync_state value (UpdatedAt)" "2024-01-12 09:30:00" "${SYNC_UPDATED_AT}"

# Reset sync state for subsequent phases
run_sqlite_server "DELETE FROM rag_sync_state;"

# ===========================================================================
# Phase 2: apply where filter, re-ingest after cleanup
# ===========================================================================
echo "=========================================="
echo "Phase 2: WHERE filter (Score >= 7)"
echo "=========================================="
run_sqlite_server "DELETE FROM rag_vec_chunks;"
run_sqlite_server "DELETE FROM rag_fts_chunks;"
run_sqlite_server "DELETE FROM rag_chunks;"
run_sqlite_server "DELETE FROM rag_documents;"

apply_schema_and_source "Score >= 7" "false"
"${RAG_INGEST}" ingest \
  -h "${SQLITE_SERVER_HOST}" -P "${SQLITE_SERVER_PORT}" \
  -u "${SQLITE_SERVER_USER}" -p "${SQLITE_SERVER_PASS}" \
  -D "${SQLITE_SERVER_DB}"

DOCS_COUNT_2="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_documents;")"
CHUNKS_COUNT_2="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_chunks;")"
FTS_COUNT_2="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_fts_chunks;")"
VEC_COUNT_2="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_vec_chunks;")"

# In sample_mysql: Score >= 7 matches Id 1,3,5,7,9 => 5 docs
assert_eq "rag_documents (where_sql)" "5" "${DOCS_COUNT_2}"
assert_eq "rag_chunks (where_sql)" "5" "${CHUNKS_COUNT_2}"
assert_eq "rag_fts_chunks (where_sql)" "5" "${FTS_COUNT_2}"
assert_eq "rag_vec_chunks (where_sql, embedding disabled)" "0" "${VEC_COUNT_2}"

print_samples

# FTS tests (phase 2)
FTS_PROXYSQL_2="$(fts_count 'ProxySQL')"
FTS_HIGH_2="$(fts_count 'High')"
FTS_LOW_2="$(fts_count 'Low')"
FTS_BM25_2="$(fts_bm25_top 'High')"

assert_eq "fts term (ProxySQL)" "1" "${FTS_PROXYSQL_2}"
assert_eq "fts term (High)" "1" "${FTS_HIGH_2}"
assert_eq "fts term (Low)" "0" "${FTS_LOW_2}"
assert_eq "fts bm25 top (High)" "posts:9#0" "${FTS_BM25_2}"

# ===========================================================================
# Phase 3: enable chunking and ensure rows split into multiple chunks
# ===========================================================================
echo "=========================================="
echo "Phase 3: Enable chunking"
echo "=========================================="
run_sqlite_server "DELETE FROM rag_sync_state;"
run_sqlite_server "DELETE FROM rag_vec_chunks;"
run_sqlite_server "DELETE FROM rag_fts_chunks;"
run_sqlite_server "DELETE FROM rag_chunks;"
run_sqlite_server "DELETE FROM rag_documents;"

apply_schema_and_source "" "false" '{"enabled":true,"unit":"chars","chunk_size":50,"overlap":10,"min_chunk_size":10}'
"${RAG_INGEST}" ingest \
  -h "${SQLITE_SERVER_HOST}" -P "${SQLITE_SERVER_PORT}" \
  -u "${SQLITE_SERVER_USER}" -p "${SQLITE_SERVER_PASS}" \
  -D "${SQLITE_SERVER_DB}"

DOCS_COUNT_3="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_documents;")"
CHUNKS_COUNT_3="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_chunks;")"
LONG_DOC_CHUNKS="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_chunks WHERE doc_id='posts:5';")"

assert_eq "rag_documents (chunking enabled)" "10" "${DOCS_COUNT_3}"
if [[ "${CHUNKS_COUNT_3}" -le "${DOCS_COUNT_3}" ]]; then
  echo "FAIL: rag_chunks should be greater than rag_documents when chunking enabled" >&2
  exit 1
fi
if [[ "${LONG_DOC_CHUNKS}" -le "1" ]]; then
  echo "FAIL: posts:5 should produce multiple chunks" >&2
  exit 1
fi

print_samples

# ===========================================================================
# Phase 4: enable embeddings (stub) and validate vec rows
# ===========================================================================
echo "=========================================="
echo "Phase 4: Enable embeddings (stub provider)"
echo "=========================================="
run_sqlite_server "DELETE FROM rag_sync_state;"
run_sqlite_server "DELETE FROM rag_vec_chunks;"
run_sqlite_server "DELETE FROM rag_fts_chunks;"
run_sqlite_server "DELETE FROM rag_chunks;"
run_sqlite_server "DELETE FROM rag_documents;"

apply_schema_and_source "" "false" '' "{\"enabled\":true,\"provider\":\"${EMBEDDING_PROVIDER}\",\"dim\":${EMBEDDING_DIM},\"input\":{\"concat\":[{\"col\":\"Title\"},{\"lit\":\"\\n\"},{\"chunk_body\":true}]}}"
"${RAG_INGEST}" ingest \
  -h "${SQLITE_SERVER_HOST}" -P "${SQLITE_SERVER_PORT}" \
  -u "${SQLITE_SERVER_USER}" -p "${SQLITE_SERVER_PASS}" \
  -D "${SQLITE_SERVER_DB}"

DOCS_COUNT_4="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_documents;")"
CHUNKS_COUNT_4="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_chunks;")"
VEC_COUNT_4="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_vec_chunks;")"

assert_eq "rag_documents (embeddings enabled)" "10" "${DOCS_COUNT_4}"
assert_eq "rag_chunks (embeddings enabled)" "10" "${CHUNKS_COUNT_4}"
assert_eq "rag_vec_chunks (embeddings enabled)" "10" "${VEC_COUNT_4}"

VEC_MATCH_1="$(vec_self_match 'posts:1#0')"
assert_eq "vec self-match (posts:1#0)" "posts:1#0" "${VEC_MATCH_1}"

print_samples

# ===========================================================================
# Phase 5: optional OpenAI-compatible embeddings test (requires env vars)
# ===========================================================================
echo "=========================================="
echo "Phase 5: OpenAI-compatible embeddings (optional)"
echo "=========================================="
if [[ -n "${OPENAI_API_BASE}" && -n "${OPENAI_API_KEY}" ]]; then
  # Cleanup existing tables for OpenAI test
  run_sqlite_server "
    DROP TABLE IF EXISTS rag_sync_state;
    DROP TABLE IF EXISTS rag_fts_chunks;
    DROP TABLE IF EXISTS rag_vec_chunks;
    DROP VIEW IF EXISTS rag_chunk_view;
    DROP TABLE IF EXISTS rag_chunks;
    DROP TABLE IF EXISTS rag_documents;
    DROP TABLE IF EXISTS rag_sources;
  "

  # Initialize schema with rag_ingest init
  "${RAG_INGEST}" init \
    -h "${SQLITE_SERVER_HOST}" -P "${SQLITE_SERVER_PORT}" \
    -u "${SQLITE_SERVER_USER}" -p "${SQLITE_SERVER_PASS}" \
    -D "${SQLITE_SERVER_DB}"

  # Recreate vec0 table with correct dimensions for the OpenAI model
  # (rag_ingest init creates 1536 by default, but nomic-embed-text-v1.5 uses 768)
  run_sqlite_server "
    DROP TABLE IF EXISTS rag_vec_chunks;
    CREATE VIRTUAL TABLE rag_vec_chunks USING vec0(
      embedding  float[${OPENAI_EMBEDDING_DIM}],
      chunk_id   TEXT,
      doc_id     TEXT,
      source_id  INTEGER,
      updated_at INTEGER
    );
  "

  # Insert source with OpenAI embedding config
  openai_embedding_json="{\"enabled\":true,\"provider\":\"openai\",\"api_base\":\"${OPENAI_API_BASE}\",\"api_key\":\"${OPENAI_API_KEY}\",\"model\":\"${OPENAI_MODEL}\",\"dim\":${OPENAI_EMBEDDING_DIM},\"input\":{\"concat\":[{\"col\":\"Title\"},{\"lit\":\"\\n\"},{\"chunk_body\":true}]}}"

  run_sqlite_server "
    INSERT INTO rag_sources (
      name, enabled, backend_type, backend_host, backend_port, backend_user, backend_pass, backend_db,
      table_name, pk_column, where_sql, doc_map_json, chunking_json, embedding_json
    ) VALUES (
      'test_posts_openai', 1,
      'mysql', '${MYSQL_HOST}', ${MYSQL_PORT}, '${MYSQL_USER}', '${MYSQL_PASS}', 'rag_test',
      'posts', 'Id', '',
      '{\"doc_id\":{\"format\":\"posts:{Id}\"},\"title\":{\"concat\":[{\"col\":\"Title\"}]},\"body\":{\"concat\":[{\"col\":\"Body\"}]},\"metadata\":{\"pick\":[\"Tags\",\"Score\"],\"rename\":{\"Tags\":\"tags\",\"Score\":\"score\"}}}',
      '{\"enabled\":false,\"unit\":\"chars\",\"chunk_size\":4000,\"overlap\":400,\"min_chunk_size\":800}',
      '${openai_embedding_json}'
    );
  "

  # Run ingestion
  "${RAG_INGEST}" ingest \
    -h "${SQLITE_SERVER_HOST}" -P "${SQLITE_SERVER_PORT}" \
    -u "${SQLITE_SERVER_USER}" -p "${SQLITE_SERVER_PASS}" \
    -D "${SQLITE_SERVER_DB}"

  # Validate results
  DOCS_COUNT_5="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_documents;")"
  CHUNKS_COUNT_5="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_chunks;")"
  VEC_COUNT_5="$(run_sqlite_server_value "SELECT COUNT(*) FROM rag_vec_chunks;")"

  assert_eq "rag_documents (openai embeddings)" "10" "${DOCS_COUNT_5}"
  assert_eq "rag_chunks (openai embeddings)" "10" "${CHUNKS_COUNT_5}"
  assert_eq "rag_vec_chunks (openai embeddings)" "10" "${VEC_COUNT_5}"

  print_samples

  # Test vector self-match (verify embeddings work correctly)
  VEC_MATCH_5="$(vec_self_match 'posts:1#0')"
  assert_eq "vec self-match (posts:1#0) with OpenAI embeddings" "posts:1#0" "${VEC_MATCH_5}"

  # Test semantic vector search using rag_ingest query command
  echo "==> Testing semantic vector search with OpenAI embeddings..."
  QUERY_OUTPUT="$("${RAG_INGEST}" query \
    -h "${SQLITE_SERVER_HOST}" -P "${SQLITE_SERVER_PORT}" \
    -u "${SQLITE_SERVER_USER}" -p "${SQLITE_SERVER_PASS}" \
    -D "${SQLITE_SERVER_DB}" \
    --text="ProxySQL RAG" \
    --source-id=1 \
    --limit=3 2>&1)"

  # Verify query returned results
  if echo "${QUERY_OUTPUT}" | grep -q "chunk_id"; then
    echo "OK: Semantic vector search returned results"
  else
    echo "FAIL: Semantic vector search did not return results"
    echo "Query output: ${QUERY_OUTPUT}"
    exit 1
  fi

  echo "OK: OpenAI embeddings test completed"
else
  echo "==> OpenAI embeddings test skipped (set OPENAI_API_BASE and OPENAI_API_KEY)"
fi

echo ""
echo "=========================================="
echo "All tests passed."
echo "=========================================="
