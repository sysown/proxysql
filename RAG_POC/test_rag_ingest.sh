#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/.." && pwd)"

SQLITE_BIN="${SQLITE_BIN:-${REPO_ROOT}/deps/sqlite3/sqlite3/sqlite3}"
MYSQL_BIN="${MYSQL_BIN:-mysql}"

MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASS="${MYSQL_PASS:-root}"

# Embedding provider configuration (for phase 4/5)
EMBEDDING_PROVIDER="${EMBEDDING_PROVIDER:-stub}"
EMBEDDING_DIM="${EMBEDDING_DIM:-1536}"
OPENAI_API_BASE="${OPENAI_API_BASE:-}"
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
export OPENAI_API_BASE="https://api.synthetic.new/openai/v1"
export OPENAI_API_KEY="your_api_key_here"
# export OPENAI_MODEL="hf:nomic-ai/nomic-embed-text-v1.5"

DB1="${ROOT_DIR}/rag_ingest_test.db"
DB_OPENAI="${ROOT_DIR}/rag_ingest_test_openai.db"

VEC_EXT="${REPO_ROOT}/deps/sqlite3/sqlite3/vec0.so"

export RAG_VEC0_EXT="${VEC_EXT}"

if [[ ! -f "${VEC_EXT}" ]]; then
  echo "FATAL: vec0.so not found at ${VEC_EXT}" >&2
  exit 1
fi

run_sqlite() {
  local db="$1"
  local sql="$2"
  "${SQLITE_BIN}" "${db}" <<SQL
.load ${VEC_EXT}
${sql}
SQL
}

apply_schema_and_source() {
  local db="$1"
  local where_sql="$2"
  local load_schema="$3"
  local chunking_json_override="${4:-}"
  local embedding_json_override="${5:-}"
  local schema_override_path="${6:-}"

  local schema_cmd=""
  if [[ "${load_schema}" == "true" ]]; then
    if [[ -n "${schema_override_path}" ]]; then
      schema_cmd=".read ${schema_override_path}"$'\n'".read ${ROOT_DIR}/sample_sqlite.sql"
    else
      schema_cmd=".read ${ROOT_DIR}/schema.sql"$'\n'".read ${ROOT_DIR}/sample_sqlite.sql"
    fi
  fi

  echo "==> SQLite DB: ${db}"
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

  "${SQLITE_BIN}" "${db}" <<SQL
.load ${VEC_EXT}
.bail on
.mode list
.separator |
.nullvalue NULL
${schema_cmd}
  UPDATE rag_sources
  SET chunking_json='${chunking_json_value}'
WHERE source_id=1;
UPDATE rag_sources
SET embedding_json='${embedding_json_value}'
WHERE source_id=1;
UPDATE rag_sources
SET where_sql='${where_sql}'
WHERE source_id=1;
SQL
}

import_mysql_seed() {
  "${MYSQL_BIN}" \
    -h"${MYSQL_HOST}" -P"${MYSQL_PORT}" \
    -u"${MYSQL_USER}" -p"${MYSQL_PASS}" \
    < "${ROOT_DIR}/sample_mysql.sql"
}

run_mysql_sql() {
  local sql="$1"
  "${MYSQL_BIN}" \
    -h"${MYSQL_HOST}" -P"${MYSQL_PORT}" \
    -u"${MYSQL_USER}" -p"${MYSQL_PASS}" \
    -e "${sql}"
}

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

fts_count() {
  local db="$1"
  local q="$2"
  run_sqlite "${db}" "SELECT COUNT(*) FROM rag_fts_chunks WHERE rag_fts_chunks MATCH '${q}';"
}

fts_bm25_top() {
  local db="$1"
  local q="$2"
  run_sqlite "${db}" "SELECT chunk_id FROM rag_fts_chunks WHERE rag_fts_chunks MATCH '${q}' ORDER BY bm25(rag_fts_chunks) LIMIT 1;"
}

vec_self_match() {
  local db="$1"
  local chunk_id="$2"
  run_sqlite "${db}" "SELECT chunk_id FROM rag_vec_chunks WHERE embedding MATCH (SELECT embedding FROM rag_vec_chunks WHERE chunk_id='${chunk_id}') ORDER BY distance LIMIT 1;"
}

print_samples() {
  local db="$1"
  echo "==> Sample rag_documents"
  run_sqlite "${db}" "SELECT doc_id, source_id, substr(title,1,40) AS title, json_extract(metadata_json,'$.Score') AS score FROM rag_documents ORDER BY doc_id LIMIT 5;"
  echo "==> Sample rag_chunks"
  run_sqlite "${db}" "SELECT chunk_id, doc_id, chunk_index, substr(body,1,50) AS body FROM rag_chunks ORDER BY chunk_id LIMIT 5;"
  echo "==> Sample rag_fts_chunks matches for 'ProxySQL'"
  run_sqlite "${db}" "SELECT chunk_id, substr(title,1,40) AS title FROM rag_fts_chunks WHERE rag_fts_chunks MATCH 'ProxySQL' ORDER BY chunk_id LIMIT 5;"
}

cleanup_db() {
  rm -f "${DB1}"
  rm -f "${DB_OPENAI}"
}

cleanup_db

# Phase 1: load schema + source, chunking disabled, no where filter
apply_schema_and_source "${DB1}" "" "true"

# Seed MySQL
import_mysql_seed

# Run rag_ingest
"${ROOT_DIR}/rag_ingest" "${DB1}"

# Validate counts (sample_mysql has 10 rows)
DOCS_COUNT="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_documents;")"
CHUNKS_COUNT="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_chunks;")"
FTS_COUNT="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_fts_chunks;")"
VEC_COUNT="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_vec_chunks;")"

assert_eq "rag_documents" "10" "${DOCS_COUNT}"
assert_eq "rag_chunks (chunking disabled)" "10" "${CHUNKS_COUNT}"
assert_eq "rag_fts_chunks" "10" "${FTS_COUNT}"
assert_eq "rag_vec_chunks (embedding disabled)" "0" "${VEC_COUNT}"

print_samples "${DB1}"

# FTS tests (phase 1)
FTS_PHRASE_1="$(fts_count "${DB1}" '"ProxySQL adds MCP"')"
FTS_SHORT_1="$(fts_count "${DB1}" 'Short')"
FTS_TAG_1="$(fts_count "${DB1}" 'Tag')"
FTS_BM25_1="$(fts_bm25_top "${DB1}" 'ProxySQL')"

assert_eq "fts phrase (ProxySQL adds MCP)" "1" "${FTS_PHRASE_1}"
assert_eq "fts term (Short)" "1" "${FTS_SHORT_1}"
assert_eq "fts term (Tag)" "1" "${FTS_TAG_1}"
assert_eq "fts bm25 top (ProxySQL)" "posts:3#0" "${FTS_BM25_1}"

# Phase 1a: update skip behavior (existing docs are not updated)
run_mysql_sql "USE rag_test; UPDATE posts SET Title='Hello RAG UPDATED' WHERE Id=1;"
"${ROOT_DIR}/rag_ingest" "${DB1}"
TITLE_AFTER_UPDATE="$(run_sqlite "${DB1}" "SELECT title FROM rag_documents WHERE doc_id='posts:1';")"
assert_eq "rag_documents title unchanged on update" "Hello RAG" "${TITLE_AFTER_UPDATE}"

# Reset MySQL data after update test
import_mysql_seed

# Phase 1b: rag_sync_state watermark (incremental ingestion)
SYNC_COL_1="$(run_sqlite "${DB1}" "SELECT json_extract(cursor_json,'$.column') FROM rag_sync_state WHERE source_id=1;")"
SYNC_VAL_1="$(run_sqlite "${DB1}" "SELECT json_extract(cursor_json,'$.value') FROM rag_sync_state WHERE source_id=1;")"

assert_eq "rag_sync_state column" "Id" "${SYNC_COL_1}"
assert_eq "rag_sync_state value (initial)" "10" "${SYNC_VAL_1}"

# Delete one doc to verify watermark prevents backfill
run_sqlite "${DB1}" "DELETE FROM rag_vec_chunks WHERE chunk_id LIKE 'posts:5#%';"
run_sqlite "${DB1}" "DELETE FROM rag_fts_chunks WHERE chunk_id LIKE 'posts:5#%';"
run_sqlite "${DB1}" "DELETE FROM rag_chunks WHERE doc_id='posts:5';"
run_sqlite "${DB1}" "DELETE FROM rag_documents WHERE doc_id='posts:5';"

DOCS_AFTER_DELETE="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_documents;")"
assert_eq "rag_documents after delete" "9" "${DOCS_AFTER_DELETE}"

"${ROOT_DIR}/rag_ingest" "${DB1}"

DOCS_AFTER_REINGEST="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_documents;")"
CHUNKS_AFTER_REINGEST="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_chunks;")"
FTS_AFTER_REINGEST="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_fts_chunks;")"

assert_eq "rag_documents after watermark reingest" "9" "${DOCS_AFTER_REINGEST}"
assert_eq "rag_chunks after watermark reingest" "9" "${CHUNKS_AFTER_REINGEST}"
assert_eq "rag_fts_chunks after watermark reingest" "9" "${FTS_AFTER_REINGEST}"

# Insert a new source row and ensure only it is ingested
run_mysql_sql "USE rag_test; INSERT INTO posts (Id, Title, Body, Tags, Score, CreationDate, UpdatedAt) VALUES (11, 'Watermark New', 'This row should be ingested via watermark.', 'wm,test', 1, '2024-01-14 10:00:00', '2024-01-14 11:00:00');"

"${ROOT_DIR}/rag_ingest" "${DB1}"

DOCS_AFTER_NEW="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_documents;")"
SYNC_VAL_2="$(run_sqlite "${DB1}" "SELECT json_extract(cursor_json,'$.value') FROM rag_sync_state WHERE source_id=1;")"

assert_eq "rag_documents after new row" "10" "${DOCS_AFTER_NEW}"
assert_eq "rag_sync_state value (after new row)" "11" "${SYNC_VAL_2}"

# Reset sync state for subsequent phases
run_sqlite "${DB1}" "DELETE FROM rag_sync_state;"

# Reset MySQL data after watermark insert
import_mysql_seed

# Phase 1c: UpdatedAt-based watermark filtering
run_sqlite "${DB1}" "DELETE FROM rag_vec_chunks;"
run_sqlite "${DB1}" "DELETE FROM rag_fts_chunks;"
run_sqlite "${DB1}" "DELETE FROM rag_chunks;"
run_sqlite "${DB1}" "DELETE FROM rag_documents;"
run_sqlite "${DB1}" "INSERT OR REPLACE INTO rag_sync_state(source_id, mode, cursor_json, last_ok_at, last_error) VALUES (1, 'poll', '{\"column\":\"UpdatedAt\",\"value\":\"2024-01-10 10:00:00\"}', NULL, NULL);"

"${ROOT_DIR}/rag_ingest" "${DB1}"

DOCS_UPDATED_AT="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_documents;")"
SYNC_UPDATED_AT="$(run_sqlite "${DB1}" "SELECT json_extract(cursor_json,'$.value') FROM rag_sync_state WHERE source_id=1;")"

assert_eq "rag_documents (UpdatedAt watermark)" "1" "${DOCS_UPDATED_AT}"
assert_eq "rag_sync_state value (UpdatedAt)" "2024-01-12 09:30:00" "${SYNC_UPDATED_AT}"

# Reset sync state for subsequent phases
run_sqlite "${DB1}" "DELETE FROM rag_sync_state;"

# Phase 2: apply where filter, re-ingest after cleanup
run_sqlite "${DB1}" "DELETE FROM rag_vec_chunks;"
run_sqlite "${DB1}" "DELETE FROM rag_fts_chunks;"
run_sqlite "${DB1}" "DELETE FROM rag_chunks;"
run_sqlite "${DB1}" "DELETE FROM rag_documents;"

apply_schema_and_source "${DB1}" "Score >= 7" "false"
"${ROOT_DIR}/rag_ingest" "${DB1}"

DOCS_COUNT_2="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_documents;")"
CHUNKS_COUNT_2="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_chunks;")"
FTS_COUNT_2="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_fts_chunks;")"
VEC_COUNT_2="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_vec_chunks;")"

# In sample_mysql: Score >= 7 matches Id 1,3,5,7,9 => 5 docs
assert_eq "rag_documents (where_sql)" "5" "${DOCS_COUNT_2}"
assert_eq "rag_chunks (where_sql)" "5" "${CHUNKS_COUNT_2}"
assert_eq "rag_fts_chunks (where_sql)" "5" "${FTS_COUNT_2}"
assert_eq "rag_vec_chunks (where_sql, embedding disabled)" "0" "${VEC_COUNT_2}"

print_samples "${DB1}"

# FTS tests (phase 2)
FTS_PROXYSQL_2="$(fts_count "${DB1}" 'ProxySQL')"
FTS_HIGH_2="$(fts_count "${DB1}" 'High')"
FTS_LOW_2="$(fts_count "${DB1}" 'Low')"
FTS_BM25_2="$(fts_bm25_top "${DB1}" 'High')"

assert_eq "fts term (ProxySQL)" "1" "${FTS_PROXYSQL_2}"
assert_eq "fts term (High)" "1" "${FTS_HIGH_2}"
assert_eq "fts term (Low)" "0" "${FTS_LOW_2}"
assert_eq "fts bm25 top (High)" "posts:9#0" "${FTS_BM25_2}"

# Phase 3: enable chunking and ensure rows split into multiple chunks
run_sqlite "${DB1}" "DELETE FROM rag_sync_state;"
run_sqlite "${DB1}" "DELETE FROM rag_vec_chunks;"
run_sqlite "${DB1}" "DELETE FROM rag_fts_chunks;"
run_sqlite "${DB1}" "DELETE FROM rag_chunks;"
run_sqlite "${DB1}" "DELETE FROM rag_documents;"

apply_schema_and_source "${DB1}" "" "false" '{"enabled":true,"unit":"chars","chunk_size":50,"overlap":10,"min_chunk_size":10}'
"${ROOT_DIR}/rag_ingest" "${DB1}"

DOCS_COUNT_3="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_documents;")"
CHUNKS_COUNT_3="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_chunks;")"
LONG_DOC_CHUNKS="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_chunks WHERE doc_id='posts:5';")"

assert_eq "rag_documents (chunking enabled)" "10" "${DOCS_COUNT_3}"
if [[ "${CHUNKS_COUNT_3}" -le "${DOCS_COUNT_3}" ]]; then
  echo "FAIL: rag_chunks should be greater than rag_documents when chunking enabled" >&2
  exit 1
fi
if [[ "${LONG_DOC_CHUNKS}" -le "1" ]]; then
  echo "FAIL: posts:5 should produce multiple chunks" >&2
  exit 1
fi

print_samples "${DB1}"

# Phase 4: enable embeddings (stub) and validate vec rows
run_sqlite "${DB1}" "DELETE FROM rag_sync_state;"
run_sqlite "${DB1}" "DELETE FROM rag_vec_chunks;"
run_sqlite "${DB1}" "DELETE FROM rag_fts_chunks;"
run_sqlite "${DB1}" "DELETE FROM rag_chunks;"
run_sqlite "${DB1}" "DELETE FROM rag_documents;"

apply_schema_and_source "${DB1}" "" "false" '' "{\"enabled\":true,\"provider\":\"${EMBEDDING_PROVIDER}\",\"dim\":${EMBEDDING_DIM},\"input\":{\"concat\":[{\"col\":\"Title\"},{\"lit\":\"\\n\"},{\"chunk_body\":true}]}}"
"${ROOT_DIR}/rag_ingest" "${DB1}"

DOCS_COUNT_4="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_documents;")"
CHUNKS_COUNT_4="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_chunks;")"
VEC_COUNT_4="$(run_sqlite "${DB1}" "SELECT COUNT(*) FROM rag_vec_chunks;")"

assert_eq "rag_documents (embeddings enabled)" "10" "${DOCS_COUNT_4}"
assert_eq "rag_chunks (embeddings enabled)" "10" "${CHUNKS_COUNT_4}"
assert_eq "rag_vec_chunks (embeddings enabled)" "10" "${VEC_COUNT_4}"

VEC_MATCH_1="$(vec_self_match "${DB1}" 'posts:1#0')"
assert_eq "vec self-match (posts:1#0)" "posts:1#0" "${VEC_MATCH_1}"

print_samples "${DB1}"

# Phase 5: optional OpenAI-compatible embeddings test (requires env vars)
if [[ -n "${OPENAI_API_BASE}" && -n "${OPENAI_API_KEY}" ]]; then
  OPENAI_SCHEMA_TMP="${ROOT_DIR}/schema_openai_tmp.sql"
  sed "s/embedding  float\[1536\]/embedding  float[${OPENAI_EMBEDDING_DIM}]/" "${ROOT_DIR}/schema.sql" > "${OPENAI_SCHEMA_TMP}"

  apply_schema_and_source "${DB_OPENAI}" "" "true" '' "{\"enabled\":true,\"provider\":\"openai\",\"api_base\":\"${OPENAI_API_BASE}\",\"api_key\":\"${OPENAI_API_KEY}\",\"model\":\"${OPENAI_MODEL}\",\"dim\":${OPENAI_EMBEDDING_DIM},\"input\":{\"concat\":[{\"col\":\"Title\"},{\"lit\":\"\\n\"},{\"chunk_body\":true}]}}" "${OPENAI_SCHEMA_TMP}"
  "${ROOT_DIR}/rag_ingest" "${DB_OPENAI}"

  DOCS_COUNT_5="$(run_sqlite "${DB_OPENAI}" "SELECT COUNT(*) FROM rag_documents;")"
  CHUNKS_COUNT_5="$(run_sqlite "${DB_OPENAI}" "SELECT COUNT(*) FROM rag_chunks;")"
  VEC_COUNT_5="$(run_sqlite "${DB_OPENAI}" "SELECT COUNT(*) FROM rag_vec_chunks;")"

  assert_eq "rag_documents (openai embeddings)" "10" "${DOCS_COUNT_5}"
  assert_eq "rag_chunks (openai embeddings)" "10" "${CHUNKS_COUNT_5}"
  assert_eq "rag_vec_chunks (openai embeddings)" "10" "${VEC_COUNT_5}"

  print_samples "${DB_OPENAI}"
  rm -f "${OPENAI_SCHEMA_TMP}"
else
  echo "==> OpenAI embeddings test skipped (set OPENAI_API_BASE and OPENAI_API_KEY)"
fi

echo "All tests passed."
