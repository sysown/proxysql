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

DB1="${ROOT_DIR}/rag_ingest_test.db"

VEC_EXT="${REPO_ROOT}/deps/sqlite3/sqlite3/vec0.so"

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

  local schema_cmd=""
  if [[ "${load_schema}" == "true" ]]; then
    schema_cmd=".read ${ROOT_DIR}/schema.sql"$'\n'".read ${ROOT_DIR}/sample_sqlite.sql"
  fi

  echo "==> SQLite DB: ${db}"
  echo "==> load_schema: ${load_schema}"
  echo "==> where_sql: ${where_sql:-<empty>}"
    local chunking_json_value='{"enabled":false,"unit":"chars","chunk_size":4000,"overlap":400,"min_chunk_size":800}'
    if [[ -n "${chunking_json_override}" ]]; then
      chunking_json_value="${chunking_json_override}"
    fi
    echo "==> chunking_json: ${chunking_json_value}"
  echo "==> embedding_json: {\"enabled\":false}"

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
SET embedding_json='{"enabled":false}'
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

echo "All tests passed."
