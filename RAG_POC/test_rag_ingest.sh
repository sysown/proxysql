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

  local schema_cmd=""
  if [[ "${load_schema}" == "true" ]]; then
    schema_cmd=".read ${ROOT_DIR}/schema.sql"$'\n'".read ${ROOT_DIR}/sample_sqlite.sql"
  fi

  echo "==> SQLite DB: ${db}"
  echo "==> load_schema: ${load_schema}"
  echo "==> where_sql: ${where_sql:-<empty>}"
  echo "==> chunking_json: {\"enabled\":false,\"unit\":\"chars\",\"chunk_size\":4000,\"overlap\":400,\"min_chunk_size\":800}"
  echo "==> embedding_json: {\"enabled\":false}"

  "${SQLITE_BIN}" "${db}" <<SQL
.load ${VEC_EXT}
${schema_cmd}
UPDATE rag_sources
SET chunking_json='{"enabled":false,"unit":"chars","chunk_size":4000,"overlap":400,"min_chunk_size":800}'
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

echo "All tests passed."
