#!/usr/bin/env bash
# Seed the RAG database opened by the ProxySQL process using Python stdlib.

set -euo pipefail

SCRIPT_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
RAG_DB_PATH="${RAG_DB_PATH:-/var/lib/proxysql/ai_features.db}"
MODE="${1:-seed}"

if [[ "${MODE}" != "seed" && "${MODE}" != "cleanup" ]]; then
    echo "usage: $0 [seed|cleanup]" >&2
    exit 2
fi

python3 - "${RAG_DB_PATH}" "${SCRIPT_DIR}/schema.sql" "${MODE}" <<'PY'
import re
import sqlite3
import sys
from pathlib import Path


db_path = Path(sys.argv[1])
schema_path = Path(sys.argv[2])
mode = sys.argv[3]
db_path.parent.mkdir(parents=True, exist_ok=True)

# Python's stdlib SQLite has FTS5 but does not load ProxySQL's statically linked
# sqlite-vec module.  ProxySQL creates rag_vec_chunks itself; this fixture only
# needs the relational and FTS portions of the schema.
schema = schema_path.read_text(encoding="utf-8")
schema = re.sub(
    r"CREATE VIRTUAL TABLE IF NOT EXISTS rag_vec_chunks\s+USING vec0\(.*?\);",
    "",
    schema,
    flags=re.DOTALL,
)

source_id = 909901
doc_id = "tap:rag:doc1"
chunk_id = "tap:rag:doc1#0"

with sqlite3.connect(db_path, timeout=30) as connection:
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(schema)
    connection.execute("DELETE FROM rag_fts_chunks WHERE chunk_id = ?", (chunk_id,))
    connection.execute("DELETE FROM rag_chunks WHERE chunk_id = ?", (chunk_id,))
    connection.execute("DELETE FROM rag_documents WHERE doc_id = ?", (doc_id,))
    connection.execute("DELETE FROM rag_sources WHERE source_id = ?", (source_id,))

    if mode == "seed":
        connection.execute(
            """
            INSERT INTO rag_sources (
                source_id, name, enabled,
                backend_type, backend_host, backend_port, backend_user,
                backend_pass, backend_db, table_name, pk_column,
                doc_map_json, chunking_json
            ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                "tap_rag_source",
                "mysql",
                "mysql",
                3306,
                "root",
                "",
                "test",
                "tap_rag_documents",
                "id",
                '{"doc_id":{"format":"tap:rag:{id}"}}',
                '{"enabled":false,"unit":"chars","chunk_size":4000,"overlap":400,"min_chunk_size":800}',
            ),
        )
        connection.execute(
            """
            INSERT INTO rag_documents
                (doc_id, source_id, source_name, pk_json, title, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                doc_id,
                source_id,
                "tap_rag_source",
                '{"id":1}',
                "TAP Document About MySQL",
                '{"tags":["mysql","tap"]}',
            ),
        )
        connection.execute(
            """
            INSERT INTO rag_chunks
                (chunk_id, doc_id, source_id, chunk_index, body, title)
            VALUES (?, ?, ?, 0, ?, ?)
            """,
            (
                chunk_id,
                doc_id,
                source_id,
                "A deterministic TAP chunk about MySQL databases and full-text search.",
                "TAP Document About MySQL",
            ),
        )
        connection.execute(
            "INSERT INTO rag_fts_chunks (chunk_id, title, body) VALUES (?, ?, ?)",
            (
                chunk_id,
                "TAP Document About MySQL",
                "A deterministic TAP chunk about MySQL databases and full-text search.",
            ),
        )

    counts = connection.execute(
        """
        SELECT
          (SELECT COUNT(*) FROM rag_documents WHERE doc_id = ?),
          (SELECT COUNT(*) FROM rag_chunks WHERE chunk_id = ?),
          (SELECT COUNT(*) FROM rag_fts_chunks WHERE chunk_id = ?)
        """,
        (doc_id, chunk_id, chunk_id),
    ).fetchone()

print(f"Documents: {counts[0]}")
print(f"Chunks: {counts[1]}")
print(f"FTS entries: {counts[2]}")
PY
