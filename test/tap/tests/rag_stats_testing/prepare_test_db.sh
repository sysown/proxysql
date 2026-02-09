#!/bin/bash

sqlite3 $(dirname $(realpath $0))/rag.db ".load $WORKSPACE/deps/sqlite3/sqlite3/vec0" \
	< $(dirname $(realpath $0))/schema.sql

sqlite3 $(dirname $(realpath $0))/rag.db ".load $WORKSPACE/deps/sqlite3/sqlite3/vec0" <<EOF
DELETE FROM rag_sources;
DELETE FROM rag_documents;
DELETE FROM rag_chunks;
DELETE FROM rag_fts_chunks;

-- First, insert a test source (required by foreign keys)
INSERT INTO rag_sources (
	source_id, name, enabled,
	backend_type, backend_host, backend_port, backend_user, backend_pass, backend_db,
	table_name, pk_column,
	doc_map_json, chunking_json
) VALUES (
	1, 'test_source', 1,
	'mysql', '127.0.0.1', 3306, 'root', 'root', 'test_db',
	'test_table', 'id',
	'{"doc_id":{"format":"test:{id}"}}',
	'{"enabled":false,"unit":"chars","chunk_size":4000,"overlap":400,"min_chunk_size":800}'
);

-- Insert a test document (requires source_id, source_name, pk_json)
INSERT INTO rag_documents (doc_id, source_id, source_name, pk_json, title, metadata_json)
VALUES ('test:doc1', 1, 'test_source', '{"id":1}', 'Test Document About MySQL', '{"Tags": "<mysql><test>"}');

-- Insert a test chunk (requires source_id)
INSERT INTO rag_chunks (chunk_id, doc_id, source_id, chunk_index, body, title)
VALUES ('test:doc1#0', 'test:doc1', 1, 0, 'This is a test chunk about MySQL databases and full-text search capabilities.', 'Test Document About MySQL');

-- Insert FTS entry
INSERT INTO rag_fts_chunks (chunk_id, title, body)
VALUES ('test:doc1#0', 'Test Document About MySQL', 'This is a test chunk about MySQL databases and full-text search capabilities.');

-- Verify the data
SELECT 'Documents:' AS table_name, COUNT(*) AS count FROM rag_documents
UNION ALL
SELECT 'Chunks:', COUNT(*) FROM rag_chunks
UNION ALL
SELECT 'FTS entries:', COUNT(*) FROM rag_fts_chunks;
EOF

