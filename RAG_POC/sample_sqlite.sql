-- Sample SQLite setup for rag_ingest testing
-- Inserts a sample rag_sources row that points to the MySQL sample.
-- Note: schema.sql must be loaded separately before this script.

-- insert a sample source
INSERT INTO rag_sources (
  source_id,
  name,
  enabled,
  backend_type,
  backend_host,
  backend_port,
  backend_user,
  backend_pass,
  backend_db,
  table_name,
  pk_column,
  where_sql,
  doc_map_json,
  chunking_json,
  embedding_json
) VALUES (
  1,
  'mysql_posts',
  1,
  'mysql',
  '127.0.0.1',
  3306,
  'root',
  'root',
  'rag_test',
  'posts',
  'Id',
  '',
  '{"doc_id":{"format":"posts:{Id}"},"title":{"concat":[{"col":"Title"}]},"body":{"concat":[{"col":"Body"}]},"metadata":{"pick":["Id","Tags","Score","CreationDate"],"rename":{"CreationDate":"CreationDate"}}}',
  '{"enabled":true,"unit":"chars","chunk_size":4000,"overlap":400,"min_chunk_size":800}',
  '{"enabled":true,"dim":1536,"model":"text-embedding-3-large","input":{"concat":[{"col":"Title"},{"lit":"\\nTags: "},{"col":"Tags"},{"lit":"\\n\\n"},{"chunk_body":true}]}}'
);
