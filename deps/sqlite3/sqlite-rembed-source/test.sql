.load dist/debug/rembed0
.bail on
.mode box
.header on
.timer on
.echo on

INSERT INTO temp.rembed_clients(name, options) VALUES
  ('text-embedding-3-small','openai'),
  ('jina-embeddings-v2-base-en','jina'),
  ('mixedbread-ai/mxbai-embed-large-v1','mixedbread'),
  ('nomic-embed-text-v1.5', 'nomic'),
  ('embed-english-v3.0', 'cohere'),
  ('snowflake-arctic-embed:s', 'ollama'),
  ('llamafile', 'llamafile'),
  (
    'mxbai-embed-large-v1-f16',
    rembed_client_options(
      'format', 'llamafile',
      --'url', 'http://mm1:8080/v1/embeddings'
      'url', 'http://mm1:8080/embedding'
    )
  );

select length(rembed('mixedbread-ai/mxbai-embed-large-v1', 'obama the person'));
.exit
select length(rembed('jina-embeddings-v2-base-en', 'obama the person'));

.exit

select length(rembed('text-embedding-3-small', 'obama the person'));
select length(rembed('llamafile', 'obama the person'));
select length(rembed('snowflake-arctic-embed:s', 'obama the person'));
select length(rembed('embed-english-v3.0', 'obama the person', 'search_document'));
select length(rembed('mxbai-embed-large-v1-f16', 'obama the person'));


