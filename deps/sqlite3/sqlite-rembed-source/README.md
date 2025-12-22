# `sqlite-rembed`

A SQLite extension for generating text embeddings from remote APIs (OpenAI, Nomic, Cohere, llamafile, Ollama, etc.). A sister project to [`sqlite-vec`](https://github.com/asg017/sqlite-vec) and [`sqlite-lembed`](https://github.com/asg017/sqlite-lembed). A work-in-progress!

## Usage

```sql
.load ./rembed0

INSERT INTO temp.rembed_clients(name, options)
 VALUES ('text-embedding-3-small', 'openai');

select rembed(
  'text-embedding-3-small',
  'The United States Postal Service is an independent agency...'
);
```

The `temp.rembed_clients` virtual table lets you "register" clients with pure `INSERT INTO` statements. The `name` field is a unique identifier for a given client, and `options` allows you to specify which 3rd party embedding service you want to use.

In this case, `openai` is a pre-defined client that will default to OpenAI's `https://api.openai.com/v1/embeddings` endpoint and will source your API key from the `OPENAI_API_KEY` environment variable. The name of the client, `text-embedding-3-small`, will be used as the embeddings model.

Other pre-defined clients include:

| Client name  | Provider                                                                             | Endpoint                                       | API Key              |
| ------------ | ------------------------------------------------------------------------------------ | ---------------------------------------------- | -------------------- |
| `openai`     | [OpenAI](https://platform.openai.com/docs/guides/embeddings)                         | `https://api.openai.com/v1/embeddings`         | `OPENAI_API_KEY`     |
| `nomic`      | [Nomic](https://docs.nomic.ai/reference/endpoints/nomic-embed-text)                  | `https://api-atlas.nomic.ai/v1/embedding/text` | `NOMIC_API_KEY`      |
| `cohere`     | [Cohere](https://docs.cohere.com/reference/embed)                                    | `https://api.cohere.com/v1/embed`              | `CO_API_KEY`         |
| `jina`       | [Jina](https://api.jina.ai/redoc#tag/embeddings)                                     | `https://api.jina.ai/v1/embeddings`            | `JINA_API_KEY`       |
| `mixedbread` | [MixedBread](https://www.mixedbread.ai/api-reference#quick-start-guide)              | `https://api.mixedbread.ai/v1/embeddings/`     | `MIXEDBREAD_API_KEY` |
| `llamafile`  | [llamafile](https://github.com/Mozilla-Ocho/llamafile)                               | `http://localhost:8080/embedding`              | None                 |
| `ollama`     | [Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md#generate-embeddings) | `http://localhost:11434/api/embeddings`        | None                 |

Different client options can be specified with `remebed_client_options()`. For example, if you have a different OpenAI-compatible service you want to use, then you can use:

```sql
INSERT INTO temp.rembed_clients(name, options) VALUES
  (
    'xyz-small-1',
    rembed_client_options(
      'format', 'openai',
      'url', 'https://api.xyz.com/v1/embeddings',
      'key', 'xyz-ca865ece65-hunter2'
    )
  );
```

Or to use a llamafile server that's on a different port:

```sql
INSERT INTO temp.rembed_clients(name, options) VALUES
  (
    'xyz-small-1',
    rembed_client_options(
      'format', 'lamafile',
      'url', 'http://localhost:9999/embedding'
    )
  );
```

### Using with `sqlite-vec`

`sqlite-rembed` works well with [`sqlite-vec`](https://github.com/asg017/sqlite-vec), a SQLite extension for vector search. Embeddings generated with `rembed()` use the same BLOB format for vectors that `sqlite-vec` uses.

Here's a sample "semantic search" application, made from a sample dataset of news article headlines.

```sql
create table articles(
  headline text
);

-- Random NPR headlines from 2024-06-04
insert into articles VALUES
  ('Shohei Ohtani''s ex-interpreter pleads guilty to charges related to gambling and theft'),
  ('The jury has been selected in Hunter Biden''s gun trial'),
  ('Larry Allen, a Super Bowl champion and famed Dallas Cowboy, has died at age 52'),
  ('After saying Charlotte, a lone stingray, was pregnant, aquarium now says she''s sick'),
  ('An Epoch Times executive is facing money laundering charge');


-- Build a vector table with embeddings of article headlines, using OpenAI's API
create virtual table vec_articles using vec0(
  headline_embeddings float[1536]
);

insert into vec_articles(rowid, headline_embeddings)
  select rowid, rembed('text-embedding-3-small', headline)
  from articles;

```

Now we have a regular `articles` table that stores text headlines, and a `vec_articles` virtual table that stores embeddings of the article headlines, using OpenAI's `text-embedding-3-small` model.

To perform a "semantic search" on the embeddings, we can query the `vec_articles` table with an embedding of our query, and join the results back to our `articles` table to retrieve the original headlines.

```sql
param set :query 'firearm courtroom'

with matches as (
  select
    rowid,
    distance
  from vec_articles
  where headline_embeddings match rembed('text-embedding-3-small', :query)
  order by distance
  limit 3
)
select
  headline,
  distance
from matches
left join articles on articles.rowid = matches.rowid;

/*
+--------------------------------------------------------------+------------------+
|                           headline                           |     distance     |
+--------------------------------------------------------------+------------------+
| The jury has been selected in Hunter Biden's gun trial       | 1.05906391143799 |
+--------------------------------------------------------------+------------------+
| Shohei Ohtani's ex-interpreter pleads guilty to charges rela | 1.2574303150177  |
| ted to gambling and theft                                    |                  |
+--------------------------------------------------------------+------------------+
| An Epoch Times executive is facing money laundering charge   | 1.27144026756287 |
+--------------------------------------------------------------+------------------+
*/
```

Notice how "firearm courtroom" doesn't appear in any of these headlines, but it can still figure out that "Hunter Biden's gun trial" is related, and the other two justice-related articles appear on top.

## Drawbacks

1. **No batch support yet.** If you use `rembed()` in a batch UPDATE or INSERT in 1,000 rows, then 1,000 HTTP requests will be made. Add a :+1: to [Issue #1](https://github.com/asg017/sqlite-rembed/issues/1) if you want to see this fixed.
2. **No builtin rate limiting.** Requests are sent sequentially so this may not come up in small demos, but `sqlite-rembed` could add features that handles rate limiting/retries implicitly. Add a :+1: to [Issue #2](https://github.com/asg017/sqlite-rembed/issues/2) if you want to see this implemented.
