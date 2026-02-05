# Posts Table Embeddings Setup Guide

This guide explains how to set up and populate virtual tables for storing and searching embeddings of the Posts table content using sqlite-rembed and sqlite-vec extensions in ProxySQL.

## Prerequisites

1. **ProxySQL** running with SQLite3 backend enabled (`--sqlite3-server` flag)
2. **Posts table** copied from MySQL to SQLite3 server (248,905 rows)
   - Use `scripts/copy_stackexchange_Posts_mysql_to_sqlite3.py` if not already copied
3. **Valid API credentials** for embedding generation
4. **Network access** to embedding API endpoint

## Setup Steps

### Step 1: Create Virtual Vector Table

Create a virtual table for storing 768-dimensional embeddings (matching nomic-embed-text-v1.5 model output):

```sql
-- Create virtual vector table for Posts embeddings
CREATE VIRTUAL TABLE Posts_embeddings USING vec0(
    embedding float[768]
);
```

### Step 2: Configure API Client

Configure an embedding API client using the `temp.rembed_clients` virtual table:

```sql
-- Configure embedding API client
-- Replace YOUR_API_KEY with actual API key
INSERT INTO temp.rembed_clients(name, options) VALUES
  ('posts-embed-client',
   rembed_client_options(
     'format', 'openai',
     'url', 'https://api.synthetic.new/openai/v1/embeddings',
     'key', 'YOUR_API_KEY',
     'model', 'hf:nomic-ai/nomic-embed-text-v1.5'
   )
  );
```

### Step 3: Generate and Insert Embeddings

#### For Testing (First 100 rows)

```sql
-- Generate embeddings for first 100 Posts
INSERT OR REPLACE INTO Posts_embeddings(rowid, embedding)
SELECT rowid, rembed('posts-embed-client',
       COALESCE(Title || ' ', '') || Body) as embedding
FROM Posts
LIMIT 100;
```

#### For Full Table (Batch Processing)

Use this optimized batch query that processes unembedded rows without requiring rowid tracking:

```sql
-- Batch process unembedded rows (processes ~1000 rows at a time)
INSERT OR REPLACE INTO Posts_embeddings(rowid, embedding)
SELECT Posts.rowid, rembed('posts-embed-client',
       COALESCE(Posts.Title || ' ', '') || Posts.Body) as embedding
FROM Posts
LEFT JOIN Posts_embeddings ON Posts.rowid = Posts_embeddings.rowid
WHERE Posts_embeddings.rowid IS NULL
LIMIT 1000;
```

**Key features of this batch query:**
- Uses `LEFT JOIN` to find Posts without existing embeddings
- `WHERE Posts_embeddings.rowid IS NULL` filters for unprocessed rows
- `LIMIT 1000` controls batch size
- Can be run repeatedly until all rows are processed
- No need to track which rowids have been processed

### Step 4: Verify Embeddings

```sql
-- Check total embeddings count
SELECT COUNT(*) as total_embeddings FROM Posts_embeddings;

-- Check embedding size (should be 3072 bytes: 768 dimensions × 4 bytes)
SELECT rowid, length(embedding) as embedding_size_bytes
FROM Posts_embeddings LIMIT 3;

-- Check percentage of Posts with embeddings
SELECT
  (SELECT COUNT(*) FROM Posts_embeddings) as with_embeddings,
  (SELECT COUNT(*) FROM Posts) as total_posts,
  ROUND(
    (SELECT COUNT(*) FROM Posts_embeddings) * 100.0 /
    (SELECT COUNT(*) FROM Posts), 2
  ) as percentage_complete;
```

## Batch Processing Strategy for 248,905 Rows

### Recommended Approach

1. **Run the batch query repeatedly** until all rows have embeddings
2. **Add delays between batches** to avoid API rate limiting
3. **Monitor progress** using the verification queries above

### Example Shell Script for Batch Processing

```bash
#!/bin/bash
# process_posts_embeddings.sh

PROXYSQL_HOST="127.0.0.1"
PROXYSQL_PORT="6030"
MYSQL_USER="root"
MYSQL_PASS="root"
BATCH_SIZE=1000
DELAY_SECONDS=5

echo "Starting Posts embeddings generation..."

while true; do
  # Execute batch query
  mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" << EOF
    INSERT OR REPLACE INTO Posts_embeddings(rowid, embedding)
    SELECT Posts.rowid, rembed('posts-embed-client',
           COALESCE(Posts.Title || ' ', '') || Posts.Body) as embedding
    FROM Posts
    LEFT JOIN Posts_embeddings ON Posts.rowid = Posts_embeddings.rowid
    WHERE Posts_embeddings.rowid IS NULL
    LIMIT $BATCH_SIZE;
EOF

  # Check if any rows were processed
  PROCESSED=$(mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" -s -N << EOF
    SELECT COUNT(*) FROM Posts_embeddings;
EOF)

  TOTAL=$(mysql -h "$PROXYSQL_HOST" -P "$PROXYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASS" -s -N << EOF
    SELECT COUNT(*) FROM Posts;
EOF)

  PERCENTAGE=$(echo "scale=2; $PROCESSED * 100 / $TOTAL" | bc)
  echo "Processed: $PROCESSED/$TOTAL rows ($PERCENTAGE%)"

  # Break if all rows processed
  if [ "$PROCESSED" -eq "$TOTAL" ]; then
    echo "All rows processed!"
    break
  fi

  # Wait before next batch
  echo "Waiting $DELAY_SECONDS seconds before next batch..."
  sleep $DELAY_SECONDS
done
```

## Similarity Search Examples

Once embeddings are generated, you can perform semantic search:

### Example 1: Find Similar Posts

```sql
-- Find Posts similar to a query about databases
SELECT p.SiteId, p.Id as PostId, p.Title, e.distance,
       substr(p.Body, 1, 100) as body_preview
FROM (
  SELECT rowid, distance
  FROM Posts_embeddings
  WHERE embedding MATCH rembed('posts-embed-client',
         'database systems and SQL queries')
  LIMIT 5
) e
JOIN Posts p ON e.rowid = p.rowid
ORDER BY e.distance;
```

### Example 2: Find Posts Similar to Specific Post

```sql
-- Find Posts similar to Post with ID 1
SELECT p2.SiteId, p2.Id as PostId, p2.Title, e.distance,
       substr(p2.Body, 1, 100) as body_preview
FROM (
  SELECT rowid, distance
  FROM Posts_embeddings
  WHERE embedding MATCH (
    SELECT embedding
    FROM Posts_embeddings
    WHERE rowid = 1  -- Change to target Post rowid
  )
  AND rowid != 1
  LIMIT 5
) e
JOIN Posts p2 ON e.rowid = p2.rowid
ORDER BY e.distance;
```

### Example 3: Find Posts About "What is ProxySQL?" with Correct LIMIT Syntax

When using `sqlite-vec`'s `MATCH` operator for similarity search, **you must include a `LIMIT` clause (or `k = ?` constraint) in the same query level as the `MATCH`**. This tells the extension how many nearest neighbors to return.

**Common error**: `ERROR 1045 (28000): A LIMIT or 'k = ?' constraint is required on vec0 knn queries.`

**Correct query**:

```sql
-- Find Posts about "What is ProxySQL?" using semantic similarity
SELECT
  p.Id,
  p.Title,
  SUBSTR(p.Body, 1, 200) AS Excerpt,
  e.distance
FROM (
  -- LIMIT must be in the subquery that contains MATCH
  SELECT rowid, distance
  FROM Posts_embeddings
  WHERE embedding MATCH rembed('posts-embed-client', 'What is ProxySQL?')
  ORDER BY distance ASC
  LIMIT 10          -- REQUIRED for vec0 KNN queries
) e
JOIN Posts p ON e.rowid = p.rowid
ORDER BY e.distance ASC;
```

**Alternative using `k = ?` constraint** (instead of `LIMIT`):

```sql
SELECT p.Id, p.Title, e.distance
FROM (
  SELECT rowid, distance
  FROM Posts_embeddings
  WHERE embedding MATCH rembed('posts-embed-client', 'What is ProxySQL?')
    AND k = 10      -- Alternative to LIMIT constraint
  ORDER BY distance ASC
) e
JOIN Posts p ON e.rowid = p.rowid
ORDER BY e.distance ASC;
```

**Key rules**:
1. `LIMIT` or `k = ?` must be in the same query level as `MATCH`
2. Cannot use both `LIMIT` and `k = ?` together – choose one
3. When joining, put `MATCH` + `LIMIT` in a subquery
4. The constraint tells `sqlite-vec` how many similar vectors to return

## Performance Considerations

1. **API Rate Limiting**: The `rembed()` function makes HTTP requests to the API
   - Batch size of 1000 with 5-second delays is conservative
   - Adjust based on API rate limits
   - Monitor API usage and costs

2. **Embedding Storage**:
   - Each embedding: 768 dimensions × 4 bytes = 3,072 bytes
   - Full table (248,905 rows): ~765 MB
   - Ensure sufficient disk space

3. **Search Performance**:
   - `vec0` virtual tables use approximate nearest neighbor search
   - Performance scales with number of vectors and dimensions
   - Use `LIMIT` clauses to control result size

## Troubleshooting

### Common Issues

1. **API Connection Errors**
   - Verify API key is valid and has quota
   - Check network connectivity to API endpoint
   - Confirm API endpoint URL is correct

2. **Embedding Generation Failures**
   - Check `temp.rembed_clients` configuration
   - Verify client name matches in `rembed()` calls
   - Test with simple text first: `SELECT rembed('posts-embed-client', 'test');`

3. **Batch Processing Stalls**
   - Check if API rate limits are being hit
   - Increase delay between batches
   - Reduce batch size

4. **Memory Issues**
   - Large batches may consume significant memory
   - Reduce batch size if encountering memory errors
   - Monitor ProxySQL memory usage

### Verification Queries

```sql
-- Check API client configuration
SELECT name, json_extract(options, '$.format') as format,
       json_extract(options, '$.model') as model
FROM temp.rembed_clients;

-- Test embedding generation
SELECT length(rembed('posts-embed-client', 'test text')) as test_embedding_size;

-- Check for embedding generation errors
SELECT rowid FROM Posts_embeddings WHERE length(embedding) != 3072;
```

## Maintenance

### Adding New Posts

When new Posts are added to the table:

```sql
-- Generate embeddings for new Posts
INSERT OR REPLACE INTO Posts_embeddings(rowid, embedding)
SELECT Posts.rowid, rembed('posts-embed-client',
       COALESCE(Posts.Title || ' ', '') || Posts.Body) as embedding
FROM Posts
LEFT JOIN Posts_embeddings ON Posts.rowid = Posts_embeddings.rowid
WHERE Posts_embeddings.rowid IS NULL;
```

### Recreating Virtual Table

If you need to recreate the virtual table:

```sql
-- Drop existing table
DROP TABLE IF EXISTS Posts_embeddings;

-- Recreate with same schema
CREATE VIRTUAL TABLE Posts_embeddings USING vec0(
    embedding float[768]
);
```

## Related Resources

1. [sqlite-rembed Integration Documentation](./sqlite-rembed-integration.md)
2. [SQLite3 Server Documentation](./SQLite3-Server.md)
3. [Vector Search Testing](../doc/vector-search-test/README.md)
4. [Copy Script](../scripts/copy_stackexchange_Posts_mysql_to_sqlite3.py)

---

*Last Updated: $(date)*