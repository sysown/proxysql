# StackExchange Posts Processor

A comprehensive script to extract, process, and index StackExchange posts for search capabilities.

## Features

- ✅ **Complete Pipeline**: Extracts parent posts and replies from source database
- 📊 **Search Ready**: Creates full-text search indexes and processed text columns
- 🚀 **Efficient**: Batch processing with memory optimization
- 🔍 **Duplicate Prevention**: Skip already processed posts
- 📈 **Progress Tracking**: Real-time statistics and performance metrics
- 🔧 **Flexible**: Configurable source/target databases
- 📝 **Rich Output**: Structured JSON with tags and metadata

## Database Schema

The script creates a comprehensive target table with these columns:

```sql
processed_posts (
  PostId BIGINT PRIMARY KEY,
  JsonData JSON NOT NULL,                    -- Complete post data
  Embeddings BLOB NULL,                      -- For future ML embeddings
  SearchText LONGTEXT NULL,                  -- Combined text for search
  TitleText VARCHAR(1000) NULL,              -- Cleaned title
  BodyText LONGTEXT NULL,                    -- Cleaned body
  RepliesText LONGTEXT NULL,                -- Combined replies
  Tags JSON NULL,                            -- Extracted tags
  CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UpdatedAt TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  -- Indexes
  KEY idx_created_at (CreatedAt),
  KEY idx_tags ((CAST(Tags AS CHAR(1000)))),  -- JSON tag index
  FULLTEXT INDEX ft_search (SearchText, TitleText, BodyText, RepliesText)
)
```

## Usage

### Basic Usage

```bash
# Process first 1000 posts
python3 stackexchange_posts.py --limit 1000

# Process with custom batch size
python3 stackexchange_posts.py --limit 10000 --batch-size 500

# Don't skip duplicates (process all posts)
python3 stackexchange_posts.py --limit 1000 --no-skip-duplicates
```

### Advanced Configuration

```bash
# Custom database connections
python3 stackexchange_posts.py \
    --source-host 192.168.1.100 \
    --source-port 3307 \
    --source-user myuser \
    --source-password mypass \
    --source-db my_stackexchange \
    --target-host 192.168.1.200 \
    --target-port 3306 \
    --target-user search_user \
    --target-password search_pass \
    --target-db search_db \
    --limit 50000 \
    --batch-size 1000
```

## Search Examples

Once processed, you can search the data using:

### 1. MySQL Full-Text Search

```sql
-- Basic search
SELECT PostId, Title
FROM processed_posts
WHERE MATCH(SearchText) AGAINST('mysql optimization' IN BOOLEAN MODE)
ORDER BY relevance DESC;

-- Boolean search operators
SELECT PostId, Title
FROM processed_posts
WHERE MATCH(SearchText) AGAINST('+database -oracle' IN BOOLEAN MODE);

-- Proximity search
SELECT PostId, Title
FROM processed_posts
WHERE MATCH(SearchText) AGAINST('"database performance"~5' IN BOOLEAN MODE);
```

### 2. Tag-based Search

```sql
-- Search by specific tags
SELECT PostId, Title
FROM processed_posts
WHERE JSON_CONTAINS(Tags, '"mysql"') AND JSON_CONTAINS(Tags, '"performance"');
```

### 3. Filtered Search

```sql
-- Search within date range
SELECT PostId, Title, JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.CreationDate')) as CreationDate
FROM processed_posts
WHERE MATCH(SearchText) AGAINST('python' IN BOOLEAN MODE)
AND JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.CreationDate')) BETWEEN '2023-01-01' AND '2023-12-31';
```

## Performance Tips

1. **Batch Size**: Use larger batches (1000-5000) for better throughput
2. **Memory**: Adjust batch size based on available memory
3. **Indexes**: The script automatically creates necessary indexes
4. **Parallel Processing**: Consider running multiple instances with different offset ranges

## Output Example

```
🚀 StackExchange Posts Processor
==================================================
Source: 127.0.0.1:3306/stackexchange
Target: 127.0.0.1:3306/stackexchange_post
Limit: 1000 posts
Batch size: 100
Skip duplicates: True
==================================================

✅ Connected to source and target databases
✅ Target table created successfully with all search columns

🔄 Processing batch 1 - posts 1 to 100
  ⏭️  Skipping 23 duplicate posts
  📝 Processing 77 posts...
  📊 Batch inserted 77 posts
  ⏱️  Progress: 100/1000 posts (10.0%)
  📈 Total processed: 77, Inserted: 77, Skipped: 23
  ⚡ Rate: 12.3 posts/sec

🎉 Processing complete!
   📊 Total batches: 10
   📝 Total processed: 800
   ✅ Total inserted: 800
   ⏭️  Total skipped: 200
   ⏱️  Total time: 45.2 seconds
   🚀 Average rate: 17.7 posts/sec

✅ Processing completed successfully!
```

## Troubleshooting

### Common Issues

1. **Table Creation Failed**: Check database permissions
2. **Memory Issues**: Reduce batch size
3. **Slow Performance**: Optimize MySQL configuration
4. **Connection Errors**: Verify database credentials

### Maintenance

```sql
-- Check table status
SHOW TABLE STATUS LIKE 'processed_posts';

-- Rebuild full-text index
ALTER TABLE processed_posts DROP INDEX ft_search,
  ADD FULLTEXT INDEX ft_search (SearchText, TitleText, BodyText, RepliesText);

-- Count processed posts
SELECT COUNT(*) FROM processed_posts;
```

## Requirements

- Python 3.7+
- mysql-connector-python
- MySQL 5.7+ (for JSON and full-text support)

Install dependencies:
```bash
pip install mysql-connector-python
```

## Other Scripts

The `scripts/` directory also contains other utility scripts:

- `nlp_search_demo.py` - Demonstrate various search techniques on processed posts:
  - Full-text search with MySQL
  - Boolean search with operators
  - Tag-based JSON queries
  - Combined search approaches
  - Statistics and search analytics
  - Data preparation for future semantic search

- `add_mysql_user.sh` - Add/replace MySQL users in ProxySQL
- `change_host_status.sh` - Change host status in ProxySQL
- `flush_query_cache.sh` - Flush ProxySQL query cache
- `kill_idle_backend_conns.py` - Kill idle backend connections
- `proxysql_config.sh` - Configure ProxySQL settings
- `stats_scrapper.py` - Scrape statistics from ProxySQL

## Search Examples

### Using the NLP Search Demo

```bash
# Show search statistics
python3 nlp_search_demo.py --mode stats

# Full-text search
python3 nlp_search_demo.py --mode full-text --query "mysql performance optimization"

# Boolean search with operators
python3 nlp_search_demo.py --mode boolean --query "+database -oracle"

# Search by tags
python3 nlp_search_demo.py --mode tags --tags mysql performance --operator AND

# Combined search with text and tags
python3 nlp_search_demo.py --mode combined --query "python optimization" --tags python

# Prepare data for semantic search
python3 nlp_search_demo.py --mode similarity --query "machine learning"
```

## License

Internal use only.
