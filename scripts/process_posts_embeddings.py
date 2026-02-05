#!/usr/bin/env python3
"""
Process Posts table embeddings using sqlite-rembed in ProxySQL SQLite3 server.

Connects to SQLite3 server via MySQL connector, configures API client,
and processes unembedded Posts rows in batches of 10.

Filters applied:
- Only PostTypeId IN (1,2) (Questions and Answers)
- Minimum text length > 30 characters (Title + Body)

Prerequisites:
1. Posts table must exist (copied from MySQL)
2. Posts_embeddings virtual table must exist:
   CREATE VIRTUAL TABLE Posts_embeddings USING vec0(embedding float[768]);

For remote API: Environment variable API_KEY must be set for API authentication.
For local Ollama: Use --local-ollama flag (no API_KEY required).
If Posts_embeddings table doesn't exist, the script will fail.

Usage Examples:

1. Remote API (requires API_KEY environment variable):
   export API_KEY='your-api-key'
   python3 process_posts_embeddings.py \
     --host 127.0.0.1 \
     --port 6030 \
     --user root \
     --password root \
     --database main \
     --client-name posts-embed-client \
     --batch-size 10

2. Local Ollama server (no API_KEY required):
   python3 process_posts_embeddings.py \
     --local-ollama \
     --host 127.0.0.1 \
     --port 6030 \
     --user root \
     --password root \
     --database main \
     --client-name posts-embed-client \
     --batch-size 10
"""

import os
import sys
import time
import argparse
import mysql.connector
from mysql.connector import Error

def parse_args():
    """Parse command line arguments."""
    epilog = """
Usage Examples:

1. Remote API (requires API_KEY environment variable):
   export API_KEY='your-api-key'
   python3 process_posts_embeddings.py --host 127.0.0.1 --port 6030

2. Local Ollama server (no API_KEY required):
   python3 process_posts_embeddings.py --local-ollama --host 127.0.0.1 --port 6030

See script docstring for full examples with all options.
"""
    parser = argparse.ArgumentParser(
        description='Process Posts table embeddings in ProxySQL SQLite3 server',
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--host', default='127.0.0.1',
                       help='ProxySQL SQLite3 server host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=6030,
                       help='ProxySQL SQLite3 server port (default: 6030)')
    parser.add_argument('--user', default='root',
                       help='Database user (default: root)')
    parser.add_argument('--password', default='root',
                       help='Database password (default: root)')
    parser.add_argument('--database', default='main',
                       help='Database name (default: main)')
    parser.add_argument('--client-name', default='posts-embed-client',
                       help='rembed client name (default: posts-embed-client)')
    parser.add_argument('--api-format', default='openai',
                       help='API format (default: openai)')
    parser.add_argument('--api-url', default='https://api.synthetic.new/openai/v1/embeddings',
                       help='API endpoint URL')
    parser.add_argument('--api-model', default='hf:nomic-ai/nomic-embed-text-v1.5',
                       help='Embedding model')
    parser.add_argument('--batch-size', type=int, default=10,
                       help='Batch size for embedding generation (default: 10)')
    parser.add_argument('--retry-delay', type=int, default=5,
                       help='Delay in seconds on error (default: 5)')
    parser.add_argument('--local-ollama', action='store_true',
                       help='Use local Ollama server instead of remote API (no API_KEY required)')

    return parser.parse_args()

def check_env(args):
    """Check required environment variables."""
    if args.local_ollama:
        # Local Ollama doesn't require API key
        return None
    api_key = os.getenv('API_KEY')
    if not api_key:
        print("ERROR: API_KEY environment variable must be set")
        print("Usage: export API_KEY='your-api-key'")
        sys.exit(1)
    return api_key

def connect_db(args):
    """Connect to SQLite3 server using MySQL connector."""
    try:
        conn = mysql.connector.connect(
            host=args.host,
            port=args.port,
            user=args.user,
            password=args.password,
            database=args.database,
            use_pure=True,
            ssl_disabled=True
        )
        return conn
    except Error as e:
        print(f"ERROR: Failed to connect to database: {e}")
        sys.exit(1)

def configure_client(conn, args, api_key):
    """Configure rembed API client."""
    cursor = conn.cursor()

    if args.local_ollama:
        # Local Ollama configuration
        insert_sql = f"""
        INSERT INTO temp.rembed_clients(name, options) VALUES
          (
            '{args.client_name}',
            rembed_client_options(
              'format', 'ollama',
              'url', 'http://localhost:11434/api/embeddings',
              'model', 'nomic-embed-text-v1.5'
            )
          );
        """
    else:
        # Remote API configuration
        insert_sql = f"""
        INSERT INTO temp.rembed_clients(name, options) VALUES
          (
            '{args.client_name}',
            rembed_client_options(
              'format', '{args.api_format}',
              'url', '{args.api_url}',
              'key', '{api_key}',
              'model', '{args.api_model}'
            )
          );
        """

    try:
        cursor.execute(insert_sql)
        conn.commit()
        print(f"✓ Configured API client '{args.client_name}'")
    except Error as e:
        print(f"ERROR: Failed to configure API client: {e}")
        print(f"SQL: {insert_sql[:200]}...")
        cursor.close()
        sys.exit(1)

    cursor.close()


def get_remaining_count(conn):
    """Get count of Posts without embeddings."""
    cursor = conn.cursor()

    count_sql = """
    SELECT COUNT(*)
    FROM Posts
    LEFT JOIN Posts_embeddings ON Posts.rowid = Posts_embeddings.rowid
    WHERE Posts.PostTypeId IN (1,2)
    AND LENGTH(COALESCE(Posts.Title || '', '') || Posts.Body) > 30
    AND Posts_embeddings.rowid IS NULL;
    """

    try:
        cursor.execute(count_sql)
        result = cursor.fetchone()
        if result and result[0] is not None:
            remaining = int(result[0])
        else:
            remaining = 0
        cursor.close()
        return remaining
    except Error as e:
        print(f"ERROR: Failed to count remaining rows: {e}")
        cursor.close()
        raise

def get_total_posts(conn):
    """Get total number of eligible Posts (PostTypeId 1,2 with text length > 30)."""
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT COUNT(*)
            FROM Posts
            WHERE PostTypeId IN (1,2)
            AND LENGTH(COALESCE(Posts.Title || '', '') || Posts.Body) > 30;
        """)
        result = cursor.fetchone()
        if result and result[0] is not None:
            total = int(result[0])
        else:
            total = 0
        cursor.close()
        return total
    except Error as e:
        print(f"ERROR: Failed to count total Posts: {e}")
        cursor.close()
        raise

def process_batch(conn, args):
    """Process a batch of unembedded Posts."""
    cursor = conn.cursor()

    insert_sql = f"""
    INSERT OR REPLACE INTO Posts_embeddings(rowid, embedding)
    SELECT Posts.rowid, rembed('{args.client_name}',
           COALESCE(Posts.Title || ' ', '') || Posts.Body) as embedding
    FROM Posts
    LEFT JOIN Posts_embeddings ON Posts.rowid = Posts_embeddings.rowid
    WHERE Posts.PostTypeId IN (1,2)
    AND LENGTH(COALESCE(Posts.Title || '', '') || Posts.Body) > 30
    AND Posts_embeddings.rowid IS NULL
    LIMIT {args.batch_size};
    """

    try:
        cursor.execute(insert_sql)
        conn.commit()
        processed = cursor.rowcount
        cursor.close()
        return processed, None
    except Error as e:
        cursor.close()
        return 0, str(e)

def main():
    """Main processing loop."""
    args = parse_args()
    api_key = check_env(args)

    print("=" * 60)
    print("Posts Table Embeddings Processor")
    print("=" * 60)
    print(f"Host: {args.host}:{args.port}")
    print(f"Database: {args.database}")
    print(f"API Client: {args.client_name}")
    print(f"Batch Size: {args.batch_size}")
    if args.local_ollama:
        print(f"Mode: Local Ollama")
        print(f"URL: http://localhost:11434/api/embeddings")
        print(f"Model: nomic-embed-text-v1.5")
    else:
        print(f"Mode: Remote API")
        print(f"API URL: {args.api_url}")
        print(f"Model: {args.api_model}")
    print("=" * 60)

    # Connect to database
    conn = connect_db(args)

    # Configure API client
    configure_client(conn, args, api_key)

    # Get initial counts
    try:
        total_posts = get_total_posts(conn)
        remaining = get_remaining_count(conn)
        processed = total_posts - remaining

        print(f"\nInitial status:")
        print(f"  Total Posts: {total_posts}")
        print(f"  Already embedded: {processed}")
        print(f"  Remaining: {remaining}")
        print("-" * 40)
    except Error as e:
        print(f"ERROR: Failed to get initial counts: {e}")
        conn.close()
        sys.exit(1)

    if remaining == 0:
        print("✓ All Posts already have embeddings. Nothing to do.")
        conn.close()
        sys.exit(0)

    # Main processing loop
    iteration = 0
    total_processed = processed
    consecutive_failures = 0
    MAX_BACKOFF_SECONDS = 300  # 5 minutes maximum backoff

    while True:
        iteration += 1

        # Get current remaining count
        try:
            remaining = get_remaining_count(conn)
        except Error as e:
            print(f"ERROR: Failed to get remaining count: {e}")
            conn.close()
            sys.exit(1)

        if remaining == 0:
            print(f"\n✓ All {total_posts} Posts have embeddings!")
            break

        # Show progress
        if total_posts > 0:
            progress_percent = (total_processed / total_posts) * 100
            progress_str = f" ({progress_percent:.1f}%)"
        else:
            progress_str = ""
        print(f"\nIteration {iteration}:")
        print(f"  Remaining: {remaining}")
        print(f"  Processed: {total_processed}/{total_posts}{progress_str}")

        # Process batch
        processed_count, error = process_batch(conn, args)

        if error:
            consecutive_failures += 1
            backoff_delay = min(args.retry_delay * (2 ** (consecutive_failures - 1)), MAX_BACKOFF_SECONDS)
            print(f"  ✗ Batch failed: {error}")
            print(f"  Consecutive failures: {consecutive_failures}")
            print(f"  Waiting {backoff_delay} seconds before retry...")
            time.sleep(backoff_delay)
            continue

        # Reset consecutive failures on any successful operation (even if no rows processed)
        consecutive_failures = 0

        if processed_count > 0:
            total_processed += processed_count
            print(f"  ✓ Processed {processed_count} rows")
            # Continue immediately (no delay on success)
        else:
            print(f"  ⓘ No rows processed (possibly concurrent process?)")
            # Small delay if no rows processed (could be race condition)
            time.sleep(1)

    # Final summary
    print("\n" + "=" * 60)
    print("Processing Complete!")
    print(f"Total Posts: {total_posts}")
    print(f"Total with embeddings: {total_processed}")
    if total_posts > 0:
        success_percent = (total_processed / total_posts) * 100
        print(f"Success rate: {success_percent:.1f}%")
    else:
        print("Success rate: N/A (no posts)")
    print("=" * 60)

    conn.close()

if __name__ == "__main__":
    main()
