#!/usr/bin/env python3
"""
NLP Search Demo for StackExchange Posts

Demonstrates various search techniques on processed posts:
- Full-text search with MySQL
- Boolean search with operators
- Tag-based JSON queries
- Combined search approaches
- Statistics and search analytics
- Data preparation for future semantic search
"""

import mysql.connector
from mysql.connector import Error, OperationalError
import json
import re
import html
from typing import List, Dict, Any, Set, Tuple
import argparse
import time
import sys
import os


class NLPSearchDemo:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.stop_words = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by',
            'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did',
            'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can', 'this', 'that', 'these', 'those',
            'i', 'you', 'he', 'she', 'it', 'we', 'they', 'me', 'him', 'her', 'us', 'them', 'my', 'your', 'his', 'its', 'our', 'their'
        }

    def connect(self):
        """Create database connection."""
        try:
            conn = mysql.connector.connect(**self.config)
            print("✅ Connected to database")
            return conn
        except Error as e:
            print(f"❌ Connection error: {e}")
            return None

    def get_table_stats(self, conn):
        """Get statistics about the processed_posts table."""
        cursor = conn.cursor(dictionary=True)

        try:
            # Basic table stats
            cursor.execute("SELECT COUNT(*) as total_posts FROM processed_posts")
            total_posts = cursor.fetchone()['total_posts']

            cursor.execute("SELECT COUNT(*) as posts_with_tags FROM processed_posts WHERE Tags IS NOT NULL AND Tags != '[]'")
            posts_with_tags = cursor.fetchone()['posts_with_tags']

            cursor.execute("SELECT MIN(JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.CreationDate'))) as earliest, "
                         "MAX(JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.CreationDate'))) as latest "
                         "FROM processed_posts")
            date_range = cursor.fetchone()

            # Get unique tags
            cursor.execute("""
                SELECT DISTINCT Tags
                FROM processed_posts
                WHERE Tags IS NOT NULL AND Tags != '[]'
                LIMIT 1000
            """)
            tags_data = cursor.fetchall()

            # Extract all unique tags
            all_tags = set()
            for row in tags_data:
                if row['Tags']:
                    try:
                        tags_list = json.loads(row['Tags'])
                        all_tags.update(tags_list)
                    except:
                        pass

            print(f"\n📊 Table Statistics:")
            print(f"   Total posts: {total_posts:,}")
            if total_posts > 0:
                print(f"   Posts with tags: {posts_with_tags:,} ({posts_with_tags/total_posts*100:.1f}%)")
            else:
                print(f"   Posts with tags: {posts_with_tags:,}")
            print(f"   Date range: {date_range['earliest'][:10]} to {date_range['latest'][:10]}")
            print(f"   Unique tags: {len(all_tags):,}")

            if all_tags:
                print(f"   Top tags: {', '.join(sorted(list(all_tags))[:20])}")

        except Error as e:
            print(f"❌ Error getting stats: {e}")
        finally:
            cursor.close()

    def full_text_search(self, conn, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Perform full-text search with MySQL."""
        cursor = conn.cursor(dictionary=True)

        start_time = time.time()
        try:
            sql = """
            SELECT PostId, TitleText, MATCH(SearchText) AGAINST(%s IN NATURAL LANGUAGE MODE) as relevance
            FROM processed_posts
            WHERE MATCH(SearchText) AGAINST(%s IN NATURAL LANGUAGE MODE)
            ORDER BY relevance DESC, CreatedAt DESC LIMIT %s
            """
            cursor.execute(sql, (query, query, limit))
            results = cursor.fetchall()
            search_method = "full-text"
        except Error:
            sql = """
            SELECT PostId, TitleText, CreatedAt
            FROM processed_posts
            WHERE SearchText LIKE %s OR TitleText LIKE %s OR BodyText LIKE %s
            ORDER BY CreatedAt DESC LIMIT %s
            """
            search_term = f"%{query}%"
            cursor.execute(sql, (search_term, search_term, search_term, limit))
            results = cursor.fetchall()
            search_method = "LIKE"

        elapsed = time.time() - start_time

        print(f"🔍 {search_method.title()} search for '{query}' ({elapsed:.3f}s):")
        for i, row in enumerate(results, 1):
            print(f"  {i}. [{row['PostId']}] {row['TitleText'][:80]}...")

        print(f"📊 Found {len(results)} results in {elapsed:.3f} seconds")
        return results

    def boolean_search(self, conn, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Perform boolean search with operators."""
        cursor = conn.cursor(dictionary=True)
        start_time = time.time()

        try:
            # Try boolean mode first
            sql = """
            SELECT PostId, TitleText,
                   MATCH(SearchText) AGAINST(%s IN BOOLEAN MODE) as relevance
            FROM processed_posts
            WHERE MATCH(SearchText) AGAINST(%s IN BOOLEAN MODE)
            ORDER BY relevance DESC, CreatedAt DESC LIMIT %s
            """
            cursor.execute(sql, (query, query, limit))
            results = cursor.fetchall()
            search_method = "boolean"
        except Error:
            # Fallback to LIKE search
            sql = """
            SELECT PostId, TitleText, CreatedAt
            FROM processed_posts
            WHERE SearchText LIKE %s
            ORDER BY CreatedAt DESC LIMIT %s
            """
            search_term = f"%{query}%"
            cursor.execute(sql, (search_term, limit))
            results = cursor.fetchall()
            search_method = "LIKE"

        elapsed = time.time() - start_time

        print(f"🔍 Boolean search for '{query}' ({elapsed:.3f}s):")
        for i, row in enumerate(results, 1):
            print(f"  {i}. [{row['PostId']}] {row['TitleText'][:80]}...")

        print(f"📊 Found {len(results)} results in {elapsed:.3f} seconds")
        return results

    def tag_search(self, conn, tags: List[str], operator: str = "AND", limit: int = 10) -> List[Dict[str, Any]]:
        """Search by tags using JSON functions."""
        cursor = conn.cursor(dictionary=True)

        try:
            # Build JSON_CONTAINS conditions
            conditions = []
            params = []

            for tag in tags:
                conditions.append(f"JSON_CONTAINS(Tags, %s)")
                params.append(f'"{tag}"')

            if operator.upper() == "AND":
                where_clause = " AND ".join(conditions)
            else:  # OR
                where_clause = " OR ".join(conditions)

            sql = f"""
            SELECT
                PostId,
                TitleText,
                JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.Tags')) as TagsJson,
                CreatedAt
            FROM processed_posts
            WHERE {where_clause}
            ORDER BY CreatedAt DESC
            LIMIT %s
            """

            start_time = time.time()
            cursor.execute(sql, params + [limit])
            results = cursor.fetchall()
            search_method = "JSON_CONTAINS"

            elapsed = time.time() - start_time

            tag_str = " AND ".join(tags) if operator == "AND" else " OR ".join(tags)
            print(f"🏷️  Tag search for {tag_str} ({elapsed:.3f}s):")
            for i, row in enumerate(results, 1):
                found_tags = json.loads(row['TagsJson']) if row['TagsJson'] else []
                print(f"  {i}. [{row['PostId']}] {row['TitleText'][:80]}...")
                print(f"     All tags: {', '.join(found_tags[:5])}{'...' if len(found_tags) > 5 else ''}")
                print()

            print(f"📊 Found {len(results)} results in {elapsed:.3f} seconds")
            return results

        except Error as e:
            print(f"❌ Tag search error: {e}")
            return []
        finally:
            cursor.close()

    def combined_search(self, conn, search_term: str = None, tags: List[str] = None,
                        date_from: str = None, date_to: str = None, limit: int = 10) -> List[Dict[str, Any]]:
        """Combined search with full-text, tags, and date filtering."""
        cursor = conn.cursor(dictionary=True)

        try:
            conditions = []
            params = []

            # Full-text search condition
            if search_term:
                conditions.append("MATCH(SearchText) AGAINST(%s IN NATURAL LANGUAGE MODE)")
                params.append(search_term)

            # Tag conditions
            if tags:
                for tag in tags:
                    conditions.append("JSON_CONTAINS(Tags, %s)")
                    params.append(f'"{tag}"')

            # Date conditions
            if date_from:
                conditions.append("JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.CreationDate')) >= %s")
                params.append(date_from)

            if date_to:
                conditions.append("JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.CreationDate')) <= %s")
                params.append(date_to)

            # Build WHERE clause
            where_clause = " AND ".join(conditions) if conditions else "1=1"

            # Build SELECT clause dynamically - only include relevance if search_term is provided
            if search_term:
                select_clause = """
                SELECT
                    PostId,
                    TitleText,
                    JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.CreationDate')) as CreationDate,
                    JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.Tags')) as TagsJson,
                    MATCH(SearchText) AGAINST(%s IN NATURAL LANGUAGE MODE) as relevance,
                    CreatedAt
                """
                order_clause = "ORDER BY relevance DESC, CreatedAt DESC"
                # Add search_term again for the SELECT clause's MATCH
                fulltext_params = [search_term] + params + [limit]
            else:
                select_clause = """
                SELECT
                    PostId,
                    TitleText,
                    JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.CreationDate')) as CreationDate,
                    JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.Tags')) as TagsJson,
                    CreatedAt
                """
                order_clause = "ORDER BY CreatedAt DESC"
                fulltext_params = params + [limit]

            sql = f"""
            {select_clause}
            FROM processed_posts
            WHERE {where_clause}
            {order_clause}
            LIMIT %s
            """

            start_time = time.time()

            try:
                # First try full-text search
                cursor.execute(sql, fulltext_params)
                results = cursor.fetchall()
                search_method = "combined"
            except Error:
                # Fallback to LIKE search
                conditions = []
                like_params = []

                # Add search term condition
                if search_term:
                    conditions.append("(SearchText LIKE %s OR TitleText LIKE %s OR BodyText LIKE %s)")
                    like_params.extend([f"%{search_term}%"] * 3)

                # Add tag conditions
                if tags:
                    for tag in tags:
                        conditions.append("JSON_CONTAINS(Tags, %s)")
                        like_params.append(f'"{tag}"')

                # Add date conditions
                if date_from:
                    conditions.append("JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.CreationDate')) >= %s")
                    like_params.append(date_from)

                if date_to:
                    conditions.append("JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.CreationDate')) <= %s")
                    like_params.append(date_to)

                where_clause = " AND ".join(conditions) if conditions else "1=1"

                like_sql = f"""
                SELECT
                    PostId,
                    TitleText,
                    JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.CreationDate')) as CreationDate,
                    JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.Tags')) as TagsJson,
                    CreatedAt
                FROM processed_posts
                WHERE {where_clause}
                ORDER BY CreatedAt DESC
                LIMIT %s
                """

                like_params.append(limit)
                cursor.execute(like_sql, like_params)
                results = cursor.fetchall()
                search_method = "LIKE"

            elapsed = time.time() - start_time

            print(f"🔍 {search_method.title()} search ({elapsed:.3f}s):")
            print(f"   Search term: {search_term or 'None'}")
            print(f"   Tags: {tags or 'None'}")
            print(f"   Date range: {date_from or 'beginning'} to {date_to or 'end'}")
            print()

            for i, row in enumerate(results, 1):
                found_tags = json.loads(row['TagsJson']) if row['TagsJson'] else []
                relevance = row.get('relevance', 0.0) if search_method == "combined" else "N/A"

                print(f"  {i}. [{row['PostId']}] {row['TitleText'][:80]}...")
                print(f"     Tags: {', '.join(found_tags[:3])}{'...' if len(found_tags) > 3 else ''}")
                print(f"     Created: {row['CreationDate']}")
                if search_method == "combined":
                    print(f"     Relevance: {relevance:.3f}")
                print()

            print(f"📊 Found {len(results)} results in {elapsed:.3f} seconds")
            return results

        except Error as e:
            print(f"❌ Combined search error: {e}")
            return []
        finally:
            cursor.close()

    def similarity_search_preparation(self, conn, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Prepare data for future semantic search by extracting relevant terms."""
        cursor = conn.cursor(dictionary=True)

        try:
            # Search and return results with text content for future embedding generation
            sql = """
            SELECT
                PostId,
                TitleText,
                BodyText,
                RepliesText,
                JSON_UNQUOTE(JSON_EXTRACT(JsonData, '$.Tags')) as TagsJson
            FROM processed_posts
            WHERE SearchText LIKE %s
            ORDER BY CreatedAt DESC
            LIMIT %s
            """

            search_term = f"%{query}%"
            cursor.execute(sql, (search_term, limit))
            results = cursor.fetchall()

            print(f"🔍 Preparation for semantic search on '{query}':")
            print(f"   Found {len(results)} relevant posts")

            # Extract text for future embeddings
            all_text = []
            for row in results:
                title = row['TitleText'] or ''
                body = row['BodyText'] or ''
                replies = row['RepliesText'] or ''
                combined = f"{title} {body} {replies}".strip()
                if combined:
                    all_text.append(combined)

            print(f"   Total text length: {sum(len(text) for text in all_text):,} characters")
            if all_text:
                print(f"   Average text length: {sum(len(text) for text in all_text) / len(all_text):,.0f} characters")

            return results

        except Error as e:
            print(f"❌ Similarity search preparation error: {e}")
            return []
        finally:
            cursor.close()

    def run_demo(self, mode: str = "stats", **kwargs):
        """Run the search demo with specified mode."""
        conn = self.connect()
        if not conn:
            return

        try:
            if mode == "stats":
                self.get_table_stats(conn)
            elif mode == "full-text":
                query = kwargs.get('query', '')
                limit = kwargs.get('limit', 10)
                self.full_text_search(conn, query, limit)
            elif mode == "boolean":
                query = kwargs.get('query', '')
                limit = kwargs.get('limit', 10)
                self.boolean_search(conn, query, limit)
            elif mode == "tags":
                tags = kwargs.get('tags', [])
                operator = kwargs.get('operator', 'AND')
                limit = kwargs.get('limit', 10)
                self.tag_search(conn, tags, operator, limit)
            elif mode == "combined":
                search_term = kwargs.get('query', None)
                tags = kwargs.get('tags', None)
                date_from = kwargs.get('date_from', None)
                date_to = kwargs.get('date_to', None)
                limit = kwargs.get('limit', 10)
                self.combined_search(conn, search_term, tags, date_from, date_to, limit)
            elif mode == "similarity":
                query = kwargs.get('query', '')
                limit = kwargs.get('limit', 20)
                self.similarity_search_preparation(conn, query, limit)
            else:
                print(f"❌ Unknown mode: {mode}")
                print("Available modes: stats, full-text, boolean, tags, combined, similarity")
        finally:
            if conn and conn.is_connected():
                conn.close()


def main():
    # Default configuration (can be overridden by environment variables)
    config = {
        "host": os.getenv("DB_HOST", "127.0.0.1"),
        "port": int(os.getenv("DB_PORT", "3306")),
        "user": os.getenv("DB_USER", "stackexchange"),
        "password": os.getenv("DB_PASSWORD", "my-password"),
        "database": os.getenv("DB_NAME", "stackexchange_post"),
        "use_pure": True,
        "ssl_disabled": True
    }

    parser = argparse.ArgumentParser(description="NLP Search Demo for StackExchange Posts")

    parser.add_argument("--host", default=config['host'], help="Database host")
    parser.add_argument("--port", type=int, default=config['port'], help="Database port")
    parser.add_argument("--user", default=config['user'], help="Database user")
    parser.add_argument("--password", default=config['password'], help="Database password")
    parser.add_argument("--database", default=config['database'], help="Database name")

    parser.add_argument("--mode", default="stats",
                       choices=["stats", "full-text", "boolean", "tags", "combined", "similarity"],
                       help="Search mode to demonstrate")

    parser.add_argument("--limit", type=int, default=10, help="Number of results to return")
    parser.add_argument("--operator", default="AND", choices=["AND", "OR"], help="Tag operator")

    parser.add_argument("--query", help="Search query for text-based searches")
    parser.add_argument("--tags", nargs='+', help="Tags to search for")
    parser.add_argument("--date-from", help="Start date (YYYY-MM-DD)")
    parser.add_argument("--date-to", help="End date (YYYY-MM-DD)")

    parser.add_argument("--stats", action="store_true", help="Show table statistics")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")

    args = parser.parse_args()

    # Override configuration with command line arguments
    config.update({
        "host": args.host,
        "port": args.port,
        "user": args.user,
        "password": args.password,
        "database": args.database
    })

    # Handle legacy --stats flag
    if args.stats:
        args.mode = "stats"

    print("🔍 NLP Search Demo for StackExchange Posts")
    print("=" * 50)
    print(f"Database: {config['host']}:{config['port']}/{config['database']}")
    print(f"Mode: {args.mode}")
    print("=" * 50)

    # Create demo instance and run
    demo = NLPSearchDemo(config)

    # Prepare kwargs based on mode
    kwargs = {
        'limit': args.limit,
        'operator': args.operator,
        'query': args.query,
        'tags': args.tags,
        'date_from': args.date_from,
        'date_to': args.date_to
    }

    # Remove None values
    kwargs = {k: v for k, v in kwargs.items() if v is not None}

    # If mode is text-based and no query provided, use the mode as query
    if args.mode in ["full-text", "boolean", "similarity"] and not args.query:
        # For compatibility with command-line usage like: python3 script.py --full-text "mysql optimization"
        if len(sys.argv) > 2 and sys.argv[1] == "--mode" and len(sys.argv) > 4:
            # Find the actual query after the mode
            mode_index = sys.argv.index("--mode")
            if mode_index + 2 < len(sys.argv):
                query_index = mode_index + 2
                query_parts = []
                while query_index < len(sys.argv) and not sys.argv[query_index].startswith("--"):
                    query_parts.append(sys.argv[query_index])
                    query_index += 1
                if query_parts:
                    kwargs['query'] = ' '.join(query_parts)

    demo.run_demo(args.mode, **kwargs)


if __name__ == "__main__":
    main()