#!/usr/bin/env python3
"""
Comprehensive StackExchange Posts Processing Script

Creates target table, extracts data from source, and processes for search.
- Retrieves parent posts (PostTypeId=1) and their replies (PostTypeId=2)
- Combines posts and tags into structured JSON
- Creates search-ready columns with full-text indexes
- Supports batch processing and duplicate checking
- Handles large datasets efficiently
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

class StackExchangeProcessor:
    def __init__(self, source_config: Dict[str, Any], target_config: Dict[str, Any]):
        self.source_config = source_config
        self.target_config = target_config
        self.stop_words = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by',
            'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did',
            'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can', 'this', 'that', 'these', 'those',
            'i', 'you', 'he', 'she', 'it', 'we', 'they', 'me', 'him', 'her', 'us', 'them', 'my', 'your', 'his', 'its', 'our', 'their'
        }

    def clean_text(self, text: str) -> str:
        """Clean and normalize text for search indexing."""
        if not text:
            return ""

        # Decode HTML entities
        text = html.unescape(text)

        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)

        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()

        # Convert to lowercase
        return text.lower()

    def parse_tags(self, tags_string: str) -> Set[str]:
        """Parse HTML-like tags string and extract unique tag values."""
        if not tags_string:
            return set()

        # Extract content between < and > tags
        tags = re.findall(r'<([^<>]+)>', tags_string)
        return set(tag.strip().lower() for tag in tags if tag.strip())

    def create_target_table(self, conn) -> bool:
        """Create the target table with all necessary columns."""
        cursor = conn.cursor()

        # SQL to create table with all search columns
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS `processed_posts` (
          `PostId` BIGINT NOT NULL,
          `JsonData` JSON NOT NULL,
          `Embeddings` BLOB NULL,
          `SearchText` LONGTEXT NULL COMMENT 'Combined text content for full-text search',
          `TitleText` VARCHAR(1000) NULL COMMENT 'Processed title text',
          `BodyText` LONGTEXT NULL COMMENT 'Processed body text',
          `RepliesText` LONGTEXT NULL COMMENT 'Combined replies text',
          `Tags` JSON NULL COMMENT 'Extracted tags',
          `CreatedAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          `UpdatedAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          PRIMARY KEY (`PostId`),
          KEY `idx_created_at` (`CreatedAt`),
          -- KEY `idx_tags` ((CAST(Tags AS CHAR(1000) CHARSET utf8mb4))),  -- Commented out for compatibility
          FULLTEXT INDEX `ft_search` (`SearchText`, `TitleText`, `BodyText`, `RepliesText`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        COMMENT='Structured StackExchange posts data with search capabilities'
        """

        try:
            cursor.execute(create_table_sql)
            conn.commit()
            print("✅ Target table created successfully with all search columns")
            return True
        except Error as e:
            print(f"❌ Error creating target table: {e}")
            return False
        finally:
            cursor.close()

    def get_parent_posts(self, conn, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve parent posts (PostTypeId=1) with pagination."""
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT Id, Title, CreationDate, Body, Tags
        FROM Posts
        WHERE PostTypeId = 1
        ORDER BY Id
        LIMIT %s OFFSET %s
        """

        try:
            cursor.execute(query, (limit, offset))
            posts = cursor.fetchall()
            return posts
        except Error as e:
            print(f"Error retrieving parent posts: {e}")
            return []
        finally:
            cursor.close()

    def get_child_posts(self, conn, parent_ids: List[int], chunk_size: int = 1000) -> Dict[int, List[str]]:
        """Retrieve child posts for given parent IDs with chunking."""
        if not parent_ids:
            return {}

        parent_to_children = {}

        # Process parent IDs in chunks
        for i in range(0, len(parent_ids), chunk_size):
            chunk = parent_ids[i:i + chunk_size]

            cursor = conn.cursor(dictionary=True)
            query = """
            SELECT ParentId, Body, Id as ReplyId
            FROM Posts
            WHERE PostTypeId = 2 AND ParentId IN (%s)
            ORDER BY ParentId, ReplyId
            """ % (','.join(['%s'] * len(chunk)))

            try:
                cursor.execute(query, chunk)
                child_posts = cursor.fetchall()

                for child in child_posts:
                    parent_id = child['ParentId']
                    if parent_id not in parent_to_children:
                        parent_to_children[parent_id] = []
                    parent_to_children[parent_id].append(child['Body'])

            except Error as e:
                print(f"Error retrieving child posts (chunk {i//chunk_size + 1}): {e}")
            finally:
                cursor.close()

        return parent_to_children

    def get_existing_posts(self, conn, post_ids: List[int]) -> Set[int]:
        """Check which post IDs already exist in the target table."""
        if not post_ids:
            return set()

        cursor = conn.cursor()
        placeholders = ','.join(['%s'] * len(post_ids))
        query = f"SELECT PostId FROM processed_posts WHERE PostId IN ({placeholders})"

        try:
            cursor.execute(query, post_ids)
            existing_ids = {row[0] for row in cursor.fetchall()}
            return existing_ids
        except Error as e:
            print(f"Error checking existing posts: {e}")
            return set()
        finally:
            cursor.close()

    def process_post_for_search(self, post_data: Dict[str, Any], replies: List[str], tags: Set[str]) -> Dict[str, str]:
        """Process a post and extract search-ready text."""
        # Extract title
        title = self.clean_text(post_data.get('Title', ''))

        # Extract body
        body = self.clean_text(post_data.get('Body', ''))

        # Process replies
        replies_text = ' '.join([self.clean_text(reply) for reply in replies if reply])

        # Combine all text for search
        combined_text = f"{title} {body} {replies_text}"

        # Add tags to search text
        if tags:
            combined_text += ' ' + ' '.join(tags)

        return {
            'title_text': title,
            'body_text': body,
            'replies_text': replies_text,
            'search_text': combined_text,
            'tags': list(tags) if tags else []
        }

    def insert_posts_batch(self, conn, posts_data: List[tuple]) -> int:
        """Insert multiple posts in a batch."""
        if not posts_data:
            return 0

        cursor = conn.cursor()
        query = """
        INSERT INTO processed_posts (PostId, JsonData, SearchText, TitleText, BodyText, RepliesText, Tags)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            JsonData = VALUES(JsonData),
            SearchText = VALUES(SearchText),
            TitleText = VALUES(TitleText),
            BodyText = VALUES(BodyText),
            RepliesText = VALUES(RepliesText),
            Tags = VALUES(Tags),
            UpdatedAt = CURRENT_TIMESTAMP
        """

        try:
            cursor.executemany(query, posts_data)
            conn.commit()
            inserted = cursor.rowcount
            print(f"  📊 Batch inserted {inserted} posts")
            return inserted
        except Error as e:
            print(f"  ❌ Error in batch insert: {e}")
            conn.rollback()
            return 0
        finally:
            cursor.close()

    def process_posts(self, limit: int = 10, batch_size: int = 100, skip_duplicates: bool = True) -> Dict[str, int]:
        """Main processing method."""
        source_conn = None
        target_conn = None

        stats = {
            'total_batches': 0,
            'total_processed': 0,
            'total_inserted': 0,
            'total_skipped': 0,
            'start_time': time.time()
        }

        try:
            # Connect to databases
            source_conn = mysql.connector.connect(**self.source_config)
            target_conn = mysql.connector.connect(**self.target_config)

            print("✅ Connected to source and target databases")

            # Create target table
            if not self.create_target_table(target_conn):
                print("❌ Failed to create target table")
                return stats

            offset = 0
            # Handle limit=0 (process all posts)
            total_limit = float('inf') if limit == 0 else limit

            while offset < total_limit:
                # Calculate current batch size
                if limit == 0:
                    current_batch_size = batch_size
                else:
                    current_batch_size = min(batch_size, limit - offset)

                # Get parent posts
                parent_posts = self.get_parent_posts(source_conn, current_batch_size, offset)
                if not parent_posts:
                    print("📄 No more parent posts to process")
                    # Special handling for limit=0 - break when no more posts
                    if limit == 0:
                        break
                    # For finite limits, break when we've processed all posts
                    if offset >= limit:
                        break

                stats['total_batches'] += 1
                print(f"\n🔄 Processing batch {stats['total_batches']} - posts {offset + 1} to {offset + len(parent_posts)}")

                # Get parent IDs
                parent_ids = [post['Id'] for post in parent_posts]

                # Check for duplicates
                if skip_duplicates:
                    existing_posts = self.get_existing_posts(target_conn, parent_ids)
                    parent_posts = [p for p in parent_posts if p['Id'] not in existing_posts]

                    duplicates_count = len(parent_ids) - len(parent_posts)
                    if duplicates_count > 0:
                        print(f"  ⏭️  Skipping {duplicates_count} duplicate posts")

                    if not parent_posts:
                        stats['total_skipped'] += len(parent_ids)
                        offset += current_batch_size
                        print(f"  ✅ All posts skipped (already exist)")
                        continue

                # Get child posts and tags
                child_posts_map = self.get_child_posts(source_conn, parent_ids)

                # Extract tags from parent posts
                all_tags = {}
                for post in parent_posts:
                    tags_from_source = self.parse_tags(post.get('Tags', ''))
                    all_tags[post['Id']] = tags_from_source

                # Process posts
                batch_data = []
                processed_count = 0

                for parent in parent_posts:
                    post_id = parent['Id']
                    replies = child_posts_map.get(post_id, [])
                    tags = all_tags.get(post_id, set())

                    # Get creation date
                    creation_date = parent.get('CreationDate')
                    if creation_date:
                        creation_date_str = creation_date.isoformat()
                    else:
                        creation_date_str = None

                    # Create JSON structure
                    post_json = {
                        "Id": post_id,
                        "Title": parent['Title'],
                        "CreationDate": creation_date_str,
                        "Body": parent['Body'],
                        "Replies": replies,
                        "Tags": sorted(list(tags))
                    }

                    # Process for search
                    search_data = self.process_post_for_search(parent, replies, tags)

                    # Add to batch
                    batch_data.append((
                        post_id,
                        json.dumps(post_json, ensure_ascii=False),
                        search_data['search_text'],
                        search_data['title_text'],
                        search_data['body_text'],
                        search_data['replies_text'],
                        json.dumps(search_data['tags'], ensure_ascii=False)
                    ))

                    processed_count += 1

                # Insert batch
                if batch_data:
                    print(f"  📝 Processing {len(batch_data)} posts...")
                    inserted = self.insert_posts_batch(target_conn, batch_data)
                    stats['total_inserted'] += inserted
                    stats['total_processed'] += processed_count

                # Advance offset
                offset += current_batch_size

                # Show progress
                elapsed = time.time() - stats['start_time']
                if limit == 0:
                    print(f"  ⏱️  Progress: {offset} posts processed")
                else:
                    print(f"  ⏱️  Progress: {offset}/{limit} posts ({offset/limit*100:.1f}%)")
                print(f"  📈 Total processed: {stats['total_processed']}, "
                      f"Inserted: {stats['total_inserted']}, "
                      f"Skipped: {stats['total_skipped']}")
                if elapsed > 0:
                    print(f"  ⚡ Rate: {stats['total_processed']/elapsed:.1f} posts/sec")

            stats['end_time'] = time.time()
            total_time = stats['end_time'] - stats['start_time']

            print(f"\n🎉 Processing complete!")
            print(f"   📊 Total batches: {stats['total_batches']}")
            print(f"   📝 Total processed: {stats['total_processed']}")
            print(f"   ✅ Total inserted: {stats['total_inserted']}")
            print(f"   ⏭️  Total skipped: {stats['total_skipped']}")
            print(f"   ⏱️  Total time: {total_time:.1f} seconds")
            if total_time > 0:
                print(f"   🚀 Average rate: {stats['total_processed']/total_time:.1f} posts/sec")

            return stats

        except Error as e:
            print(f"❌ Database error: {e}")
            return stats
        except Exception as e:
            print(f"❌ Error: {e}")
            return stats
        finally:
            if source_conn and source_conn.is_connected():
                source_conn.close()
            if target_conn and target_conn.is_connected():
                target_conn.close()
            print("\n🔌 Database connections closed")

def main():
    # Default configurations (can be overridden by environment variables)
    source_config = {
        "host": os.getenv("SOURCE_DB_HOST", "127.0.0.1"),
        "port": int(os.getenv("SOURCE_DB_PORT", "3306")),
        "user": os.getenv("SOURCE_DB_USER", "stackexchange"),
        "password": os.getenv("SOURCE_DB_PASSWORD", "my-password"),
        "database": os.getenv("SOURCE_DB_NAME", "stackexchange"),
        "use_pure": True,
        "ssl_disabled": True
    }

    target_config = {
        "host": os.getenv("TARGET_DB_HOST", "127.0.0.1"),
        "port": int(os.getenv("TARGET_DB_PORT", "3306")),
        "user": os.getenv("TARGET_DB_USER", "stackexchange"),
        "password": os.getenv("TARGET_DB_PASSWORD", "my-password"),
        "database": os.getenv("TARGET_DB_NAME", "stackexchange_post"),
        "use_pure": True,
        "ssl_disabled": True
    }

    parser = argparse.ArgumentParser(description="Comprehensive StackExchange Posts Processing")
    parser.add_argument("--source-host", default=source_config['host'], help="Source database host")
    parser.add_argument("--source-port", type=int, default=source_config['port'], help="Source database port")
    parser.add_argument("--source-user", default=source_config['user'], help="Source database user")
    parser.add_argument("--source-password", default=source_config['password'], help="Source database password")
    parser.add_argument("--source-db", default=source_config['database'], help="Source database name")

    parser.add_argument("--target-host", default=target_config['host'], help="Target database host")
    parser.add_argument("--target-port", type=int, default=target_config['port'], help="Target database port")
    parser.add_argument("--target-user", default=target_config['user'], help="Target database user")
    parser.add_argument("--target-password", default=target_config['password'], help="Target database password")
    parser.add_argument("--target-db", default=target_config['database'], help="Target database name")

    parser.add_argument("--limit", type=int, default=10, help="Number of parent posts to process")
    parser.add_argument("--batch-size", type=int, default=100, help="Batch size for processing")
    parser.add_argument("--warning-large-batches", action="store_true", help="Show warnings for batch sizes > 1000")
    parser.add_argument("--skip-duplicates", action="store_true", default=True, help="Skip posts that already exist")
    parser.add_argument("--no-skip-duplicates", action="store_true", help="Disable duplicate skipping")

    parser.add_argument("--verbose", action="store_true", help="Show detailed progress")

    args = parser.parse_args()

    # Override configurations with command line arguments
    source_config.update({
        "host": args.source_host,
        "port": args.source_port,
        "user": args.source_user,
        "password": args.source_password,
        "database": args.source_db
    })

    target_config.update({
        "host": args.target_host,
        "port": args.target_port,
        "user": args.target_user,
        "password": args.target_password,
        "database": args.target_db
    })

    skip_duplicates = args.skip_duplicates and not args.no_skip_duplicates

    # Check for large batch size
    if args.warning_large_batches and args.batch_size > 1000:
        print(f"⚠️  WARNING: Large batch size ({args.batch_size}) may cause connection issues")
        print("   Consider using smaller batches (1000-5000) for better stability")

    print("🚀 StackExchange Posts Processor")
    print("=" * 50)
    print(f"Source: {source_config['host']}:{source_config['port']}/{source_config['database']}")
    print(f"Target: {target_config['host']}:{target_config['port']}/{target_config['database']}")
    print(f"Limit: {'All posts' if args.limit == 0 else args.limit} posts")
    print(f"Batch size: {args.batch_size}")
    print(f"Skip duplicates: {skip_duplicates}")
    print("=" * 50)

    # Create processor and run
    processor = StackExchangeProcessor(source_config, target_config)
    stats = processor.process_posts(
        limit=args.limit,
        batch_size=args.batch_size,
        skip_duplicates=skip_duplicates
    )

    if stats['total_processed'] > 0:
        print(f"\n✅ Processing completed successfully!")
    else:
        print(f"\n❌ No posts were processed!")

if __name__ == "__main__":
    main()