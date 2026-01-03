#!/usr/bin/env python3
"""
Script to retrieve StackExchange posts from MySQL and store them as JSON in a target database.
Supports separate source and target database connections with duplicate checking.
Retrieves parent posts (PostTypeId=1) and their replies (PostTypeId=2),
collecting all unique tags.
"""

import mysql.connector
from mysql.connector import Error
import json
import re
from typing import List, Dict, Any, Set
import argparse

def parse_tags(tags_string: str) -> Set[str]:
    """
    Parse HTML-like tags string and extract unique tag values.
    Example: '<mysql><innodb><myisam>' -> {'mysql', 'innodb', 'myisam'}
    """
    if not tags_string:
        return set()

    # Extract content between < and > tags
    tags = re.findall(r'<([^<>]+)>', tags_string)
    return set(tag.strip().lower() for tag in tags if tag.strip())

def get_parent_posts(conn, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
    """Retrieve parent posts (PostTypeId=1) with specified fields, supports pagination."""
    cursor = conn.cursor(dictionary=True)
    query = """
    SELECT Id, Title, CreationDate, Body
    FROM Posts
    WHERE PostTypeId = 1
    ORDER BY Id
    LIMIT %s OFFSET %s
    """

    try:
        cursor.execute(query, (limit, offset))
        posts = cursor.fetchall()
        print(f"Retrieved {len(posts)} parent posts (offset: {offset})")
        return posts
    except Error as e:
        print(f"Error retrieving parent posts: {e}")
        return []
    finally:
        cursor.close()

def get_child_posts(conn, parent_ids: List[int], chunk_size: int = 1000) -> Dict[int, List[str]]:
    """Retrieve child posts (PostTypeId=2) for given parent IDs, sorted by their ID, with chunking."""
    if not parent_ids:
        return {}

    parent_to_children = {}

    # Process parent IDs in chunks to avoid IN clause limitations
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

            # Group child bodies by ParentId
            for child in child_posts:
                parent_id = child['ParentId']
                if parent_id not in parent_to_children:
                    parent_to_children[parent_id] = []
                parent_to_children[parent_id].append(child['Body'])

            print(f"Retrieved {len(child_posts)} child posts in chunk {i//chunk_size + 1}")
        except Error as e:
            print(f"Error retrieving child posts (chunk {i//chunk_size + 1}): {e}")
        finally:
            cursor.close()

    print(f"Total retrieved: {len(child_posts)} child posts for {len(parent_to_children)} parents")
    return parent_to_children

def get_all_tags(conn, post_ids: List[int], chunk_size: int = 1000) -> Dict[int, Set[str]]:
    """Retrieve and parse all unique tags for given post IDs, with chunking."""
    if not post_ids:
        return {}

    post_tags = {}

    # Process post IDs in chunks to avoid IN clause limitations
    for i in range(0, len(post_ids), chunk_size):
        chunk = post_ids[i:i + chunk_size]

        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT Id, Tags
        FROM Posts
        WHERE Id IN (%s) AND Tags IS NOT NULL
        """ % (','.join(['%s'] * len(chunk)))

        try:
            cursor.execute(query, chunk)
            tag_rows = cursor.fetchall()

            # Parse tags for each post
            for row in tag_rows:
                post_id = row['Id']
                tags_string = row['Tags']
                post_tags[post_id] = parse_tags(tags_string)

            print(f"Processed {len(tag_rows)} tag entries in chunk {i//chunk_size + 1}")
        except Error as e:
            print(f"Error retrieving tags (chunk {i//chunk_size + 1}): {e}")
        finally:
            cursor.close()

    print(f"Total tags processed for {len(post_tags)} posts")
    return post_tags

def get_existing_posts(conn, post_ids: List[int]) -> Set[int]:
    """Check which post IDs already exist in the target table."""
    if not post_ids:
        return set()

    cursor = conn.cursor()
    # Use safer parameterized query to avoid SQL injection
    placeholders = ','.join(['%s'] * len(post_ids))
    query = f"SELECT PostId FROM processed_posts WHERE PostId IN ({placeholders})"

    try:
        cursor.execute(query, post_ids)
        existing_ids = {row[0] for row in cursor.fetchall()}
        print(f"Found {len(existing_ids)} existing posts in target table")
        return existing_ids
    except Error as e:
        print(f"Error checking existing posts: {e}")
        return set()
    finally:
        cursor.close()

def create_target_table(conn) -> bool:
    """Create the target table if it doesn't exist."""
    cursor = conn.cursor()

    # SQL to create the table if it doesn't exist
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS `processed_posts` (
      `PostId` BIGINT NOT NULL,
      `JsonData` JSON NOT NULL,
      `Embeddings` BLOB NULL,
      `CreatedAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      `UpdatedAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (`PostId`),
      KEY `idx_created_at` (`CreatedAt`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    COMMENT='Structured StackExchange posts data in JSON format with embeddings field'
    """

    try:
        cursor.execute(create_table_sql)
        conn.commit()
        print("Target table created or already exists")
        return True
    except Error as e:
        print(f"Error creating target table: {e}")
        return False
    finally:
        cursor.close()

def insert_posts_batch(conn, posts_data: List[tuple]) -> int:
    """Insert multiple posts in a batch for better performance."""
    if not posts_data:
        return 0

    cursor = conn.cursor()
    query = """
    INSERT INTO processed_posts (PostId, JsonData)
    VALUES (%s, %s)
    ON DUPLICATE KEY UPDATE
        JsonData = VALUES(JsonData),
        UpdatedAt = CURRENT_TIMESTAMP
    """

    try:
        cursor.executemany(query, posts_data)
        conn.commit()
        inserted = cursor.rowcount
        print(f"Batch inserted {inserted} posts")
        return inserted
    except Error as e:
        print(f"Error in batch insert: {e}")
        conn.rollback()
        return 0
    finally:
        cursor.close()

def main():
    # Source database configuration (where StackExchange data is)
    source_config = {
        "host": "127.0.0.1",
        "port": 3306,
        "user": "stackexchange",
        "password": "my-password",
        "database": "stackexchange",
        "use_pure": True,
        "ssl_disabled": True
    }

    # Target database configuration (where to store JSON data)
    # Use different credentials/server for production
    target_config = {
        "host": "127.0.0.1",
        "port": 3306,
        "user": "stackexchange",
        "password": "my-password",
        "database": "stackexchange_post",
        "use_pure": True,
        "ssl_disabled": True
    }

    parser = argparse.ArgumentParser(description="Retrieve StackExchange posts from MySQL and store as JSON")
    parser.add_argument("--limit", type=int, default=10, help="Number of parent posts to process")
    parser.add_argument("--batch-size", type=int, default=100, help="Batch size for JSON generation")
    parser.add_argument("--skip-duplicates", action="store_true", default=True, help="Skip posts that already exist in target")
    args = parser.parse_args()

    source_conn = None
    target_conn = None

    try:
        # Connect to source database
        source_conn = mysql.connector.connect(**source_config)
        print("Connected to source database")

        # Connect to target database
        target_conn = mysql.connector.connect(**target_config)
        print("Connected to target database")

        # Create target table if it doesn't exist
        if not create_target_table(target_conn):
            print("Failed to create target table. Exiting.")
            return

        # Process posts in batches
        batch_count = 0
        processed_ids = set()  # Track all successfully processed IDs
        offset = 0

        while offset < args.limit:
            # Calculate batch size (but don't exceed remaining posts)
            current_batch_size = min(args.batch_size, args.limit - offset)

            # Get next batch of parent posts
            parent_posts = get_parent_posts(source_conn, current_batch_size, offset)
            if not parent_posts:
                break

            batch_count += 1
            print(f"\n=== Processing batch {batch_count} - posts {offset + 1} to {offset + len(parent_posts)} ===")

            # Get parent IDs for this batch
            parent_ids = [post['Id'] for post in parent_posts]

            # Check for duplicates in this batch
            if args.skip_duplicates:
                existing_posts = get_existing_posts(target_conn, parent_ids)
                parent_posts = [p for p in parent_posts if p['Id'] not in existing_posts]
                print(f"  New posts in this batch: {len(parent_posts)}")

                if not parent_posts:
                    print(f"  Skipping batch {batch_count} - all posts already exist")
                    offset += current_batch_size  # Advance offset
                    continue

            # Get child posts and tags ONLY for non-duplicate posts
            new_parent_ids = [post['Id'] for post in parent_posts]  # Only non-duplicate posts

            if new_parent_ids:  # Only if there are new posts to process
                child_posts_map = get_child_posts(source_conn, new_parent_ids)
                tags_map = get_all_tags(source_conn, new_parent_ids)
            else:
                child_posts_map = {}
                tags_map = {}

            # Process this batch immediately
            batch_data = []
            for parent in parent_posts:
                post_id = parent['Id']

                # Combine tags from parent posts
                all_tags = set()
                if post_id in tags_map:
                    all_tags.update(tags_map[post_id])

                # Create JSON structure
                post_json = {
                    "Id": post_id,
                    "Title": parent['Title'],
                    "CreationDate": parent['CreationDate'].isoformat() if parent['CreationDate'] else None,
                    "Body": parent['Body'],
                    "Replies": child_posts_map.get(post_id, []),
                    "Tags": sorted(list(all_tags))
                }

                # Serialize JSON to string for MySQL
                batch_data.append((post_id, json.dumps(post_json, ensure_ascii=False)))

            # Insert this batch
            if batch_data:
                print(f"  Inserting {len(batch_data)} posts...")
                insert_count = insert_posts_batch(target_conn, batch_data)

                # Track which IDs were actually processed
                processed_ids.update([item[0] for item in batch_data])

            # ALWAYS advance offset by batch size, regardless of how many were actually processed
            offset += current_batch_size
            print(f"  ✅ Batch {batch_count} completed. Offset advanced to: {offset}/{args.limit}")
            print(f"  📊 Total unique IDs in target table: {len(processed_ids)}")

        print(f"\n🎉 Processing complete!")
        print(f"   Total batches processed: {batch_count}")
        print(f"   Final offset: {offset}/{args.limit}")
        print(f"   Unique IDs in target table: {len(processed_ids)}")

        # Verify actual count in database
        cursor = target_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM processed_posts")
        db_count = cursor.fetchone()[0]

        print(f"\n📊 Verification:")
        print(f"  Total unique IDs in database: {db_count}")

        if processed_ids:
            inserted_in_this_run = len(processed_ids)
            if db_count >= inserted_in_this_run:
                existing_posts = db_count - inserted_in_this_run
                print(f"  Existing posts before this run: {existing_posts}")
                print(f"  Posts inserted in this run: {inserted_in_this_run}")
                print(f"  ✅ Verification successful")
            else:
                print(f"  ⚠️  Database count is less than expected - possible error")
        else:
            print(f"  No new posts were inserted in this run")

        cursor.close()

    except Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if source_conn and source_conn.is_connected():
            source_conn.close()
            print("\nSource database connection closed")
        if target_conn and target_conn.is_connected():
            target_conn.close()
            print("Target database connection closed")

if __name__ == "__main__":
    main()