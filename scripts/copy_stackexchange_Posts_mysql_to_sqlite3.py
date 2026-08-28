#!/usr/bin/env python3
"""
Copy Posts table from MySQL to ProxySQL SQLite3 server.
Uses Python MySQL connectors for direct database access.
"""

import mysql.connector
import sys
import time

# Configuration
SOURCE_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "stackexchange",
    "password": "my-password",
    "database": "stackexchange",
    "use_pure": True,
    "ssl_disabled": True
}

DEST_CONFIG = {
    "host": "127.0.0.1",
    "port": 6030,
    "user": "root",
    "password": "root",
    "database": "main",
    "use_pure": True,
    "ssl_disabled": True
}

TABLE_NAME = "Posts"
LIMIT = 0  # 0 for all rows, otherwise limit for testing
BATCH_SIZE = 5000  # Larger batch for full copy
CLEAR_TABLE_FIRST = True  # Delete existing data before copying

COLUMNS = [
    "SiteId", "Id", "PostTypeId", "AcceptedAnswerId", "ParentId",
    "CreationDate", "DeletionDate", "Score", "ViewCount", "Body",
    "OwnerUserId", "OwnerDisplayName", "LastEditorUserId", "LastEditorDisplayName",
    "LastEditDate", "LastActivityDate", "Title", "Tags", "AnswerCount",
    "CommentCount", "FavoriteCount", "ClosedDate", "CommunityOwnedDate", "ContentLicense"
]

def escape_sql_value(value):
    """Escape a value for SQL insertion."""
    if value is None:
        return "NULL"
    # Convert to string
    s = str(value)
    # Escape single quotes by doubling
    escaped = s.replace("'", "''")
    return f"'{escaped}'"

def generate_insert(row):
    """Generate INSERT statement for a single row."""
    values_str = ", ".join(escape_sql_value(v) for v in row)
    columns_str = ", ".join(COLUMNS)
    return f"INSERT INTO {TABLE_NAME} ({columns_str}) VALUES ({values_str})"

def main():
    print(f"Copying {TABLE_NAME} from MySQL to SQLite3 server...")
    print(f"Source: {SOURCE_CONFIG['host']}:{SOURCE_CONFIG['port']}")
    print(f"Destination: {DEST_CONFIG['host']}:{DEST_CONFIG['port']}")
    if LIMIT > 0:
        print(f"Limit: {LIMIT} rows")
    else:
        print(f"Copying all rows")

    # Connect to source (MySQL)
    try:
        source_conn = mysql.connector.connect(**SOURCE_CONFIG)
        source_cursor = source_conn.cursor()
        print("✓ Connected to MySQL source")
    except Exception as e:
        print(f"✗ Failed to connect to source MySQL: {e}")
        sys.exit(1)

    # Connect to destination (ProxySQL SQLite3 server)
    try:
        dest_conn = mysql.connector.connect(**DEST_CONFIG)
        dest_cursor = dest_conn.cursor()
        print("✓ Connected to SQLite3 server destination")
    except Exception as e:
        print(f"✗ Failed to connect to destination SQLite3 server: {e}")
        source_conn.close()
        sys.exit(1)

    try:
        # Clear destination table if requested
        if CLEAR_TABLE_FIRST:
            print("Clearing destination table...")
            dest_cursor.execute(f"DELETE FROM {TABLE_NAME}")
            dest_conn.commit()
            print("✓ Destination table cleared")

        # Build query with optional LIMIT
        query = f"SELECT * FROM {TABLE_NAME}"
        if LIMIT > 0:
            query += f" LIMIT {LIMIT}"

        print(f"Executing query: {query}")
        source_cursor.execute(query)

        rows = 0
        errors = 0
        start = time.time()
        last_report = start

        # Fetch and insert rows
        print("Starting copy...")
        while True:
            batch = source_cursor.fetchmany(BATCH_SIZE)
            if not batch:
                break

            for row in batch:
                try:
                    insert_sql = generate_insert(row)
                    dest_cursor.execute(insert_sql)
                    rows += 1
                except Exception as e:
                    errors += 1
                    if errors <= 3:
                        print(f"Error inserting row {rows+1}: {e}")
                        if errors == 1:
                            print(f"  Sample INSERT (first 300 chars): {insert_sql[:300]}...")

            # Commit batch
            dest_conn.commit()

            # Progress reporting every 1000 rows or 5 seconds
            now = time.time()
            if rows % 1000 == 0 or (now - last_report) >= 5:
                elapsed = now - start
                rate = rows / elapsed if elapsed > 0 else 0
                print(f"  Processed {rows} rows ({rate:.1f} rows/sec)")
                last_report = now

        # Final commit
        dest_conn.commit()

        elapsed = time.time() - start
        print(f"\n✓ Copy completed:")
        print(f"  Rows copied: {rows}")
        print(f"  Errors: {errors}")
        print(f"  Time: {elapsed:.1f}s")
        if elapsed > 0:
            print(f"  Rate: {rows/elapsed:.1f} rows/sec")

        # Verify counts if no errors
        if errors == 0:
            # Get source count
            if LIMIT > 0:
                expected = min(LIMIT, rows)
            else:
                source_cursor.execute(f"SELECT COUNT(*) FROM {TABLE_NAME}")
                expected = source_cursor.fetchone()[0]

            dest_cursor.execute(f"SELECT COUNT(*) FROM {TABLE_NAME}")
            actual = dest_cursor.fetchone()[0]

            print(f"\n✓ Verification:")
            print(f"  Expected rows: {expected}")
            print(f"  Actual rows: {actual}")
            if expected == actual:
                print(f"  ✓ Counts match!")
            else:
                print(f"  ✗ Count mismatch!")

    except Exception as e:
        print(f"\n✗ Error during copy: {e}")
        sys.exit(1)
    finally:
        # Cleanup
        source_cursor.close()
        source_conn.close()
        dest_cursor.close()
        dest_conn.close()
        print("\nConnections closed.")

if __name__ == "__main__":
    main()