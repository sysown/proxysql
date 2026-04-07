#!/usr/bin/env python3
import mysql.connector
import time
import argparse
import sys
import signal

def main():
    parser = argparse.ArgumentParser(description="Generate noise by polling stats tables")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6032)
    parser.add_argument("--user", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--interval", type=float, default=0.5)
    args = parser.parse_args()

    def signal_handler(sig, frame):
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        conn = mysql.connector.connect(
            host=args.host,
            port=args.port,
            user=args.user,
            password=args.password,
            autocommit=True
        )
        cursor = conn.cursor()

        while True:
            cursor.execute("SELECT * FROM stats_mysql_query_digest")
            cursor.fetchall()
            cursor.execute("SELECT * FROM stats_mysql_connection_pool")
            cursor.fetchall()
            time.sleep(args.interval)
    except Exception as e:
        print(f"Error in noise poller: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
