#!/usr/bin/env python3
"""mysqlx operational behavioural validation.

Exercises two specific behaviours from issue #5678:

1. PROXYSQL SHUTDOWN SLOW mid-traffic: open N X-Protocol clients
   running steady queries, issue `PROXYSQL SHUTDOWN SLOW` through the
   admin port, verify each client sees a clean Mysqlx::Error frame
   with code 1053 instead of a TCP RST. In docker-isolated TAP runs the
   shutdown command is sent by the wrapper so this observer cannot block
   inside the admin command while clients are still active.

2. LOAD MYSQLX ROUTES TO RUNTIME mid-traffic: open N clients on a
   route, drop the route from admin, reload, verify in-flight sessions
   continue while new connections get refused.

Requires `mysql-connector-python` (`pip install mysql-connector-python`)
and a running ProxySQL with the mysqlx plugin loaded.

This is NOT a TAP unit test. It runs against live infrastructure. See
test/scripts/mysqlx/README.md for the full setup recipe.
"""

import argparse
import sys
import threading
import time
from typing import List

try:
    import mysqlx
except ImportError:
    sys.stderr.write(
        "ERROR: mysql-connector-python not installed. "
        "Run: pip install mysql-connector-python\n"
    )
    sys.exit(1)


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--proxysql-host", default="127.0.0.1")
    p.add_argument("--proxysql-port", type=int, default=6603,
                   help="X-Protocol listener port on ProxySQL")
    p.add_argument("--admin-host", default="127.0.0.1")
    p.add_argument("--admin-port", type=int, default=6032,
                   help="ProxySQL admin port")
    p.add_argument("--admin-user", default="admin")
    p.add_argument("--admin-pass", default="admin")
    p.add_argument("--user", required=True, help="X-Protocol test user")
    p.add_argument("--password", required=True)
    p.add_argument("--clients", type=int, default=5,
                   help="Concurrent client count")
    p.add_argument("--external-shutdown", action="store_true",
                   help="Don't issue PROXYSQL SHUTDOWN SLOW from this "
                        "process; expect an external actor to send it "
                        "while this process observes client disconnects")
    p.add_argument("--shutdown-wait-sec", type=float, default=5.0,
                   help="How long to wait for externally triggered "
                        "shutdown notifications")
    p.add_argument("--scenario", choices=["shutdown", "reload", "all"],
                   default="all")
    p.add_argument("--route-name", default="r1",
                   help="Route name to drop in the reload scenario")
    return p.parse_args()


def open_session(args):
    return mysqlx.get_session({
        "host": args.proxysql_host,
        "port": args.proxysql_port,
        "user": args.user,
        "password": args.password,
        "ssl-mode": "DISABLED",
        "compression": "disabled",
    })


def steady_traffic_thread(args, stop_event, results: List[dict], idx: int):
    """Run a query loop until stop_event fires; record outcome."""
    record = {"idx": idx, "queries": 0, "error": None,
              "error_class": None, "error_code": None}
    sess = None
    try:
        sess = open_session(args)
        while not stop_event.is_set():
            sess.sql("SELECT 1").execute().fetch_all()
            record["queries"] += 1
            time.sleep(0.01)
    except Exception as e:
        record["error"] = str(e)
        record["error_class"] = type(e).__name__
        # mysql-connector-python raises mysqlx.errors.OperationalError
        # for both "TCP RST" and "Mysqlx::Error frame received"; the
        # error code distinguishes them. 1053 = clean shutdown notify;
        # anything else (including no .errno attribute) means TCP RST.
        record["error_code"] = getattr(e, "errno", None)
    finally:
        try:
            if sess is not None:
                sess.close()
        except Exception:
            pass
    results.append(record)


def issue_admin_shutdown(args):
    print("Issuing `PROXYSQL SHUTDOWN SLOW` through the admin port ...")
    try:
        import mysql.connector  # admin port speaks classic protocol
    except ImportError as e:
        print(f"Admin shutdown unavailable: {type(e).__name__}: {e}")
        return False

    adm = None
    try:
        adm = mysql.connector.connect(
            host=args.admin_host, port=args.admin_port,
            user=args.admin_user, password=args.admin_pass,
            ssl_disabled=True,
        )
        cur = adm.cursor()
        try:
            cur.execute("PROXYSQL SHUTDOWN SLOW")
            print("Admin shutdown command accepted.")
            return True
        except Exception as e:
            errno = getattr(e, "errno", None)
            msg = str(e)
            if errno in (2006, 2013) or "Lost connection" in msg or "gone away" in msg:
                print(f"Admin shutdown disconnected as expected: {type(e).__name__}: {e}")
                return True
            print(f"Admin shutdown command failed: {type(e).__name__}: {e}")
            return False
    except Exception as e:
        print(f"Admin shutdown connection failed: {type(e).__name__}: {e}")
        return False
    finally:
        if adm is not None:
            try:
                adm.close()
            except Exception:
                pass


def scenario_shutdown(args):
    print("=== Scenario 1: PROXYSQL SHUTDOWN SLOW mid-traffic ===")
    stop = threading.Event()
    results: List[dict] = []
    threads = [
        threading.Thread(target=steady_traffic_thread,
                         args=(args, stop, results, i),
                         daemon=True)
        for i in range(args.clients)
    ]
    for t in threads:
        t.start()
    time.sleep(2)  # let clients establish steady traffic

    if args.external_shutdown:
        print("Waiting for an external actor to issue PROXYSQL SHUTDOWN SLOW ...")
        time.sleep(args.shutdown_wait_sec)
    else:
        if not issue_admin_shutdown(args):
            stop.set()
            for t in threads:
                t.join(timeout=5)
            return 1
        # Give the server a moment to close the listener and notify clients.
        time.sleep(3)

    for t in threads:
        t.join(timeout=10)
    stop.set()
    for t in threads:
        t.join(timeout=1)

    print(f"Collected {len(results)} client outcomes:")
    clean_close = 0
    tcp_rst = 0
    other = 0
    for r in results:
        if r["error_code"] == 1053:
            clean_close += 1
        elif r["error"] is not None:
            tcp_rst += 1
        else:
            other += 1
        print(f"  client {r['idx']}: queries={r['queries']} "
              f"err={r['error_class']} code={r['error_code']}")

    print(f"\nResult: {clean_close} clean (1053), {tcp_rst} non-1053 errors, "
          f"{other} no-error")
    if clean_close == args.clients:
        print("PASS: every client received a clean shutdown notification")
        return 0
    else:
        print("FAIL: at least one client did not see Mysqlx::Error 1053")
        return 1


def scenario_reload(args):
    print(f"=== Scenario 2: drop+reload route '{args.route_name}' "
          f"mid-traffic ===")
    stop = threading.Event()
    results: List[dict] = []
    threads = [
        threading.Thread(target=steady_traffic_thread,
                         args=(args, stop, results, i),
                         daemon=True)
        for i in range(args.clients)
    ]
    for t in threads:
        t.start()
    time.sleep(2)

    print(f"Dropping route '{args.route_name}' from admin and reloading...")
    try:
        import mysql.connector  # admin port speaks classic protocol
        adm = mysql.connector.connect(
            host=args.admin_host, port=args.admin_port,
            user=args.admin_user, password=args.admin_pass,
            ssl_disabled=True,
        )
        cur = adm.cursor()
        cur.execute(f"DELETE FROM mysqlx_routes WHERE name='{args.route_name}'")
        cur.execute("LOAD MYSQLX ROUTES TO RUNTIME")
        adm.commit()
        adm.close()
    except Exception as e:
        print(f"Admin drop+reload failed: {e}")
        stop.set()
        for t in threads:
            t.join(timeout=5)
        return 1

    # New connection to the route should be refused.
    print("Attempting new connection to dropped route...")
    new_conn_refused = False
    try:
        s = open_session(args)
        s.close()
        print("  unexpected: new connection succeeded")
    except Exception as e:
        new_conn_refused = True
        print(f"  expected: new connection refused: {type(e).__name__}: {e}")

    # Existing clients should keep running for a few more seconds.
    time.sleep(5)
    stop.set()
    for t in threads:
        t.join(timeout=5)

    survivors = sum(1 for r in results
                    if r["error"] is None and r["queries"] > 100)
    print(f"\nResult: {survivors}/{args.clients} clients survived the reload, "
          f"new connection refused: {new_conn_refused}")
    if survivors == args.clients and new_conn_refused:
        print("PASS")
        return 0
    print("FAIL")
    return 1


def main():
    args = parse_args()
    rc = 0
    if args.scenario in ("shutdown", "all"):
        rc |= scenario_shutdown(args)
    if args.scenario in ("reload", "all"):
        rc |= scenario_reload(args)
    sys.exit(rc)


if __name__ == "__main__":
    main()
