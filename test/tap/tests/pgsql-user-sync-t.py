#!/usr/bin/env python3
"""Run the PostgreSQL user synchronizer against real services."""

import json
import os
import secrets
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import psycopg
import pymysql
from psycopg import sql


ROOT = Path(os.environ.get("WORKSPACE", Path(__file__).resolve().parents[3]))
SCRIPT = ROOT / "tools/pgsql_user_sync/proxysql_pgsql_user_sync.py"
PROFILE = "tap-real"


class Tap:
    def __init__(self):
        self.count = 0
        self.failures = 0

    def check(self, condition, description):
        self.count += 1
        print(f"{'ok' if condition else 'not ok'} {self.count} - {description}")
        if not condition:
            self.failures += 1


def env(name, default=None):
    value = os.environ.get(name, default)
    if not value:
        raise RuntimeError(f"required environment variable {name} is not set")
    return value


def source_connection():
    return psycopg.connect(
        host=env("TAP_PGSQLSERVER_HOST"),
        port=int(env("TAP_PGSQLSERVER_PORT", "5432")),
        dbname="postgres",
        user=env("TAP_PGSQLSERVER_USERNAME"),
        password=env("TAP_PGSQLSERVER_PASSWORD"),
        autocommit=True,
    )


def admin_connection():
    return pymysql.connect(
        host=env("TAP_ADMINHOST", "127.0.0.1"),
        port=int(env("TAP_ADMINPORT", "6032")),
        user=env("TAP_ADMINUSERNAME", "radmin"),
        password=env("TAP_ADMINPASSWORD", "radmin"),
        database="main",
        autocommit=True,
    )


def admin_execute(query, params=()):
    with admin_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, params)


def admin_row(username, runtime=False):
    table = "runtime_pgsql_users" if runtime else "pgsql_users"
    with admin_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT username,password,active,default_hostgroup,attributes "
                f"FROM {table} WHERE username=%s AND backend=1",
                (username,),
            )
            return cursor.fetchone()


def create_source_role(connection, schema, username, password):
    with connection.cursor() as cursor:
        cursor.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                sql.Identifier(username), sql.Literal(password)
            )
        )
        cursor.execute(
            sql.SQL("CREATE SCHEMA {} AUTHORIZATION CURRENT_USER").format(
                sql.Identifier(schema)
            )
        )
        cursor.execute(
            sql.SQL(
                "CREATE FUNCTION {}.export_login_role() "
                "RETURNS TABLE(username text, password text) "
                "LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$ "
                "SELECT rolname::text, rolpassword FROM pg_catalog.pg_authid "
                "WHERE rolname = {} AND rolcanlogin AND rolpassword IS NOT NULL $$"
            ).format(sql.Identifier(schema), sql.Literal(username))
        )


def source_verifier(connection, username):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT rolpassword FROM pg_catalog.pg_authid WHERE rolname=%s",
            (username,),
        )
        return cursor.fetchone()[0]


def write_config(path, schema, workdir):
    path.write_text(
        "\n".join(
            (
                "[source]",
                f"host = {env('TAP_PGSQLSERVER_HOST')}",
                f"port = {env('TAP_PGSQLSERVER_PORT', '5432')}",
                "database = postgres",
                f"username = {env('TAP_PGSQLSERVER_USERNAME')}",
                f"password = {env('TAP_PGSQLSERVER_PASSWORD')}",
                f"function = {schema}.export_login_role",
                "",
                "[proxysql]",
                f"host = {env('TAP_PGSQLADMIN_HOST', '127.0.0.1')}",
                f"port = {env('TAP_PGSQLADMIN_PORT', '6132')}",
                f"username = {env('TAP_ADMINUSERNAME', 'radmin')}",
                f"password = {env('TAP_ADMINPASSWORD', 'radmin')}",
                "",
                "[sync]",
                f"profile = {PROFILE}",
                "default_hostgroup = 0",
                "missing_role_action = disable",
                "adopt_existing_users = false",
                "allow_empty_snapshot = false",
                "save_to_disk = true",
                f"lock_file = {workdir / 'pgsql-user-sync.lock'}",
                "",
            )
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)


def direct_login(username, password):
    with psycopg.connect(
        host=env("TAP_PGSQLSERVER_HOST"),
        port=int(env("TAP_PGSQLSERVER_PORT", "5432")),
        dbname="postgres",
        user=username,
        password=password,
        connect_timeout=5,
    ) as connection:
        connection.execute("SELECT 1")


def cleanup(connection, schema, username):
    success = True
    try:
        admin_execute("DELETE FROM pgsql_users WHERE username=%s", (username,))
        admin_execute("LOAD PGSQL USERS TO RUNTIME")
        admin_execute("SAVE PGSQL USERS TO DISK")
    except Exception:
        success = False
    if connection is not None:
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                        sql.Identifier(schema)
                    )
                )
                cursor.execute(
                    sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(username))
                )
        except Exception:
            success = False
    return success


def main():
    tap = Tap()
    suffix = uuid.uuid4().hex[:16]
    username = f"tap_psync_{suffix}"
    schema = f"tap_psync_schema_{suffix}"
    password = secrets.token_urlsafe(24)
    source = None

    try:
        source = source_connection()
        create_source_role(source, schema, username, password)
        direct_login(username, password)
        tap.check(True, "login role exists on the real PostgreSQL backend")

        with tempfile.TemporaryDirectory(prefix="pgsql-user-sync-") as temp:
            workdir = Path(temp)
            config = workdir / "pgsql-user-sync.ini"
            write_config(config, schema, workdir)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--config", str(config)],
                text=True,
                capture_output=True,
            )
            if result.returncode != 0:
                print(f"# synchronizer diagnostic: {result.stderr.strip()}")
            repeated = subprocess.run(
                [sys.executable, str(SCRIPT), "--config", str(config)],
                text=True,
                capture_output=True,
            )
            if repeated.returncode != 0:
                print(f"# repeated synchronizer diagnostic: {repeated.stderr.strip()}")

        tap.check(result.returncode == 0, "real synchronizer run succeeds")
        verifier = source_verifier(source, username)
        main_row = admin_row(username)
        runtime_row = admin_row(username, runtime=True)
        if (
            main_row is None
            or main_row[1] != verifier
            or int(main_row[2]) != 1
            or int(main_row[3]) != 0
        ):
            print(
                "# main row diagnostic: "
                f"present={main_row is not None} "
                f"verifier_match={main_row is not None and main_row[1] == verifier} "
                f"active={main_row[2] if main_row else None} "
                f"hostgroup={main_row[3] if main_row else None} "
                f"attributes={(main_row[4] if main_row else None)!r}"
            )
        if (
            runtime_row is None
            or runtime_row[1] != verifier
            or int(runtime_row[2]) != 1
            or int(runtime_row[3]) != 0
        ):
            print(
                "# runtime row diagnostic: "
                f"present={runtime_row is not None} "
                f"verifier_match={runtime_row is not None and runtime_row[1] == verifier} "
                f"active={runtime_row[2] if runtime_row else None} "
                f"hostgroup={runtime_row[3] if runtime_row else None}"
            )
        tap.check(
            main_row is not None
            and main_row[1] == verifier
            and int(main_row[2]) == 1
            and int(main_row[3]) == 0
            and json.loads(main_row[4]).get("proxysql_pgsql_user_sync")
            == {"profile": PROFILE},
            "synchronizer automatically creates the real pgsql_users row",
        )
        tap.check(
            runtime_row is not None
            and runtime_row[1] == verifier
            and int(runtime_row[2]) == 1
            and int(runtime_row[3]) == 0,
            "synchronizer loads the user into runtime_pgsql_users",
        )
        repeated_is_noop = (
            repeated.returncode == 0
            and "loaded=false saved=false" in repeated.stdout
        )
        if not repeated_is_noop:
            print(f"# repeated synchronizer output: {repeated.stdout.strip()}")
        tap.check(
            repeated_is_noop,
            "repeated synchronization detects no backend-runtime drift",
        )
    except Exception as error:
        print(f"# real integration failure class: {type(error).__name__}")
        tap.check(False, "real PostgreSQL to ProxySQL synchronization completes")
    finally:
        tap.check(cleanup(source, schema, username), "test data is removed")
        if source is not None:
            source.close()

    print(f"1..{tap.count}")
    return 1 if tap.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
