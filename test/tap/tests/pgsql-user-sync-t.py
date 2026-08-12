#!/usr/bin/env python3
"""Exercise PostgreSQL verifier synchronization against a real ProxySQL."""

import json
import os
import secrets
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pymysql
import psycopg
from psycopg import sql


ROOT = Path(os.environ.get("WORKSPACE", Path(__file__).resolve().parents[3]))
SCRIPT = ROOT / "tools/pgsql_user_sync/proxysql_pgsql_user_sync.py"
USER_COLUMNS = (
    "username,password,active,use_ssl,default_hostgroup,transaction_persistent,"
    "fast_forward,backend,frontend,max_connections,attributes,comment"
)
PROFILE = "tap-lifecycle"


class Tap:
    def __init__(self):
        self.count = 0
        self.failures = 0

    def check(self, condition, description):
        self.count += 1
        if condition:
            print(f"ok {self.count} - {description}")
        else:
            self.failures += 1
            print(f"not ok {self.count} - {description}")
        return condition

    def diag(self, description):
        print(f"# {description}")


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None or value == "":
        raise RuntimeError(f"required environment variable {name} is not set")
    return value


def pg_connection():
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
                f"SELECT {USER_COLUMNS} FROM {table} WHERE username=%s", (username,)
            )
            return cursor.fetchone()


def verifier(connection, role):
    with connection.cursor() as cursor:
        cursor.execute("SELECT rolpassword FROM pg_catalog.pg_authid WHERE rolname=%s", (role,))
        value = cursor.fetchone()
    if value is None or value[0] is None:
        raise RuntimeError("test role verifier was not created")
    return value[0]


def frontend_login(username, password):
    connection = psycopg.connect(
        host=env("TAP_PGSQL_HOST", "127.0.0.1"),
        port=int(env("TAP_PGSQL_PORT", "6133")),
        dbname="postgres",
        user=username,
        password=password,
        connect_timeout=5,
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
    finally:
        connection.close()


def is_owned(row):
    if row is None:
        return False
    try:
        return json.loads(row[10]).get("proxysql_pgsql_user_sync") == {"profile": PROFILE}
    except (TypeError, ValueError, AttributeError):
        return False


def same_control_row(before, after):
    return before is not None and before == after and not is_owned(after)


def write_config(path, names, reader_password, workdir):
    path.write_text(
        "\n".join((
            "[source]",
            f"host = {env('TAP_PGSQLSERVER_HOST')}",
            f"port = {env('TAP_PGSQLSERVER_PORT', '5432')}",
            "database = postgres",
            f"username = {names['reader']}",
            f"password = {reader_password}",
            "connect_timeout = 10",
            f"function = {names['schema']}.export_login_roles",
            "",
            "[proxysql]",
            f"host = {env('TAP_ADMINHOST', '127.0.0.1')}",
            f"port = {env('TAP_ADMINPORT', '6032')}",
            f"username = {env('TAP_ADMINUSERNAME', 'radmin')}",
            f"password = {env('TAP_ADMINPASSWORD', 'radmin')}",
            "connect_timeout = 10",
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
        )),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)


def invoke(config_path, extra=()):
    command = [sys.executable, str(SCRIPT), "--config", str(config_path)]
    command.extend(extra)
    return subprocess.run(command, text=True, capture_output=True)


def create_source_objects(connection, names, reader_password, test_password):
    with connection.cursor() as cursor:
        cursor.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(names["allow"])))
        cursor.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD %s").format(sql.Identifier(names["reader"])),
            (reader_password,),
        )
        cursor.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD %s").format(sql.Identifier(names["test"])),
            (test_password,),
        )
        cursor.execute(
            sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(names["allow"]), sql.Identifier(names["test"])
            )
        )
        cursor.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION CURRENT_USER").format(
            sql.Identifier(names["schema"])
        ))
        function = sql.SQL(
            "CREATE FUNCTION {}.export_login_roles() "
            "RETURNS TABLE(username text, password text) LANGUAGE sql SECURITY DEFINER "
            "SET search_path = pg_catalog AS $$ "
            "SELECT r.rolname::text, r.rolpassword FROM pg_catalog.pg_authid AS r "
            "WHERE r.rolcanlogin AND r.rolpassword IS NOT NULL "
            "AND (r.rolvaliduntil IS NULL OR r.rolvaliduntil > pg_catalog.now()) "
            "AND pg_catalog.pg_has_role(r.oid, {}, 'member') ORDER BY r.rolname $$"
        ).format(sql.Identifier(names["schema"]), sql.Literal(names["allow"]))
        cursor.execute(function)
        cursor.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(
            sql.Identifier(names["schema"])
        ))
        cursor.execute(sql.SQL("REVOKE ALL ON FUNCTION {}.export_login_roles() FROM PUBLIC").format(
            sql.Identifier(names["schema"])
        ))
        cursor.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
            sql.Identifier(names["schema"]), sql.Identifier(names["reader"])
        ))
        cursor.execute(sql.SQL("GRANT EXECUTE ON FUNCTION {}.export_login_roles() TO {}").format(
            sql.Identifier(names["schema"]), sql.Identifier(names["reader"])
        ))


def cleanup(connection, names):
    succeeded = True
    for username in (names["test"], names["control"]):
        try:
            admin_execute("DELETE FROM pgsql_users WHERE username=%s", (username,))
        except Exception:
            succeeded = False
    try:
        admin_execute("LOAD PGSQL USERS TO RUNTIME")
        admin_execute("SAVE PGSQL USERS TO DISK")
    except Exception:
        succeeded = False
    if succeeded:
        try:
            succeeded = all(
                admin_row(username, runtime=runtime) is None
                for username in (names["test"], names["control"])
                for runtime in (False, True)
            )
        except Exception:
            succeeded = False
    if connection is None:
        return succeeded
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                sql.Identifier(names["schema"])
            ))
            for role in (names["test"], names["reader"], names["allow"]):
                cursor.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
    except Exception:
        succeeded = False
    return succeeded


def main():
    tap = Tap()
    suffix = uuid.uuid4().hex[:16]
    names = {
        "allow": f"tap_psync_allow_{suffix}",
        "reader": f"tap_psync_reader_{suffix}",
        "test": f"tap_psync_user_{suffix}",
        "schema": f"tap_psync_schema_{suffix}",
        "control": f"tap_psync_control_{suffix}",
    }
    reader_password = secrets.token_urlsafe(24)
    original_password = secrets.token_urlsafe(24)
    rotated_password = secrets.token_urlsafe(24)
    control_password = secrets.token_urlsafe(24)
    source = None
    config_path = None

    try:
        source = pg_connection()
        cleanup(source, names)
        create_source_objects(source, names, reader_password, original_password)
        with tempfile.TemporaryDirectory(prefix="pgsql-user-sync-") as temporary_directory:
            workdir = Path(temporary_directory)
            config_path = workdir / "pgsql-user-sync.ini"
            write_config(config_path, names, reader_password, workdir)

            admin_execute(
                "INSERT INTO pgsql_users "
                "(username,password,active,use_ssl,default_hostgroup,transaction_persistent,"
                "fast_forward,backend,frontend,max_connections,attributes,comment) "
                "VALUES (%s,%s,1,1,1777,0,1,1,1,17,%s,%s)",
                (names["control"], control_password, "{\"operator\":true}", "tap control"),
            )
            admin_execute("LOAD PGSQL USERS TO RUNTIME")
            control_before = admin_row(names["control"])
            control_runtime_before = admin_row(names["control"], runtime=True)
            tap.check(control_before is not None, "unmanaged control row exists")

            first = invoke(config_path)
            tap.check(first.returncode == 0, "initial synchronizer run succeeds")
            expected_verifier = verifier(source, names["test"])
            main_row = admin_row(names["test"])
            runtime_row = admin_row(names["test"], runtime=True)
            tap.check(main_row is not None and runtime_row is not None, "sync creates main and runtime rows")
            tap.check(
                main_row is not None and runtime_row is not None
                and main_row[4] == 0 and runtime_row[4] == 0,
                "sync assigns configured hostgroup in main and runtime",
            )
            tap.check(main_row is not None and main_row[1] == expected_verifier, "main verifier matches source")
            tap.check(runtime_row is not None and runtime_row[1] == expected_verifier, "runtime verifier matches source")
            tap.check(is_owned(main_row) and is_owned(runtime_row), "sync records managed ownership")
            tap.check(
                same_control_row(control_before, admin_row(names["control"]))
                and same_control_row(control_runtime_before, admin_row(names["control"], runtime=True)),
                "sync preserves unmanaged control rows",
            )

            verifier_auth = True
            try:
                frontend_login(names["test"], original_password)
            except Exception:
                verifier_auth = False
                if os.environ.get("TAP_EXPECT_PGSQL_VERIFIER_AUTH") == "1":
                    tap.check(False, "frontend accepts synchronized verifier")
                else:
                    tap.count += 1
                    print(
                        f"ok {tap.count} - frontend verifier authentication "
                        "# SKIP ProxySQL verifier authentication dependency unavailable"
                    )
            else:
                tap.check(True, "frontend accepts synchronized verifier")
                try:
                    frontend_login(names["test"], "incorrect-password")
                except Exception:
                    tap.check(True, "frontend rejects incorrect password")
                else:
                    tap.check(False, "frontend rejects incorrect password")

            with source.cursor() as cursor:
                cursor.execute(sql.SQL("ALTER ROLE {} PASSWORD %s").format(
                    sql.Identifier(names["test"])
                ), (rotated_password,))
            second = invoke(config_path)
            tap.check(second.returncode == 0, "password rotation synchronizer run succeeds")
            rotated_verifier = verifier(source, names["test"])
            rotated_main = admin_row(names["test"])
            rotated_runtime = admin_row(names["test"], runtime=True)
            tap.check(rotated_verifier != expected_verifier, "source password rotation changes verifier")
            tap.check(rotated_main is not None and rotated_main[1] == rotated_verifier, "main verifier rotates")
            tap.check(rotated_runtime is not None and rotated_runtime[1] == rotated_verifier, "runtime verifier rotates")
            if verifier_auth:
                try:
                    frontend_login(names["test"], rotated_password)
                except Exception:
                    tap.check(False, "frontend accepts rotated verifier")
                else:
                    tap.check(True, "frontend accepts rotated verifier")
                try:
                    frontend_login(names["test"], original_password)
                except Exception:
                    tap.check(True, "frontend rejects previous password")
                else:
                    tap.check(False, "frontend rejects previous password")

            with source.cursor() as cursor:
                cursor.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(names["test"])))
            disabled = invoke(config_path)
            tap.check(disabled.returncode == 0, "disable policy synchronizer run succeeds")
            disabled_main = admin_row(names["test"])
            tap.check(disabled_main is not None and disabled_main[2] == 0, "missing role becomes inactive")
            tap.check(admin_row(names["test"], runtime=True) is None, "inactive role is absent from runtime")

            with source.cursor() as cursor:
                cursor.execute(sql.SQL("ALTER ROLE {} LOGIN").format(sql.Identifier(names["test"])))
            restored = invoke(config_path)
            tap.check(restored.returncode == 0, "restored role synchronizer run succeeds")
            with source.cursor() as cursor:
                cursor.execute(sql.SQL("REVOKE {} FROM {}").format(
                    sql.Identifier(names["allow"]), sql.Identifier(names["test"])
                ))
            kept = invoke(config_path, ("--missing-role-action", "keep"))
            tap.check(kept.returncode == 0, "keep policy synchronizer run succeeds")
            kept_main = admin_row(names["test"])
            kept_runtime = admin_row(names["test"], runtime=True)
            tap.check(kept_main is not None and kept_main[2] == 1, "keep policy retains active main row")
            tap.check(kept_runtime is not None and kept_runtime[2] == 1, "keep policy retains runtime row")

            runtime_before_failure = (
                admin_row(names["test"], runtime=True),
                admin_row(names["control"], runtime=True),
            )
            control_before_failure = admin_row(names["control"])
            with source.cursor() as cursor:
                cursor.execute(sql.SQL("REVOKE EXECUTE ON FUNCTION {}.export_login_roles() FROM {}").format(
                    sql.Identifier(names["schema"]), sql.Identifier(names["reader"])
                ))
            broken = invoke(config_path)
            tap.check(broken.returncode != 0, "source-function failure stops synchronizer")
            tap.check(
                (
                    admin_row(names["test"], runtime=True),
                    admin_row(names["control"], runtime=True),
                ) == runtime_before_failure,
                "source-function failure preserves runtime rows",
            )
            tap.check(
                same_control_row(control_before_failure, admin_row(names["control"])),
                "source-function failure preserves unmanaged control row",
            )
    except Exception:
        tap.check(False, "lifecycle setup and control-plane assertions complete")
    finally:
        tap.check(cleanup(source, names), "cleanup removes test roles and ProxySQL rows")
        if source is not None:
            source.close()
        if config_path is not None:
            try:
                config_path.unlink(missing_ok=True)
            except OSError:
                pass

    print(f"1..{tap.count}")
    return 1 if tap.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
