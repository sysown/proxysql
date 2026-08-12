import base64
import importlib.util
import json
import os
import stat
import sys
import tempfile
from dataclasses import replace
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "proxysql_pgsql_user_sync.py"
ASSET_DIR = SCRIPT.parent


def load_module():
    spec = importlib.util.spec_from_file_location("proxysql_pgsql_user_sync", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def write_config(self, *, mode=0o600, text=None):
        if text is None:
            text = """\
[source]
host = postgresql.example
port = 5432
database = postgres
username = source_reader
password = source-secret

[proxysql]
host = 127.0.0.1
port = 6032
username = admin
password = admin-secret

[sync]
profile = primary-cluster
"""
        handle = tempfile.NamedTemporaryFile(mode="w", delete=False)
        self.addCleanup(lambda: os.unlink(handle.name))
        with handle:
            handle.write(text)
        os.chmod(handle.name, mode)
        return Path(handle.name)

    def test_defaults_and_cli_hostgroup_override(self):
        path = self.write_config()
        cfg = self.mod.load_config(path, self.mod.CLIOverrides(default_hostgroup=12))
        self.assertEqual(12, cfg.sync.default_hostgroup)
        self.assertEqual("disable", cfg.sync.missing_role_action)
        self.assertFalse(cfg.sync.allow_empty_snapshot)
        self.assertTrue(cfg.sync.save_to_disk)
        self.assertEqual("proxysql_auth", cfg.source.function_schema)
        self.assertEqual("export_login_roles", cfg.source.function_name)

    def test_cli_overrides_take_precedence(self):
        path = self.write_config(text="""\
[source]
host = source
port = 5432
database = db
username = reader
password = source-password
connect_timeout = 30
function = auth.roles

[proxysql]
host = proxy
port = 6032
username = admin
password = proxy-password
connect_timeout = 20

[sync]
profile = p1
default_hostgroup = 4
missing_role_action = keep
save_to_disk = true
""")
        cfg = self.mod.load_config(
            path,
            self.mod.CLIOverrides(
                default_hostgroup=12, missing_role_action="disable", save_to_disk=False
            ),
        )
        self.assertEqual(12, cfg.sync.default_hostgroup)
        self.assertEqual("disable", cfg.sync.missing_role_action)
        self.assertFalse(cfg.sync.save_to_disk)
        self.assertEqual("auth", cfg.source.function_schema)
        self.assertEqual("roles", cfg.source.function_name)
        self.assertEqual(30, cfg.source.connect_timeout)

    def test_rejects_world_readable_config(self):
        path = self.write_config(mode=0o604)
        with self.assertRaisesRegex(self.mod.SyncError, "permissions"):
            self.mod.load_config(path, self.mod.CLIOverrides())

    def test_group_read_requires_root_owner_and_owner_only_is_allowed(self):
        path = self.write_config(mode=0o640)
        root_metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=0)
        with patch.object(self.mod.Path, "stat", return_value=root_metadata):
            self.mod.load_config(path, self.mod.CLIOverrides())

        non_root_metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=1000)
        with patch.object(self.mod.Path, "stat", return_value=non_root_metadata):
            with self.assertRaisesRegex(self.mod.SyncError, "permissions"):
                self.mod.load_config(path, self.mod.CLIOverrides())

        path = self.write_config(mode=0o600)
        owner_only_metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1000)
        with patch.object(self.mod.Path, "stat", return_value=owner_only_metadata):
            self.mod.load_config(path, self.mod.CLIOverrides())

    def test_rejects_group_write_even_when_root_owned(self):
        path = self.write_config(mode=0o660)
        root_metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o660, st_uid=0)
        with patch.object(self.mod.Path, "stat", return_value=root_metadata):
            with self.assertRaisesRegex(self.mod.SyncError, "permissions"):
                self.mod.load_config(path, self.mod.CLIOverrides())

    def test_rejects_invalid_profile_and_function(self):
        for profile in ("", "-bad", "a" * 65):
            path = self.write_config(text="""\
[source]
host = source
port = 5432
database = db
username = reader
password = secret
[proxysql]
host = proxy
port = 6032
username = admin
password = secret
[sync]
profile = %s
""" % profile)
            with self.assertRaisesRegex(self.mod.SyncError, "profile"):
                self.mod.load_config(path, self.mod.CLIOverrides())

        for function in ("roles", "auth.bad-name", "1auth.roles", "auth.roles.extra"):
            path = self.write_config(text="""\
[source]
host = source
port = 5432
database = db
username = reader
password = secret
function = %s
[proxysql]
host = proxy
port = 6032
username = admin
password = secret
[sync]
profile = p
""" % function)
            with self.assertRaisesRegex(self.mod.SyncError, "function"):
                self.mod.load_config(path, self.mod.CLIOverrides())

    def test_rejects_invalid_values_and_missing_fields(self):
        path = self.write_config(text="""\
[source]
host = source
port = 0
database = db
username = reader
password = secret
connect_timeout = -1
[proxysql]
host = proxy
port = 6032
username = admin
password = secret
[sync]
profile = p
default_hostgroup = -1
missing_role_action = remove
adopt_existing_users = maybe
allow_empty_snapshot = false
save_to_disk = true
""")
        with self.assertRaises(self.mod.SyncError):
            self.mod.load_config(path, self.mod.CLIOverrides())

        path = self.write_config(text="""\
[source]
host = source
port = 5432
database = db
username = reader
[proxysql]
host = proxy
port = 6032
username = admin
password = secret
[sync]
profile = p
""")
        with self.assertRaisesRegex(self.mod.SyncError, "password"):
            self.mod.load_config(path, self.mod.CLIOverrides())

    def test_parse_args_supports_overrides(self):
        args = self.mod.parse_args(
            [
                "--config",
                "/tmp/config",
                "--default-hostgroup",
                "12",
                "--missing-role-action",
                "keep",
                "--no-save-to-disk",
                "--dry-run",
                "--verbose",
            ]
        )
        self.assertEqual(Path("/tmp/config"), args.config)
        self.assertEqual(12, args.default_hostgroup)
        self.assertEqual("keep", args.missing_role_action)
        self.assertFalse(args.save_to_disk)
        self.assertTrue(args.dry_run)
        self.assertTrue(args.verbose)


class SnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def valid_scram(self):
        key = base64.b64encode(b"x" * 32).decode()
        salt = base64.b64encode(b"salt").decode()
        return "SCRAM-SHA-256$4096:%s$%s:%s" % (salt, key, key)

    def test_accepts_lowercase_md5_and_sorts_users(self):
        rows = [("zeta", "md5" + "a" * 32), ("alice", "md5" + "b" * 32)]
        result = self.mod.validate_snapshot(rows, False)
        self.assertEqual(["alice", "zeta"], list(result))
        self.assertEqual("md5" + "b" * 32, result["alice"].password)

    def test_accepts_valid_scram(self):
        result = self.mod.validate_snapshot([("alice", self.valid_scram())], False)
        self.assertEqual("alice", result["alice"].username)

    def test_rejects_invalid_verifiers_without_leaking_value(self):
        bad_values = [
            "MD5" + "a" * 32,
            "md5" + "g" * 32,
            "md5" + "a" * 31,
            "SCRAM-SHA-256$0:c2FsdA==$eA==:eA==",
            "SCRAM-SHA-256$4096:not-base64$eA==:eA==",
            "SCRAM-SHA-256$4096:c2FsdA==$eA==:eA==",
        ]
        for value in bad_values:
            with self.assertRaises(self.mod.SyncError) as ctx:
                self.mod.validate_verifier(value)
            self.assertNotIn(value, str(ctx.exception))

    def test_rejects_duplicate_without_leaking_verifier(self):
        verifier = "md5" + "b" * 32
        with self.assertRaisesRegex(self.mod.SyncError, "duplicate") as ctx:
            self.mod.validate_snapshot([("alice", verifier), ("alice", verifier)], False)
        self.assertNotIn(verifier, str(ctx.exception))

    def test_empty_snapshot_requires_opt_in(self):
        with self.assertRaisesRegex(self.mod.SyncError, "empty"):
            self.mod.validate_snapshot([], False)
        self.assertEqual({}, self.mod.validate_snapshot([], True))

    def test_rejects_bad_shape_types_nuls_and_long_utf8_names(self):
        for rows in (["not-a-row"], [("alice", "md5" + "a" * 32, "extra")], [(None, "md5" + "a" * 32)], [("a\x00b", "md5" + "a" * 32)], [("é" * 32, "md5" + "a" * 32)]):
            with self.assertRaises(self.mod.SyncError):
                self.mod.validate_snapshot(rows, True)


class PlannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()
        cls.verifier_a = "md5" + "a" * 32
        cls.verifier_b = "md5" + "b" * 32

    def settings(self, **kwargs):
        values = dict(profile="p", default_hostgroup=0, missing_role_action="disable",
                      adopt_existing_users=False)
        values.update(kwargs)
        return self.mod.SyncSettings(**values)

    def role(self, username, password=None):
        return self.mod.SourceRole(username, password or self.verifier_a)

    def user(self, username, *, password=None, profile=None, active=1, **kwargs):
        attributes = kwargs.pop("attributes", "")
        if profile is not None:
            attributes = json.dumps({"proxysql_pgsql_user_sync": {"profile": profile}},
                                    separators=(",", ":"))
        values = dict(username=username, password=password or self.verifier_a, active=active,
                      use_ssl=0, default_hostgroup=3, transaction_persistent=1,
                      fast_forward=0, backend=1, frontend=1, max_connections=100,
                      attributes=attributes, comment="kept")
        values.update(kwargs)
        return self.mod.ProxySQLUser(**values)

    def test_create_uses_configured_hostgroup(self):
        plan = self.mod.build_plan(
            {"alice": self.role("alice")}, [], [], self.settings(default_hostgroup=17)
        )
        action = plan.actions[0]
        self.assertEqual(self.mod.ActionKind.CREATE, action.kind)
        self.assertEqual(17, action.after.default_hostgroup)
        self.assertEqual((1, 1), (action.after.backend, action.after.frontend))
        self.assertEqual(1, action.after.transaction_persistent)
        self.assertEqual(10000, action.after.max_connections)
        self.assertEqual({"proxysql_pgsql_user_sync": {"profile": "p"}},
                         json.loads(action.after.attributes))

    def test_managed_update_changes_only_password_active_and_ownership(self):
        main = self.user("alice", profile="p", password=self.verifier_a,
                         attributes=json.dumps({"other": {"value": 1},
                                                 "proxysql_pgsql_user_sync": {"profile": "p"}},
                                                separators=(",", ":")),
                         active=0, use_ssl=1, default_hostgroup=22,
                         transaction_persistent=0, fast_forward=1, backend=1,
                         frontend=1, max_connections=9, comment="operator")
        plan = self.mod.build_plan({"alice": self.role("alice", self.verifier_b)},
                                   [main], [main], self.settings())
        action = plan.actions[0]
        self.assertEqual(self.mod.ActionKind.UPDATE, action.kind)
        self.assertEqual(self.verifier_b, action.after.password)
        self.assertEqual(1, action.after.active)
        self.assertEqual((1, 22, 0, 1, 1, 9, "operator"),
                         (action.after.use_ssl, action.after.default_hostgroup,
                          action.after.transaction_persistent, action.after.fast_forward,
                          action.after.backend, action.after.max_connections,
                          action.after.comment))
        self.assertEqual(json.loads(main.attributes), json.loads(action.after.attributes))

    def test_missing_action_is_configurable(self):
        owned = self.user("alice", profile="p", active=1)
        disabled = self.mod.build_plan({}, [owned], [owned], self.settings(profile="p"))
        kept = self.mod.build_plan({}, [owned], [owned],
                                   self.settings(profile="p", missing_role_action="keep"))
        self.assertEqual(self.mod.ActionKind.DISABLE, disabled.actions[0].kind)
        self.assertEqual(0, disabled.actions[0].after.active)
        self.assertEqual((), kept.actions)

    def test_aborts_for_unmanaged_main_runtime_drift(self):
        main = self.user("local", password=self.verifier_b)
        runtime = replace(main, password=self.verifier_a)
        with self.assertRaisesRegex(self.mod.SyncError, "unmanaged.*runtime"):
            self.mod.build_plan({}, [main], [runtime], self.settings())

    def test_unmanaged_conflict_requires_adoption(self):
        existing = self.user("alice")
        with self.assertRaisesRegex(self.mod.SyncError, "unmanaged"):
            self.mod.build_plan({"alice": self.role("alice")}, [existing], [existing],
                                self.settings())
        plan = self.mod.build_plan({"alice": self.role("alice", self.verifier_b)},
                                   [existing], [existing],
                                   self.settings(adopt_existing_users=True))
        self.assertEqual(self.mod.ActionKind.UPDATE, plan.actions[0].kind)
        self.assertEqual(self.verifier_b, plan.actions[0].after.password)

    def test_cross_profile_conflict_aborts(self):
        existing = self.user("alice", profile="other")
        with self.assertRaisesRegex(self.mod.SyncError, "another profile"):
            self.mod.build_plan({"alice": self.role("alice")}, [existing], [existing],
                                self.settings())

    def test_duplicate_admin_rows_are_rejected(self):
        first = self.user("alice", profile="p")
        second = replace(first, backend=0, frontend=1)
        with self.assertRaisesRegex(self.mod.SyncError, "multiple.*alice"):
            self.mod.build_plan({"alice": self.role("alice")}, [first, second], [],
                                self.settings())

    def test_ownership_helpers_validate_and_normalize(self):
        self.assertIsNone(self.mod.decode_ownership(""))
        self.assertEqual("p", self.mod.decode_ownership(
            '{"proxysql_pgsql_user_sync":{"profile":"p"}}'))
        self.assertEqual('{"a":1,"proxysql_pgsql_user_sync":{"profile":"p"}}',
                         self.mod.with_ownership('{"a":1}', "p"))
        for bad in ('[]', '{"proxysql_pgsql_user_sync": []}',
                    '{"proxysql_pgsql_user_sync": null}',
                    '{"proxysql_pgsql_user_sync": {"profile": 1}}', '{bad'):
            with self.assertRaises(self.mod.SyncError):
                self.mod.decode_ownership(bad)
        with self.assertRaisesRegex(self.mod.SyncError, "another profile"):
            self.mod.with_ownership('{"proxysql_pgsql_user_sync":{"profile":"old"}}', "p")

    def test_unchanged_rows_need_no_action_or_load(self):
        owned = self.user("alice", profile="p")
        plan = self.mod.build_plan({"alice": self.role("alice")}, [owned], [owned],
                                   self.settings())
        self.assertEqual((), plan.actions)
        self.assertFalse(plan.requires_load)
        self.assertEqual(1, plan.counts["unchanged"])

    def test_managed_runtime_drift_requires_load(self):
        main = self.user("alice", profile="p", active=1)
        runtime = replace(main, active=0)
        plan = self.mod.build_plan({"alice": self.role("alice")}, [main], [runtime],
                                   self.settings())
        self.assertEqual((), plan.actions)
        self.assertTrue(plan.requires_load)

    def test_inactive_main_row_is_expected_absent_from_runtime(self):
        main = self.user("alice", profile="p", active=0)
        plan = self.mod.build_plan({}, [main], [], self.settings())
        self.assertEqual((), plan.actions)
        self.assertFalse(plan.requires_load)


class FakeCursor:
    def __init__(self, rows=()):
        self.rows = list(rows)
        self.executions = []

    def execute(self, query, params=None):
        self.executions.append((query, params))

    def fetchall(self):
        return list(self.rows)


class FakeConnection:
    def __init__(self, rows=()):
        self.cursor_object = FakeCursor(rows)
        self.closed = False

    def cursor(self):
        return self.cursor_object

    def close(self):
        self.closed = True


class FakeSQL:
    class Identifier:
        def __init__(self, value):
            self.value = value

    class SQL:
        def __init__(self, value):
            self.value = value

        def format(self, *identifiers):
            values = tuple(identifier.value for identifier in identifiers)
            return self.value.format(*('"%s"' % value for value in values))


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()
        cls.verifier_a = "md5" + "a" * 32
        cls.verifier_b = "md5" + "b" * 32

    def setUp(self):
        self.config = self.mod.AppConfig(
            source=self.mod.SourceConfig("source", 5432, "roles", "reader", "source-secret"),
            proxysql=self.mod.ProxySQLConfig("proxy", 6032, "admin", "admin-secret"),
            sync=self.mod.SyncSettings(profile="p"),
        )
        self.connection = FakeConnection()
        self.cursor = self.connection.cursor_object

    def fake_connect(self, **kwargs):
        self.connect_kwargs = kwargs
        return self.connection

    def user(self, username="alice", password=None, active=1):
        return self.mod.ProxySQLUser(
            username=username, password=password or self.verifier_a, active=active,
            use_ssl=0, default_hostgroup=3, transaction_persistent=1,
            fast_forward=0, backend=1, frontend=1, max_connections=100,
            attributes='{"proxysql_pgsql_user_sync":{"profile":"p"}}', comment="sync",
        )

    def update_action(self):
        before = self.user(password=self.verifier_a)
        return self.mod.SyncAction(
            self.mod.ActionKind.UPDATE, before, replace(before, password=self.verifier_b)
        )

    def test_source_composes_schema_and_function_as_identifiers(self):
        self.connection.cursor_object.rows = [("alice", self.verifier_a)]
        source = self.mod.PostgreSQLSource(
            self.config, connect=self.fake_connect, sql_module=FakeSQL
        )
        self.assertEqual([("alice", self.verifier_a)], source.fetch_snapshot())
        query, params = self.cursor.executions[-1]
        self.assertEqual(
            'SELECT username::text, password FROM "proxysql_auth"."export_login_roles"()', query
        )
        self.assertIsNone(params)
        self.assertEqual("source", self.connect_kwargs["host"])
        self.assertEqual("roles", self.connect_kwargs["dbname"])

    def test_admin_fetches_exact_projection_from_both_tables(self):
        self.connection.cursor_object.rows = [("alice", self.verifier_a, 1, 0, 3, 1, 0, 1, 1, 100, "", "")]
        adapter = self.mod.ProxySQLAdmin(self.config, connect=self.fake_connect)
        self.assertEqual("alice", adapter.fetch_main_users()[0].username)
        self.assertEqual("alice", adapter.fetch_runtime_users()[0].username)
        main_sql = self.cursor.executions[-2][0]
        runtime_sql = self.cursor.executions[-1][0]
        projection = ("username,password,active,use_ssl,default_hostgroup,transaction_persistent,"
                      "fast_forward,backend,frontend,max_connections,attributes,comment")
        self.assertEqual("SELECT %s FROM pgsql_users" % projection, main_sql)
        self.assertEqual("SELECT %s FROM runtime_pgsql_users" % projection, runtime_sql)
        self.assertTrue(self.connect_kwargs["autocommit"])

    def test_admin_update_uses_bound_parameters(self):
        adapter = self.mod.ProxySQLAdmin(self.config, connect=self.fake_connect)
        adapter.apply_actions((self.update_action(),))
        sql, params = self.cursor.executions[-1]
        self.assertIn("password=%s", sql)
        self.assertNotIn(self.verifier_b, sql)
        self.assertEqual(self.verifier_b, params[0])
        self.assertEqual(("alice", 1), params[-2:])

    def test_admin_create_and_disable_use_explicit_columns_and_bound_keys(self):
        adapter = self.mod.ProxySQLAdmin(self.config, connect=self.fake_connect)
        created = self.user("new")
        disabled = self.user("old", active=0)
        adapter.apply_actions((
            self.mod.SyncAction(self.mod.ActionKind.CREATE, None, created),
            self.mod.SyncAction(self.mod.ActionKind.DISABLE, self.user("old"), disabled),
        ))
        create_sql, create_params = self.cursor.executions[-2]
        disable_sql, disable_params = self.cursor.executions[-1]
        self.assertIn("INSERT INTO pgsql_users (username,password,active", create_sql)
        self.assertEqual("new", create_params[0])
        self.assertEqual("UPDATE pgsql_users SET active=%s WHERE username=%s AND backend=%s", disable_sql)
        self.assertEqual((0, "old", 1), disable_params)

    def test_admin_runtime_commands_use_postgresql_users(self):
        adapter = self.mod.ProxySQLAdmin(self.config, connect=self.fake_connect)
        adapter.load_runtime()
        adapter.save_to_disk()
        self.assertEqual(
            "LOAD PGSQL USERS TO RUNTIME", self.cursor.executions[-2][0]
        )
        self.assertEqual("SAVE PGSQL USERS TO DISK", self.cursor.executions[-1][0])

    def test_drivers_are_imported_only_when_default_connectors_are_used(self):
        self.assertNotIn("psycopg", self.mod.__dict__)
        self.assertNotIn("psycopg2", self.mod.__dict__)
        self.assertNotIn("pymysql", self.mod.__dict__)
        self.mod.PostgreSQLSource(self.config, connect=self.fake_connect, sql_module=FakeSQL).fetch_snapshot()
        self.mod.ProxySQLAdmin(self.config, connect=self.fake_connect).fetch_main_users()
        self.assertNotIn("psycopg", self.mod.__dict__)
        self.assertNotIn("psycopg2", self.mod.__dict__)
        self.assertNotIn("pymysql", self.mod.__dict__)

    def test_default_source_connector_uses_psycopg3(self):
        fake_psycopg = ModuleType("psycopg")
        fake_psycopg.connect = self.fake_connect
        fake_psycopg.sql = FakeSQL
        self.connection.cursor_object.rows = [("alice", self.verifier_a)]
        with patch.dict(sys.modules, {"psycopg": fake_psycopg}):
            source = self.mod.PostgreSQLSource(self.config)
            self.assertEqual([("alice", self.verifier_a)], source.fetch_snapshot())
        self.assertEqual("source", self.connect_kwargs["host"])


class FakeSource:
    def __init__(self, rows=(), error=None):
        self.rows = list(rows)
        self.error = error

    def fetch_snapshot(self):
        if self.error:
            raise self.error
        return list(self.rows)


class FakeAdmin:
    def __init__(self, main=(), runtime=(), fail_apply=False, fail_save=False):
        self.main = list(main)
        self.runtime = list(runtime)
        self.fail_apply = fail_apply
        self.fail_save = fail_save
        self.calls = []

    def fetch_main_users(self):
        self.calls.append("main")
        return list(self.main)

    def fetch_runtime_users(self):
        self.calls.append("runtime")
        return list(self.runtime)

    def apply_actions(self, actions):
        self.calls.append("apply")
        if self.fail_apply:
            raise RuntimeError("apply failed")

    def load_runtime(self):
        self.calls.append("load")

    def save_to_disk(self):
        self.calls.append("save")
        if self.fail_save:
            raise RuntimeError("save failed")


class OrchestrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()
        cls.verifier = "md5" + "a" * 32

    def setUp(self):
        self.config = self.mod.AppConfig(
            source=self.mod.SourceConfig("source", 5432, "roles", "reader", "source-secret"),
            proxysql=self.mod.ProxySQLConfig("proxy", 6032, "admin", "admin-secret"),
            sync=self.mod.SyncSettings(profile="p"),
        )
        self.rows = [("alice", self.verifier)]

    def owned_user(self, active=1):
        return self.mod.ProxySQLUser(
            username="alice", password=self.verifier, active=active, use_ssl=0,
            default_hostgroup=0, transaction_persistent=1, fast_forward=0, backend=1,
            frontend=1, max_connections=10000,
            attributes='{"proxysql_pgsql_user_sync":{"profile":"p"}}', comment="",
        )

    def test_source_failure_is_secret_safe(self):
        secret = "source-secret"
        with self.assertRaises(self.mod.SyncError) as ctx:
            self.mod.run_sync(self.config, FakeSource(error=self.mod.SyncError(secret)), FakeAdmin(),
                              dry_run=False, verbose=False)
        self.assertNotIn(secret, str(ctx.exception))

    def test_dry_run_does_not_write_load_or_save(self):
        admin = FakeAdmin()
        summary = self.mod.run_sync(self.config, FakeSource(self.rows), admin,
                                    dry_run=True, verbose=False)
        self.assertEqual("dry-run", summary.outcome)
        self.assertEqual(["main", "runtime"], admin.calls)
        self.assertFalse(summary.loaded)
        self.assertFalse(summary.saved)
        self.assertEqual(1, summary.counts["created"])

    def test_write_failure_never_loads_runtime(self):
        admin = FakeAdmin(fail_apply=True)
        with self.assertRaises(self.mod.SyncError):
            self.mod.run_sync(self.config, FakeSource(self.rows), admin,
                              dry_run=False, verbose=False)
        self.assertNotIn("load", admin.calls)
        self.assertNotIn("save", admin.calls)

    def test_loads_on_actions_and_saves_only_after_load(self):
        admin = FakeAdmin()
        summary = self.mod.run_sync(self.config, FakeSource(self.rows), admin,
                                    dry_run=False, verbose=False)
        self.assertEqual(["main", "runtime", "apply", "load", "save"], admin.calls)
        self.assertTrue(summary.loaded)
        self.assertTrue(summary.saved)

    def test_loads_runtime_drift_without_actions(self):
        main = self.owned_user()
        runtime = replace(main, active=0)
        admin = FakeAdmin([main], [runtime])
        summary = self.mod.run_sync(self.config, FakeSource(self.rows), admin,
                                    dry_run=False, verbose=False)
        self.assertEqual(["main", "runtime", "load", "save"], admin.calls)
        self.assertEqual(0, summary.counts["updated"])

    def test_save_failure_follows_successful_load(self):
        admin = FakeAdmin(fail_save=True)
        with self.assertRaises(self.mod.SyncError):
            self.mod.run_sync(self.config, FakeSource(self.rows), admin,
                              dry_run=False, verbose=False)
        self.assertEqual(["main", "runtime", "apply", "load", "save"], admin.calls)

    def test_exclusive_lock_reports_contention(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sync.lock"
            with self.mod.exclusive_lock(path) as first:
                self.assertTrue(first)
                with self.mod.exclusive_lock(path) as second:
                    self.assertFalse(second)
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_summary_has_non_negative_duration(self):
        summary = self.mod.run_sync(self.config, FakeSource(self.rows), FakeAdmin(),
                                    dry_run=True, verbose=False)
        self.assertIsInstance(summary, self.mod.RunSummary)
        self.assertGreaterEqual(summary.duration_seconds, 0.0)
        with self.assertRaises(AttributeError):
            summary.outcome = "changed"


class AssetTests(unittest.TestCase):
    """Keep the operator-facing deployment sample complete and safe."""

    def test_source_function_has_security_boundaries(self):
        sql = (ASSET_DIR / "create_source_function.sql").read_text()
        for required in (
            "SECURITY DEFINER",
            "SET search_path = pg_catalog",
            "rolcanlogin",
            "rolvaliduntil",
            "REVOKE ALL",
        ):
            self.assertIn(required, sql)
        self.assertIn("proxysql_auth_managed", sql)
        self.assertIn("pg_has_role", sql)
        self.assertIn("proxysql_auth_reader", sql)

    def test_example_configuration_is_loadable_with_protected_permissions(self):
        source = (ASSET_DIR / "proxysql_pgsql_user_sync.ini.example").read_text()
        self.assertIn("[source]", source)
        self.assertIn("[proxysql]", source)
        self.assertIn("[sync]", source)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pgsql-user-sync.ini"
            path.write_text(
                source.replace("REPLACE_WITH_SOURCE_PASSWORD", "source-secret")
                .replace("REPLACE_WITH_PROXYSQL_PASSWORD", "proxysql-secret"),
                encoding="utf-8",
            )
            os.chmod(path, 0o600)
            module = load_module()
            config = module.load_config(path, module.CLIOverrides())
            self.assertEqual("proxysql_auth", config.source.function_schema)
            self.assertEqual("export_login_roles", config.source.function_name)

    def test_requirements_pin_supported_driver_majors(self):
        requirements = (ASSET_DIR / "requirements.txt").read_text()
        self.assertIn("psycopg[binary]>=3.2.13,<4", requirements)
        self.assertIn("PyMySQL>=1.1.1,<2", requirements)

    def test_readme_documents_scheduler_and_cluster_safety(self):
        readme = (ASSET_DIR / "README.md").read_text()
        for required in (
            "absolute",
            "LOAD SCHEDULER TO RUNTIME",
            "SAVE SCHEDULER TO DISK",
            "disable",
            "keep",
            "adopt_existing_users",
            "dry-run",
            "non-transactional",
            "unmanaged",
            "log",
            "disk",
            "install -o proxysql -g proxysql -m 0600",
            "root:proxysql",
            "0640",
        ):
            self.assertIn(required, readme)
        self.assertIn("one authoritative ProxySQL node", readme)
        self.assertIn("every node", readme)


if __name__ == "__main__":
    unittest.main()
