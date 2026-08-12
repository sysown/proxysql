import base64
import importlib.util
import json
import os
import stat
import sys
import tempfile
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "proxysql_pgsql_user_sync.py"


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


if __name__ == "__main__":
    unittest.main()
