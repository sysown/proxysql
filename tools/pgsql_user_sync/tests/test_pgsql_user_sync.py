import base64
import importlib.util
import os
import sys
import tempfile
import unittest
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

    def test_accepts_group_read_but_not_group_write(self):
        path = self.write_config(mode=0o640)
        self.mod.load_config(path, self.mod.CLIOverrides())
        path = self.write_config(mode=0o660)
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


if __name__ == "__main__":
    unittest.main()
