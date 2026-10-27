"""Automatic exact-identity storage, independent versions and remote lookup."""
import importlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import test_dependency_artifact_make as preparation_fixture


class AutomaticStoreTests(unittest.TestCase):
    setUp = preparation_fixture.PreparationTests.setUp
    prepare = preparation_fixture.PreparationTests.prepare
    count = preparation_fixture.PreparationTests.count

    def install_version(self, version):
        template = self.root / 'template' / ('openssl-' + version)
        if not template.exists():
            shutil.copytree(str(self.root / 'template/openssl-3.5.7'), str(template))
        header = template / 'include/openssl/opensslv.h'
        header.write_text(header.read_text().replace('OPENSSL_VERSION_PATCH 7',
                                                   'OPENSSL_VERSION_PATCH ' + version.split('.')[-1]))
        archive = self.root / 'deps/libssl' / ('openssl-' + version + '.tar.gz')
        if not archive.exists():
            with tarfile.open(str(archive), 'w:gz') as tar:
                tar.add(str(template), arcname=template.name)
            Path(str(archive) + '.sha256').write_text(
                self.identity.digest_file(archive) + '  ' + archive.name + '\n')
        flags = self.root / 'common_mk/openssl_flags.mk'
        import re
        flags.write_text(re.sub(r'(OPENSSL_VERSION\s*:=\s*)[0-9.]+',
                                r'\g<1>' + version, flags.read_text()))
        link = self.root / 'deps/libssl/openssl'
        link.unlink()
        link.symlink_to('openssl-' + version)
        self.tree = self.root / 'deps/libssl' / ('openssl-' + version)

    def test_version_a_b_a_uses_separate_bundles_without_recompiling_a(self):
        self.env['DEPS_ARTIFACT_REMOTE'] = '0'
        first = self.prepare()
        shutil.rmtree(str(self.tree))
        self.install_version('3.5.8')
        second = self.prepare()
        self.assertNotEqual(first['fingerprint'], second['fingerprint'])
        entry = self.root / '.cache/dependency-artifacts/bundles/openssl' / second['fingerprint'] / 'entry.json'
        self.assertEqual('3.5.8', json.loads(entry.read_text())['identity']['version'])
        self.install_version('3.5.7')
        self.assertEqual('prebuilt', self.prepare()['origin'])
        self.assertEqual(2, self.count())

    def test_unrelated_core_commit_preserves_dependency_signature(self):
        self.env['DEPS_ARTIFACT_REMOTE'] = '0'
        before = self.identity.build_identity('openssl', self.root, self.env)
        for args in [('init', '-q'), ('config', 'user.name', 'Test'),
                     ('config', 'user.email', 'test@example.invalid')]:
            subprocess.run(['git', '-C', str(self.root)] + list(args), check=True)
        (self.root / 'core.cpp').write_text('core change\n')
        subprocess.run(['git', '-C', str(self.root), 'add', 'core.cpp'], check=True)
        subprocess.run(['git', '-C', str(self.root), 'commit', '-qm', 'unrelated core change'], check=True)
        self.assertEqual(before, self.identity.build_identity('openssl', self.root, self.env))

    def test_source_only_openssl_upgrade_preserves_duckdb_key(self):
        base = self.root / 'deps/duckdb'
        base.mkdir()
        for name in ('build.mk', 'verify-source.bash'):
            shutil.copyfile(str(preparation_fixture.ROOT / 'deps/duckdb' / name), str(base / name))
        archive = base / 'duckdb-1.4.5.tar.gz'
        archive.write_bytes(b'independent DuckDB source fixture')
        Path(str(archive) + '.sha256').write_text(self.identity.digest_file(archive) + '  ' + archive.name + '\n')
        before = self.identity.build_identity('duckdb', self.root, self.env)
        self.install_version('3.5.8')
        self.assertEqual(before, self.identity.build_identity('duckdb', self.root, self.env))

    def test_cold_miss_creates_bundle_and_clean_tree_reuses_it(self):
        self.env['DEPS_ARTIFACT_REMOTE'] = '0'
        result = self.prepare()
        key = result['fingerprint']
        directory = self.root / '.cache/dependency-artifacts/bundles/openssl' / key
        self.assertTrue((directory / 'entry.json').is_file())
        self.assertTrue((directory / 'bundle.tar.gz').is_file())
        shutil.rmtree(str(self.tree))
        self.assertEqual('prebuilt', self.prepare()['origin'])
        self.assertEqual(1, self.count())

    def test_shared_cache_serializes_cold_misses_from_separate_checkouts(self):
        other = self.root / 'other'
        shutil.copytree(str(self.root / 'deps'), str(other / 'deps'), symlinks=True)
        shutil.copytree(str(self.root / 'common_mk'), str(other / 'common_mk'))
        makefile = other / 'deps/Makefile'
        makefile.write_text(makefile.read_text().replace('PROXYSQL_PATH := ' + str(self.root),
                                                        'PROXYSQL_PATH := ' + str(other)))
        environment = dict(self.env, DEPS_ARTIFACT_CACHE_DIR=str(self.root / 'shared'))
        processes = [subprocess.Popen(['make', '--no-print-directory', '-C', str(root / 'deps'), 'libssl'],
                                      env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                     for root in (self.root, other)]
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(0, process.returncode, (stdout + stderr).decode())
        self.assertEqual(1, self.count())
        first = json.loads((self.tree / '.proxysql-dependency.json').read_text())
        second = json.loads((other / 'deps/libssl/openssl-3.5.7/.proxysql-dependency.json').read_text())
        self.assertEqual(first['fingerprint'], second['fingerprint'])
        self.assertEqual({'source', 'prebuilt'}, {first['origin'], second['origin']})

    def test_missing_bundle_for_accepted_source_is_repaired_without_compile(self):
        self.env['DEPS_ARTIFACT_REMOTE'] = '0'
        first = self.prepare()
        directory = self.root / '.cache/dependency-artifacts/bundles/openssl' / first['fingerprint']
        shutil.rmtree(str(directory))
        self.assertFalse(self.prepare()['changed'])
        self.assertTrue((directory / 'entry.json').exists())
        self.assertEqual(1, self.count())

    def test_settings_a_b_a_coexist_and_restore_without_rebuilding_a(self):
        self.env['DEPS_ARTIFACT_REMOTE'] = '0'
        first = self.prepare()
        self.env['OPENSSL_CONFIGURE_FLAGS'] = 'no-shared no-tests -fPIC -DSECOND_CONFIG'
        second = self.prepare()
        self.assertNotEqual(first['fingerprint'], second['fingerprint'])
        self.assertEqual(2, self.count())
        del self.env['OPENSSL_CONFIGURE_FLAGS']
        self.assertEqual('prebuilt', self.prepare()['origin'])
        self.assertEqual(2, self.count())
        directories = self.root / '.cache/dependency-artifacts/bundles/openssl'
        self.assertTrue((directories / first['fingerprint'] / 'entry.json').exists())
        self.assertTrue((directories / second['fingerprint'] / 'entry.json').exists())

    def test_wrong_identity_in_keyed_directory_is_rejected(self):
        self.env['DEPS_ARTIFACT_REMOTE'] = '0'
        first = self.prepare()
        directory = self.root / '.cache/dependency-artifacts/bundles/openssl' / first['fingerprint']
        entry = json.loads((directory / 'entry.json').read_text())
        entry['identity']['version'] = '9.9.9'
        (directory / 'entry.json').write_text(json.dumps(entry))
        shutil.rmtree(str(self.tree))
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(1, self.count())

    def test_corrupt_automatic_bundle_is_not_a_source_fallback(self):
        self.env['DEPS_ARTIFACT_REMOTE'] = '0'
        first = self.prepare()
        archive = (self.root / '.cache/dependency-artifacts/bundles/openssl' /
                   first['fingerprint'] / 'bundle.tar.gz')
        archive.write_bytes(b'corrupt')
        shutil.rmtree(str(self.tree))
        with self.assertRaisesRegex(ValueError, 'SHA-256|size'):
            self.prepare()
        self.assertEqual(1, self.count())

    def test_explicit_source_repairs_corrupt_local_bundle_from_valid_source_outputs(self):
        first = self.prepare()
        directory = self.root / '.cache/dependency-artifacts/bundles/openssl' / first['fingerprint']
        (directory / 'bundle.tar.gz').write_bytes(b'corrupt')
        result = self.prepare('source')
        self.assertFalse(result['changed'])
        self.assertEqual(1, self.count())
        shutil.rmtree(str(self.tree))
        self.assertEqual('prebuilt', self.prepare()['origin'])
        self.assertEqual(1, self.count())

    def test_remote_lookup_uses_computed_signature_and_validates_identity(self):
        store = importlib.import_module('store')
        self.env['DEPS_ARTIFACT_REMOTE'] = '0'
        first = self.prepare()
        directory = self.root / '.cache/dependency-artifacts/bundles/openssl' / first['fingerprint']
        entry = json.loads((directory / 'entry.json').read_text())
        class Response(io.BytesIO):
            def geturl(self): return store.entry_url('openssl', first['fingerprint'])
        with patch.object(store, 'urlopen', return_value=Response(json.dumps(entry).encode())) as fetch:
            found = store.remote_entry('openssl', entry['identity'], self.env)
        self.assertEqual(entry, found)
        self.assertIn(first['fingerprint'], fetch.call_args[0][0])
        entry['url'] = 'https://attacker.invalid/bundle.tar.gz'
        with patch.object(store, 'urlopen', return_value=Response(json.dumps(entry).encode())):
            with self.assertRaisesRegex(ValueError, 'URL|url'):
                store.remote_entry('openssl', entry['identity'], self.env)

    def test_remote_404_is_miss_but_invalid_json_is_integrity_failure(self):
        store = importlib.import_module('store')
        identity = self.identity.build_identity('openssl', self.root, self.env)
        with patch.object(store, 'urlopen', side_effect=HTTPError('https://github.com/x', 404, '', {}, None)):
            self.assertIsNone(store.remote_entry('openssl', identity, self.env))
        key = self.identity.fingerprint(identity)
        class Response(io.BytesIO):
            def geturl(self): return store.entry_url('openssl', key)
        with patch.object(store, 'urlopen', return_value=Response(b'{"format":1,"format":2}')):
            with self.assertRaises(ValueError):
                store.remote_entry('openssl', identity, self.env)


if __name__ == '__main__':
    unittest.main()
