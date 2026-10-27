"""Automatic exact-identity storage, independent versions and remote lookup."""
import importlib
import io
import json
import re
from pathlib import Path
import shutil
import tarfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

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
        flags.write_text(re.sub(r'(OPENSSL_VERSION\s*:=\s*)[0-9.]+',
                                r'\g<1>' + version, flags.read_text()))
        link = self.root / 'deps/libssl/openssl'
        link.unlink()
        link.symlink_to('openssl-' + version)
        self.tree = self.root / 'deps/libssl' / ('openssl-' + version)

    def test_version_a_b_a_uses_separate_bundles_without_recompiling_a(self):
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
        result = self.prepare()
        key = result['fingerprint']
        directory = self.root / '.cache/dependency-artifacts/bundles/openssl' / key
        self.assertTrue((directory / 'entry.json').is_file())
        self.assertTrue((directory / 'bundle.tar.gz').is_file())
        shutil.rmtree(str(self.tree))
        self.assertEqual('prebuilt', self.prepare()['origin'])
        self.assertEqual(1, self.count())

    def test_corrupt_pairs_fail_automatic_use_and_source_can_repair(self):
        first = self.prepare()
        directory = self.root / '.cache/dependency-artifacts/bundles/openssl' / first['fingerprint']
        metadata = directory / 'entry.json'
        entry = json.loads(metadata.read_text())
        for name, data in (('bundle.tar.gz', b'corrupt'), ('entry.json', b'{}')):
            (directory / name).write_bytes(data)
            with self.assertRaises(ValueError):
                self.prepare()
            self.assertFalse(self.prepare('source')['changed'])
        entry['identity']['version'] = '9.9.9'
        metadata.write_text(json.dumps(entry))
        with self.assertRaisesRegex(ValueError, 'fingerprint does not match identity'):
            self.prepare()
        self.prepare('source')
        shutil.rmtree(str(self.tree))
        self.assertEqual('prebuilt', self.prepare()['origin'])
        self.assertEqual(1, self.count())

    def test_remote_lookup_uses_computed_signature_and_validates_identity(self):
        store = importlib.import_module('store')
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

    def test_missing_or_unavailable_remote_falls_back_only_in_auto(self):
        store = importlib.import_module('store')
        self.env['DEPS_ARTIFACT_REMOTE'] = '1'
        for error in (HTTPError('https://github.com/x', 404, '', {}, None), URLError('offline')):
            with self.subTest(error=error), patch.object(store, 'urlopen', side_effect=error):
                with self.assertRaises(store.Unavailable):
                    self.prepare('prebuilt')
                self.assertEqual('source', self.prepare()['origin'])
            shutil.rmtree(str(self.root / '.cache/dependency-artifacts/bundles'))
            shutil.rmtree(str(self.tree))
        self.assertEqual(2, self.count())


if __name__ == '__main__':
    unittest.main()
