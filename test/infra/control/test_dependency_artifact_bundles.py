"""Bundle safety and completeness, without compiling either dependency."""
import copy
import hashlib
import importlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'deps/artifacts'))


def fixture_tree(tree, dependency):
    files = {'LICENSE': b'license'}
    if dependency == 'duckdb':
        files.update({'src/include/duckdb.h': b'header',
                      'build/release/src/libduckdb_static.a': b'!<arch>\n',
                      'build/release/extension/parquet/libparquet_extension.a': b'!<arch>\n',
                      'build/release/DuckDBExports.cmake': (
                          b'  IMPORTED_LOCATION_RELEASE "/old/build/release/src/libduckdb_static.a"\n'
                          b'  IMPORTED_LOCATION_RELEASE "/old/build/release/extension/parquet/libparquet_extension.a"\n')})
    else:
        files.update({'libssl.a': b'!<arch>\n', 'libcrypto.a': b'!<arch>\n',
                      'include/openssl/ssl.h': b'ssl header',
                      'include/openssl/crypto.h': b'crypto header',
                      'include/openssl/configuration.h': b'generated configuration',
                      'include/openssl/opensslv.h': b'# define OPENSSL_VERSION_MAJOR 3\n'
                      b'# define OPENSSL_VERSION_MINOR 5\n# define OPENSSL_VERSION_PATCH 7\n',
                      'providers/legacy.so': b'provider', 'apps/openssl.cnf': b'configuration'})
    for relative, data in files.items():
        path = tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return files


def fixture_identity(dependency):
    return {'format_version': 1, 'dependency': dependency, 'eligible': True,
            'version': '1.4.5' if dependency == 'duckdb' else '3.5.7'}


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('bundles')
        self.identity = importlib.import_module('identity')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tree = self.root / 'original'
        fixture_tree(self.tree, 'duckdb')

    def bundle(self, dep='duckdb', tree=None):
        output = self.root / (dep + '.tar.gz')
        entry = self.api.create_bundle(dep, tree or self.tree, fixture_identity(dep), output)
        entry.update(url='https://github.com/sysown/proxysql/releases/download/deps/a.tar.gz',
                     provenance={})
        return output, entry

    def rewrite(self, source, entry, change):
        with tarfile.open(str(source), 'r:gz') as archive:
            members = [(copy.copy(member), archive.extractfile(member).read())
                       for member in archive.getmembers() if member.isfile()]
        members = change(members)
        with tarfile.open(str(source), 'w:gz') as archive:
            for member, data in members:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data) if member.isfile() else None)
        entry['sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
        entry['size'] = source.stat().st_size

    def test_roundtrip_both_dependencies_and_deterministic_archives(self):
        for dep in ('duckdb', 'openssl'):
            with self.subTest(dep=dep):
                tree = self.root / dep
                files = fixture_tree(tree, dep)
                bundle, entry = self.bundle(dep, tree)
                first = bundle.read_bytes()
                self.bundle(dep, tree)
                self.assertEqual(first, bundle.read_bytes())
                target = self.root / 'different/workspace' / dep
                self.api.restore_bundle(bundle, entry, target)
                for name, data in files.items():
                    self.assertEqual(data, (target / name).read_bytes())

    def test_missing_required_archive_or_generated_header_fails_packaging(self):
        for dep, missing in [('duckdb', 'build/release/extension/parquet/libparquet_extension.a'),
                              ('openssl', 'include/openssl/configuration.h')]:
            tree = self.root / dep
            fixture_tree(tree, dep)
            (tree / missing).unlink()
            with self.subTest(dep=dep), self.assertRaises(ValueError):
                self.bundle(dep, tree)

    def test_wrong_openssl_headers_fail(self):
        tree = self.root / 'ssl'
        fixture_tree(tree, 'openssl')
        (tree / 'include/openssl/opensslv.h').write_text('#define OPENSSL_VERSION_MAJOR 1\n')
        with self.assertRaisesRegex(ValueError, 'version'):
            self.bundle('openssl', tree)

    def test_outer_digest_and_size_must_match(self):
        archive, entry = self.bundle()
        for key, value in [('sha256', '0' * 64), ('size', entry['size'] + 1)]:
            wrong = dict(entry, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.api.restore_bundle(archive, wrong, self.root / 'destination')

    def test_archive_paths_links_devices_duplicates_and_undeclared_files_fail(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
                           ('payload/link', tarfile.SYMTYPE), ('payload/device', tarfile.CHRTYPE),
                           ('payload/undeclared', tarfile.REGTYPE),
                           ('payload/src/include/duckdb.h', tarfile.REGTYPE)]:
            archive, entry = self.bundle()
            def add(members):
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = '../../escape' if kind == tarfile.SYMTYPE else ''
                return members + [(info, b'bad')]
            self.rewrite(archive, entry, add)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.api.restore_bundle(archive, entry, self.root / 'destination')
            self.assertFalse((self.root / 'escape').exists())

    def test_inner_digest_identity_and_missing_file_fail(self):
        for mutation in ('digest', 'identity', 'missing'):
            archive, entry = self.bundle()
            def change(members):
                if mutation == 'missing':
                    return [(m, d) for m, d in members if not m.name.endswith('duckdb.h')]
                result = []
                for member, data in members:
                    if mutation == 'digest' and member.name.endswith('duckdb.h'):
                        data = b'change'
                    if mutation == 'identity' and member.name == 'manifest.json':
                        manifest = json.loads(data)
                        manifest['identity']['version'] = '9.9.9'
                        data = json.dumps(manifest).encode()
                    result.append((member, data))
                return result
            self.rewrite(archive, entry, change)
            message = 'SHA-256 mismatch' if mutation == 'digest' else 'identity|incomplete'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, message):
                self.api.restore_bundle(archive, entry, self.root / 'destination')

    def test_promotion_failure_preserves_previous_tree(self):
        archive, entry = self.bundle()
        target = self.root / 'destination'
        target.mkdir()
        (target / 'previous').write_text('still usable')
        real_replace = self.api.os.replace
        def fail_promotion(src, dst):
            if Path(dst) == target and 'stage-' in Path(src).name:
                raise OSError('simulated disk failure')
            return real_replace(src, dst)
        with patch.object(self.api.os, 'replace', side_effect=fail_promotion):
            with self.assertRaises(OSError):
                self.api.restore_bundle(archive, entry, target)
        self.assertEqual('still usable', (target / 'previous').read_text())

    def test_openssl_tracked_symlink_is_preserved(self):
        tree = self.root / 'ssl'
        fixture_tree(tree, 'openssl')
        archive, entry = self.bundle('openssl', tree)
        link = self.root / 'libssl/openssl'
        link.parent.mkdir()
        link.symlink_to('openssl-3.5.7')
        self.api.restore_bundle(archive, entry, link)
        self.assertTrue(link.is_symlink())
        self.assertTrue((link / 'include/openssl/configuration.h').is_file())

    def test_openssl_tracked_symlink_below_symlinked_checkout_is_preserved(self):
        tree = self.root / 'ssl'
        fixture_tree(tree, 'openssl')
        archive, entry = self.bundle('openssl', tree)
        directory = self.root / 'checkout/libssl'
        directory.mkdir(parents=True)
        (self.root / 'checkout-link').symlink_to('checkout', target_is_directory=True)
        link = self.root / 'checkout-link/libssl/openssl'
        link.symlink_to('openssl-3.5.7')
        self.api.restore_bundle(archive, entry, link)
        self.assertTrue(link.is_symlink())
        self.assertTrue((link / 'include/openssl/configuration.h').is_file())

    def test_unexpected_openssl_symlink_redirection_is_rejected(self):
        tree = self.root / 'ssl'
        fixture_tree(tree, 'openssl')
        archive, entry = self.bundle('openssl', tree)
        link = self.root / 'libssl/openssl'
        link.parent.mkdir()
        outside = self.root / 'outside'
        outside.mkdir()
        link.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'unexpected.*symlink'):
            self.api.restore_bundle(archive, entry, link)
        self.assertEqual([], list(outside.iterdir()))

    def test_openssl_versioned_directory_symlink_redirection_is_rejected(self):
        tree = self.root / 'ssl'
        fixture_tree(tree, 'openssl')
        archive, entry = self.bundle('openssl', tree)
        link = self.root / 'libssl/openssl'
        link.parent.mkdir()
        outside = self.root / 'outside'
        outside.mkdir()
        (link.parent / 'openssl-3.5.7').symlink_to(outside)
        link.symlink_to('openssl-3.5.7')
        with self.assertRaisesRegex(ValueError, 'unexpected.*symlink'):
            self.api.restore_bundle(archive, entry, link)
        self.assertEqual([], list(outside.iterdir()))


if __name__ == '__main__':
    unittest.main()
