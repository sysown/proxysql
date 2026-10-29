"""Dependency identities are independent of ProxySQL revisions, not toolchains."""
import copy
import hashlib
import importlib
import json
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'deps/artifacts'))


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('identity')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = {'CC': 'cc', 'CXX': 'c++'}
        for dep, directory, version in [('duckdb', 'duckdb', '1.4.5'),
                                         ('openssl', 'libssl', '3.5.7')]:
            d = self.root / 'deps' / directory
            d.mkdir(parents=True)
            source = d / (dep + '-' + version + '.tar.gz')
            source.write_bytes(b'vendored source')
            source.with_suffix('.gz.sha256').write_text(
                hashlib.sha256(source.read_bytes()).hexdigest() + '  ' + source.name + '\n')
            (d / 'build.mk').write_text(
                'DUCKDB_VERSION := 1.4.5\nDUCKDB_CMAKE_FLAGS := -DCMAKE_BUILD_TYPE=Release\n'
                if dep == 'duckdb' else 'OPENSSL_CONFIGURE_FLAGS := no-shared no-tests -fPIC\n')
            (d / 'verify-source.bash').write_text('# verifier\n')
        (self.root / 'common_mk').mkdir()
        (self.root / 'common_mk/openssl_flags.mk').write_text('OPENSSL_VERSION := 3.5.7\n')
        self.facts = {'os': 'Linux', 'arch': 'x86_64', 'distro': ['ubuntu', '24.04'],
                      'libc': ['glibc', '2.39'], 'cc': 'gcc 13', 'cxx': 'gcc 13',
                      'target': 'x86_64-linux-gnu', 'runtime': 'libstdc++'}
        self.actual_toolchain_identity = self.api.toolchain_identity
        self.probe = patch.object(self.api, 'toolchain_identity', return_value=self.facts)
        self.probe.start()
        self.addCleanup(self.probe.stop)

    def identity(self, dep='duckdb'):
        return self.api.build_identity(dep, self.root, self.env)

    def entry(self):
        identity = self.identity()
        return {'dependency': 'duckdb', 'identity': identity,
                'fingerprint': self.api.fingerprint(identity),
                'url': 'https://github.com/sysown/proxysql/releases/download/deps-v1/a.tar.gz',
                'sha256': 'a' * 64, 'size': 123, 'provenance': {'commit': 'b' * 40}}

    def registry(self, entries):
        path = self.root / 'lock.json'
        path.write_text(json.dumps({'format_version': 1, 'artifacts': entries}))
        return self.api.load_registry(path)

    def test_canonical_fingerprint_and_revision_independence(self):
        first = self.identity()
        self.env.update(GIT_VERSION='4.0.1', GITHUB_SHA='other', PROXYSQL40='1', DEBUG='1')
        self.assertEqual(first, self.identity())
        self.assertEqual(self.api.fingerprint({'a': 1, 'b': 2}),
                         self.api.fingerprint({'b': 2, 'a': 1}))

    def test_toolchain_commands_override_an_inherited_locale(self):
        self.assertEqual('C', self.api.command_output(
            [sys.executable, '-c', 'import os; print(os.environ["LC_ALL"])'],
            {'LC_ALL': 'C.UTF-8'}))

    def test_source_recipe_toolchain_and_flags_invalidate(self):
        first = self.api.fingerprint(self.identity())
        for key in ('CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS', 'DUCKDB_CMAKE_FLAGS'):
            with self.subTest(key=key):
                self.env[key] = '-fPIC'
                self.assertNotEqual(first, self.api.fingerprint(self.identity()))
                del self.env[key]
        for key in ('cxx', 'libc', 'arch', 'runtime', 'distro'):
            with self.subTest(key=key), patch.object(self.api, 'toolchain_identity',
                    return_value={**self.facts, key: 'different'}):
                self.assertNotEqual(first, self.api.fingerprint(self.identity()))
        recipe = self.root / 'deps/duckdb/build.mk'
        recipe.write_text(recipe.read_text() + '# changed recipe\n')
        self.assertNotEqual(first, self.api.fingerprint(self.identity()))

    def test_tsan_identity_is_ineligible_for_bundles_and_distinct_from_normal(self):
        normal = self.identity()
        self.env['WITHTSAN'] = '1'
        tsan = self.identity()
        self.assertFalse(tsan['eligible'])
        self.assertNotEqual(self.api.fingerprint(normal), self.api.fingerprint(tsan))
        for key in ('CFLAGS', 'CXXFLAGS', 'LDFLAGS'):
            self.assertIn('-fsanitize=thread', tsan['flags'][key])
        self.assertIn('-DENABLE_THREAD_SANITIZER=ON', tsan['settings'])
        self.assertIn('-DSKIP_EXTENSIONS=jemalloc', tsan['settings'])

    def test_tsan_duckdb_identity_preserves_the_effective_final_overrides(self):
        self.env['WITHTSAN'] = '1'
        self.env['DUCKDB_CMAKE_FLAGS'] = (
            '-DENABLE_THREAD_SANITIZER=ON -DENABLE_THREAD_SANITIZER=OFF '
            '-DSKIP_EXTENSIONS=jemalloc -DSKIP_EXTENSIONS=other')
        options = self.identity()['settings']
        self.assertEqual(options[-2:], ['-DENABLE_THREAD_SANITIZER=ON',
                                       '-DSKIP_EXTENSIONS=jemalloc'])

    def test_actual_source_digest_is_checked(self):
        (self.root / 'deps/duckdb/duckdb-1.4.5.tar.gz').write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.identity()

    def test_other_dependency_and_root_makefile_do_not_invalidate(self):
        first = self.identity()
        (self.root / 'deps/libssl/build.mk').write_text('unrelated')
        (self.root / 'deps/Makefile').write_text('other dependency change')
        self.assertEqual(first, self.identity())

    def test_missing_toolchain_facts_and_unknown_dependencies_fail(self):
        with patch.object(self.api, 'toolchain_identity', side_effect=ValueError('compiler unavailable')):
            with self.assertRaisesRegex(ValueError, 'compiler'):
                self.identity()
        with self.assertRaises(ValueError):
            self.identity('unknown')

    def test_custom_paths_and_unregistered_operating_system_are_ineligible(self):
        self.env['CPATH'] = '/custom/includes'
        self.assertFalse(self.identity()['eligible'])
        self.env.pop('CPATH')
        with patch.object(self.api, 'toolchain_identity', return_value={**self.facts, 'os': 'FreeBSD'}):
            self.assertFalse(self.identity()['eligible'])

    def test_unprobed_dependency_compiler_and_cpu_overrides_are_ineligible(self):
        cases = [
            ('duckdb', 'DUCKDB_CMAKE_FLAGS', '-DCMAKE_CXX_COMPILER=/custom/compiler'),
            ('duckdb', 'DUCKDB_CMAKE_FLAGS', '-D CMAKE_C_COMPILER:FILEPATH=/custom/cc'),
            ('duckdb', 'DUCKDB_CMAKE_FLAGS', '-DCMAKE_CXX_FLAGS=-march=native'),
            ('duckdb', 'DUCKDB_CMAKE_FLAGS', '-DCMAKE_CXX_FLAGS:STRING=-O3'),
            ('openssl', 'OPENSSL_CONFIGURE_FLAGS', 'no-shared CC=/custom/cc'),
            ('openssl', 'OPENSSL_CONFIGURE_FLAGS', 'no-shared "CC=/custom/cc"'),
            ('openssl', 'OPENSSL_CONFIGURE_FLAGS', 'no-shared -mtune=native'),
            ('openssl', 'OPENSSL_CONFIGURE_FLAGS', '--cross-compile-prefix=/custom/'),
            ('duckdb', 'CXXFLAGS', '-mcpu=native'),
            ('duckdb', 'CMAKE_CXX_FLAGS', '-O3'),
        ]
        for dependency, name, value in cases:
            with self.subTest(name=name, value=value):
                self.env[name] = value
                self.assertFalse(self.identity(dependency)['eligible'])
                del self.env[name]
        self.assertTrue(self.identity()['eligible'])
        self.assertTrue(self.identity('openssl')['eligible'])

    def test_libc_is_running_version_independent_of_python_linkage(self):
        with patch.object(self.api.platform, 'system', return_value='Linux'), \
                patch.object(self.api.platform, 'libc_ver', return_value=('glibc', '2.3.4')), \
                patch.object(self.api.os, 'confstr', return_value='glibc 2.28'), \
                patch.object(self.api.Path, 'read_text', return_value='ID=fixture\nVERSION_ID="1.0"\n'), \
                patch.object(self.api, 'command_output', return_value='fixture'):
            facts = self.actual_toolchain_identity(self.env)
            self.assertEqual(['glibc', '2.28'], facts['libc'])
            self.assertEqual(['fixture', '1.0'], facts['distro'])
            with patch.object(self.api.os, 'confstr', side_effect=ValueError('unavailable')):
                with self.assertRaises(self.api.ToolchainUnavailable):
                    self.actual_toolchain_identity(self.env)

    def test_duckdb_native_arch_cmake_boolean_overrides_are_ineligible(self):
        for value in ('ON', 'on', 'YES', 'TRUE', 'Y', '1', '2', 'custom', 'OFF '):
            for option in ('-DNATIVE_ARCH=', '-DNATIVE_ARCH:BOOL=', '-D NATIVE_ARCH:BOOL='):
                with self.subTest(option=option, value=value):
                    self.env['DUCKDB_CMAKE_FLAGS'] = option + shlex.quote(value)
                    self.assertFalse(self.identity()['eligible'])
        for value in ('OFF', 'off', 'NO', 'FALSE', 'N', '0', '', 'IGNORE', 'NOTFOUND', 'cpu-NOTFOUND'):
            with self.subTest(value=value):
                self.env['DUCKDB_CMAKE_FLAGS'] = '-D NATIVE_ARCH:BOOL=' + value
                self.assertTrue(self.identity()['eligible'])

    def test_registry_accepts_empty_or_exact_entry(self):
        self.assertEqual([], self.registry([])['artifacts'])
        entry = self.entry()
        self.assertEqual([entry], self.registry([entry])['artifacts'])

    def test_registry_rejects_duplicates_and_invalid_entries(self):
        entry = self.entry()
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.registry([entry, entry])
        for key, value in [('sha256', 'bad'), ('fingerprint', '0' * 64),
                           ('size', -1), ('url', 'http://example.com/a'),
                           ('dependency', 'other')]:
            with self.subTest(key=key):
                invalid = copy.deepcopy(entry)
                invalid[key] = value
                with self.assertRaises(ValueError):
                    self.registry([invalid])

    def test_registry_rejects_unknown_schema_and_duplicate_json_keys(self):
        path = self.root / 'lock.json'
        for data in ('{"format_version":2,"artifacts":[]}',
                     '{"format_version":1,"format_version":1,"artifacts":[]}'):
            path.write_text(data)
            with self.assertRaises(ValueError):
                self.api.load_registry(path)


if __name__ == '__main__':
    unittest.main()
