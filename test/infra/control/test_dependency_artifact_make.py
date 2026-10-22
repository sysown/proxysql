"""Preparation modes, concurrency, and the real Make-facing source recipe."""
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

from test_dependency_artifact_bundles import fixture_tree

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'deps/artifacts'))


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('manage')
        self.identity = importlib.import_module('identity')
        self.bundles = importlib.import_module('bundles')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = dict(os.environ, CC='cc', CXX='c++', GIT_VERSION='3.0.0-test')
        for key in ('CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS', 'MAKEFLAGS',
                    'DUCKDB_CMAKE_FLAGS', 'OPENSSL_CONFIGURE_FLAGS', 'DEPS_MODE'):
            self.env.pop(key, None)
        shutil.copytree(ROOT / 'deps/artifacts', self.root / 'deps/artifacts',
                        ignore=shutil.ignore_patterns('__pycache__'))
        (self.root / 'deps/artifacts/lock.json').write_text('{"format_version":1,"artifacts":[]}')
        (self.root / 'common_mk').mkdir()
        shutil.copy(ROOT / 'common_mk/openssl_flags.mk', self.root / 'common_mk')
        directory = self.root / 'deps/libssl'
        directory.mkdir()
        shutil.copy(ROOT / 'deps/libssl/build.mk', directory)
        (directory / 'verify-source.bash').write_text('#!/bin/sh\nexit 0\n')
        (directory / 'verify-source.bash').chmod(0o755)
        (directory / 'openssl').symlink_to('openssl-3.5.7')
        template = self.root / 'template/openssl-3.5.7'
        fixture_tree(template, 'openssl')
        (template / 'config').write_text('#!/bin/sh\nexit 0\n')
        (template / 'config').chmod(0o755)
        (template / 'Makefile').write_text('all:\n\t@sleep 0.05\n\t@echo built >> ' +
                                           str(self.root / 'source-builds') + '\n')
        source = directory / 'openssl-3.5.7.tar.gz'
        with tarfile.open(str(source), 'w:gz') as archive:
            archive.add(str(template), arcname=template.name)
        Path(str(source) + '.sha256').write_text(self.identity.digest_file(source) + '  ' + source.name + '\n')
        (self.root / 'deps/Makefile').write_text(
            'PROXYSQL_PATH := ' + str(self.root) + '\n.DEFAULT_GOAL := libssl\n'
            'CC := cc\nCXX := c++\nexport CC CXX\n'
            'include $(PROXYSQL_PATH)/common_mk/openssl_flags.mk\n'
            'include $(PROXYSQL_PATH)/deps/libssl/build.mk\n'
            'cleanbuild:\n\trm -rf libssl/openssl-3.5.7\n')
        self.tree = directory / 'openssl-3.5.7'
        self.probe = patch.object(self.identity, 'toolchain_identity',
                                  return_value={'os': 'Linux', 'arch': 'fixture'})
        # Direct API tests use the real toolchain, as subprocess Make does.

    def prepare(self, mode='auto'):
        return self.api.prepare_dependency('openssl', self.root, mode, self.env)

    def count(self):
        path = self.root / 'source-builds'
        return len(path.read_text().splitlines()) if path.exists() else 0

    def register(self):
        self.prepare('source')
        identity = self.identity.build_identity('openssl', self.root, self.env)
        output = self.root / 'bundle.tar.gz'
        entry = self.bundles.create_bundle('openssl', self.tree, identity, output)
        entry.update(url='https://github.com/sysown/proxysql/releases/download/deps/a.tar.gz', provenance={})
        (self.root / 'deps/artifacts/lock.json').write_text(json.dumps({'format_version': 1, 'artifacts': [entry]}))
        cache = self.root / '.cache/dependency-artifacts'
        cache.mkdir(parents=True, exist_ok=True)
        shutil.copy(output, cache / (entry['sha256'] + '.tar.gz'))
        return entry

    def make(self, *args, env=None):
        return subprocess.run(['make', '--no-print-directory', '-C', str(self.root / 'deps')] + list(args),
                              env=env or self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=30)

    def test_empty_registry_source_fallback_and_noop(self):
        with patch.object(self.api, 'download_artifact', side_effect=AssertionError('network used')):
            self.assertEqual('source', self.prepare()['origin'])
            stamp = self.tree / '.proxysql-build-complete'
            before = stamp.stat().st_mtime_ns
            self.assertFalse(self.prepare()['changed'])
            self.assertEqual(before, stamp.stat().st_mtime_ns)
        self.assertEqual(1, self.count())

    def test_prebuilt_missing_and_invalid_mode_do_not_compile(self):
        for mode in ('prebuilt', 'typo'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.prepare(mode)
        self.assertEqual(0, self.count())

    def test_prebuilt_hit_relocated_and_mode_transitions(self):
        self.register()
        shutil.rmtree(str(self.tree))
        self.assertEqual('prebuilt', self.prepare('prebuilt')['origin'])
        before = (self.tree / '.proxysql-build-complete').stat().st_mtime_ns
        self.assertFalse(self.prepare('prebuilt')['changed'])
        self.assertEqual(before, (self.tree / '.proxysql-build-complete').stat().st_mtime_ns)
        self.assertEqual(1, self.count())
        self.assertEqual('source', self.prepare('source')['origin'])
        self.assertEqual(2, self.count())
        self.assertEqual('prebuilt', self.prepare('prebuilt')['origin'])
        self.assertEqual(2, self.count())

    def test_corrupt_registered_cache_fails_without_source_fallback(self):
        entry = self.register()
        shutil.rmtree(str(self.tree))
        (self.root / '.cache/dependency-artifacts' / (entry['sha256'] + '.tar.gz')).write_bytes(b'bad')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.prepare()
        self.assertEqual(1, self.count())
        self.assertFalse(self.tree.exists())

    def test_unavailable_download_falls_back_only_in_auto(self):
        entry = self.register()
        shutil.rmtree(str(self.tree))
        (self.root / '.cache/dependency-artifacts' / (entry['sha256'] + '.tar.gz')).unlink()
        with patch.object(self.api, 'download_artifact', side_effect=self.api.Unavailable('offline')):
            with self.assertRaises(ValueError):
                self.prepare('prebuilt')
            self.assertEqual('source', self.prepare()['origin'])
        self.assertEqual(2, self.count())

    def test_interrupted_download_does_not_poison_cache(self):
        entry = self.register()
        cache = self.root / '.cache/dependency-artifacts'
        (cache / (entry['sha256'] + '.tar.gz')).unlink()
        class Interrupted:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def geturl(self): return entry['url']
            def read(self, size): raise URLError('connection lost')
        with patch.object(self.api, 'urlopen', return_value=Interrupted()):
            with self.assertRaises(self.api.Unavailable):
                self.api.download_artifact(entry, cache)
        self.assertFalse(list(cache.glob('*.tar.gz')))
        self.assertFalse(list(cache.glob('.download-*')))

    def test_v3_target_set_does_not_include_duckdb(self):
        result = subprocess.run(['make', '-s', '-C', str(ROOT / 'deps'), '-f', 'Makefile',
                                 '-f', '-', 'print-targets', 'PROXYSQL40=0'],
                                input='print-targets:\n\t@echo "$(targets)"\n',
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn('duckdb', result.stdout.split())

    def test_direct_plugin_object_prepares_duckdb_before_compilation(self):
        target = ROOT / 'plugins/duckdb/obj/duckdb_engine.o'
        result = subprocess.run(['make', '--no-print-directory', '-n', '-B', '-C',
                                 str(ROOT / 'plugins/duckdb'), str(target),
                                 'PROXYSQL40=1', 'MAKE=/bin/true'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('DEPS_MODE=auto duckdb', result.stdout)
        self.assertLess(result.stdout.index('DEPS_MODE=auto duckdb'),
                        result.stdout.index('-c -o ' + str(target)))

    def test_missing_header_and_changed_flags_rebuild_source(self):
        self.prepare('source')
        (self.tree / 'include/openssl/configuration.h').unlink()
        self.prepare('source')
        self.assertEqual(2, self.count())
        self.env['CFLAGS'] = '-fPIC'
        self.prepare('source')
        self.assertEqual(3, self.count())

    def test_make_clean_restore_and_incremental_consumers(self):
        self.register()
        consumer = self.root / 'consumer'
        makefile = self.root / 'deps/Makefile'
        with makefile.open('a') as stream:
            stream.write('\n../consumer: $(OPENSSL_BUILD_STAMP)\n\t@touch ../consumer\n')
        self.assertEqual(0, self.make('cleanbuild').returncode)
        first = self.make('libssl', '../consumer', 'DEPS_MODE=prebuilt')
        self.assertEqual(0, first.returncode, first.stderr + first.stdout)
        before = consumer.stat().st_mtime_ns
        makefile.write_text(makefile.read_text() + '# unrelated Makefile change\n')
        second = self.make('libssl', '../consumer', 'DEPS_MODE=prebuilt')
        self.assertEqual(0, second.returncode, second.stderr + second.stdout)
        self.assertEqual(before, consumer.stat().st_mtime_ns)
        self.assertEqual(1, self.count())

    def test_make_dry_run_does_not_prepare_or_compile(self):
        result = self.make('-n', 'libssl')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(self.tree.exists())
        self.assertEqual(0, self.count())

    def test_concurrent_preparation_builds_once_and_preserves_jobserver(self):
        cli = [sys.executable, str(self.root / 'deps/artifacts/manage.py'), 'prepare',
               '--dependency', 'openssl', '--root', str(self.root), '--mode', 'source']
        processes = [subprocess.Popen(cli, env=self.env, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, universal_newlines=True) for _ in range(2)]
        for process in processes:
            out, err = process.communicate(timeout=30)
            self.assertEqual(0, process.returncode, out + err)
        self.assertEqual(1, self.count())
        result = self.make('-j2', 'libssl', 'DEPS_MODE=source')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn('jobserver unavailable', result.stderr)

    def test_python_free_source_mode_is_incremental_and_rejects_prebuilt_origin(self):
        self.register()
        self.prepare('prebuilt')
        tools = self.root / 'bin'
        tools.mkdir()
        for name in ('bash', 'perl', 'make', 'dirname', 'sed', 'cksum', 'cat', 'rm', 'cp',
                     'mkdir', 'tar', 'gzip', 'uname', 'cc', 'c++', 'touch', 'sleep', 'sh',
                     'awk', 'nproc', 'test'):
            path = shutil.which(name)
            if path:
                (tools / name).symlink_to(path)
        env = dict(self.env, PATH=str(tools))
        for _ in range(2):
            result = self.make('libssl', 'DEPS_MODE=source', env=env)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(2, self.count())
        result = self.make('libssl', 'DEPS_MODE=prebuilt', env=env)
        self.assertNotEqual(0, result.returncode)


if __name__ == '__main__':
    unittest.main()
