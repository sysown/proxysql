"""Preparation modes, concurrency, and the real Make-facing source recipe."""
import importlib
import fcntl
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
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
        self.env = dict(os.environ, CC='cc', CXX='c++', GIT_VERSION='3.0.0-test', DEPS_ARTIFACT_REMOTE='0')
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
        (template / 'include/openssl/x509.h').write_text('another public header')
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
        # Isolate legacy registry/download cases from the new automatic store.
        shutil.rmtree(str(cache / 'bundles'), ignore_errors=True)
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

    def test_tsan_rebuilds_normal_source_and_bypasses_all_bundle_lookups(self):
        self.prepare('source')
        self.env['WITHTSAN'] = '1'
        with patch.object(self.api.store, 'local_entry', side_effect=AssertionError('TSAN must not restore bundles')), \
             patch.object(self.api.store, 'remote_entry', side_effect=AssertionError('TSAN must not download bundles')), \
             patch.object(self.api.store, 'save_local', side_effect=AssertionError('TSAN must not cache bundles')):
            result = self.prepare('prebuilt')
            self.assertEqual('source', result['origin'])
            self.assertTrue(result['changed'])
            self.assertEqual(2, self.count())
            self.assertFalse(self.prepare()['changed'], 'one source tree can serve subsequent phases of the same build')

    def assert_tsan_openssl_compilation(self, python_free=False, custom_flags=False):
        # Model configure's generated flags, then really compile and archive an
        # object. Replacing those flags at recursive make time must fail here.
        template = self.root / 'template/openssl-3.5.7'
        (template / 'fixture.c').write_text(
            '#ifndef PACKAGE_REQUIRED\n#error missing configured flag\n#endif\n'
            '#ifndef OBJECT_REQUIRED\n#error missing per-object flag\n#endif\n'
            'int shared_value;\nint fixture_value(void) { return ++shared_value; }\n')
        (template / 'config').write_text(
            '#!/bin/sh\nset -eu\n'
            'printf "%s\\n" "${CFLAGS:-}" "${CXXFLAGS:-}" "${LDFLAGS:-}" > configured-flags\n'
            'printf "CFLAGS := %s -DPACKAGE_REQUIRED\\n" "${CFLAGS:-}" > Makefile\n'
            "cat >> Makefile <<'MAKEFILE'\n"
            'all: libssl.a libcrypto.a\n'
            'fixture.o: CFLAGS += -DOBJECT_REQUIRED\n'
            'fixture.o: fixture.c\n\t$(CC) $(CFLAGS) -c fixture.c -o fixture.o\n'
            'libssl.a libcrypto.a: fixture.o\n\tar rcs $@ fixture.o\n'
            'MAKEFILE\n')
        source = self.root / 'deps/libssl/openssl-3.5.7.tar.gz'
        with tarfile.open(str(source), 'w:gz') as archive:
            archive.add(str(template), arcname=template.name)
        Path(str(source) + '.sha256').write_text(
            self.identity.digest_file(source) + '  ' + source.name + '\n')
        env = self.python_free_environment() if python_free else dict(self.env)
        env['WITHTSAN'] = '1'
        args = ['-j2', 'libssl', 'DEPS_MODE=prebuilt']
        if custom_flags:
            args += ['CFLAGS=-DKEEP_C', 'CXXFLAGS=-DKEEP_CXX', 'LDFLAGS=-Wl,--as-needed']
        result = self.make(*args, env=env)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn('jobserver unavailable', result.stderr)
        configured = (self.tree / 'configured-flags').read_text().splitlines()
        for flags in configured:
            self.assertIn('-fsanitize=thread', flags)
        if custom_flags:
            self.assertIn('-DKEEP_C', configured[0])
            self.assertIn('-DKEEP_CXX', configured[1])
            self.assertIn('-Wl,--as-needed', configured[2])
        for name in ('libssl.a', 'libcrypto.a'):
            symbols = subprocess.check_output(['nm', '-u', str(self.tree / name)], text=True)
            self.assertIn('__tsan_read', symbols)
            self.assertIn('__tsan_write', symbols)
        consumer = self.root / 'consumer.c'
        consumer.write_text('int fixture_value(void);\nint main(void) { return fixture_value() != 1; }\n')
        subprocess.run(['cc', '-fsanitize=thread', str(consumer), str(self.tree / 'libcrypto.a'),
                        '-o', str(self.root / 'consumer')], check=True, capture_output=True, text=True)
        self.assertEqual('source\n', (self.tree / '.proxysql-origin').read_text())

    def test_tsan_openssl_compiles_instrumented_configured_objects(self):
        self.assert_tsan_openssl_compilation()

    def test_tsan_openssl_preserves_custom_flags_and_instrumentation(self):
        self.assert_tsan_openssl_compilation(custom_flags=True)

    def test_python_free_tsan_openssl_compiles_instrumented_configured_objects(self):
        self.assert_tsan_openssl_compilation(python_free=True)

    def test_python_free_tsan_openssl_preserves_custom_flags_and_instrumentation(self):
        self.assert_tsan_openssl_compilation(python_free=True, custom_flags=True)

    def test_prebuilt_missing_and_invalid_mode_do_not_compile(self):
        for mode in ('prebuilt', 'typo'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.prepare(mode)
        self.assertEqual(0, self.count())

    def test_unavailable_optional_identity_probe_uses_source_escape_hatch(self):
        with patch.object(self.api, 'build_identity', side_effect=self.identity.ToolchainUnavailable('C++ runtime probe unavailable')):
            result = self.prepare('auto')
            self.assertEqual('source', result['origin'])
            self.assertEqual(1, self.count())
            with self.assertRaises(ValueError):
                self.prepare('prebuilt')

    def test_corrupt_vendored_source_is_not_an_availability_miss(self):
        (self.root / 'deps/libssl/openssl-3.5.7.tar.gz').write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.prepare('auto')
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

    def test_short_download_eof_falls_back_only_in_auto(self):
        entry = self.register()
        shutil.rmtree(str(self.tree))
        cache = self.root / '.cache/dependency-artifacts'
        archive = cache / (entry['sha256'] + '.tar.gz')
        partial = archive.read_bytes()[:-1]
        archive.unlink()
        class ShortResponse(io.BytesIO):
            def geturl(self): return entry['url']
        with patch.object(self.api, 'urlopen', side_effect=lambda *a, **kw: ShortResponse(partial)):
            with self.assertRaises(self.api.Unavailable):
                self.prepare('prebuilt')
            self.assertEqual(1, self.count())
            self.assertEqual('source', self.prepare('auto')['origin'])
        self.assertEqual(2, self.count())
        self.assertFalse(archive.exists())
        self.assertFalse(list(cache.glob('.download-*')))

    def test_complete_download_with_wrong_digest_fails_without_fallback(self):
        entry = self.register()
        shutil.rmtree(str(self.tree))
        cache = self.root / '.cache/dependency-artifacts'
        archive = cache / (entry['sha256'] + '.tar.gz')
        data = archive.read_bytes()
        wrong = bytes([data[0] ^ 1]) + data[1:]
        archive.unlink()
        class WrongResponse(io.BytesIO):
            def geturl(self): return entry['url']
        with patch.object(self.api, 'urlopen', side_effect=lambda *a, **kw: WrongResponse(wrong)):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                self.prepare('auto')
        self.assertEqual(1, self.count())
        self.assertFalse(self.tree.exists())
        self.assertFalse(list(cache.glob('.download-*')))

    def test_archive_transport_errors_are_unavailable_and_partial_downloads_removed(self):
        from http.client import HTTPException
        import ssl
        entry = dict(url='https://example.com/dependency.tar.gz', sha256='a' * 64, size=10)
        for error in (ssl.SSLError('TLS read interrupted'), HTTPException('response interrupted')):
            class Interrupted:
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def geturl(self): return entry['url']
                def read(self, size): raise error
            with self.subTest(error=error), patch.object(self.api, 'urlopen', return_value=Interrupted()):
                with self.assertRaisesRegex(self.api.Unavailable, 'artifact download unavailable'):
                    self.api.download_artifact(entry, self.root / 'transport-cache')
                self.assertFalse(list((self.root / 'transport-cache').iterdir()))

    def test_accepted_source_recreates_missing_bundle_without_remote_lookup(self):
        result = self.prepare('source')
        cache = self.root / '.cache/dependency-artifacts/bundles/openssl' / result['fingerprint']
        shutil.rmtree(str(cache))
        self.env['DEPS_ARTIFACT_REMOTE'] = '1'
        import store
        with patch.object(store, 'remote_entry', side_effect=AssertionError('unnecessary network lookup')):
            self.assertFalse(self.prepare()['changed'])
        self.assertTrue((cache / 'entry.json').is_file())
        self.assertEqual(1, self.count())

    def test_python36_response_read_timeout_is_unavailable(self):
        # Before Python 3.10 socket.timeout was not a TimeoutError subclass.
        class LegacySocketTimeout(OSError): pass
        class TimedOut:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def geturl(self): return 'https://example.com/dependency.tar.gz'
            def read(self, size): raise LegacySocketTimeout('read timed out')
        entry = dict(url='https://example.com/dependency.tar.gz', sha256='a' * 64, size=10)
        with patch('socket.timeout', LegacySocketTimeout), \
                patch.object(self.api, 'urlopen', return_value=TimedOut()):
            with self.assertRaises(self.api.Unavailable):
                self.api.download_artifact(entry, self.root / 'download-cache')
        self.assertFalse(list((self.root / 'download-cache').iterdir()))

    def test_exported_cxxflags_match_dependency_then_plugin_preparation(self):
        for name in ('makefiles_vars.mk', 'makefiles_paths.mk'):
            (self.root / 'include').mkdir(exist_ok=True)
            shutil.copy(ROOT / 'include' / name, self.root / 'include' / name)
        archive = self.root / 'deps/duckdb/duckdb/build/release/src/libduckdb_static.a'
        with (self.root / 'deps/Makefile').open('a') as stream:
            stream.write('\n.PHONY: duckdb\nduckdb:\n\t@echo "$(CXXFLAGS)" >> ../dependency-flags\n'
                         '\t@mkdir -p ' + str(archive.parent) + '\n\t@touch ' + str(archive) + '\n')
        env = dict(self.env, CXXFLAGS='-O2')
        result = self.make('duckdb', 'DEPS_MODE=prebuilt', env=env)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        result = subprocess.run(['make', '--no-print-directory', '-C', str(ROOT / 'plugins/duckdb'),
                                 'PROXYSQL_PATH=' + str(self.root), str(archive), 'DEPS_MODE=prebuilt'],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(['-O2', '-O2'], (self.root / 'dependency-flags').read_text().splitlines())

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

    def test_missing_other_public_header_invalidates_prepared_outputs(self):
        self.prepare('source')
        (self.tree / 'include/openssl/x509.h').unlink()
        self.prepare('source')
        self.assertTrue((self.tree / 'include/openssl/x509.h').is_file())
        self.assertEqual(2, self.count())

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

    def python_free_environment(self):
        tools = self.root / 'bin'
        tools.mkdir(exist_ok=True)
        for name in ('bash', 'perl', 'make', 'dirname', 'sed', 'cksum', 'cat', 'rm', 'cp',
                     'mkdir', 'tar', 'gzip', 'uname', 'cc', 'c++', 'touch', 'sleep', 'sh',
                     'awk', 'nproc', 'test', 'find', 'sort', 'grep', 'basename', 'tr',
                     'sha256sum', 'shasum', 'sha256', 'as', 'ar', 'ld'):
            path = shutil.which(name)
            if path and not (tools / name).exists():
                (tools / name).symlink_to(path)
        return dict(self.env, PATH=str(tools))

    def install_real_source_verifier(self):
        directory = self.root / 'deps/libssl'
        shutil.copy(ROOT / 'deps/libssl/verify-source.bash', directory)
        template = self.root / 'template/openssl-3.5.7'
        (template / 'Configure').write_text('# fixture configure\n')
        source = directory / 'openssl-3.5.7.tar.gz'
        with tarfile.open(str(source), 'w:gz') as archive:
            archive.add(str(template), arcname=template.name)
        Path(str(source) + '.sha256').write_text(self.identity.digest_file(source) + '  ' + source.name + '\n')
        return source

    def test_python_free_reuse_verifies_checksum_sidecar_before_accepting_tree(self):
        source = self.install_real_source_verifier()
        env = self.python_free_environment()
        result = self.make('libssl', 'DEPS_MODE=source', env=env)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        checksum = Path(str(source) + '.sha256')
        before = checksum.stat()
        checksum.write_text('0' * 64 + '  ' + source.name + '\n')
        os.utime(str(checksum), ns=(before.st_atime_ns, before.st_mtime_ns))
        result = self.make('libssl', 'DEPS_MODE=source', env=env)
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('SHA-256 mismatch', result.stderr)
        self.assertEqual(1, self.count())

    def test_python_free_sidecar_contents_participate_in_source_signature(self):
        source = self.install_real_source_verifier()
        env = self.python_free_environment()
        result = self.make('libssl', 'DEPS_MODE=source', env=env)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        checksum = Path(str(source) + '.sha256')
        before = checksum.stat()
        checksum.write_text(checksum.read_text().replace('  ', ' '))
        os.utime(str(checksum), ns=(before.st_atime_ns, before.st_mtime_ns))
        result = self.make('libssl', 'DEPS_MODE=source', env=env)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(2, self.count())

    def test_python_free_source_archive_corruption_fails_hard(self):
        source = self.install_real_source_verifier()
        env = self.python_free_environment()
        result = self.make('libssl', 'DEPS_MODE=source', env=env)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        source.write_bytes(b'corrupt')
        result = self.make('libssl', 'DEPS_MODE=source', env=env)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('SHA-256 mismatch', result.stderr)
        self.assertEqual(1, self.count())

    def test_relocated_python_free_source_tree_is_a_noop(self):
        self.install_real_source_verifier()
        env = self.python_free_environment()
        result = self.make('libssl', 'DEPS_MODE=source', env=env)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        before = (self.tree / '.proxysql-build-complete').stat().st_mtime_ns
        original = self.root
        self.root = original.with_name(original.name + '-relocated')
        original.rename(self.root)
        # Python 3.6's TemporaryDirectory cleanup requires its original path.
        self.addCleanup(self.root.rename, original)
        self.tree = self.root / 'deps/libssl/openssl-3.5.7'
        makefile = self.root / 'deps/Makefile'
        makefile.write_text(makefile.read_text().replace(str(original), str(self.root)))
        env['PATH'] = str(self.root / 'bin')
        result = self.make('libssl', 'DEPS_MODE=source', env=env)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(before, (self.tree / '.proxysql-build-complete').stat().st_mtime_ns)
        self.assertEqual(1, self.count())

    def test_python_free_lock_survives_exec_and_serializes_preparation(self):
        env = self.python_free_environment()
        entered, release = self.root / 'entered', self.root / 'release'
        (self.root / 'deps/libssl/verify-source.bash').write_text(
            '#!/bin/sh\ntouch ' + str(entered) + '\nwhile [ ! -f ' + str(release) +
            ' ]; do sleep 0.02; done\n')
        cli = ['make', '--no-print-directory', '-C', str(self.root / 'deps'),
               'libssl', 'DEPS_MODE=source']
        processes = [subprocess.Popen(cli, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      universal_newlines=True)]
        try:
            deadline = time.monotonic() + 10
            while not entered.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(entered.exists(), 'source recipe did not start')
            with (self.root / '.cache/dependency-artifacts/openssl.lock').open('a') as lock:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            processes.append(subprocess.Popen(cli, env=env, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, universal_newlines=True))
        finally:
            release.touch()
            results = [process.communicate(timeout=30) for process in processes]
        for process, (out, err) in zip(processes, results):
            self.assertEqual(0, process.returncode, out + err)
        self.assertEqual(1, self.count())

    def test_python_free_missing_payload_rebuilds(self):
        env = self.python_free_environment()
        result = self.make('libssl', 'DEPS_MODE=source', env=env)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        for index, name in enumerate(('include/openssl/x509.h', 'apps/openssl.cnf', 'LICENSE', 'providers/legacy.so'), 2):
            with self.subTest(name=name):
                (self.tree / name).unlink()
                result = self.make('libssl', 'DEPS_MODE=source', env=env)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertTrue((self.tree / name).is_file())
                self.assertEqual(index, self.count())

    def test_python_free_duckdb_inventory_includes_headers_archives_and_licenses(self):
        directory = self.root / 'deps/duckdb'
        directory.mkdir()
        for name in ('build.mk', 'list-static-archives.sh'):
            shutil.copy(ROOT / 'deps/duckdb' / name, directory / name)
        (directory / 'verify-source.bash').write_text('# fixture verifier\n')
        template, tree = self.root / 'duckdb-template', directory / 'duckdb'
        fixture_tree(template, 'duckdb')
        for name in ('src/include/duckdb.hpp', 'third_party/library/LICENSE'):
            path = template / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('public output')
        (directory / 'duckdb-1.4.5.tar.gz').write_bytes(b'fixture source')
        (directory / 'duckdb-1.4.5.tar.gz.sha256').write_text('fixture checksum\n')
        with (self.root / 'deps/Makefile').open('a') as stream:
            stream.write('\n.PHONY: dependency-source-duckdb\ndependency-source-duckdb:\n'
                         '\t@cp -R ' + str(template) + ' ' + str(tree) + '\n'
                         '\t@echo built >> ../source-builds\n')
        env = self.python_free_environment()
        cli = ['bash', str(self.root / 'deps/artifacts/prepare.bash'),
               'duckdb', str(self.root), 'source']
        result = subprocess.run(cli, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        for index, name in enumerate(('src/include/duckdb.hpp', 'third_party/library/LICENSE',
                                     'build/release/extension/parquet/libparquet_extension.a'), 2):
            with self.subTest(name=name):
                (tree / name).unlink()
                result = subprocess.run(cli, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        universal_newlines=True, timeout=30)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertTrue((tree / name).is_file())
                self.assertEqual(index, self.count())

    def test_python_free_source_mode_is_incremental_and_rejects_prebuilt_origin(self):
        self.register()
        self.prepare('prebuilt')
        env = self.python_free_environment()
        for _ in range(2):
            result = self.make('libssl', 'DEPS_MODE=source', env=env)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(2, self.count())
        result = self.make('libssl', 'DEPS_MODE=prebuilt', env=env)
        self.assertNotEqual(0, result.returncode)


if __name__ == '__main__':
    unittest.main()
