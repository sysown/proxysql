"""TSAN source builds must instrument dependencies and start with clean outputs."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class TSANDependencyBuildTests(unittest.TestCase):
    def flags(self, tsan):
        makefile = '''probe-tsan-environment:
\t@printf '%s\\n' '$(DEPS_MODE)' '$(CFLAGS)' '$(CXXFLAGS)' '$(LDFLAGS)' '$(TSAN_CMAKE_FLAGS)' '$(DUCKDB_CMAKE_FLAGS)' '$(targets)'
'''
        result = subprocess.run(['make', '-s', '-C', str(ROOT / 'deps'), '-f', 'Makefile', '-f', '-',
                                 'probe-tsan-environment', 'WITHTSAN=' + str(tsan), 'WITHASAN=0',
                                 'PROXYSQL40=1', 'DEPS_MODE=prebuilt', 'CFLAGS=-DKEEP_C',
                                 'CXXFLAGS=-DKEEP_CXX', 'LDFLAGS=-Wl,--as-needed'], input=makefile,
                                text=True, capture_output=True, check=True)
        return result.stdout.splitlines()

    def test_tsan_forces_source_and_preserves_instrumented_compiler_and_linker_flags(self):
        mode, cflags, cxxflags, ldflags, cmake, duckdb, targets = self.flags(1)
        self.assertEqual(mode, 'source')
        for value, original in [(cflags, '-DKEEP_C'), (cxxflags, '-DKEEP_CXX'),
                                (ldflags, '-Wl,--as-needed')]:
            self.assertIn(original, value)
            self.assertIn('-fsanitize=thread', value)
        for name in ('CMAKE_C_FLAGS', 'CMAKE_CXX_FLAGS', 'CMAKE_EXE_LINKER_FLAGS', 'CMAKE_SHARED_LINKER_FLAGS'):
            self.assertIn('-D' + name + '="', cmake)
        self.assertIn('-DENABLE_THREAD_SANITIZER=ON', duckdb)
        self.assertIn('-DSKIP_EXTENSIONS=jemalloc', duckdb)
        self.assertNotIn('jemalloc', targets.split())

    def test_normal_dependency_build_policy_and_flags_are_preserved(self):
        mode, cflags, cxxflags, ldflags, cmake, duckdb, targets = self.flags(0)
        self.assertEqual((mode, cflags, cxxflags, ldflags),
                         ('prebuilt', '-DKEEP_C', '-DKEEP_CXX', '-Wl,--as-needed'))
        self.assertEqual(cmake, '')
        self.assertNotIn('ENABLE_THREAD_SANITIZER', duckdb)
        self.assertIn('jemalloc', targets.split())

    def test_direct_sqlite_compile_and_shared_link_carry_tsan(self):
        result = subprocess.run(['make', '-Bn', '-C', str(ROOT / 'deps'),
                                 'sqlite3/sqlite3/sqlite3.o', 'WITHTSAN=1', 'WITHASAN=0',
                                 'CC=cc'], text=True, capture_output=True, check=True)
        lines = result.stdout.splitlines()
        compile_line = next(line for line in lines if '-c -o sqlite3.o' in line)
        link_line = next(line for line in lines if '-o libsqlite3.so' in line)
        self.assertIn('-fsanitize=thread', compile_line)
        self.assertIn('-fsanitize=thread', link_line)

    def test_recursive_custom_make_keeps_tsan_with_command_line_flag_overrides(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'child.mk').write_text("all:\n\t@printf '%s\\n' '$(CFLAGS)' '$(CXXFLAGS)' '$(LDFLAGS)'\n")
            (root/'parent.mk').write_text('WITHTSAN=1\ninclude ' + str(ROOT/'common_mk/tsan_dependencies.mk') +
                '\nall:\n\t@$(MAKE) -s -f ' + str(root/'child.mk') + ' $(TSAN_MAKE_FLAGS)\n')
            result = subprocess.run(['make', '-s', '-f', str(root/'parent.mk'),
                                     'CFLAGS=-DKEEP_C', 'CXXFLAGS=-DKEEP_CXX', 'LDFLAGS=-Wl,--as-needed'],
                                    text=True, capture_output=True, check=True)
            self.assertTrue(all('-fsanitize=thread' in line for line in result.stdout.splitlines()), result.stdout)

    def test_re2_recursive_override_keeps_its_language_and_build_flags(self):
        probe = "probe-re2-flags:\n\t@printf '%s\\n' '$(TSAN_RE2_MAKE_FLAGS)'\n"
        result = subprocess.run(['make', '-s', '-C', str(ROOT/'deps'), '-f', 'Makefile', '-f', '-',
                                 'probe-re2-flags', 'WITHTSAN=1', 'WITHASAN=0', 'CXXFLAGS=-DKEEP_CXX'],
                                input=probe, text=True, capture_output=True, check=True)
        self.assertIn('-std=c++', result.stdout)
        self.assertIn('-fsanitize=thread', result.stdout)
        self.assertIn('-DKEEP_CXX', result.stdout)
        self.assertIn('-O3', result.stdout)

    def test_test_connector_builds_receive_tsan_flags_too(self):
        probe = "probe-test-deps:\n\t@printf '%s\\n' '$(CFLAGS)' '$(CXXFLAGS)' '$(LDFLAGS)' '$(TSAN_CMAKE_FLAGS)'\n"
        result = subprocess.run(['make', '-s', '-C', str(ROOT/'test/deps'), '-f', 'Makefile', '-f', '-',
                                 'probe-test-deps', 'WITHTSAN=1', 'WITHASAN=0'], input=probe,
                                text=True, capture_output=True, check=True)
        values = result.stdout.splitlines()
        self.assertEqual(len(values), 4)
        self.assertTrue(all('-fsanitize=thread' in value for value in values), values)

    @unittest.skipUnless(all(shutil.which(tool) for tool in ('gcc', 'g++', 'nm', 'readelf')),
                         'real TSAN dependency link check needs the GNU toolchain')
    def test_old_libtool_static_archives_link_instrumented_consumers(self):
        probe = "probe-libtool-flags:\n\t@printf '%s\\n' '$(TSAN_LIBTOOL_CONFIGURE_FLAGS)' '$(TSAN_MAKE_FLAGS)'\n"
        result = subprocess.run(['make', '-s', '-C', str(ROOT/'deps'), '-f', 'Makefile', '-f', '-',
                                 'probe-libtool-flags', 'WITHTSAN=1', 'WITHASAN=0'], input=probe,
                                text=True, capture_output=True, check=True)
        configure_flags, make_flags = result.stdout.splitlines()
        overrides = shlex.split(make_flags)
        for dependency, archive_name, subdirectory, library in (
                ('libdaemon', 'libdaemon-0.14.tar.gz', 'libdaemon', 'libdaemon'),
                ('cityhash', 'cityhash-1.1.1-5-gf5dc541.tar.gz', 'src', 'libcityhash')):
            with self.subTest(dependency=dependency), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with tarfile.open(ROOT/'deps'/dependency/archive_name) as archive:
                    archive.extractall(root, filter='data')
                source = next(root.iterdir())
                for name in ('config.guess', 'config.sub'):
                    shutil.copy(ROOT/'deps/libdaemon'/name, source/name)
                    (source/name).chmod(0o755)
                # Configure without instrumentation so this link-only regression
                # also runs on hosts whose ASLR layout cannot execute TSAN.
                env = dict(os.environ, CC='gcc', CXX='g++', CFLAGS='', CXXFLAGS='', LDFLAGS='', LIBS='')
                options = ['--disable-examples'] if dependency == 'libdaemon' else []
                configured = subprocess.run(['./configure', *options, *shlex.split(configure_flags)], cwd=source, env=env,
                                            text=True, capture_output=True)
                self.assertEqual(configured.returncode, 0, configured.stdout + configured.stderr)
                built = subprocess.run(['make', '-C', subdirectory, library + '.la', *overrides],
                                       cwd=source, env=env, text=True, capture_output=True)
                self.assertEqual(built.returncode, 0, (built.stdout + built.stderr)[-6000:])
                outputs = source/subdirectory/'.libs'
                self.assertTrue((outputs/(library + '.a')).is_file())
                symbols = subprocess.check_output(['nm', '-u', str(outputs/(library + '.a'))], text=True)
                self.assertIn('__tsan_', symbols)
                if dependency == 'libdaemon':
                    consumer = source/'consumer.c'
                    consumer.write_text('#include "libdaemon/dlog.h"\nint main(void) { daemon_set_verbosity(1); return 0; }\n')
                    compiler, includes = 'gcc', source
                else:
                    consumer = source/'consumer.cc'
                    consumer.write_text('#include "city.h"\nint main() { return CityHash64("tsan", 4) == 0; }\n')
                    compiler, includes = 'g++', source/'src'
                linked = subprocess.run([compiler, '-fsanitize=thread', '-I' + str(includes), str(consumer),
                                         str(outputs/(library + '.a')), '-o', str(source/'consumer')],
                                        text=True, capture_output=True)
                self.assertEqual(linked.returncode, 0, linked.stdout + linked.stderr)
                dynamic = subprocess.check_output(['readelf', '-d', str(source/'consumer')], text=True)
                self.assertIn('libtsan.so', dynamic)

    def test_docker_entrypoint_cleans_before_tsan_source_dependencies(self):
        source = (ROOT / 'docker/images/proxysql/deb-compliant/entrypoint/entrypoint.bash').read_text()
        body = source[source.index('if [[ -z ${PROXYSQL_BUILD_TYPE:-} ]]'):source.index('touch /opt/proxysql/src/proxysql')]
        for tsan in ('0', '1'):
            with self.subTest(tsan=tsan), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                calls = root / 'calls'
                make = root / 'make'
                make.write_text('#!/bin/sh\nprintf "%s|%s\\n" "$DEPS_MODE" "$*" >> "$CALLS"\n')
                make.chmod(0o755)
                env = dict(os.environ, MAKE=str(make), MAKEOPT='', CALLS=str(calls),
                           DEPS_MODE='prebuilt', WITHTSAN=tsan, PROXYSQL40='1',
                           PROXYSQL_BUILD_TYPE='debug', BLD_NAME='ubuntu24-tap')
                subprocess.run(['bash', '-eu', '-c', body], env=env, check=True,
                               text=True, capture_output=True)
                rows = calls.read_text().splitlines()
                self.assertEqual(len(rows), 3 if tsan == '1' else 2)
                self.assertTrue(all(row.startswith(('source' if tsan == '1' else 'prebuilt') + '|') for row in rows))
                if tsan == '1':
                    self.assertIn('cleanall', rows[0])
                self.assertIn('build_deps', rows[-2])
                self.assertIn('build_tap_test_debug', rows[-1])


if __name__ == '__main__':
    unittest.main()
