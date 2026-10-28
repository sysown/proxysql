"""TSAN source builds must instrument dependencies and start with clean outputs."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class TSANDependencyBuildTests(unittest.TestCase):
    def test_tsan_default_prepares_jemalloc_headers_without_linking_the_allocator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ('common_mk', 'include', 'src', 'deps/libssl', 'deps/duckdb'):
                (root / directory).mkdir(parents=True, exist_ok=True)
            for path in ('deps/Makefile', 'deps/libssl/build.mk', 'deps/duckdb/build.mk',
                         'include/makefiles_vars.mk'):
                shutil.copy(ROOT / path, root / path)
            for path in (ROOT / 'common_mk').glob('*.mk'):
                shutil.copy(path, root / 'common_mk' / path.name)
            shutil.copytree(ROOT / 'deps/jemalloc', root / 'deps/jemalloc',
                            ignore=shutil.ignore_patterns('jemalloc', 'jemalloc-5.2.0'))
            (root / 'deps/jemalloc/jemalloc').symlink_to('jemalloc-5.2.0')
            (root / 'src/proxysql_global.cpp').touch()
            probe = "probe-targets:\n\t@printf '%s\\n' '$(targets)'\n"
            command = ['make', '--no-print-directory', '-C', str(root / 'deps'),
                       'WITHTSAN=1', 'GIT_VERSION=4.0.0-test', 'NPROCS=2']
            targets = subprocess.run(command + ['-s', '-f', 'Makefile', '-f', '-', 'probe-targets'],
                                     input=probe, text=True, capture_output=True, check=True).stdout.split()
            # Exercise the actual default graph, omitting the expensive unrelated
            # dependencies. A TSAN exclusion leaves the generated header absent.
            omit = ['--assume-old=' + target for target in targets if target != 'jemalloc']
            built = subprocess.run(command + ['-j2', 'default', *omit], text=True, capture_output=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            headers = root / 'deps/jemalloc/jemalloc/include/jemalloc'
            self.assertTrue((headers / 'jemalloc.h').is_file(),
                            'NOJEM disables allocator linkage, but proxysql.h still needs jemalloc.h')
            consumer = root / 'consumer.cpp'
            consumer.write_text('#include <jemalloc.h>\n#include <stdlib.h>\n'
                                'int main() { void *p = malloc(16); free(p); return 0; }\n')
            linked = subprocess.run(['c++', '-DNOJEM', '-fsanitize=thread', '-I' + str(headers),
                                     str(consumer), '-o', str(root / 'consumer')],
                                    text=True, capture_output=True)
            self.assertEqual(linked.returncode, 0, linked.stdout + linked.stderr)
            # Read the production executable's expanded link inputs as well.
            link_probe = "probe-link:\n\t@printf '%s\\n' '$(MYLIBS)'\n"
            rendered = subprocess.run(
                ['make', '-s', '-C', str(ROOT / 'src'), '-f', 'Makefile', '-f', '-',
                 'probe-link', 'WITHTSAN=1', 'WITHASAN=0'],
                input=link_probe, text=True, capture_output=True, check=True)
            self.assertNotIn('-ljemalloc', rendered.stdout)

    def test_openssl_consumers_can_link_instrumented_archives(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ('common_mk', 'include', 'src', 'deps/artifacts',
                              'deps/libssl/openssl', 'deps/duckdb', 'deps/curl/curl',
                              'deps/postgresql/postgresql/src/interfaces/libpq',
                              'deps/libusual/libusual', 'test/deps',
                              'test/deps/mysql-connector-c/mysql-connector-c',
                              'test/deps/mysql-connector-c-8.4.0/mysql-connector-c'):
                (root / directory).mkdir(parents=True, exist_ok=True)
            for path in ('deps/Makefile', 'test/deps/Makefile', 'include/makefiles_vars.mk',
                         'include/makefiles_paths.mk',
                         'deps/libssl/build.mk', 'deps/duckdb/build.mk',
                         'deps/artifacts/prepare.bash'):
                shutil.copy(ROOT / path, root / path)
            for path in (ROOT / 'common_mk').glob('*.mk'):
                shutil.copy(path, root / 'common_mk' / path.name)
            for dependency in ('postgresql', 'libusual'):
                for path in (ROOT / 'deps' / dependency).glob('*.patch'):
                    shutil.copy(path, root / 'deps' / dependency / path.name)
            (root / 'deps/postgresql/postgresql-16.10.tar.gz').touch()
            (root / 'src/proxysql_global.cpp').touch()
            (root / 'deps/libssl/openssl/.proxysql-build-complete').touch()
            source = root / 'library.c'
            source.write_text('int shared_value;\nint fixture_value(void) { return ++shared_value; }\n')
            subprocess.run(['cc', '-fsanitize=thread', '-c', str(source), '-o', str(root / 'library.o')],
                           check=True, capture_output=True)
            for name in ('libssl.a', 'libcrypto.a'):
                subprocess.run(['ar', 'rcs', str(root / 'deps/libssl/openssl' / name),
                                str(root / 'library.o')], check=True, capture_output=True)
            consumer = root / 'consumer.c'
            consumer.write_text('int fixture_value(void);\nint main(void) { return fixture_value() != 1; }\n')
            for dependency in ('curl', 'postgresql', 'libusual'):
                with self.subTest(dependency=dependency):
                    rendered = subprocess.run(
                        ['make', '-B', '-n', '--no-print-directory', '-C', str(root / 'deps'),
                         dependency, 'MAKE=/bin/true', 'GIT_VERSION=4.0.0-test', 'WITHTSAN=1'],
                        text=True, capture_output=True)
                    self.assertEqual(rendered.returncode, 0, rendered.stdout + rendered.stderr)
                    command = next(line for line in rendered.stdout.splitlines()
                                   if line.startswith('cd ' + dependency + '/') and './configure' in line)
                    tokens = shlex.split(command)
                    environment = dict(token.split('=', 1) for token in tokens[tokens.index('&&') + 1:
                                       tokens.index('./configure')])
                    flags = shlex.split(environment.get('LDFLAGS', ''))
                    libraries = shlex.split(environment.get('LIBS', ''))
                    if dependency == 'libusual':
                        libraries = ['-lssl', '-lcrypto'] + libraries
                    linked = subprocess.run(['cc', str(consumer), *flags, *libraries,
                                             '-o', str(root / 'consumer')], text=True, capture_output=True)
                    self.assertEqual(linked.returncode, 0, linked.stdout + linked.stderr)
            (root / 'CMakeLists.txt').write_text(
                'cmake_minimum_required(VERSION 3.16)\nproject(SSLConsumer C)\n'
                'add_executable(consumer consumer.c)\n'
                'target_link_libraries(consumer PRIVATE "' +
                str(root / 'deps/libssl/openssl/libssl.a') + '")\n')
            for target in ('mysql_client', 'mysql8_client'):
                with self.subTest(dependency=target):
                    rendered = subprocess.run(
                        ['make', '-B', '-n', '--no-print-directory', '-C', str(root / 'test/deps'),
                         target, 'MAKE=/bin/true', 'GIT_VERSION=4.0.0-test', 'WITHTSAN=1'],
                        text=True, capture_output=True)
                    self.assertEqual(rendered.returncode, 0, rendered.stdout + rendered.stderr)
                    flags = [token for line in rendered.stdout.replace('\\\n', ' ').splitlines()
                             if '-DOPENSSL_SSL_LIBRARY=' in line
                             for token in shlex.split(line)
                             if token.startswith('-DCMAKE_EXE_LINKER_FLAGS=')]
                    build = root / target
                    configured = subprocess.run(['cmake', '-S', str(root), '-B', str(build), *flags],
                                                text=True, capture_output=True)
                    self.assertEqual(configured.returncode, 0, configured.stdout + configured.stderr)
                    linked = subprocess.run(['cmake', '--build', str(build)], text=True, capture_output=True)
                    self.assertEqual(linked.returncode, 0, linked.stdout + linked.stderr)

    def test_source_policy_preserves_dependency_compiler_settings(self):
        probe = """probe-tsan-policy:
\t@printf '%s\\n' '$(DEPS_MODE)' '$(CFLAGS)' '$(CXXFLAGS)' '$(LDFLAGS)' '$(DUCKDB_CMAKE_FLAGS)'
"""
        for tsan in ('0', '1'):
            with self.subTest(tsan=tsan):
                result = subprocess.run(
                    ['make', '-s', '-C', str(ROOT / 'deps'), '-f', 'Makefile', '-f', '-',
                     'probe-tsan-policy', 'WITHTSAN=' + tsan, 'WITHASAN=0', 'PROXYSQL40=1',
                     'DEPS_MODE=prebuilt', 'CFLAGS=-DKEEP_C', 'CXXFLAGS=-DKEEP_CXX',
                     'LDFLAGS=-Wl,--as-needed'], input=probe, text=True,
                    capture_output=True, check=True)
                mode, cflags, cxxflags, ldflags, duckdb = result.stdout.splitlines()
                self.assertEqual(mode, 'source' if tsan == '1' else 'prebuilt')
                self.assertEqual((cflags, cxxflags, ldflags),
                                 ('-DKEEP_C', '-DKEEP_CXX', '-Wl,--as-needed'))
                self.assertEqual('-DENABLE_THREAD_SANITIZER=ON' in duckdb, tsan == '1')

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
