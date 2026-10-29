"""Real header preparation, compiler instrumentation, and consumer-link regressions."""
from pathlib import Path
import shlex
import os
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

    def test_allocator_disabled_in_all_production_link_inputs(self):
        probe = "probe-link:\n\t@printf '%s\\n' '$(LIBPROXYSQLAR) $(MYLIBS) $(LIBS)'\n"
        for platform in ('Linux', 'Darwin'):
            for options, allocator_expected in ((['NOJEMALLOC=0'], True),
                                                (['NOJEMALLOC=1'], False),
                                                (['WITHTSAN=1'], False),
                                                (['WITHASAN=1'], False)):
                with self.subTest(platform=platform, options=options):
                    rendered = subprocess.run(
                        ['make', '-s', '-C', str(ROOT / 'src'), '-f', 'Makefile', '-f', '-',
                         'probe-link', 'UNAME_S=' + platform, 'WITHTSAN=0', 'WITHASAN=0',
                         *options],
                        env={k: v for k, v in os.environ.items() if k != 'NOJEMALLOC'},
                        input=probe, text=True, capture_output=True, check=True)
                    inputs = shlex.split(rendered.stdout)
                    self.assertTrue(any(value.endswith('/libproxysql.a') for value in inputs))
                    linked = any(value == '-ljemalloc' or value.endswith('/libjemalloc.a')
                                 for value in inputs)
                    self.assertEqual(linked, allocator_expected, rendered.stdout)

    def test_tsan_duckdb_configures_required_options_after_custom_flags(self):
        # Configure a real CMake cache through the production Make flags. A
        # flag hidden in another definition must not disable TSAN or jemalloc's
        # exclusion; a later conflicting definition must not win either.
        cases = ('-DMETADATA=-DENABLE_THREAD_SANITIZER=ON',
                 '-DMETADATA=-DSKIP_EXTENSIONS=jemalloc',
                 '-DENABLE_THREAD_SANITIZER=ON -DENABLE_THREAD_SANITIZER=OFF',
                 '-DSKIP_EXTENSIONS=jemalloc -DSKIP_EXTENSIONS=other')
        for flags in cases:
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / 'deps/duckdb/duckdb'
                source.mkdir(parents=True)
                (source / 'CMakeLists.txt').write_text(
                    'cmake_minimum_required(VERSION 3.16)\nproject(options NONE)\n'
                    'option(ENABLE_THREAD_SANITIZER "Enable TSAN" OFF)\n'
                    'set(SKIP_EXTENSIONS "" CACHE STRING "Excluded extensions")\n')
                recipe = root / 'deps/duckdb/build.mk'
                shutil.copy(ROOT / 'deps/duckdb/build.mk', recipe)
                # Dry-run the real source recipe; only its configure command
                # is executed, against a tiny real CMake project. This avoids
                # pretending the probe builds DuckDB itself.
                (source.parent / 'duckdb-1.4.5.tar.gz').touch()
                (source.parent / 'verify-source.bash').touch()
                rendered = subprocess.run(
                    ['make', '-n', '-B', '-s', '-C', str(root / 'deps'), '-f', str(recipe),
                     'dependency-source-duckdb', 'WITHTSAN=1', 'PROXYSQL_PATH=' + str(root),
                     'DUCKDB_CMAKE_FLAGS=' + flags],
                    text=True, capture_output=True, check=True)
                command = next(line for line in rendered.stdout.splitlines()
                               if '&& cmake -S . -B build/release ' in line)
                result = subprocess.run(['bash', '-e', '-c', command], cwd=root / 'deps',
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                cache = dict(line.split('=', 1) for line in
                             (source / 'build/release/CMakeCache.txt').read_text().splitlines()
                             if line and not line.startswith(('//', '#')) and '=' in line)
                self.assertEqual(cache['ENABLE_THREAD_SANITIZER:BOOL'], 'ON')
                self.assertEqual(cache['SKIP_EXTENSIONS:STRING'], 'jemalloc')

    def test_tsan_make_rejects_invalid_mode_before_forcing_source(self):
        recipe = ('include ' + str(ROOT / 'common_mk/tsan_dependencies.mk') + '\n'
                  'mode-probe:\n\t@echo $(DEPS_MODE)\n')
        for mode in ('typo', 'auto source'):
            with self.subTest(mode=mode):
                result = subprocess.run(['make', '-s', '-f', '-', 'mode-probe',
                                         'WITHTSAN=1', 'DEPS_MODE=' + mode],
                                        input=recipe, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('DEPS_MODE must be auto, source, or prebuilt', result.stderr)
        for mode in ('auto', 'source', 'prebuilt'):
            result = subprocess.run(['make', '-s', '-f', '-', 'mode-probe',
                                     'WITHTSAN=1', 'DEPS_MODE=' + mode],
                                    input=recipe, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'source')

    def test_openssl_consumers_can_link_instrumented_archives(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ('common_mk', 'include', 'src', 'deps/artifacts',
                              'deps/libssl/openssl', 'deps/duckdb', 'deps/curl/curl',
                              'deps/postgresql/postgresql/src/interfaces/libpq',
                              'deps/libusual/libusual'):
                (root / directory).mkdir(parents=True, exist_ok=True)
            for path in ('deps/Makefile', 'include/makefiles_vars.mk',
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



if __name__ == '__main__':
    unittest.main()
