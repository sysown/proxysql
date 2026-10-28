"""Real header preparation, compiler instrumentation, and consumer-link regressions."""
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
