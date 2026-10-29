"""Validate the configured DuckDB archive set without compiling DuckDB."""
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
VALIDATOR = ROOT / 'deps/duckdb/list-static-archives.sh'


class DuckDBArchives(unittest.TestCase):
    def fixture(self, root, jemalloc=False):
        paths = ['src/libduckdb_static.a',
                 'extension/core_functions/libcore_functions_extension.a',
                 'extension/parquet/libparquet_extension.a']
        paths += [f'third_party/{name}/libduckdb_{name}.a' for name in
                  ('fastpforlib', 'fmt', 'fsst', 'hyperloglog', 'pg_query', 'mbedtls',
                   'miniz', 're2', 'skiplistlib', 'utf8proc', 'yyjson', 'zstd')]
        if jemalloc:
            paths.append('extension/jemalloc/libjemalloc_extension.a')
        # A copied build cache may record its original absolute directory.
        (root / 'DuckDBExports.cmake').write_text('\n'.join(
            f'  IMPORTED_LOCATION_RELEASE "/original/build/release/{path}"'
            for path in paths) + '\n  IMPORTED_LOCATION_RELEASE "/original/build/release/src/libduckdb.dylib"\n')
        for path in paths:
            file = root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b'!<arch>\n')
        return paths

    def run_validator(self, root):
        return subprocess.run(['sh', str(VALIDATOR), str(root)], text=True,
                              capture_output=True, timeout=10)

    def test_complete_platform_specific_sets(self):
        for jemalloc in (False, True):
            with self.subTest(jemalloc=jemalloc), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                paths = self.fixture(root, jemalloc)
                result = self.run_validator(root)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(set(result.stdout.splitlines()), {str(root / p) for p in paths})

    def test_missing_archive_cannot_be_hidden_by_unrelated_extra_archive(self):
        for missing in ('third_party/re2/libduckdb_re2.a', 'extension/jemalloc/libjemalloc_extension.a'):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.fixture(root, jemalloc=True)
                (root / missing).unlink()
                (root / 'unrelated.a').write_bytes(b'!<arch>\n')
                result = self.run_validator(root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(missing, result.stderr)
                self.assertEqual(result.stdout, '')

    def test_missing_or_empty_manifest_fails_closed(self):
        for contents in (None, '', '  IMPORTED_LOCATION_RELEASE "/old/build/release/third_party/re2/libduckdb_re2.a"'):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                if contents is not None:
                    (root / 'DuckDBExports.cmake').write_text(contents)
                result = self.run_validator(root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('DuckDB', result.stderr)
                self.assertEqual(result.stdout, '')

    def test_plugin_makefile_checks_its_configured_archives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build = root / 'build/release'
            build.mkdir(parents=True)
            self.fixture(build)
            cmd = [shutil.which('gmake') or 'make', '-s', '-C', str(ROOT / 'plugins/duckdb'),
                   'check-duckdb-archives', f'DUCKDB_PATH={root}']
            result = subprocess.run(cmd, text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            (build / 'extension/parquet/libparquet_extension.a').unlink()
            result = subprocess.run(cmd, text=True, capture_output=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('libparquet_extension.a', result.stderr)

    def test_up_to_date_plugin_still_rejects_a_missing_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build = root / 'build/release'
            build.mkdir(parents=True)
            self.fixture(build)
            make = shutil.which('gmake') or 'make'
            directory = ROOT / 'plugins/duckdb'
            objects = subprocess.run(
                [make, '-s', '-f', 'Makefile', '-f', '-', 'inspect-objects'],
                cwd=directory, text=True, capture_output=True, check=True,
                input="inspect-objects:\n\t@echo '$(OBJS)'\n").stdout.split()
            output = root / 'already-built.so'
            output.write_bytes(b'previously linked plugin')
            # Suppress compilation of real source objects. The compiler must
            # not run: this output is newer than every link prerequisite.
            skip = [arg for obj in objects for arg in ('-o', obj)]
            cmd = [make, '-s', str(output), f'PLUGIN_SO={output}', f'DUCKDB_PATH={root}',
                   'CXX=false', *skip]
            result = subprocess.run(cmd, cwd=directory, text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            (build / 'extension/parquet/libparquet_extension.a').unlink()
            result = subprocess.run(cmd, cwd=directory, text=True, capture_output=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('libparquet_extension.a', result.stderr)
            self.assertEqual(output.read_bytes(), b'previously linked plugin')


if __name__ == '__main__':
    unittest.main()
