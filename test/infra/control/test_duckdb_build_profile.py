"""Check the source recipe against DuckDB's actual architecture-profile logic."""
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class DuckDBBuildProfile(unittest.TestCase):
    def test_default_release_preserves_compiler_cpu_baseline(self):
        make = shutil.which('gmake') or 'make'
        probe = "flags:\n\t@printf '%s\\n' '$(DUCKDB_CMAKE_FLAGS)'\n"
        result = subprocess.run(
            [make, '-s', '-f', str(ROOT / 'deps/duckdb/build.mk'), '-f', '-', 'flags'],
            input=probe, text=True, capture_output=True, check=True)
        flags = shlex.split(result.stdout.strip())
        archive = next((ROOT / 'deps/duckdb').glob('duckdb-*.tar.xz'))
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            with tarfile.open(archive, 'r:xz') as upstream:
                name = archive.name[:-len('.tar.xz')] + '/scripts/architecture_flags.cmake'
                (source / 'architecture_flags.cmake').write_bytes(upstream.extractfile(name).read())
            (source / 'probe.cpp').write_text('int profile_probe() { return 0; }\n')
            (source / 'CMakeLists.txt').write_text(
                'cmake_minimum_required(VERSION 3.14)\nproject(profile_probe CXX)\n'
                'set(DUCKDB_OPTIMIZATION_PROFILE CLI CACHE STRING "Architecture profile")\n'
                'set(CMAKE_SYSTEM_NAME Linux)\nset(CMAKE_SYSTEM_PROCESSOR x86_64)\n'
                'include(architecture_flags.cmake)\nadd_library(probe STATIC probe.cpp)\n'
                'duckdb_apply_architecture_flags()\n')
            for profile, extra in (('default', []), ('upstream_cli', ['-DDUCKDB_OPTIMIZATION_PROFILE=CLI'])):
                with self.subTest(profile=profile):
                    build = source / profile
                    configured = subprocess.run(
                        ['cmake', '-S', str(source), '-B', str(build),
                         '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', *flags, *extra],
                        text=True, capture_output=True)
                    self.assertEqual(configured.returncode, 0, configured.stdout + configured.stderr)
                    command = json.loads((build / 'compile_commands.json').read_text())[0]['command']
                    if profile == 'default':
                        self.assertNotIn('-march=', command)
                        self.assertNotIn('-mcpu=', command)
                    else:
                        self.assertIn('-march=x86-64-v3', command)


if __name__ == '__main__':
    unittest.main()
