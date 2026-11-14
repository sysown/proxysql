"""Publication profiles must use the requested C and C++ compiler families."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class BuildProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        scripts = self.root / 'deps/artifacts'
        scripts.mkdir(parents=True)
        shutil.copy(ROOT / 'deps/artifacts/build.bash', scripts)
        self.tools = self.root / 'bin'
        self.tools.mkdir()
        for name, body in {
            'git': 'echo v4.0.0-fixture',
            'make': 'echo reached-source-build >&2; exit 29',
            'gcc': "printf '#define __GNUC__ 13\\n'",
            'g++': "printf '#define __GNUC__ 13\\n'",
            'clang': "printf '#define __GNUC__ 4\\n#define __clang__ 1\\n'",
            'clang++': "printf '#define __GNUC__ 4\\n#define __clang__ 1\\n'",
        }.items():
            path = self.tools / name
            path.write_text('#!/bin/sh\n' + body + '\n')
            path.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.tools) + os.pathsep + os.environ['PATH'])
        self.env.pop('CC', None)
        self.env.pop('CXX', None)

    def build(self, profile, **compiler_env):
        env = dict(self.env, **compiler_env)
        return subprocess.run(['bash', str(self.root / 'deps/artifacts/build.bash'), profile,
                               'duckdb', str(self.root / 'output'), 'sysown/proxysql',
                               'dependency-artifacts-v1-1-1'], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=15)

    def test_clang_profile_rejects_gcc_cxx_before_source_build(self):
        result = self.build('ubuntu24-amd64-clang', CC='clang', CXX='g++')
        self.assertNotEqual(0, result.returncode)
        self.assertIn('CXX', result.stderr)
        self.assertNotIn('reached-source-build', result.stderr)

    def test_gcc_profile_rejects_clang_cxx_before_source_build(self):
        result = self.build('ubuntu24-amd64-gcc', CC='gcc', CXX='clang++')
        self.assertNotEqual(0, result.returncode)
        self.assertIn('CXX', result.stderr)
        self.assertNotIn('reached-source-build', result.stderr)

    def test_profile_defaults_select_both_matching_compilers(self):
        for profile in ('ubuntu24-amd64-clang', 'ubuntu24-amd64-gcc', 'macos14-arm64-clang'):
            with self.subTest(profile=profile):
                # Provide a deterministic cc default, independent of the host.
                cc = self.tools / 'cc'
                if not cc.exists():
                    cc.symlink_to('gcc')
                result = self.build(profile)
                self.assertEqual(29, result.returncode, result.stdout + result.stderr)
                self.assertIn('reached-source-build', result.stderr)


if __name__ == '__main__':
    unittest.main()
