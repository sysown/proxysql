"""Exact CI cache keys and prepare/save bridge behavior."""
import importlib.util
import subprocess
import sys
import unittest

import test_dependency_artifact_make as preparation_fixture

ROOT = preparation_fixture.ROOT
spec = importlib.util.spec_from_file_location('dependency_ci', ROOT / 'deps/artifacts/ci.py')
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class DependencyCIAPITests(unittest.TestCase):
    setUp = preparation_fixture.PreparationTests.setUp

    def test_keys_include_full_identity_and_are_workspace_relative(self):
        keys = ci.dependency_keys(self.root, self.env)
        identity = self.identity.build_identity('openssl', self.root, self.env)
        fingerprint = self.identity.fingerprint(identity)
        self.assertEqual({'eligible': True, 'fingerprint': fingerprint,
                          'key': 'proxysql-deps-v1-openssl-' + fingerprint,
                          'path': '.cache/dependency-artifacts/bundles/openssl/' + fingerprint}, keys['openssl'])

    def test_prepare_saves_bundle_and_runs_probe_before_returning(self):
        smoke = self.root / 'test/infra/control/dependency-artifacts-smoke.bash'
        smoke.parent.mkdir(parents=True)
        smoke.write_text('#!/bin/bash\nset -euo pipefail\ntest "$1" = openssl\ntest -s "$2/libssl.a"\n')
        result = ci.prepare_dependencies(self.root, self.env)['openssl']
        cache = self.root / '.cache/dependency-artifacts/bundles/openssl' / result['fingerprint']
        self.assertTrue((cache / 'bundle.tar.gz').is_file())
        smoke.write_text('exit 47\n')
        with self.assertRaises(subprocess.CalledProcessError):
            ci.prepare_dependencies(self.root, self.env)
        self.assertFalse(cache.exists(), 'failed smoke must discard the local bundle')

    def test_make_dry_run_never_prepares_or_writes_cache(self):
        environment = dict(self.env, MAKEFLAGS='n -j4 --jobserver-auth=3,4')
        result = subprocess.run([sys.executable, str(ROOT / 'deps/artifacts/ci.py'),
                                 'prepare', '--root', str(self.root)], env=environment,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(self.tree.exists())
        self.assertFalse((self.root / '.cache').exists())

    def test_local_bundle_symlinks_are_rejected(self):
        result = self.api.prepare_dependency('openssl', self.root, 'auto', self.env)
        directory = self.root / '.cache/dependency-artifacts/bundles/openssl' / result['fingerprint']
        target = directory / 'bundle.tar.gz'
        target.rename(directory / 'other.tar.gz')
        target.symlink_to('other.tar.gz')
        with self.assertRaisesRegex(ValueError, 'regular files'):
            self.api.prepare_dependency('openssl', self.root, 'auto', self.env)


if __name__ == '__main__':
    unittest.main()
