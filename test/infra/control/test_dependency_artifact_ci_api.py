"""Exact CI cache keys and prepare/save bridge behavior."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_dependency_artifact_make as preparation_fixture

ROOT = preparation_fixture.ROOT
spec = importlib.util.spec_from_file_location('dependency_ci', ROOT / 'deps/artifacts/ci.py')
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class DependencyCIAPITests(unittest.TestCase):
    setUp = preparation_fixture.PreparationTests.setUp

    def test_keys_include_full_identity_and_are_workspace_relative(self):
        keys = ci.dependency_keys(self.root, self.env)
        self.assertEqual({'openssl'}, set(keys))
        identity = self.identity.build_identity('openssl', self.root, self.env)
        fingerprint = self.identity.fingerprint(identity)
        self.assertEqual({'eligible': True, 'fingerprint': fingerprint,
                          'key': 'proxysql-deps-v1-openssl-' + fingerprint,
                          'path': '.cache/dependency-artifacts/bundles/openssl/' + fingerprint}, keys['openssl'])

    def test_ineligible_configuration_and_external_store_do_not_advertise_ci_key(self):
        for override in ({'CPATH': '/external/headers'},
                         {'DEPS_ARTIFACT_CACHE_DIR': str(self.root / 'shared')}):
            with self.subTest(override=override):
                row = ci.dependency_keys(self.root, dict(self.env, **override))['openssl']
                self.assertFalse(row['eligible'])
                self.assertEqual('', row['key'])
                self.assertEqual('', row['path'])

    def test_bad_requested_dependency_is_rejected(self):
        for value in ('openssl openssl', '../openssl', 'zlib'):
            with self.assertRaises(ValueError):
                ci.selected_dependencies({'DEPS_ARTIFACT_DEPENDENCIES': value})

    def test_key_probe_does_not_create_compiled_outputs(self):
        ci.dependency_keys(self.root, self.env)
        self.assertFalse(self.tree.exists())
        self.assertFalse((self.root / 'source-builds').exists())

    def test_prepare_saves_bundle_and_runs_probe_before_returning(self):
        smoke = self.root / 'test/infra/control/dependency-artifacts-smoke.bash'
        smoke.parent.mkdir(parents=True)
        smoke.write_text('#!/bin/bash\nset -euo pipefail\ntest "$1" = openssl\ntest -s "$2/libssl.a"\n')
        result = ci.prepare_dependencies(self.root, self.env)['openssl']
        cache = self.root / '.cache/dependency-artifacts/bundles/openssl' / result['fingerprint']
        self.assertTrue((cache / 'entry.json').is_file())
        self.assertTrue((cache / 'bundle.tar.gz').is_file())
        smoke.write_text('exit 47\n')
        with self.assertRaises(subprocess.CalledProcessError):
            ci.prepare_dependencies(self.root, self.env)

    def test_make_dry_run_never_prepares_or_writes_cache(self):
        environment = dict(self.env, MAKEFLAGS='n -j4 --jobserver-auth=3,4')
        result = subprocess.run([sys.executable, str(ROOT / 'deps/artifacts/ci.py'),
                                 'prepare', '--root', str(self.root)], env=environment,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('dry run', result.stdout)
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
