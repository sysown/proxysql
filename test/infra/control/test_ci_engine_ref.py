"""Exercise paired-ref selection without fetching or changing production refs."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SELECTOR = ROOT / 'test/infra/control/resolve-ci-engine-ref.bash'


class EngineRefTests(unittest.TestCase):
    def test_pair_pin_and_production_transition(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            subprocess.run(['git', 'init', '-q', folder], check=True)
            (root / '.github').mkdir()
            pin = 'a' * 40
            (root / '.github/ci-tier-engine-ref').write_text(pin + '\n')
            env = dict(os.environ)
            env.pop('CI_ENGINE_REF', None)
            def select():
                return subprocess.run(['bash', str(SELECTOR)], cwd=root, env=env, text=True, capture_output=True)
            self.assertEqual(select().stdout.strip(), pin)
            env['CI_ENGINE_REF'] = 'explicit-candidate'
            self.assertEqual(select().stdout.strip(), 'explicit-candidate')
            env.pop('CI_ENGINE_REF')
            (root / '.github/ci-tier-engine-ref').write_text('bad-ref\n')
            self.assertNotEqual(select().returncode, 0)
            (root / '.github/ci-tier-engine-ref').write_text(pin + '\n')
            (root / '.github/ci-tier-engine-ref').unlink()
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            'commit', '--allow-empty', '-qm', 'legacy engine'], cwd=root, check=True)
            subprocess.run(['git', 'update-ref', 'refs/remotes/origin/GH-Actions', 'HEAD'], cwd=root, check=True)
            result = select()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('catalogue', result.stderr)
            self.assertIn('pin', result.stderr)
            (root / '.github/ci-tier-consumers.json').write_text('{}')
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            'commit', '-qm', 'engine available'], cwd=root, check=True)
            subprocess.run(['git', 'update-ref', 'refs/remotes/origin/GH-Actions', 'HEAD'], cwd=root, check=True)
            self.assertEqual(select().stdout.strip(), 'origin/GH-Actions')

    def test_fanout_guard_and_unit_tests_without_engine_ref(self):
        text = (ROOT / 'test/infra/control/run-ci-lint.bash').read_text()
        section = text[text.index('if git rev-parse'):]
        before_else = section.split('\nelse\n', 1)[0]
        self.assertIn('Check selected-tier fanout', before_else)
        after_guard = section.split('\nfi\n', 1)[1]
        self.assertIn('Test selected-tier fanout validator', after_guard)


if __name__ == '__main__':
    unittest.main()
