#!/usr/bin/env python3
"""Executable regression: retired bootstrap must fail before ordinary startup."""
import subprocess
import sys
import tempfile
from pathlib import Path

core = str(Path(sys.argv[1]).resolve())
forms = [
    ['--aws-managed-bootstrap', '/tmp/not-a-real-manifest.json'],
    ['--aws-managed-bootstrap=/tmp/not-a-real-manifest.json'],
    ['--aws-managed-bootstrap'],
    ['--aws-managed-bootstrap='],
    ['--aws-managed-bootstrap=/tmp/not-a-real-manifest.json', '--load-plugin=/nonexistent-retired-cli-test.so'],
    ['--aws-managed-bootstrap=/tmp/not-a-real-manifest.json', '--config=/nonexistent-retired-cli-test.cnf'],
]
for arguments in forms:
    # With the old implementation, --help guarantees that RED cannot launch a
    # daemon or read a real deployment. After rejection is proven, also exercise
    # the actual legacy invocation without any foreground/exit-on-error flags.
    for help_arguments in (['--help'], []):
        with tempfile.TemporaryDirectory(prefix='retired-bootstrap-') as directory:
            result = subprocess.run([core, *help_arguments, *arguments, '--datadir', directory],
                                    cwd=directory, capture_output=True, text=True, timeout=5)
            assert result.returncode == 1, (arguments, result.returncode, result.stderr)
            assert 'removed' in result.stderr and 'aws-deployment.json' in result.stderr, result.stderr
            assert not list(Path(directory).iterdir()), 'rejected invocation wrote startup state'
    print('PASS:', arguments[0], 'rejected before startup, with and without --help')
result = subprocess.run([core, '--help'], capture_output=True, text=True, timeout=5)
assert result.returncode == 0 and '--aws-managed-bootstrap' not in result.stdout
print('PASS: ordinary help remains available without the removed option')
