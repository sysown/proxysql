#!/usr/bin/env python3
from pathlib import Path
import subprocess


def run(*args):
    print('+', ' '.join(args), flush=True)
    subprocess.run(args, check=True)


p = Path('test/infra/control/run-tests-isolated.bash')
text = p.read_text()
old = '''if [ "${COVERAGE_MODE}" = "1" ]; then
    echo ">>> Code coverage enabled - reports will be saved to ${COVERAGE_REPORT_DIR}"
    mkdir -p "${COVERAGE_REPORT_DIR}"
fi
'''
new = '''if [ "${COVERAGE_MODE}" = "1" ]; then
    echo ">>> Code coverage enabled - reports will be saved to ${COVERAGE_REPORT_DIR}"
    mkdir -p "${COVERAGE_REPORT_DIR}"

    # Coverage workflows use sparse checkout for source trees, so the tracked
    # root codecov.yml may not be materialized in the worktree even though it
    # exists at HEAD. codecov-action is explicitly pointed at this path; restore
    # just that file from the tested commit without broadening sparse checkout.
    if [ ! -f "${WORKSPACE}/codecov.yml" ]; then
        if git -C "${WORKSPACE}" cat-file -e HEAD:codecov.yml 2>/dev/null; then
            git -C "${WORKSPACE}" show HEAD:codecov.yml > "${WORKSPACE}/codecov.yml"
            echo ">>> Materialized codecov.yml from HEAD for coverage upload"
        else
            echo ">>> WARNING: codecov.yml is not tracked at HEAD"
        fi
    fi
fi
'''

if old in text:
    p.write_text(text.replace(old, new, 1))
elif 'Materialized codecov.yml from HEAD for coverage upload' not in text:
    raise RuntimeError('run-tests-isolated.bash coverage anchor missing')

run('bash', '-n', str(p))
run('git', 'diff', '--check')
run('git', 'diff', '--', str(p))
run('git', 'add', str(p))

if subprocess.run(['git', 'diff', '--cached', '--quiet']).returncode != 0:
    run('git', 'config', 'user.name', 'github-actions[bot]')
    run('git', 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com')
    run('git', 'commit', '-m', 'ci: materialize Codecov config for sparse coverage jobs')
    run('git', 'push', 'origin', 'HEAD:test/coverage-low-lib-files')

print('Codecov sparse-checkout materialization fix validated and pushed.')
