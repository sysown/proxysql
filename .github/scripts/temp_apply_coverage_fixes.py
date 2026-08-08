#!/usr/bin/env python3
from pathlib import Path
import subprocess


def run(*args):
    print('+', ' '.join(args), flush=True)
    subprocess.run(args, check=True)


def expr(body):
    return '${{ ' + body + ' }}'


def add_permissions(text, filename):
    tests = text.index('  tests:\n')
    steps = text.index('    steps:\n', tests)
    header = text[tests:steps]
    if '    permissions:' in header:
        if '    permissions: write-all' not in header:
            raise RuntimeError(filename + ': unexpected permissions block')
        return text
    runs = text.index('    runs-on:', tests, steps)
    eol = text.index('\n', runs) + 1
    return text[:eol] + '    permissions: write-all\n' + text[eol:]


def coverage_block(infra, coverage_name):
    return f'''    - name: Archive coverage report
      if: {expr('!cancelled()')}
      uses: actions/upload-artifact@v4
      with:
        name: {expr('github.workflow')}-{expr('env.SHA')}-coverage-run#{expr('github.run_number')}
        path: |
          proxysql/ci_infra_logs/{infra}/coverage-report/
        if-no-files-found: ignore

    - name: Report missing coverage file
      if: {expr("!cancelled() && hashFiles('proxysql/ci_infra_logs/**/coverage-report/*.info') == ''")}
      run: |
        echo "No coverage report was produced; skipping Codecov upload."

    - name: Upload coverage to Codecov
      if: {expr("!cancelled() && hashFiles('proxysql/ci_infra_logs/**/coverage-report/*.info') != ''")}
      uses: codecov/codecov-action@v4
      with:
        codecov_yml_path: {expr('github.workspace')}/proxysql/codecov.yml
        override_commit: {expr('inputs.trigger && fromJson(inputs.trigger).event.workflow_run.head_sha || github.sha')}
        files: proxysql/ci_infra_logs/{infra}/coverage-report/{infra}.info
        flags: integration-tests
        name: {coverage_name}
        use_oidc: true
        disable_search: true
        plugins: noop
        root_dir: proxysql
        disable_file_fixes: true
        fail_ci_if_error: false
        verbose: true

'''


def patch_gh_actions():
    wfroot = Path('.github/workflows')
    targets = {
        'ci-legacy-g2.yml': ('ci-legacy-g2', 'tap-legacy-g2-coverage', 'fixed'),
        'ci-basictests.yml': ('ci-basictests', 'tap-basictests-coverage', 'matrix'),
        'ci-taptests-pgsql-cluster.yml': ('ci-taptests-pgsql-cluster', 'tap-pgsql-cluster-sync-coverage', 'matrix'),
    }

    sparse_old = '''        sparse-checkout: |
          test/infra
          test/tap/groups
          test/scripts
'''
    sparse_new = '''        # Source trees are required so Codecov can resolve repo-root LCOV SF: paths.
        sparse-checkout: |
          include
          lib
          src
          test/infra
          test/tap
          test/scripts
'''

    for filename, (infra, coverage_name, mode) in targets.items():
        p = wfroot / filename
        text = p.read_text()
        text = add_permissions(text, filename)

        if mode == 'fixed':
            old = expr('inputs.trigger && fromJson(inputs.trigger).event.workflow_run.head_sha || github.sha') + '_ubuntu22-tap_src'
            new = expr('inputs.trigger && fromJson(inputs.trigger).event.workflow_run.head_sha || github.sha') + '_ubuntu24-tap-genai-gcov_src'
            if old in text:
                text = text.replace(old, new, 1)
            elif new not in text:
                raise RuntimeError(filename + ': BLDCACHE anchor missing')
            oldv = '        HANDOFF_VARIANT: ubuntu22-tap\n'
            newv = '        HANDOFF_VARIANT: ubuntu24-tap-genai-gcov\n'
            if oldv in text:
                text = text.replace(oldv, newv, 1)
            elif newv not in text:
                raise RuntimeError(filename + ': handoff variant anchor missing')
        else:
            old = "        testdist: [ 'ubuntu22-tap' ]"
            new = "        testdist: [ 'ubuntu24-tap-genai-gcov' ]"
            if old in text:
                text = text.replace(old, new, 1)
            elif new not in text:
                raise RuntimeError(filename + ': testdist anchor missing')

        if filename == 'ci-basictests.yml':
            if '        HANDOFF_TYPES: src\n' in text:
                text = text.replace('        HANDOFF_TYPES: src\n', '        HANDOFF_TYPES: src test\n', 1)
            elif '        HANDOFF_TYPES: src test\n' not in text:
                raise RuntimeError(filename + ': handoff types anchor missing')

        if sparse_old in text:
            text = text.replace(sparse_old, sparse_new, 1)
        elif not all(v in text for v in ('\n          include\n', '\n          lib\n', '\n          src\n', '\n          test/tap\n')):
            raise RuntimeError(filename + ': sparse checkout anchor missing')

        run_line = '        test/infra/control/run-tests-isolated.bash\n'
        if '        export COVERAGE=1\n' not in text:
            if run_line not in text:
                raise RuntimeError(filename + ': run-tests-isolated anchor missing')
            text = text.replace(run_line, '        export COVERAGE=1\n' + run_line, 1)

        if 'uses: codecov/codecov-action@v4' not in text:
            marker = '    - uses: LouisBrunner/checks-action@v2.0.0\n'
            idx = text.rfind(marker)
            if idx < 0:
                raise RuntimeError(filename + ': final checks-action marker missing')
            text = text[:idx] + coverage_block(infra, coverage_name) + text[idx:]

        p.write_text(text)

    for filename in targets:
        text = (wfroot / filename).read_text()
        required = [
            'permissions: write-all', 'ubuntu24-tap-genai-gcov', 'export COVERAGE=1',
            'uses: codecov/codecov-action@v4', 'flags: integration-tests', 'use_oidc: true',
            '\n          include\n', '\n          lib\n', '\n          src\n', '\n          test/tap\n',
        ]
        missing = [v for v in required if v not in text]
        if missing:
            raise RuntimeError(filename + ': missing ' + repr(missing))

    # All standard isolated-TAP workflows must either collect coverage or be an
    # explicitly classified exception. Unexpected omissions fail before commit.
    intentional = {
        'ci-unittests.yml',       # dedicated ASAN+gcov unit coverage workflow
        'ci-mysqlx.yml',          # special mysqlx/plugin handoff, not gcov build
        'ci-repltests.yml',       # separate replication harness
        'ci-shuntest.yml',        # separate shun harness
        'ci-selftests.yml',       # direct daemon selftests
        'ci-pg-compat.yml',       # compatibility/JUnit workflow
    }
    uncovered = []
    for p in sorted(wfroot.glob('*.yml')):
        text = p.read_text()
        if 'test/infra/control/run-tests-isolated.bash' in text and 'export COVERAGE=1' not in text and p.name not in intentional:
            uncovered.append(p.name)
    if uncovered:
        raise RuntimeError('Unclassified isolated TAP workflows without coverage: ' + ', '.join(uncovered))

    run('git', 'diff', '--check')
    run('git', 'diff', '--', *[str(wfroot / f) for f in targets])
    run('git', 'add', *[str(wfroot / f) for f in targets])
    run('git', 'commit', '-m', 'ci: enable coverage for missing TAP workflows')
    run('git', 'push', 'origin', 'HEAD:GH-Actions')


def patch_pr_branch():
    run('git', 'fetch', 'origin', 'test/coverage-low-lib-files')
    run('git', 'switch', '-C', 'test/coverage-low-lib-files', 'origin/test/coverage-low-lib-files')

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
        text = text.replace(old, new, 1)
    elif 'Materialized codecov.yml from HEAD for coverage upload' not in text:
        raise RuntimeError('run-tests-isolated.bash coverage anchor missing')
    p.write_text(text)

    run('bash', '-n', str(p))
    run('git', 'diff', '--check')
    run('git', 'diff', '--', str(p))
    run('git', 'add', str(p))
    staged = subprocess.run(['git', 'diff', '--cached', '--quiet'])
    if staged.returncode != 0:
        run('git', 'commit', '-m', 'ci: materialize Codecov config for sparse coverage jobs')
        run('git', 'push', 'origin', 'HEAD:test/coverage-low-lib-files')


if __name__ == '__main__':
    run('git', 'config', 'user.name', 'github-actions[bot]')
    run('git', 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com')
    patch_gh_actions()
    patch_pr_branch()
    print('All requested coverage fixes applied and validated.')
