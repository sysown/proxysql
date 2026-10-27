#!/usr/bin/env python3
"""Capture infrastructure immediately before Docker CLI teardown, then delegate."""
import argparse
from contextlib import redirect_stdout
import fcntl
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from ci_collect_infra_logs import collect

VALUE_OPTIONS = {'-H', '--host', '-c', '--context', '--config', '--log-level',
                 '-p', '--project-name', '-f', '--file', '--env-file', '--profile',
                 '--project-directory', '--ansi', '--progress', '--parallel'}


def command_position(args, start=0):
    index = start
    while index < len(args) and args[index].startswith('-'):
        option = args[index]
        index += 2 if option in VALUE_OPTIONS else 1
    return index


def removal_targets(real, args):
    index = command_position(args)
    if index >= len(args): return [], [real]
    prefix = [real, *args[:index]]
    position = index
    if args[index] == 'container': position += 1
    if position < len(args) and args[position] in ('rm', 'remove'):
        return [v for v in args[position+1:] if re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]*', v)], prefix
    if args[index] == 'compose':
        position = command_position(args, index+1)
        if position < len(args) and args[position] in ('down', 'rm'):
            result = subprocess.run([real, *args[:position], 'ps', '-aq'],
                                    capture_output=True, text=True, timeout=5)
            return result.stdout.split(), prefix
    return [], prefix


def wrapper_main(real, args):
    # No shell evaluation, Docker output redirection or exit-code translation.
    # The final exec preserves the caller's normal Docker CLI semantics.
    if not os.environ.get('CI_INFRA_DIAG_ACTIVE'):
        os.environ['CI_INFRA_DIAG_ACTIVE'] = '1'
        try:
            targets, prefix = removal_targets(real, args)
            if targets:
                output = Path(os.environ['CI_INFRA_DIAGNOSTICS_ROOT'])
                output.mkdir(parents=True, exist_ok=True)
                with (output/'collection.lock').open('w') as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    # Collector messages go to stderr; command-substitution
                    # users must receive only the original Docker stdout.
                    with redirect_stdout(sys.stderr):
                        collect('', output, all_containers=True, container_ids=targets,
                                docker_command=prefix, timeout=20)
        except Exception as error:
            print('Infrastructure diagnostic hook: '+str(error), file=sys.stderr)
        finally:
            os.environ.pop('CI_INFRA_DIAG_ACTIVE', None)
    os.execv(real, [real, *args])


def install():
    real = os.environ.get('CI_INFRA_REAL_DOCKER') or shutil.which('docker')
    if not real:
        print('Docker unavailable; native host logs can still be collected.')
        return
    directory = Path(os.environ['RUNNER_TEMP'])/'infrastructure-docker-bin'
    directory.mkdir(parents=True, exist_ok=True)
    executable = directory/'docker'
    executable.write_text('#!'+sys.executable+'\nimport sys\nsys.path.insert(0,'+repr(str(Path(__file__).resolve().parent))+')\n'
                          'from ci_docker_diagnostics import wrapper_main\nwrapper_main('+repr(real)+',sys.argv[1:])\n')
    executable.chmod(0o755)
    with open(os.environ['GITHUB_PATH'],'a') as output: output.write(str(directory)+'\n')
    with open(os.environ['GITHUB_ENV'],'a') as output:
        output.write('CI_INFRA_REAL_DOCKER='+real+'\n')
    print('Installed infrastructure diagnostics before Docker removal commands.')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install',action='store_true')
    args=parser.parse_args()
    if args.install: install()
