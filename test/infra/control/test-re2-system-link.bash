#!/usr/bin/env bash
# No ProxySQL/dependency build: exercise the real shared flags with tiny libraries.
set -euo pipefail
script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
if [[ $(uname -s) != Linux ]]; then
    echo 'RE2 system-library link regression requires a Linux ELF linker'
    exit 0
fi
python3 - "$repo_root" <<'PY'
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

root = Path(sys.argv[1])
cc = shlex.split(os.environ.get('CC', 'cc'))
ld = shlex.split(os.environ.get('LD', 'ld'))
ar = shlex.split(os.environ.get('AR', 'ar'))

def run(args):
    result = subprocess.run(args, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(shlex.join(args) + '\n' + result.stdout + result.stderr)
    return result.stdout

with tempfile.TemporaryDirectory(prefix='re2-system-link-') as temp:
    work = Path(temp)
    pc = work / 'pkgconfig'
    pc.mkdir()
    sources = {
        'rt': 'int rt_feature(void) { return 40; }',
        'absl_base': 'extern int rt_feature(void); int absl_base(void) { return rt_feature(); }',
        'absl_tail': 'int absl_tail(void) { return 1; }',
        're2': 'extern int absl_base(void), absl_tail(void); int re2_answer(void) { return absl_base()+absl_tail(); }',
        'after_static': 'int after_state(void) { return 1; }',
        'after_dynamic': 'int after_state(void) { return 2; }',
        'consumer': 'extern int re2_answer(void), after_state(void); int answer(void) { return re2_answer()+after_state(); }',
    }
    for name, source in sources.items():
        (work / (name + '.c')).write_text(source + '\n')
        run(cc + ['-fPIC', '-ffreestanding', '-fno-stack-protector', '-c', str(work / (name + '.c')), '-o', str(work / (name + '.o'))])
    for name, obj in [('absl_base', 'absl_base'), ('absl_tail', 'absl_tail'), ('re2', 're2'), ('after', 'after_static')]:
        run(ar + ['rcs', str(work / ('lib' + name + '.a')), str(work / (obj + '.o'))])
    for name, obj in [('rt', 'rt'), ('after', 'after_dynamic')]:
        run(ld + ['-nostdlib', '-shared', '-soname', 'lib' + name + '.so', '-o', str(work / ('lib' + name + '.so')), str(work / (obj + '.o'))])
    # Use real pkg-config metadata. No librt.a exists in this isolated search path.
    base = 'Name: absl_base\nDescription: Link fixture\nVersion: 1\nLibs: -L' + str(work) + ' -labsl_base -lrt -labsl_tail\n'
    (pc / 'absl_base.pc').write_text(base)
    packages = 'absl_check absl_log core_headers fixed_array flags flat_hash_map flat_hash_set hash inlined_vector optional span str_format strings synchronization'.split()
    for package in packages:
        name = 'absl_' + package
        (pc / (name + '.pc')).write_text('Name: ' + name + '\nDescription: Link fixture\nVersion: 1\nRequires: absl_base\n')
    makefile = work / 'flags.mk'
    makefile.write_text('include $(PROXYSQL_PATH)/include/makefiles_paths.mk\nprint:\n\t@printf "%s\\n" "$(RE2_STATIC_LIBS)"\n')
    def flags(platform):
        value = run(['make', '--no-print-directory', '-s', '-f', str(makefile), 'PROXYSQL_PATH=' + str(root), 'ABSL_PKG_CONFIG_PATH=' + str(pc), 'RE2_STATIC_LIB=' + str(work / 'libre2.a'), 'UNAME_S=' + platform, 'print'])
        return shlex.split(value)
    linux = flags('Linux')
    freebsd = flags('FreeBSD')
    darwin = flags('Darwin')
    assert darwin == freebsd + ['-framework', 'CoreFoundation'], (darwin, freebsd)
    assert not any('--push-state' in flag or '--pop-state' in flag for flag in freebsd)
    assert linux.count('-lrt') == 1, linux
    def linker_flags(args):
        return [part for arg in args for part in (arg[4:].split(',') if arg.startswith('-Wl,') else [arg])]
    for mode, expected in [('static', 42), ('dynamic', 43)]:
        output = work / (mode + '.so')
        # -nostdlib prevents host system archives from hiding the missing-static case.
        run(ld + ['-nostdlib', '-shared', '--no-undefined', str(work / 'consumer.o'), '-rpath', str(work), '-B' + mode] + linker_flags(linux) + ['-lafter', '-Bdynamic', '-o', str(output)])
        result = run([sys.executable, '-c', 'import ctypes,sys; print(ctypes.CDLL(sys.argv[1]).answer())', str(output)])
        assert int(result) == expected, (mode, result)
        needed = run(['readelf', '-d', str(output)])
        assert 'Shared library: [librt.so]' in needed, needed
        assert ('Shared library: [libafter.so]' in needed) == (mode == 'dynamic'), needed
        assert 'libabsl' not in needed and 'libre2' not in needed, needed
        print('PASS: incoming ' + mode + ' mode retained; vendored archives static; realtime dependency dynamic')
    print('PASS: Darwin and FreeBSD flags unchanged')
PY
