"""Exact build identities and the committed dependency artifact registry."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
from urllib.parse import urlsplit

FORMAT_VERSION = 1
DEPENDENCIES = ('duckdb', 'openssl')
FLAGS = ('CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS', 'MACOSX_DEPLOYMENT_TARGET',
         'SDKROOT', 'CMAKE_TOOLCHAIN_FILE', 'CMAKE_GENERATOR', 'CMAKE_PREFIX_PATH',
         'CMAKE_OSX_ARCHITECTURES', 'ARCHFLAGS', 'CROSS_COMPILE', 'KERNEL_BITS',
         'CMAKE_C_FLAGS', 'CMAKE_CXX_FLAGS', 'CMAKE_EXE_LINKER_FLAGS')


class ToolchainUnavailable(ValueError):
    """Optional artifact compatibility probes cannot identify this environment."""


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def fingerprint(identity):
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True).encode()).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def load_json(path, limit=4 * 1024 * 1024):
    with Path(path).open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('JSON metadata exceeds size limit')
    return json.loads(data, object_pairs_hook=unique_object)


def assignment(path, name):
    text = Path(path).read_text().replace('\\\n', ' ')
    match = re.search(r'^' + re.escape(name) + r'\s*[:?]?=\s*(.*?)\s*$', text, re.M)
    if not match:
        raise ValueError('missing dependency setting: ' + name)
    return match.group(1)


def configuration(dependency, root):
    root = Path(root)
    if dependency == 'duckdb':
        directory, setting = 'duckdb', 'DUCKDB_CMAKE_FLAGS'
        version = assignment(root / 'deps/duckdb/build.mk', 'DUCKDB_VERSION')
    elif dependency == 'openssl':
        directory, setting = 'libssl', 'OPENSSL_CONFIGURE_FLAGS'
        version = assignment(root / 'common_mk/openssl_flags.mk', 'OPENSSL_VERSION')
    else:
        raise ValueError('unknown dependency: ' + dependency)
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){2}', version):
        raise ValueError('invalid dependency version')
    base = root / 'deps' / directory
    return {'directory': directory, 'version': version, 'setting': setting,
            'archive': base / (dependency + '-' + version + '.tar.gz'),
            'recipe': base / 'build.mk',
            'tree': base / ('duckdb' if dependency == 'duckdb' else 'openssl-' + version)}


def command_output(args, environ, input_data=None):
    environment = dict(os.environ)
    environment.update(environ)
    environment['LC_ALL'] = 'C'
    try:
        return subprocess.check_output(args, env=environment,
                                       input=input_data, stderr=subprocess.PIPE,
                                       timeout=30).decode().strip()
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise ToolchainUnavailable('unable to identify toolchain: ' + ' '.join(shlex.quote(arg) for arg in args)) from exc


def linux_libc_identity():
    # Python 3.6's platform.libc_ver() reports Python's symbol requirements,
    # which can be much older than the running libc (e.g. 2.3.4 vs 2.28).
    try:
        version = os.confstr('CS_GNU_LIBC_VERSION')
    except (AttributeError, OSError, ValueError) as exc:
        raise ToolchainUnavailable('unable to query running libc') from exc
    match = re.fullmatch(r'glibc ([0-9]+(?:\.[0-9]+)+)', version or '')
    if not match:
        raise ToolchainUnavailable('unsupported or missing running libc identity')
    return ['glibc', match.group(1)]


def toolchain_identity(environ):
    env = dict(environ)
    system = platform.system()
    facts = {'os': system, 'arch': platform.machine()}
    for name, default, language in (('CC', 'cc', 'c'), ('CXX', 'g++', 'c++')):
        command = shlex.split(env.get(name) or default)
        flags = shlex.split(env.get('CPPFLAGS', '') + ' ' +
                            env.get('CXXFLAGS' if language == 'c++' else 'CFLAGS', ''))
        macros = command_output(command + flags + ['-dM', '-E', '-x', language, '-'], env, b'')
        facts[name.lower()] = {'command': command,
                               'version': command_output(command + ['--version'], env),
                               'target': command_output(command + ['-dumpmachine'], env),
                               'macros': hashlib.sha256(macros.encode()).hexdigest()}
    runtime = command_output(shlex.split(env.get('CXX') or 'g++') +
                             shlex.split(env.get('CPPFLAGS', '') + ' ' + env.get('CXXFLAGS', '')) +
                             ['-dM', '-E', '-x', 'c++', '-include', 'cstddef', '-'], env, b'')
    facts['runtime'] = hashlib.sha256(runtime.encode()).hexdigest()
    if system == 'Linux':
        release = {}
        try:
            release_text = Path('/etc/os-release').read_text()
        except OSError as exc:
            raise ToolchainUnavailable('missing distribution identity') from exc
        for line in release_text.splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                release[key] = value.strip('"\'')
        if not release.get('ID') or not release.get('VERSION_ID'):
            raise ToolchainUnavailable('missing distribution identity')
        facts.update(distro=[release['ID'], release['VERSION_ID']], libc=linux_libc_identity())
        if not all(facts['libc']):
            raise ToolchainUnavailable('missing libc identity')
    elif system == 'Darwin':
        facts['sdk'] = command_output(['xcrun', '--show-sdk-version'], env)
        facts['deployment_target'] = env.get('MACOSX_DEPLOYMENT_TARGET', '')
    return facts


def build_identity(dependency, root, environ):
    root = Path(root)
    conf = configuration(dependency, root)
    archive = conf['archive']
    checksum = Path(str(archive) + '.sha256').read_text().split()
    actual = digest_file(archive)
    if len(checksum) != 2 or checksum[1].lstrip('*') != archive.name or checksum[0].lower() != actual:
        raise ValueError(dependency + ' source SHA-256 mismatch')
    code_dir = Path(__file__).resolve().parent
    helper = {p.name: digest_file(p) for name in ('identity.py', 'bundles.py', 'manage.py', 'prepare.bash')
              for p in [code_dir / name] if p.exists()}
    setting = environ.get(conf['setting'], assignment(conf['recipe'], conf['setting']))
    flags = {key: environ.get(key, '') for key in FLAGS}
    # Custom toolchain files can include arbitrary other files. Source fallback
    # is safer than claiming that hashing the top-level file captures all inputs.
    eligible = not (flags['CMAKE_TOOLCHAIN_FILE'] or 'CMAKE_TOOLCHAIN_FILE=' in setting or
                    environ.get('CPATH') or environ.get('CPLUS_INCLUDE_PATH') or
                    environ.get('C_INCLUDE_PATH') or environ.get('LIBRARY_PATH'))
    # These settings can replace the probed compiler/flags or depend on host
    # CPU facts not represented by the probes. Preserve source builds, but do
    # not advertise compatibility for configurations we cannot identify.
    setting_tokens = shlex.split(setting)
    unprobed_setting = re.search(
        r'CMAKE_(?:[A-Z0-9_]*COMPILER[A-Z0-9_]*|[A-Z0-9_]*FLAGS[A-Z0-9_]*|'
        r'TOOLCHAIN_FILE|SYSROOT[A-Z0-9_]*|OSX_SYSROOT)\b|'
        r'(?:^|\s)(?:CC|CXX|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS)\s*=|'
        r'--(?:cross-compile-prefix|sysroot)(?:=|\s)', ' '.join(setting_tokens))
    native_cpu = re.search(r'-(?:march|mtune|mcpu)\s*=\s*native\b',
                           ' '.join([setting] + [environ.get(key, '') for key in
                                                FLAGS + ('CC', 'CXX')]))
    # DuckDB's NATIVE_ARCH option enables CPU-dependent compilation without
    # adding a native flag to these inputs. CMake cache booleans treat every
    # value other than a false constant as enabled when read as a variable.
    native_arch = False
    if dependency == 'duckdb':
        tokens = iter(setting_tokens)
        for token in tokens:
            definition = next(tokens, '') if token == '-D' else token[2:] if token.startswith('-D') else ''
            match = re.fullmatch(r'NATIVE_ARCH(?::[^=]+)?=(.*)', definition, re.S)
            if match:
                value = match.group(1).upper()
                native_arch = native_arch or (value not in
                    ('', '0', 'OFF', 'NO', 'FALSE', 'N', 'IGNORE', 'NOTFOUND')
                    and not value.endswith('-NOTFOUND'))
    eligible = eligible and not (unprobed_setting or native_cpu or native_arch or
                                 flags['CMAKE_C_FLAGS'] or flags['CMAKE_CXX_FLAGS'] or
                                 flags['CMAKE_EXE_LINKER_FLAGS'] or flags['CROSS_COMPILE'])
    toolchain = toolchain_identity(environ)
    eligible = eligible and toolchain.get('os') in ('Linux', 'Darwin')
    return {'format_version': FORMAT_VERSION, 'dependency': dependency,
            'version': conf['version'], 'source_sha256': actual,
            'recipe_sha256': digest_file(conf['recipe']),
            'verifier_sha256': digest_file(archive.parent / 'verify-source.bash'),
            'helper': helper, 'toolchain': toolchain,
            'settings': setting_tokens, 'flags': flags,
            'eligible': eligible,
            'custom_paths': {key: environ.get(key, '') for key in
                             ('CPATH', 'CPLUS_INCLUDE_PATH', 'C_INCLUDE_PATH', 'LIBRARY_PATH')}}


def validate_entry(entry):
    if not isinstance(entry, dict):
        raise ValueError('invalid artifact entry')
    for key in ('dependency', 'fingerprint', 'identity', 'url', 'sha256', 'size', 'provenance'):
        if key not in entry:
            raise ValueError('missing artifact field: ' + key)
    identity = entry['identity']
    if (entry['dependency'] not in DEPENDENCIES or not isinstance(identity, dict) or
            identity.get('dependency') != entry['dependency'] or
            identity.get('format_version') != FORMAT_VERSION or identity.get('eligible') is not True):
        raise ValueError('invalid artifact identity')
    for key in ('fingerprint', 'sha256'):
        if not isinstance(entry[key], str) or not re.fullmatch(r'[0-9a-f]{64}', entry[key]):
            raise ValueError('invalid artifact ' + key)
    if fingerprint(identity) != entry['fingerprint']:
        raise ValueError('artifact fingerprint does not match identity')
    if type(entry['size']) is not int or entry['size'] <= 0 or not isinstance(entry['provenance'], dict):
        raise ValueError('invalid artifact size/provenance')
    url = urlsplit(entry['url'])
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.fragment:
        raise ValueError('artifact URL must use HTTPS without credentials')
    return entry


def load_registry(path):
    registry = load_json(path)
    if (not isinstance(registry, dict) or registry.get('format_version') != FORMAT_VERSION or
            not isinstance(registry.get('artifacts'), list)):
        raise ValueError('unsupported dependency registry schema')
    seen = set()
    for entry in registry['artifacts']:
        validate_entry(entry)
        key = (entry['dependency'], entry['fingerprint'])
        if key in seen:
            raise ValueError('duplicate artifact identity: ' + ':'.join(key))
        seen.add(key)
    return registry
