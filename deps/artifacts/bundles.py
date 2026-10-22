"""Portable dependency payloads with verified, staged installation."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

from identity import (FORMAT_VERSION, configuration, digest_file, fingerprint,
                      unique_object, validate_entry)

ROOT = Path(__file__).resolve().parents[2]
MAX_METADATA = 4 * 1024 * 1024
MAX_UNPACKED = 4 * 1024 * 1024 * 1024
MAX_FILES = 100000


def safe_path(name):
    if (not isinstance(name, str) or not name or '\\' in name or '\x00' in name or
            name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/')) or
            str(PurePosixPath(name)) != name):
        raise ValueError('unsafe artifact path: ' + repr(name))
    return name


def duckdb_archives(tree):
    result = subprocess.run(['sh', str(ROOT / 'deps/duckdb/list-static-archives.sh'),
                             str(tree / 'build/release')], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
    if result.returncode:
        raise ValueError(result.stderr.strip())
    return [Path(p).relative_to(tree).as_posix() for p in result.stdout.splitlines()]


def validate_tree(dependency, tree, version=None):
    tree = Path(tree).resolve()
    if dependency == 'duckdb':
        required = ['src/include/duckdb.h', 'build/release/DuckDBExports.cmake']
        required += duckdb_archives(tree)
    elif dependency == 'openssl':
        required = ['libssl.a', 'libcrypto.a', 'include/openssl/ssl.h',
                    'include/openssl/crypto.h', 'include/openssl/opensslv.h',
                    'include/openssl/configuration.h', 'apps/openssl.cnf']
        version = version or configuration('openssl', ROOT)['version']
        header = tree / 'include/openssl/opensslv.h'
        if not header.is_file():
            raise ValueError('missing OpenSSL version header')
        content = header.read_text()
        for name, value in zip(('MAJOR', 'MINOR', 'PATCH'), version.split('.')):
            if not re.search(r'^\s*#\s*define\s+OPENSSL_VERSION_' + name +
                             r'\s+' + re.escape(value) + r'\b', content, re.M):
                raise ValueError('OpenSSL header version does not match ' + version)
    else:
        raise ValueError('unknown dependency: ' + dependency)
    for name in required:
        path = tree / name
        if not path.is_file() or path.is_symlink() or not path.stat().st_size:
            raise ValueError('missing or empty dependency output: ' + str(path))
    if not any(p.is_file() and p.name.upper().startswith(('LICENSE', 'COPYING'))
               for p in tree.iterdir()):
        raise ValueError('missing dependency license')


def collect_payload(dependency, tree):
    tree = Path(tree).resolve()
    validate_tree(dependency, tree)
    if dependency == 'duckdb':
        files = [p.relative_to(tree).as_posix() for p in (tree / 'src/include').rglob('*')
                 if p.is_file() or p.is_symlink()]
        files += ['build/release/DuckDBExports.cmake'] + duckdb_archives(tree)
        license_dirs = [tree, tree / 'third_party', tree / 'extension']
    else:
        files = [p.relative_to(tree).as_posix() for p in (tree / 'include/openssl').rglob('*')
                 if p.is_file() or p.is_symlink()]
        files += ['libssl.a', 'libcrypto.a', 'apps/openssl.cnf']
        files += [p.relative_to(tree).as_posix() for p in (tree / 'providers').rglob('*')
                  if p.is_file() and p.suffix in ('.so', '.dylib')]
        license_dirs = [tree]
    for directory in license_dirs:
        paths = directory.iterdir() if directory == tree else directory.rglob('*')
        files += [p.relative_to(tree).as_posix() for p in paths
                  if p.is_file() and p.name.upper().startswith(('LICENSE', 'NOTICE', 'COPYING'))]
    for name in files:
        safe_path(name)
        path = tree / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('non-regular dependency payload: ' + name)
    return sorted(set(files))


def create_bundle(dependency, tree, identity, output):
    tree, output = Path(tree).resolve(), Path(output)
    if identity.get('dependency') != dependency or identity.get('eligible') is not True:
        raise ValueError('dependency is ineligible for artifact packaging')
    files = collect_payload(dependency, tree)
    manifest = {'format_version': FORMAT_VERSION, 'identity': identity,
                'fingerprint': fingerprint(identity), 'files': {}}
    for name in files:
        path = tree / name
        manifest['files'][name] = {'sha256': digest_file(path), 'size': path.stat().st_size}
    metadata = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    if len(metadata) > MAX_METADATA:
        raise ValueError('artifact manifest exceeds size limit')
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=str(output.parent), delete=False) as stream:
            temporary = Path(stream.name)
            with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed:
                with tarfile.open(mode='w|', fileobj=compressed, format=tarfile.PAX_FORMAT) as tar:
                    info = tarfile.TarInfo('manifest.json')
                    info.size, info.mode = len(metadata), 0o644
                    tar.addfile(info, io.BytesIO(metadata))
                    for name in files:
                        info = tarfile.TarInfo('payload/' + name)
                        info.size, info.mode = manifest['files'][name]['size'], 0o644
                        with (tree / name).open('rb') as source:
                            tar.addfile(info, source)
        os.replace(str(temporary), str(output))
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return {'dependency': dependency, 'identity': identity, 'fingerprint': fingerprint(identity),
            'sha256': digest_file(output), 'size': output.stat().st_size}


def verify_archive(archive, entry):
    if Path(archive).stat().st_size != entry['size'] or digest_file(archive) != entry['sha256']:
        raise ValueError('dependency archive SHA-256/size mismatch: ' + str(archive))


def extract_verified(archive, entry, stage):
    with tarfile.open(str(archive), 'r|gz') as tar:
        header = tar.next()
        if (header is None or header.name != 'manifest.json' or not header.isfile() or
                not 0 < header.size <= MAX_METADATA):
            raise ValueError('missing or oversized dependency manifest')
        manifest = json.loads(tar.extractfile(header).read(), object_pairs_hook=unique_object)
        if (not isinstance(manifest, dict) or manifest.get('format_version') != FORMAT_VERSION or
                manifest.get('identity') != entry['identity'] or
                manifest.get('fingerprint') != entry['fingerprint'] or
                not isinstance(manifest.get('files'), dict)):
            raise ValueError('dependency manifest identity/schema mismatch')
        files = manifest['files']
        if not 0 < len(files) <= MAX_FILES:
            raise ValueError('invalid dependency payload file count')
        total = 0
        for name, data in files.items():
            safe_path(name)
            if (not isinstance(data, dict) or type(data.get('size')) is not int or
                    data['size'] < 0 or not isinstance(data.get('sha256'), str) or
                    not re.fullmatch(r'[0-9a-f]{64}', data['sha256'])):
                raise ValueError('invalid dependency file metadata')
            total += data['size']
        if total > MAX_UNPACKED:
            raise ValueError('dependency payload exceeds size limit')
        seen = set()
        # tar.next() returns the already consumed first member once when the
        # iterator starts. Explicit next() calls keep streaming state unambiguous.
        while True:
            member = tar.next()
            if member is None:
                break
            safe_path(member.name.rstrip('/') if member.isdir() else member.name)
            if not member.name.startswith('payload/'):
                raise ValueError('undeclared dependency archive member: ' + member.name)
            name = member.name[len('payload/'):].rstrip('/') if member.isdir() else member.name[len('payload/'):]
            safe_path(name)
            if member.isdir():
                if not any(path.startswith(name + '/') for path in files):
                    raise ValueError('undeclared payload directory')
                continue
            if not member.isfile() or name not in files or name in seen:
                raise ValueError('non-regular, duplicate or undeclared payload member: ' + name)
            data = files[name]
            if member.size != data['size']:
                raise ValueError('dependency file size mismatch: ' + name)
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with tar.extractfile(member) as source, target.open('xb') as output:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    output.write(block)
                    digest.update(block)
            if digest.hexdigest() != data['sha256']:
                raise ValueError('dependency file SHA-256 mismatch: ' + name)
            target.chmod(0o644)
            seen.add(name)
        if seen != set(files):
            raise ValueError('incomplete dependency payload')
        validate_tree(entry['dependency'], stage, entry['identity']['version'])
        if set(collect_payload(entry['dependency'], stage)) != set(files):
            raise ValueError('dependency payload includes unsupported files')


def restore_bundle(archive, entry, destination):
    validate_entry(entry)
    verify_archive(archive, entry)
    destination = Path(destination).absolute()
    if destination.is_symlink():
        expected = destination.parent / ('openssl-' + entry['identity']['version'])
        if entry['dependency'] != 'openssl' or destination.resolve() != expected:
            raise ValueError('unexpected dependency destination symlink')
        destination = expected
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.dependency-stage-', dir=str(destination.parent)))
    backup = None
    try:
        extract_verified(archive, entry, stage)
        if destination.exists():
            backup = Path(tempfile.mkdtemp(prefix='.dependency-backup-', dir=str(destination.parent)))
            backup.rmdir()
            os.replace(destination, backup)
        try:
            os.replace(stage, destination)
        except BaseException:
            if backup is not None:
                os.replace(backup, destination)
            raise
    finally:
        if stage.exists():
            shutil.rmtree(str(stage))
        if backup is not None and backup.exists() and destination.exists():
            shutil.rmtree(str(backup))
