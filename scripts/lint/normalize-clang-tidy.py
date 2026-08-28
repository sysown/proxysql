#!/usr/bin/env python3
"""
normalize-clang-tidy.py

Normalize clang-tidy outputs (export-fixes YAML or textual stderr/stdout)
and emit lines in the form:

  <absolute-canonical-file>:<line>: <check> - <message>

Only diagnostics whose canonical file path is under <repo_root>/include/ or
<repo_root>/lib/ are emitted. This prevents diagnostics originating from
deps/ (e.g., include/../deps/...) from slipping through.
"""

import sys
import os
import re
import yaml
import subprocess


def get_repo_root():
    try:
        out = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL)
        return os.path.realpath(out.decode().strip())
    except Exception:
        return os.path.realpath(os.getcwd())


def canonical_path(path, repo_root):
    if not path:
        return None
    # Ignore placeholders like <built-in> or <unknown>
    if path.startswith("<") and path.endswith(">"):
        return None
    if os.path.isabs(path):
        return os.path.realpath(path)
    # If relative, interpret relative to repo root
    return os.path.realpath(os.path.join(repo_root, path))


def is_in_repo_include_or_lib(cpath, repo_root):
    if not cpath:
        return False
    inc = os.path.realpath(os.path.join(repo_root, "include"))
    lib = os.path.realpath(os.path.join(repo_root, "lib"))
    try:
        # os.path.commonpath raises ValueError if paths are on different drives
        common_inc = os.path.commonpath([cpath, inc])
        if common_inc == inc:
            return True
    except Exception:
        pass
    try:
        common_lib = os.path.commonpath([cpath, lib])
        if common_lib == lib:
            return True
    except Exception:
        pass
    return False


def offset_to_line(cpath, offset):
    try:
        with open(cpath, 'rb') as fh:
            data = fh.read()
        # offset is a byte offset; count newlines before it
        return data[:offset].count(b"\n") + 1
    except Exception:
        return 0


def main():
    if len(sys.argv) != 2:
        print("Usage: normalize-clang-tidy.py <export-fixes.yaml-or-raw-output>")
        return 2

    path = sys.argv[1]
    if not os.path.exists(path):
        # Nothing to normalize
        return 0

    repo_root = get_repo_root()
    content = open(path, 'r', errors='ignore').read()
    diagnostics = set()

    # Try parsing as export-fixes YAML first
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and 'Diagnostics' in data:
            for diag in data.get('Diagnostics', []):
                msg = diag.get('DiagnosticMessage', {}) or {}
                raw_file = msg.get('FilePath')
                cpath = canonical_path(raw_file, repo_root)
                if not cpath:
                    continue
                if not is_in_repo_include_or_lib(cpath, repo_root):
                    continue
                offset = msg.get('FileOffset', None)
                if offset is None:
                    line_no = msg.get('FileLine', 0) or 0
                else:
                    line_no = offset_to_line(cpath, int(offset))
                check = diag.get('CheckName') or diag.get('DiagnosticName') or ''
                message = (msg.get('Message') or '').strip()
                diagnostics.add(f"{cpath}:{line_no}: {check} - {message}")
        else:
            # Not the expected YAML structure; fall back to textual parsing
            raise ValueError("not yaml diagnostics")
    except Exception:
        # Fallback: parse clang-tidy textual output lines
        # Typical clang-tidy message format:
        # /path/to/file:123:45: warning: message [check-name]
        pat = re.compile(r"(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+:)?\s*(?P<kind>warning|error|note):?\s*(?P<msg>.*)\s*\[(?P<check>[^\]]+)\]$")
        for line in content.splitlines():
            m = pat.match(line)
            if not m:
                continue
            raw_file = m.group('file')
            cpath = canonical_path(raw_file, repo_root)
            if not cpath:
                continue
            if not is_in_repo_include_or_lib(cpath, repo_root):
                continue
            line_no = m.group('line')
            check = m.group('check')
            message = m.group('msg').strip()
            diagnostics.add(f"{cpath}:{line_no}: {check} - {message}")

    for l in sorted(diagnostics):
        print(l)


if __name__ == '__main__':
    sys.exit(main())
