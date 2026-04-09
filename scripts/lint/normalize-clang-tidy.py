#!/usr/bin/env python3
import sys
import yaml
import os

"""
Normalizer for clang-tidy outputs.

Behavior:
- If passed an export-fixes YAML (the old behavior), parse it and emit normalized lines.
- If passed a textual clang-tidy stderr/stdout file (from running clang-tidy without export-fixes), parse those diagnostics as well.

Emitted line format:
<file>:<line>: <check> - <message>
"""

import re

if len(sys.argv) != 2:
    print("Usage: normalize-clang-tidy.py <export-fixes.yaml-or-raw-output>")
    sys.exit(2)

path = sys.argv[1]
if not os.path.exists(path):
    # No diagnostics
    sys.exit(0)

content = open(path, 'r', errors='ignore').read()
diagnostics = set()

# Try YAML first
try:
    data = yaml.safe_load(content)
    if isinstance(data, dict) and 'Diagnostics' in data:
        for diag in data.get('Diagnostics', []):
            msg = diag.get('DiagnosticMessage', {})
            file = msg.get('FilePath', '<unknown>')
            offset = msg.get('FileOffset', 0)
            # Map offset to line if possible
            try:
                with open(file, 'rb') as fh:
                    b = fh.read()
                line_no = b[:offset].count(b"\n") + 1
            except Exception:
                line_no = 0
            check = diag.get('CheckName', '')
            message = msg.get('Message', '').strip()
            diagnostics.add(f"{file}:{line_no}: {check} - {message}")
    else:
        raise Exception("not yaml diagnostics")
except Exception:
    # Fallback: parse clang-tidy textual output lines
    # Typical clang-tidy message format:
    # /path/to/file:123:45: warning: message [check-name]
    # We capture file, line, message and check-name
    for line in content.splitlines():
        m = re.match(r"(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+:)?\s*(?P<kind>warning|error|note):?\s*(?P<msg>.*)\s*\[(?P<check>[^\]]+)\]$", line)
        if m:
            file = m.group('file')
            line_no = m.group('line')
            check = m.group('check')
            message = m.group('msg').strip()
            diagnostics.add(f"{file}:{line_no}: {check} - {message}")

for l in sorted(diagnostics):
    print(l)
