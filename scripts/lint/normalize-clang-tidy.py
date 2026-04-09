#!/usr/bin/env python3
import sys
import yaml
import os

"""
Simple normalizer for clang-tidy export-fixes YAML. Produces sorted text lines:
<file>:<line>: <check> - <message>
"""

if len(sys.argv) != 2:
    print("Usage: normalize-clang-tidy.py <export-fixes.yaml>")
    sys.exit(2)

path = sys.argv[1]
if not os.path.exists(path):
    # No diagnostics
    sys.exit(0)

data = yaml.safe_load(open(path))
diagnostics = []
for diag in data.get('Diagnostics', []):
    msg = diag.get('DiagnosticMessage', {})
    file = msg.get('FilePath', '<unknown>')
    offset = msg.get('FileOffset', 0)
    # Best effort to map offset to line
    try:
        with open(file, 'rb') as fh:
            content = fh.read()
        line_no = content[:offset].count(b"\n") + 1
    except Exception:
        line_no = 0
    check = diag.get('CheckName', '')
    message = msg.get('Message', '').strip()
    diagnostics.append(f"{file}:{line_no}: {check} - {message}")

for l in sorted(set(diagnostics)):
    print(l)
