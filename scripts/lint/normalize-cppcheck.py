#!/usr/bin/env python3
import sys
import re
import os

"""
Normalize cppcheck stderr output. Produce lines like:
<file>:<line>: <id> - <message>
"""

path = sys.argv[1] if len(sys.argv) > 1 else None
data = ''
if path and os.path.exists(path):
    data = open(path).read()
else:
    data = sys.stdin.read()

lines = []
for raw in data.splitlines():
    # cppcheck prints: [path:line]: (id) message
    m = re.match(r"\[(?P<file>[^:]+):(?P<line>\d+)\] (?P<id>[^:]+): (?P<msg>.*)", raw)
    if m:
        lines.append(f"{m.group('file')}:{m.group('line')}: {m.group('id').strip()} - {m.group('msg').strip()}")

for l in sorted(set(lines)):
    print(l)
