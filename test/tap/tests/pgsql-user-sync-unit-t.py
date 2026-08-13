#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path

root = Path(os.environ.get("WORKSPACE", Path(__file__).resolve().parents[3]))
suite = root / "test/tap/pgsql_user_sync/tests/test_pgsql_user_sync.py"
raise SystemExit(subprocess.call(
    [sys.executable, str(suite)], cwd=root
))
