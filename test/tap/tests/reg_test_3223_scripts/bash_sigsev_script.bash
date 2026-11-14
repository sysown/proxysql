#!/usr/bin/bash

# A piped core handler can delay SIGSEGV termination past the REST timeout,
# even with ulimit -c 0. Disable dumping with PR_SET_DUMPABLE in the process
# that raises the signal, preserving the expected exit 139.
exec python3 - <<'PY'
import ctypes
import os
import signal

libc = ctypes.CDLL(None, use_errno=True)
PR_SET_DUMPABLE = 4
if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE) failed")
os.kill(os.getpid(), signal.SIGSEGV)
PY
