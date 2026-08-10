"""Run a per-language behavior program and translate its exit code into
pytest semantics. The CLI contract: `<prog> <behavior>` -> exit 0 pass,
exit 1 assertion-failure (reason on stderr), exit 2 usage/infra error."""
import os
import subprocess

import pytest

def run_behavior(program, behavior):
    if not os.path.exists(program):
        pytest.skip(f"{program} not present in this image")
    r = subprocess.run(
        [program, behavior], capture_output=True, text=True, timeout=120,
        env=os.environ.copy(),
    )
    if r.returncode == 0:
        return
    detail = f"{program} {behavior} -> exit {r.returncode}\nstderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    if r.returncode == 2:
        pytest.fail(f"infra/usage error (not a behavior failure): {detail}")
    pytest.fail(detail)
