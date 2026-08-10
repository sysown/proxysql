"""Run a per-language behavior program and translate its exit code into
pytest semantics. The CLI contract: `<prog> <behavior>` -> exit 0 pass,
exit 1 assertion-failure (reason on stderr), exit 2 usage/infra error."""
import os
import subprocess

import pytest

def run_behavior(program, behavior):
    if not os.path.exists(program):
        pytest.skip(f"{program} not present in this image")
    timeout = int(os.environ.get("PGCOMPAT_BEHAVIOR_TIMEOUT", "120"))
    try:
        r = subprocess.run(
            [program, behavior], capture_output=True, text=True, timeout=timeout,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired as exc:
        # Report a hung driver as a test FAILURE, not a pytest ERROR: an
        # uncaught TimeoutExpired aborts the item during call teardown and
        # loses the partial output, which is exactly what identifies where the
        # driver hung. TimeoutExpired's captured streams are bytes (or None)
        # even with text=True, so decode defensively.
        def _text(stream):
            if stream is None:
                return ""
            return stream.decode(errors="replace") if isinstance(stream, bytes) else stream

        pytest.fail(
            f"{program} {behavior} -> timed out after {timeout}s\n"
            f"stderr:\n{_text(exc.stderr)}\nstdout:\n{_text(exc.stdout)}"
        )
    if r.returncode == 0:
        return
    detail = f"{program} {behavior} -> exit {r.returncode}\nstderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    if r.returncode == 2:
        pytest.fail(f"infra/usage error (not a behavior failure): {detail}")
    pytest.fail(detail)
