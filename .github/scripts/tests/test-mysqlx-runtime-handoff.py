#!/usr/bin/env python3
from pathlib import Path
import os
import subprocess
import tempfile

import yaml


ROOT = Path(__file__).resolve().parents[3]


def workflow_steps(path: str, job: str) -> list[dict]:
    with (ROOT / path).open(encoding="utf-8") as stream:
        workflow = yaml.safe_load(stream)
    return workflow["jobs"][job]["steps"]


def named_step(steps: list[dict], name: str) -> dict:
    for step in steps:
        if step.get("name") == name:
            return step
    raise AssertionError(f"workflow step not found: {name}")


def compile_shared(output: Path, source: str, *link_args: str) -> None:
    result = subprocess.run(
        ["cc", "-shared", "-fPIC", "-x", "c", "-", "-o", str(output), *link_args],
        input=source,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def run_script(step: dict, cwd: Path, tier: str = "v40") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + step["run"]],
        cwd=cwd,
        env={**os.environ, "IS_V40": str(tier == "v40").lower()},
        text=True,
        capture_output=True,
        check=False,
    )


def create_workspace(root: Path, dynamic_libpq: bool) -> tuple[Path, Path]:
    repo = root / "proxysql"
    tap_dir = repo / "test/tap/tap"
    plugin_dir = repo / "plugins/mysqlx"
    libpq_dir = repo / "deps/postgresql/postgresql/src/interfaces/libpq"
    tap_dir.mkdir(parents=True)
    plugin_dir.mkdir(parents=True)
    libpq_dir.mkdir(parents=True)
    (plugin_dir / "ProxySQL_MySQLX_Plugin.so").write_bytes(b"mysqlx-plugin")

    libtap = tap_dir / "libtap.so"
    libpq = libpq_dir / "libpq.so.5"
    if dynamic_libpq:
        compile_shared(libpq, "void pq_fixture(void) {}", "-Wl,-soname,libpq.so.5")
        compile_shared(
            libtap,
            "extern void pq_fixture(void); void tap_fixture(void) { pq_fixture(); }",
            f"-L{libpq_dir}",
            "-Wl,--no-as-needed",
            "-l:libpq.so.5",
        )
    else:
        compile_shared(libtap, "void tap_fixture(void) {}")
    return repo, libpq


stage = named_step(
    workflow_steps(".github/workflows/ci-builds.yml", "builds"),
    "Stage compiled runtime libraries in test handoff",
)
assert "inputs.trusted" in stage["if"]
assert "matrix.tier" not in stage["if"]
for trusted in (False, True):
    for tier in ('v30', 'v31', 'v40'):
        expression = stage['if'].removeprefix('${{').removesuffix('}}').strip()
        expression = expression.replace('inputs.trusted', str(trusted)).replace('success()', 'True').replace('matrix.tier', repr(tier)).replace('&&', ' and ')
        assert eval(expression, {'__builtins__': {}}, {}) == trusted


with tempfile.TemporaryDirectory() as directory:
    cwd = Path(directory)
    repo, _ = create_workspace(cwd, dynamic_libpq=False)
    result = run_script(stage, cwd)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "libtap.so uses static libpq" in result.stdout
    runtime_dir = repo / "test/tap/tap/_runtime_libs"
    assert not (runtime_dir / "libpq.so.5").exists()
    assert (runtime_dir / "ProxySQL_MySQLX_Plugin.so").read_bytes() == b"mysqlx-plugin"

with tempfile.TemporaryDirectory() as directory:
    cwd = Path(directory)
    repo, libpq = create_workspace(cwd, dynamic_libpq=True)
    expected_libpq = libpq.read_bytes()
    result = run_script(stage, cwd)
    assert result.returncode == 0, result.stdout + result.stderr
    runtime_dir = repo / "test/tap/tap/_runtime_libs"
    assert (runtime_dir / "libpq.so.5").read_bytes() == expected_libpq

with tempfile.TemporaryDirectory() as directory:
    cwd = Path(directory)
    _, libpq = create_workspace(cwd, dynamic_libpq=True)
    libpq.unlink()
    result = run_script(stage, cwd)
    assert result.returncode != 0
    assert "cannot stage libpq.so.5" in result.stdout + result.stderr

with tempfile.TemporaryDirectory() as directory:
    cwd = Path(directory)
    repo, _ = create_workspace(cwd, dynamic_libpq=False)
    (repo / "test/tap/tap/libtap.so").write_bytes(b"not-an-elf")
    result = run_script(stage, cwd)
    assert result.returncode != 0
    assert "cannot inspect test/tap/tap/libtap.so" in result.stdout + result.stderr

for tier in ('v30', 'v31'):
    with tempfile.TemporaryDirectory() as directory:
        cwd = Path(directory)
        repo, libpq = create_workspace(cwd, dynamic_libpq=True)
        (repo / "plugins/mysqlx/ProxySQL_MySQLX_Plugin.so").unlink()
        result = run_script(stage, cwd, tier)
        assert result.returncode == 0, result.stdout + result.stderr
        runtime_dir = repo / "test/tap/tap/_runtime_libs"
        assert (runtime_dir / "libpq.so.5").read_bytes() == libpq.read_bytes()
        assert not (runtime_dir / "ProxySQL_MySQLX_Plugin.so").exists()

print("MySQLX runtime handoff contract passed")
