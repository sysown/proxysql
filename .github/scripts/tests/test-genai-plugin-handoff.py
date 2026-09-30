#!/usr/bin/env python3
from pathlib import Path
import json
import shutil
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


def run_script(step: dict, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + step["run"]],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


build_steps = workflow_steps(".github/workflows/ci-builds.yml", "builds")
ai_steps = workflow_steps(".github/workflows/ci-ai-gcov.yml", "tests")
stage = named_step(build_steps, "Stage GenAI plugin in test handoff")
restore = named_step(ai_steps, "Restore compiled GenAI plugin from build handoff")
verify = named_step(ai_steps, "Verify binary")

assert "inputs.trusted" in stage["if"]
assert "matrix.tier == 'v40'" in stage["if"]
for trusted in (False, True):
    for tier in ('v30', 'v31', 'v40'):
        expression = stage['if'].removeprefix('${{').removesuffix('}}').strip()
        expression = expression.replace('inputs.trusted', str(trusted)).replace('success()', 'True').replace('matrix.tier', repr(tier)).replace('&&', ' and ')
        assert eval(expression, {'__builtins__': {}}, {}) == (trusted and tier == 'v40')


names = [step.get("name") for step in ai_steps]
assert names.index("Restore selected product handoff") < names.index(restore["name"])
assert names.index(restore["name"]) < names.index(verify["name"])
assert names.index(verify["name"]) < names.index("Start infrastructure")

with tempfile.TemporaryDirectory() as directory:
    cwd = Path(directory)
    repo = cwd / "proxysql"
    source = repo / "plugins/genai/ProxySQL_GenAI_Plugin.so"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"genai-plugin")

    result = run_script(stage, cwd)
    assert result.returncode == 0, result.stdout + result.stderr
    staged = repo / "test/tap/tap/_runtime_libs/ProxySQL_GenAI_Plugin.so"
    assert staged.read_bytes() == b"genai-plugin"

    source.unlink()
    staged.unlink()
    result = run_script(stage, cwd)
    assert result.returncode != 0
    assert "ProxySQL_GenAI_Plugin.so" in result.stdout + result.stderr

for version, payload, succeeds, restored_expected in [
    ('ProxySQL version 3.0.12', None, True, False),
    ('ProxySQL version 3.1.12', None, True, False),
    ('ProxySQL version 3.1.12', b'unused-plugin', True, False),
    ('ProxySQL version 4.0.12', b'genai-plugin', True, True),
    ('ProxySQL version 4.0.12', None, False, False),
    ('ProxySQL version 4.0.12', b'', False, False),
    ('invalid version', b'genai-plugin', False, False),
    (None, b'genai-plugin', False, False),
]:
    with tempfile.TemporaryDirectory() as directory:
        cwd = Path(directory)
        repo = cwd / "proxysql"
        control = cwd / "ci-control/.github/scripts"
        control.mkdir(parents=True)
        shutil.copyfile(ROOT / '.github/scripts/ci_tier_plan.py', control / 'ci_tier_plan.py')
        (repo / 'src').mkdir(parents=True)
        if version is not None:
            (repo / 'src/ci-tier.json').write_text(json.dumps({'version': version}))
        staged = repo / "test/tap/tap/_runtime_libs/ProxySQL_GenAI_Plugin.so"
        if payload is not None:
            staged.parent.mkdir(parents=True)
            staged.write_bytes(payload)

        result = run_script(restore, cwd)
        assert (result.returncode == 0) == succeeds, (version, payload, result.stdout, result.stderr)
        restored = repo / "plugins/genai/ProxySQL_GenAI_Plugin.so"
        assert restored.exists() == restored_expected, (version, payload)
        if restored_expected:
            assert restored.read_bytes() == payload
        if version == 'ProxySQL version 4.0.12' and not payload:
            assert 'Required GenAI plugin missing' in result.stdout + result.stderr

        # Binary verification remains common to products with and without plugins.
        binary = repo / "src/proxysql"
        binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        result = run_script(verify, cwd)
        assert result.returncode == 0, result.stdout + result.stderr
        binary.unlink()
        result = run_script(verify, cwd)
        assert result.returncode != 0

print("GenAI plugin handoff contract passed")
