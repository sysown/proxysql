#!/usr/bin/env python3
from pathlib import Path
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
restore = named_step(ai_steps, "Restore GenAI plugin from build handoff")
verify = named_step(ai_steps, "Verify binary and GenAI plugin")

assert "inputs.trusted" in stage["if"]
assert "contains(matrix.type,'-genai')" in stage["if"]

names = [step.get("name") for step in ai_steps]
assert names.index("Download build handoff") < names.index(restore["name"])
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

with tempfile.TemporaryDirectory() as directory:
    cwd = Path(directory)
    repo = cwd / "proxysql"
    staged = repo / "test/tap/tap/_runtime_libs/ProxySQL_GenAI_Plugin.so"
    staged.parent.mkdir(parents=True)
    staged.write_bytes(b"genai-plugin")

    result = run_script(restore, cwd)
    assert result.returncode == 0, result.stdout + result.stderr
    restored = repo / "plugins/genai/ProxySQL_GenAI_Plugin.so"
    assert restored.read_bytes() == b"genai-plugin"

    staged.unlink()
    restored.unlink()
    result = run_script(restore, cwd)
    assert result.returncode != 0
    assert "ProxySQL_GenAI_Plugin.so" in result.stdout + result.stderr

    binary = repo / "src/proxysql"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    restored.parent.mkdir(parents=True, exist_ok=True)
    restored.write_bytes(b"genai-plugin")
    result = run_script(verify, cwd)
    assert result.returncode == 0, result.stdout + result.stderr

    restored.unlink()
    result = run_script(verify, cwd)
    assert result.returncode != 0
    assert "ProxySQL_GenAI_Plugin.so" in result.stdout + result.stderr

print("GenAI plugin handoff contract passed")
