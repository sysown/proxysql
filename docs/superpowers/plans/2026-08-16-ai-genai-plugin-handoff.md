# AI GenAI Plugin Build Handoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the already-built GenAI plugin from the central GenAI build to both reusable AI TAP shards.

**Architecture:** Keep the existing `src` and `test` workflow artifacts. Add one producer step that places the GenAI plugin in the established `test/tap/tap/_runtime_libs/` handoff directory and one shared AI-consumer step that restores it to its canonical workspace path. Exercise the actual workflow shell steps against temporary files in a contract test.

**Tech Stack:** GitHub Actions YAML, Bash, Python 3, PyYAML.

## Global Constraints

- Preserve the existing build matrix and ASAN label selection.
- Preserve `CI-unit-tests-asan-coverage` unchanged.
- Do not add a separate AI build or compile anything in the fan-out jobs.
- Do not change the shared `_src` cache path contract.
- Do not change the isolated test harness's plugin lookup rules.
- A missing GenAI plugin must fail at both the producer and consumer boundaries.

---

### Task 1: Enforce and implement the GenAI plugin handoff

**Files:**

- Create: `.github/scripts/tests/test-genai-plugin-handoff.py`
- Modify: `.github/workflows/ci-builds.yml`
- Modify: `.github/workflows/ci-ai-gcov.yml`

**Interfaces:**

- Consumes: `plugins/genai/ProxySQL_GenAI_Plugin.so` produced by the `ubuntu24-tap-genai-gcov` central build.
- Produces: `test/tap/tap/_runtime_libs/ProxySQL_GenAI_Plugin.so` in the test handoff and restores it as `plugins/genai/ProxySQL_GenAI_Plugin.so` in each AI shard.

- [ ] **Step 1: Write the failing workflow behavior test**

Create `.github/scripts/tests/test-genai-plugin-handoff.py`. Load the real workflow steps with PyYAML, run their `run:` scripts against temporary repository trees, and assert their observable file-copy and failure behavior:

```python
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
```

This test catches three production breaks: the central GenAI build omits the plugin, the shared AI consumer does not restore it, or infrastructure can start without an explicit plugin verification.

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
python3 .github/scripts/tests/test-genai-plugin-handoff.py
```

Expected: FAIL with `workflow step not found: Stage GenAI plugin in test handoff` because neither handoff step exists yet.

- [ ] **Step 3: Add the producer staging step**

In `.github/workflows/ci-builds.yml`, after `Check build` and before cache/handoff packing, add:

```yaml
    - name: Stage GenAI plugin in test handoff
      if: ${{ inputs.trusted && success() && steps.cache-check.outputs.cache-hit != 'true' && contains(matrix.type,'-genai') }}
      run: |
        set -euo pipefail
        cd proxysql/
        plugin_src="plugins/genai/ProxySQL_GenAI_Plugin.so"
        plugin_dest="test/tap/tap/_runtime_libs/ProxySQL_GenAI_Plugin.so"
        if [ ! -s "${plugin_src}" ]; then
          echo "ERROR: required GenAI plugin missing after build: ${plugin_src}" >&2
          exit 1
        fi
        mkdir -p "$(dirname "${plugin_dest}")"
        cp -L "${plugin_src}" "${plugin_dest}"
        test -s "${plugin_dest}"
        ls -la "$(dirname "${plugin_dest}")"
```

- [ ] **Step 4: Add the shared consumer restore and verification steps**

In `.github/workflows/ci-ai-gcov.yml`, immediately after `Download build handoff`, add:

```yaml
    - name: Restore GenAI plugin from build handoff
      run: |
        set -euo pipefail
        cd proxysql/
        plugin_src="test/tap/tap/_runtime_libs/ProxySQL_GenAI_Plugin.so"
        plugin_dest="plugins/genai/ProxySQL_GenAI_Plugin.so"
        if [ ! -s "${plugin_src}" ]; then
          echo "ERROR: required GenAI plugin missing from build handoff: ${plugin_src}" >&2
          exit 1
        fi
        mkdir -p "$(dirname "${plugin_dest}")"
        cp "${plugin_src}" "${plugin_dest}"
        test -s "${plugin_dest}"
```

Rename `Verify binary` to `Verify binary and GenAI plugin` and extend it to fail explicitly when the restored plugin is missing:

```yaml
    - name: Verify binary and GenAI plugin
      run: |
        chmod +x proxysql/src/proxysql
        file proxysql/src/proxysql
        test -s proxysql/plugins/genai/ProxySQL_GenAI_Plugin.so || {
          echo "ERROR: ProxySQL_GenAI_Plugin.so was not restored" >&2
          exit 1
        }
```

- [ ] **Step 5: Run the behavior test and verify GREEN**

Run:

```bash
python3 .github/scripts/tests/test-genai-plugin-handoff.py
```

Expected: exit 0 and `GenAI plugin handoff contract passed`.

- [ ] **Step 6: Run regression validation**

Run:

```bash
.github/scripts/tests/test-resolve-tap-build-mode.bash
python3 - <<'PY'
import yaml
for path in (
    ".github/workflows/ci-builds.yml",
    ".github/workflows/ci-ai-gcov.yml",
):
    with open(path, encoding="utf-8") as stream:
        yaml.safe_load(stream)
    print(f"parsed {path}")
PY
git diff --check
```

Expected: all resolver cases pass, both workflows parse, and `git diff --check` exits 0.

- [ ] **Step 7: Inspect scope and commit**

Run:

```bash
git status --short
git diff -- .github/workflows/ci-builds.yml \
  .github/workflows/ci-ai-gcov.yml \
  .github/scripts/tests/test-genai-plugin-handoff.py
git add .github/workflows/ci-builds.yml \
  .github/workflows/ci-ai-gcov.yml \
  .github/scripts/tests/test-genai-plugin-handoff.py
git commit -m "fix(ci): hand off GenAI plugin to AI shards"
```

Expected: only the two reusable workflows and their behavior test are in the implementation commit.

### Task 2: Publish the `GH-Actions` fix for review

**Files:** None.

**Interfaces:**

- Consumes: the verified `fix/ai-genai-plugin-handoff` branch.
- Produces: a draft pull request targeting `GH-Actions`.

- [ ] **Step 1: Re-run fresh verification before publishing**

Run the commands from Task 1, Steps 5 and 6 again and require every command to exit 0.

- [ ] **Step 2: Push and open the pull request**

Run:

```bash
git push -u origin fix/ai-genai-plugin-handoff
gh pr create --draft --base GH-Actions \
  --head fix/ai-genai-plugin-handoff \
  --title "fix(ci): hand off GenAI plugin to AI shards" \
  --body-file /tmp/ai-genai-plugin-handoff-pr.md
```

The PR body must explain the missing-plugin root cause, the established `_runtime_libs` producer/consumer fix, local validation, and that PR 6083 requires an empty commit after merge for end-to-end verification.
