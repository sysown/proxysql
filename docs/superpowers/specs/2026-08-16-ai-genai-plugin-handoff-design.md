# AI GenAI Plugin Build Handoff Design

## Problem

`CI-ai-g1` and `CI-ai-g2` consume the `ubuntu24-tap-genai-gcov` build
handoff. That build successfully produces
`plugins/genai/ProxySQL_GenAI_Plugin.so`, but `ci-builds.yml` stages plugin
shared objects only for the `-tap-mysqlx` matrix entry. The AI consumer then
unpacks only the `src` and `test` handoffs and starts the isolated harness
without restoring the GenAI plugin. Infrastructure startup fails before any
AI TAP test runs.

## Scope

Fix only the reusable build-to-test handoff on the `GH-Actions` branch:

- Preserve the existing build matrix and ASAN label selection.
- Preserve `CI-unit-tests-asan-coverage` unchanged.
- Do not add a separate AI build or compile anything in the fan-out jobs.
- Do not change the shared `_src` cache path contract.
- Do not change the isolated test harness's plugin lookup rules.

## Considered Approaches

### 1. Carry the plugin in the existing test handoff (selected)

Stage the GenAI plugin under `test/tap/tap/_runtime_libs/` in the central
GenAI build, then restore it to `plugins/genai/` in the reusable AI consumer.
This follows the established MySQLX plugin handoff pattern and keeps the
shared source-cache path list unchanged.

### 2. Add the plugin directly to the source handoff

This would place a matrix-specific runtime artifact in a broadly shared
source contract and diverge from the existing plugin convention. It also
risks cache-version mismatches between the producer and numerous consumers.

### 3. Make the test harness fall back to `_runtime_libs`

This would couple a general-purpose local/Docker harness to a GitHub Actions
artifact layout and could hide a broken CI handoff until infrastructure
startup. The harness should continue to require the plugin at its canonical
workspace path.

## Selected Design

### Producer

For every `-genai` TAP build, `ci-builds.yml` will:

1. Create `test/tap/tap/_runtime_libs/`.
2. Require `plugins/genai/ProxySQL_GenAI_Plugin.so` to exist.
3. Copy the dereferenced shared object into `_runtime_libs`.
4. Verify and list the staged file before packing `test/`.

The copy is mandatory for a GenAI build. It must not use `|| true`, because a
successful build that cannot provide its required runtime plugin is a corrupt
handoff and should fail at the producer boundary.

The MySQLX-specific staging of `libpq.so.5`, `libre2.so.10`, and
`ProxySQL_MySQLX_Plugin.so` remains unchanged.

### Consumer

After `ci-ai-gcov.yml` unpacks the `src` and `test` handoffs, it will:

1. Create `proxysql/plugins/genai/`.
2. Require the staged GenAI plugin in `_runtime_libs`.
3. Copy it to `proxysql/plugins/genai/ProxySQL_GenAI_Plugin.so`.
4. Verify that both the ProxySQL executable and restored plugin exist before
   infrastructure startup.

Both `CI-ai-g1` and `CI-ai-g2` reuse `ci-ai-gcov.yml`, so one consumer change
fixes both shards.

## Failure Behavior

- A GenAI build that does not produce the plugin fails while staging the
  handoff, with the plugin path in the error.
- An AI consumer receiving an old or incomplete handoff fails in its explicit
  verification step, before Docker setup.
- Non-GenAI TAP builds do not require or stage the GenAI plugin.

## Verification

Add a workflow-contract test that initially fails against the current
workflows and asserts:

- the `-genai` producer stages the GenAI plugin mandatorily into
  `_runtime_libs`;
- the AI consumer restores it to `plugins/genai/`;
- the consumer verifies the restored file before infrastructure startup.

Then run the contract test, the existing TAP-mode resolver test, and YAML
parsing for the changed workflows. The end-to-end verification is a fresh PR
6083 run after this `GH-Actions` change merges; pushing an empty commit after
the merge will cause the central build and both AI shards to consume the new
workflow definitions.
