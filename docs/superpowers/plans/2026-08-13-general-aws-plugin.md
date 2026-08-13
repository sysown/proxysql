# General AWS Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the v4 AWS IAM plugin to the general AWS plugin and make `PROXYSQL40=1` the only build switch, while retaining IAM database authentication as its first isolated capability.

**Architecture:** The v4 build always produces `plugins/aws/ProxySQL_Aws_Plugin.so` and the package always carries it, but the daemon loads and initializes AWS only when the operator lists the plugin in `plugins`. The vendored SDK remains a concrete native dependency under `deps/aws-sdk-cpp`, SDK types stay inside the plugin, and the core ABI retains the precise IAM token-source capability interface.

**Tech Stack:** GNU Make, Bash packaging scripts, C++17 plugin ABI, statically linked AWS SDK for C++ 1.11.869 (`core` and `rds`), TAP unit tests, GitHub Actions.

---

### Task 1: Lock the General-Plugin Build Contract With a Failing Gate

**Files:**
- Modify: `test/infra/control/check-vendored-aws-sdk-build.bash`

- [ ] **Step 1: Extend the existing black-box gate before production changes**

Add exact assertions for the new public build contract:

```bash
plugin_makefile="$repo_root/plugins/aws/Makefile"
workflow="$repo_root/.github/workflows/CI-aws.yml"

for obsolete_token in PROXYSQLAWSIAM PROXYSQLAWS \
        ProxySQL_AwsIam_Plugin.so plugins/aws_iam; do
    if git -C "$repo_root" grep -n "$obsolete_token" -- \
            Makefile deps/Makefile common_mk plugins .github docker \
            README.md doc etc test/tap/tests/unit; then
        fail "obsolete AWS plugin build/name token remains: $obsolete_token"
    fi
done

grep -Fq 'PLUGIN_SO := $(PLUGIN_DIR)/ProxySQL_Aws_Plugin.so' \
    "$plugin_makefile" || fail 'general AWS plugin artifact is not configured'
grep -Fq "'plugins/aws/**'" "$workflow" || \
    fail 'general AWS plugin CI path is not watched'
grep -Fq 'PROXYSQL40=1 make -j' "$workflow" || \
    fail 'v4 CI does not use the sole supported build switch'
```

Also replace the packaging assertion for forwarding `PROXYSQLAWSIAM=1` with an assertion that all four package entrypoints stage `ProxySQL_Aws_Plugin.so` inside their existing `PROXYSQL40=1` branch.

- [ ] **Step 2: Run the gate and capture RED**

Run:

```bash
bash test/infra/control/check-vendored-aws-sdk-build.bash
```

Expected: FAIL because `plugins/aws/Makefile` and `.github/workflows/CI-aws.yml` do not exist and the old flag/name tokens remain.

- [ ] **Step 3: Commit only after later tasks make the gate green**

Do not commit the red test alone on this shared feature branch; keep it as the acceptance gate for Tasks 2 and 3.

### Task 2: Rename the Plugin and Make It a Standard v4 Build Artifact

**Files:**
- Move: `plugins/aws_iam/Makefile` → `plugins/aws/Makefile`
- Move: `plugins/aws_iam/src/aws_iam_plugin.cpp` → `plugins/aws/src/aws_plugin.cpp`
- Modify: `plugins/aws/Makefile`
- Modify: `plugins/aws/src/aws_plugin.cpp`
- Modify: `common_mk/aws_sdk_cpp_flags.mk`
- Modify: `deps/Makefile`
- Modify: `Makefile`
- Modify: `etc/proxysql.cnf`

- [ ] **Step 1: Rename the plugin files without changing IAM capability types**

Use an `apply_patch` move for both files. Rename only plugin-level identifiers:

```make
PLUGIN_DIR := $(PROXYSQL_PATH)/plugins/aws
PLUGIN_SO := $(PLUGIN_DIR)/ProxySQL_Aws_Plugin.so
SRCS := $(PLUGIN_DIR)/src/aws_plugin.cpp
OBJS := $(ODIR)/aws_plugin.o $(ODIR)/Aws_Iam_Token_Manager.o
```

Keep `AwsIamTokenSource`, `AwsIamTokenManager`, `aws_iam_region`, and IAM metrics unchanged because they identify the first capability rather than the plugin.

- [ ] **Step 2: Remove the second plugin build gate**

The general plugin Makefile must require only v4:

```make
ifneq ($(PROXYSQL40),1)
$(error plugins/aws requires PROXYSQL40=1)
endif
```

Its concrete AWS archive recipe must inherit the caller jobserver and use only the v4 switch:

```make
$(AWS_SDK_CPP_RDS_LIB):
	$(MAKE) -C $(PROXYSQL_PATH)/deps PROXYSQL40=1 $@
```

Do not put `-j` in any Makefile recipe.

- [ ] **Step 3: Generalize plugin descriptor and status names**

Rename plugin lifecycle functions to `aws_plugin_init`, `aws_plugin_start`, `aws_plugin_stop`, and `aws_plugin_status_json`. Publish this descriptor and keep the IAM provider registration as one capability:

```cpp
const char *aws_plugin_status_json() {
    return "{\"status\":\"ready\",\"provider\":\"aws\","
           "\"capabilities\":[\"aws_iam\"]}";
}

static const ProxySQL_PluginDescriptor descriptor {
    "aws",
    PROXYSQL_PLUGIN_ABI_VERSION,
    &aws_plugin_init,
    &aws_plugin_start,
    &aws_plugin_stop,
    &aws_plugin_status_json,
    nullptr
};
```

Preserve the existing retained-module lifetime, SDK initialization order, token cleansing, regional RDS client cache, and source destruction behavior.

- [ ] **Step 4: Make AWS SDK flags depend only on v4**

In `common_mk/aws_sdk_cpp_flags.mk`, rename build-only variables from `AWS_IAM_*` to `AWS_SDK_CPP_*` and replace the old conditional with:

```make
AWS_SDK_CPP_MODE_STAMP := $(PROXYSQL_PATH)/deps/aws-sdk-cpp/.proxysql-build-mode
AWS_SDK_CPP_BUILD_MODE := disabled

ifeq ($(PROXYSQL40),1)
AWS_SDK_CPP_VERSION := 1.11.869
AWS_SDK_CPP_BUILD_MODE := enabled:$(AWS_SDK_CPP_VERSION):static
# install/include/lib/static archive definitions
endif
```

Update the plugin Makefile to consume the renamed variables. No core or unit-test link rule may consume the SDK flags.

- [ ] **Step 5: Make the concrete SDK archive a normal v4 dependency**

Replace the old conditional in `deps/Makefile` with:

```make
ifeq ($(PROXYSQL40),1)
targets += $(AWS_SDK_CPP_RDS_LIB)
endif
```

Retain `$(AWS_SDK_CPP_RDS_LIB)` as the concrete file target and retain `aws_sdk_cpp_clean` as the explicit cleanup target.

- [ ] **Step 6: Build the plugin from every v4 source target**

Remove `export PROXYSQLAWSIAM`. In all four normal/debug legacy/default source recipes, use the same v4-only form:

```make
$(if $(filter 1,$(PROXYSQL40)),cd plugins/aws && OPTZ="${O2} -ggdb" PROXYSQL40=1 CC=${CC} CXX=${CXX} ${MAKE},@echo "[skip] AWS plugin (PROXYSQL40 not set)")
```

Update clean, install, and uninstall paths to `plugins/aws/ProxySQL_Aws_Plugin.so`. Preserve plain recursive `${MAKE}` calls with no hard-coded `-j`.

- [ ] **Step 7: Verify the focused build behavior**

Run:

```bash
PROXYSQL40=1 make -C plugins/aws -j
PROXYSQL40=1 make -C deps -j aws_sdk_cpp_clean
PROXYSQL40=0 make -C plugins/aws -j -n
```

Expected: plugin build PASS; explicit SDK cleanup target PASS; non-v4 dry run FAIL with `plugins/aws requires PROXYSQL40=1`. After the cleanup check, rebuild with `PROXYSQL40=1 make -C plugins/aws -j` before continuing.

### Task 3: Rename Tests, CI, Packaging, Installation, and Documentation

**Files:**
- Move: `test/tap/tests/unit/aws_iam_plugin_load_unit-t.cpp` → `test/tap/tests/unit/aws_plugin_load_unit-t.cpp`
- Move: `.github/workflows/CI-aws-iam.yml` → `.github/workflows/CI-aws.yml`
- Modify: `test/tap/tests/unit/Makefile`
- Modify: `test/infra/control/check-vendored-aws-sdk-build.bash`
- Modify: four `docker/images/proxysql/*-compliant/entrypoint/entrypoint.bash` files
- Modify: `docker/images/proxysql/rhel-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec`
- Modify: `docker/images/proxysql/suse-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec`
- Modify: `README.md`
- Modify: `doc/aws_iam_database_authentication.md`
- Modify: `doc/PLUGIN_API.md`
- Modify: `etc/proxysql.cnf`

- [ ] **Step 1: Rename the loader and linkage targets**

Use these public test names and paths:

```make
.PHONY: aws_plugin_linkage-t aws_plugin_build

aws_plugin_build:
	$(MAKE) -C $(PROXYSQL_PATH)/plugins/aws all \
		PROXYSQL40=1 CC=$(CC) CXX=$(CXX)

aws_plugin_load_unit-t: aws_plugin_load_unit-t.cpp $(TEST_HELPERS_OBJ) \
		$(LIBPROXYSQLAR) aws_plugin_build
```

In that target's existing full compiler invocation, replace its path define
with this exact argument while retaining the current include and link flags:

```make
-DPROXYSQL_AWS_PLUGIN_PATH=\"$(PROXYSQL_PATH)/plugins/aws/ProxySQL_Aws_Plugin.so\"
```

Update the C++ fixture macro to `PROXYSQL_AWS_PLUGIN_PATH`. Retain all 11 lifecycle assertions, including source usability after plugin-manager unload and final registry shutdown.

Delete the stale `PROXYSQLAWSIAM` include/link branches and `AWS_IAM_MODE_STAMP` helper prerequisite from the unit Makefile; units exercise core abstractions and must not link the SDK.

- [ ] **Step 2: Make all v4 package entrypoints stage the AWS plugin**

Remove every `PROXYSQLAWSIAM` environment branch and forwarding assignment. Inside the existing `PROXYSQL40=1` blocks, require and stage:

```bash
plugins/aws/ProxySQL_Aws_Plugin.so
ProxySQL_Aws_Plugin.so
```

Always stage `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md` under `/usr/share/doc/proxysql/aws-sdk-cpp/` for v4 packages. Rename helper/error text from “AWS IAM plugin” to “AWS plugin”.

- [ ] **Step 3: Simplify RPM attribution gates**

Remove `RPMBUILD_WITH_AWS_IAM` and the `with_aws_iam` define. Put the AWS attribution paths under the existing v4 `with_plugins` block in both specs:

```spec
%if 0%{?with_plugins}
%dir /usr/lib/proxysql
/usr/lib/proxysql/*.so
%dir /usr/share/doc/proxysql
%dir /usr/share/doc/proxysql/aws-sdk-cpp
/usr/share/doc/proxysql/aws-sdk-cpp/*
%endif
```

- [ ] **Step 4: Rename and simplify CI**

Rename the workflow to `CI-aws.yml`, set `name: CI-AWS`, and watch `plugins/aws/**`. The plugin job must use only:

```yaml
- name: Build static AWS plugin
  run: PROXYSQL40=1 make -j
```

Update artifact and test paths to `plugins/aws/ProxySQL_Aws_Plugin.so`, `aws_plugin_linkage-t`, and `aws_plugin_load_unit-t`. Retain the AWS/CRT DSO rejection for both daemon and plugin. Keep real-IAM runner variables named `AWS_IAM_*` because they describe that integration test capability.

- [ ] **Step 5: Update operator-facing names without diluting IAM names**

Document:

```text
PROXYSQL40=1 make -j
/usr/lib/proxysql/ProxySQL_Aws_Plugin.so
plugins/aws/ProxySQL_Aws_Plugin.so
plugin descriptor: aws
```

Keep `backend_auth.type=aws_iam`, `aws_iam_region`, IAM metrics, and IAM permission examples unchanged. Explain that IAM DB authentication is the first AWS plugin capability and that loading the plugin is the only runtime enablement action.

- [ ] **Step 6: Run the acceptance gate to GREEN**

Run:

```bash
bash test/infra/control/check-vendored-aws-sdk-build.bash
```

Expected: the complete fixture matrix passes and prints the pinned SDK verification success; no obsolete build flag or plugin artifact/path remains in active build, CI, packaging, tests, or operator docs.

- [ ] **Step 7: Commit the rename and build-contract implementation**

```bash
git add -A
git diff --cached --check
git commit -m "refactor(aws): generalize the v4 AWS plugin"
```

### Task 4: Verify Static Isolation, Runtime Optionality, and Regressions

**Files:**
- Modify if a regression requires it: files already listed in Tasks 1–3
- Create: `.superpowers/sdd/2026-08-13-vendored-aws-sdk-static/general-aws-plugin-report.md`

- [ ] **Step 1: Run the complete v4 build**

Run:

```bash
PROXYSQL40=1 make -j
```

Expected: PASS; it builds `src/proxysql` and `plugins/aws/ProxySQL_Aws_Plugin.so` without another AWS feature flag.

- [ ] **Step 2: Verify daemon/plugin linkage ownership**

Run `nm -C` and `ldd` through files to avoid pipefail/SIGPIPE ambiguity:

```bash
nm -C src/proxysql > /tmp/proxysql-aws-core.nm
! grep -q 'Aws::' /tmp/proxysql-aws-core.nm
nm -C plugins/aws/ProxySQL_Aws_Plugin.so > /tmp/proxysql-aws-plugin.nm
grep -q 'Aws::RDS::RDSClient::GenerateConnectAuthToken' /tmp/proxysql-aws-plugin.nm
aws_dso_pattern='aws-cpp-sdk|aws-crt-cpp|aws-c-[[:alnum:]_-]+|aws-checksums|aws-lc|s2n'
for artifact in src/proxysql plugins/aws/ProxySQL_Aws_Plugin.so; do
    ! ldd "$artifact" | grep -Eqi "$aws_dso_pattern"
done
```

Expected: daemon has no AWS symbols; plugin has the RDS signer; neither artifact dynamically links AWS SDK/CRT DSOs.

- [ ] **Step 3: Run focused lifecycle and IAM regressions**

Run:

```bash
PROXYSQL40=1 make -C test/tap/tests/unit -j \
  aws_plugin_linkage-t aws_plugin_load_unit-t \
  aws_iam_token_manager_unit-t aws_iam_connection_config_unit-t \
  aws_iam_session_state_unit-t aws_iam_kill_helper_unit-t
./test/tap/tests/unit/aws_plugin_load_unit-t
./test/tap/tests/unit/aws_iam_token_manager_unit-t
./test/tap/tests/unit/aws_iam_connection_config_unit-t
./test/tap/tests/unit/aws_iam_session_state_unit-t
./test/tap/tests/unit/aws_iam_kill_helper_unit-t
```

Expected: loader 11/11 and existing IAM suites retain their current assertion totals with no failures.

- [ ] **Step 4: Verify runtime optionality and incremental behavior**

Run:

```bash
PROXYSQL40=1 make -j -n > /tmp/proxysql40-noop.make
! grep -Eq '(^|[[:space:]])(g\+\+|cc|c\+\+|ar|cmake)[[:space:]]' \
  /tmp/proxysql40-noop.make
```

Run the loader test only after explicitly configuring its plugin path; separately verify the normal test/daemon path creates no AWS provider until the plugin is loaded. Expected: repeated build schedules no compile/archive/link commands and the registry starts empty.

- [ ] **Step 5: Validate workflow and package scripts**

Run:

```bash
bash -n test/infra/control/check-vendored-aws-sdk-build.bash \
  docker/images/proxysql/deb-compliant/entrypoint/entrypoint.bash \
  docker/images/proxysql/rhel-compliant/entrypoint/entrypoint.bash \
  docker/images/proxysql/suse-compliant/entrypoint/entrypoint.bash \
  docker/images/proxysql/tarball-compliant/entrypoint/entrypoint.bash
python3 - <<'PY'
import yaml
with open('.github/workflows/CI-aws.yml', encoding='utf-8') as source:
    yaml.safe_load(source)
PY
```

If `rpmspec` exists, parse both specs with `with_plugins=1`. Expected: syntax/YAML/spec parsing passes and v4 plugin/legal paths are present.

- [ ] **Step 6: Run final scope and whitespace audits**

Run:

```bash
! git grep -n -E 'PROXYSQLAWSIAM|PROXYSQLAWS|ProxySQL_AwsIam_Plugin|plugins/aws_iam' -- \
  Makefile deps/Makefile common_mk plugins .github docker README.md doc etc \
  test/infra/control test/tap/tests/unit
! git diff HEAD~1 -- Makefile deps/Makefile plugins/aws/Makefile \
  test/tap/tests/unit/Makefile | \
  grep -E '^\+.*(\$\{MAKE\}|\$\(MAKE\)).*-j'
git diff --check
git status --short
```

Expected: no obsolete build/plugin name, no hard-coded recursive `-j`, no whitespace failure, and only the report is uncommitted.

- [ ] **Step 7: Record evidence and request independent review**

Write the exact commands, results, assertion totals, static-link evidence, and limitations into the report. Request review of the full implementation range, specifically plugin lifetime, v4-only build behavior, package legal files, Darwin linking, and CI coverage.

- [ ] **Step 8: Address findings, rerun affected gates, commit, and push**

After a CLEAN/READY verdict:

```bash
git add -A
git diff --cached --check
git commit -m "docs: record general AWS plugin verification"
git push
```

Expected: clean worktree and the feature branch updated on origin.
