# Task 12 report: operations, CI, integration contract, and release checks

## Outcome

Task 12 adds the operator guide, documentation index entry, focused CI
workflow, strict linkage/legal checker, and acceptance-evidence mapping for AWS
IAM database authentication. There are no production implementation changes.

The operator guide covers the system AWS SDK for C++ 1.9+ build, Apache-2.0
and GPL-3.0-or-later packaging duties, standard process credential chain,
least-privilege `rds-db:connect`, RDS database-user and CA preparation, exact
ProxySQL Admin SQL, monitoring names, canary/rollback procedure, generic and
redacted failures, clock skew, non-goals, and the no-password-fallback rule.

The CI workflow provides:

- a normal SDK-free build and exact checker rejection;
- an openSUSE Tumbleweed system-SDK feature build using the Cloud:Tools RPM;
- an exact missing-SDK configuration failure;
- focused fake-provider ASan and TSan jobs;
- a GitHub-hosted, secret-safe real-AWS configuration preflight; and
- an opt-in, labeled self-hosted real-RDS execution contract using GitHub OIDC.

The release checker verifies SDK version, current build mode and discovery
identity, binary freshness, shared `core`/`rds` resolution with no unrelated
AWS service library, or the final static signing symbol for development. For
shared releases every resolved AWS DSO must have a system-package owner. The
audited packages must own distinct upstream LICENSE and NOTICE files with the
expected Apache/AWS content. It never sources metadata or prints environment
values.

## Files changed

- `.github/workflows/CI-aws-iam.yml`
- `doc/README.md`
- `doc/aws_iam_database_authentication.md`
- `docs/superpowers/specs/2026-08-12-aws-iam-database-auth-design.md`
- `test/infra/control/check-aws-iam-linkage.bash`
- `test/infra/control/check-aws-iam-linkage-test.bash`

The behavioral checker test is an additional direct test dependency for the
new release script.

## TDD and debugging evidence

The initial behavioral test preceded the checker. Its RED was:

```text
cp: cannot stat '.../check-aws-iam-linkage.bash': No such file or directory
```

The first GREEN exercised shared Linux, Darwin, static metadata/symbol,
unexpected services, minimum version, feature-off/shared mismatch, package
legal material, SDK-free behavior, APK inventory, hostile paths containing
spaces and a literal command-substitution string, and credential redaction.

Systematic review then found five meaningful RED cases:

- `ldd` output with `libaws-cpp-sdk-rds.so => not found` was accepted;
- legal material could come from an unrelated installed SDK package and one
  copyright file could satisfy both records;
- enabled metadata could certify an older binary;
- a valid SemVer `+` build suffix was rejected; and
- one owned shared DSO plus one unowned DSO could pass, while Homebrew legal
  inventory was not bound to the linked formula prefix.

Each received a focused failing case before remediation. The final GREEN is:

```text
1..25
ok 1 - shared Linux linkage, package ownership, and redacted output
...
ok 12 - unresolved shared-library rejection
ok 13 - per-DSO package ownership gate
ok 15 - linked-package legal ownership binding
ok 16 - distinct LICENSE and NOTICE material gate
...
ok 21 - binary freshness binding
ok 22 - RPM ownership branch
ok 23 - Homebrew ownership branch
ok 24 - unrelated Homebrew linkage rejection
ok 25 - Alpine APK ownership branch
```

The original Alpine feature-build design was also rejected during review:
ProxySQL includes `execinfo.h` and uses glibc backtrace APIs while Alpine 3.22
does not provide that interface. The feature-on job was changed to a
digest-pinned glibc-based openSUSE Tumbleweed container and the repository's
documented openSUSE source-build dependency set.

## Verification

The exact missing-SDK check used an empty temporary prefix:

```bash
AWS_SDK_CPP_ROOT="$missing_root" PROXYSQLAWSIAM=1 \
  PROXYSQL40=1 make -j build_src
```

It exited 2 and contained exactly the required diagnostic:

```text
AWS SDK for C++ 1.9 or newer with core and rds is required
```

The normal feature-off binary was rejected with exit 1 and the exact current
mode diagnostic:

```text
AWS IAM linkage check failed: binary is not an AWS IAM-enabled build (feature is disabled)
```

`ldd src/proxysql` contained no `aws-cpp-sdk` dependency.

The SDK-independent controlled TLS/MySQL protocol test rebuilt and passed
16/16 assertions. It covered protected clear-password transport, exact large
token delivery, endpoint SNI/verification, wrong hostname/untrusted CA/early
close/cancellation failures, secret cleanup, ordinary password coexistence,
and pre-acquisition TLS policy rejection.

The final release-check suite passed 25/25. Both scripts passed `bash -n` and
ShellCheck. PyYAML loaded the workflow and found the six intended jobs; every
embedded `run` block passed `bash -n`. Extracted workflow branches proved:

- exact missing-notice status/output is accepted only to emit the explicit
  release-packaging `BLOCKED` warning and summary; and
- an unrelated-service/status-2 failure remains a hard failure and is not
  masked as the known packaging-policy result.

The real-AWS preflight was exercised with absent, partial, and complete fake
configuration. The scheduled-runner path checks accepted executable/readable
paths containing spaces and rejected a missing suite. No secret values were
printed.

A focused scan found no fake-secret markers, placeholder TODO/TBD values, AWS
access-key-shaped values, or credential assignments in the guide/workflow.
All authored Make invocations use `PROXYSQL40=1` and parallel `-j`; none
explicitly sets ClickHouse. No clean or cleanall command was used.

The final normal repository build was:

```bash
PROXYSQL40=1 make -j
```

It exited 0. `git diff --check` passed.

## System package and release-notice evidence

Official Alpine v3.22 package metadata reports AWS SDK for C++ 1.11.400 and
Apache-2.0, but exact package-content searches found no LICENSE, NOTICE,
COPYING, or copyright file. That package therefore cannot satisfy the release
contract, in addition to the unrelated Alpine host-build incompatibility.

The current openSUSE Cloud:Tools `aws-sdk-cpp.spec`, queried from the official
OBS API, reports version 1.11.862 and Apache-2.0. Its `%files libs` contains
shared `libaws*so` files and changelogs; `%files devel` contains headers, CMake,
and pkg-config metadata. Neither manifest owns upstream `LICENSE.txt` or
`NOTICE.txt`. The normal feature-on compilation/linkage portion is expected to
pass, but the separately named policy audit accepts only the exact strict
missing-notice failure and reports release packaging blocked. It never weakens
the checker or qualifies the artifact for release.

## Optional real-AWS contract

The GitHub-hosted `real-aws-preflight` job skips only when the entire protected
contract is absent and fails partial configuration. Complete configuration
schedules `real-aws-integration` on a runner labeled `self-hosted`, `linux`,
`x64`, and `aws-iam-integration`. Once scheduled it hard-fails a missing or
non-executable external suite and a missing, non-absolute, or unreadable CA
file before OIDC credential configuration.

GitHub cannot run a diagnostic step before assigning a matching self-hosted
runner. If no online runner has all four labels, the configured job remains
visibly queued. This platform scheduling limitation is documented without
claiming that controlled fake coverage verifies RDS.

## Independent review

The first independent review found the five checker/workflow defects recorded
above. After their remediation, its rereview found one further Important
ownership defect: the union of package owners did not prove ownership for each
resolved DSO and the Homebrew branch was not formula-path-bound. Focused RED
tests reproduced both cases; per-DSO owner checks and Homebrew prefix binding
made the suite pass 25/25.

A fresh bounded independent rereview returned `CLEAN/READY`. Its only residual
was that the local host cannot execute the SDK-on/openSUSE build.

## Limitations

This host has no real AWS SDK for C++, AWS credentials, RDS endpoint, or
externally provisioned integration runner. No SDK was downloaded or vendored.
Therefore local SDK-on compilation/linkage and real-RDS authentication are not
claimed. The openSUSE package installation/full feature-on build is CI design
validated through workflow syntax, official package/spec metadata, and the
repository's documented dependency list, but was not run locally.

The system-SDK build is not release-qualified because the selected RPM owns no
upstream LICENSE/NOTICE files. This is a release-blocking limitation, not an
acceptance or bypass.

## Commit

Implementation, documentation, tests, and CI:
`bddadb74e` (`docs: add AWS IAM database authentication guide`).

This report is committed separately so it can record the implementation hash.
