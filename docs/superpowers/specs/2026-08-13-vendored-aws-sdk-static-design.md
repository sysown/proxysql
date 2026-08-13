# Vendored AWS SDK for C++ Static-Link Design

**Date:** 2026-08-13  
**Status:** Approved for specification review  
**Extends:** `docs/superpowers/specs/2026-08-12-aws-iam-database-auth-design.md`

## Approved 4.0 plugin amendment

AWS IAM database authentication is delivered as the optional v4.0
`ProxySQL_AwsIam_Plugin.so`.  The pinned SDK and CRT archives are statically
linked into that plugin, not `src/proxysql`; the default daemon and a v4.0
daemon built without `PROXYSQLAWSIAM=1` remain free of AWS SDK code.  This
amendment supersedes every reference below that says the SDK is linked into
the core daemon or extracted below `build/`.  The native dependency target
unpacks the immutable LFS archive under `deps/aws-sdk-cpp/`, alongside the
repository's other dependency builds.

## Goal

Replace the optional externally installed AWS SDK for C++ integration with a
reproducible vendored source bundle and statically link the AWS SDK code used
by IAM database-token generation into the optional v4.0 AWS IAM plugin when
`PROXYSQLAWSIAM=1`.

The default build remains SDK-free: it must not compile the bundle, link AWS
archives, initialize the AWS runtime, or start IAM provider workers.

## Non-goals

- Do not vendor prebuilt SDK libraries or download source during a build.
- Do not broaden IAM authentication to frontend clients, PostgreSQL, monitors,
  Secrets Manager, or per-user roles.
- Do not statically link system OpenSSL, curl, zlib, libc++, or libc; the
  static-link requirement applies to the vendored AWS SDK and AWS CRT archives.
- Do not claim real-RDS verification without configured credentials and an
  IAM-enabled RDS/Aurora endpoint.

## Vendor Bundle

`deps/aws-sdk-cpp/` will contain exactly one versioned source bundle:

```text
deps/aws-sdk-cpp/
  aws-sdk-cpp-1.11.869-with-crt.tar.xz
  aws-sdk-cpp-1.11.869-with-crt.sha256
  aws-sdk-cpp-1.11.869-sources.json
  LICENSE
  NOTICE
  THIRD_PARTY_NOTICES.md
```

The archive is tracked by Git LFS at that repository path.  A checkout must
hydrate the LFS object before a feature-on build; the build itself reads and
extracts the already local archive and never downloads SDK source.

The tarball is created from upstream tag `1.11.869` and has all nested source
trees expanded at their upstream pinned commits. This includes
`aws-crt-cpp` and its `aws-c-*`, `aws-checksums`, `aws-lc`, and `s2n` source
trees required by that revision. It is a conventional complete source bundle:
source tests, feature-probe inputs, examples, documentation, and test fixtures
remain because upstream CMake can use source-side probes even with tests
disabled. Only VCS metadata, generated build directories, machine-local AWS
configuration, and prebuilt object/library files are excluded. CMake disables
all SDK test/example/tool targets during the ProxySQL build.

`aws-sdk-cpp-1.11.869-sources.json` records the top-level tag/commit and every
expanded submodule repository URL and pinned commit. The SHA-256 file covers
the committed bundle, and the verifier pins that same expected digest in its
own code so the digest file is not the sole trust input. The license and notice
files are copied from the pinned source trees and named in
`THIRD_PARTY_NOTICES.md`; the bundle therefore carries the Apache-2.0
attribution required for the SDK and the notices required by its vendored
transitive sources.

No build target runs `git`, `curl`, `wget`, CMake FetchContent, ExternalProject
downloads, package-manager SDK installs, or `AWS_SDK_CPP_ROOT` discovery to
obtain AWS SDK source.

## Static Build and Link Architecture

When `PROXYSQLAWSIAM=1`, a dedicated dependency rule verifies the bundle
checksum, extracts it below `deps/aws-sdk-cpp/`, and configures an offline
CMake build. CMake is passed the extracted source directory and system paths
only for ProxySQL's existing OpenSSL, curl, and zlib dependencies. It builds:

- AWS SDK `core` and `rds` as static archives;
- the exact static AWS CRT archives needed by those targets;
- no AWS SDK test, example, tool, or unrelated service target.

The SDK uses C++17 and its legacy CMake mode compatible with the pinned
release. The configure step sets static-library mode, disables SDK testing and
code generation, restricts services to `core;rds`, and validates that every
AWS source dependency comes from the extracted bundle. Its generated Make
fragment supplies only the necessary include paths, archive paths, and
ordered system link flags to ProxySQL.

The final AWS IAM plugin must contain
`Aws::RDS::RDSClient::GenerateConnectAuthToken`, while `src/proxysql` contains
no AWS SDK symbol or dynamic `aws-cpp-sdk-*`, `aws-c-*`, `aws-crt-cpp`, `s2n`,
or AWS-LC dependency. System OpenSSL/curl/zlib dependencies may remain
dynamic.

Feature-on source and build identity are derived from the committed vendor
manifest and bundle SHA-256, CMake options, compiler identity, target
architecture, and relevant system-library paths. A changed identity causes a
new private build directory; an unchanged invocation is a true no-op. Parallel
`make -j` invocations serialize only bundle extraction/configuration for the
same identity and consume immutable generated fragments.

`AWS_SDK_CPP_ROOT`, external `find_package(AWSSDK)`, SDK package ownership
checks, and the openSUSE Cloud:Tools repository are removed from the feature
path. A feature-on build fails early only when the committed bundle or its
integrity/license manifest is missing, malformed, or incompatible with the
host toolchain.

## Review and CI Corrections

### Session token-source lifetime

`MySQL_Session` owns an `AwsIamTokenSourceLease` for the lifetime of an
in-flight IAM token request. It acquires the lease before registering the
worker inbox waiter; all wait-path requests, cancellation, waiting-session
metric updates, success completion, timeout, error, destructor, and shutdown
paths use that lease rather than a raw global pointer. The lease is released
only after the request is canceled or completed and the session-owned state is
cleared. This makes `shutdown_global_aws_iam_token_source()` wait safely for
waiting sessions before it destroys the source.

### Workflow failures

Every AWS IAM workflow checkout uses full history and tags so the repository's
version derivation always sees a valid `X.Y.Z` version. The new IAM tests are
registered in `test/tap/groups/groups.json` with the repository's appropriate
unit or TAP groups. Workflow diagnostics use portable `grep -F`, not `rg`.

The former openSUSE external-SDK job becomes an Ubuntu feature-on job that
builds the vendored static bundle. It verifies the final binary's static AWS
symbol and absence of AWS dynamic libraries. No job installs an AWS SDK C++
package. The real-AWS preflight/self-hosted runner contract remains separate;
it is not satisfied by the controlled fake-source protocol test.

## Error Handling and Security

- Bundle verification fails closed before compiling AWS-facing code.
- Build diagnostics report the bundle version, expected and actual checksum,
  and required host dependency category only; they never print credentials or
  generated tokens.
- The static-link audit rejects missing archives, an AWS DSO, an unrelated AWS
  service archive, omitted attribution, or an archive outside the generated
  bundle build tree.
- The existing redacted IAM token failures and SDK-off behavior are preserved.

## Test and Acceptance Matrix

1. A manifest test builds a small synthetic bundle with an exact dependency
   list, then proves checksum mismatch, absent nested tree, hostile path, stale
   mode stamp, and archive injection failures are rejected before linking.
2. A feature-on build from the real committed bundle runs offline after source
   preparation, produces static `core`/`rds` linkage, and passes the IAM unit
   suite plus controlled TLS/auth-switch test.
3. A feature-off build contains no AWS headers, archives, symbols, DSOs, or
   provider threads and preserves ordinary password tests.
4. A deterministic session test holds a token request while shutdown begins;
   it proves shutdown waits for the session lease, cancellation is safe, and a
   republished source cannot be invoked by the old wait state. Run it repeatedly
   and under TSan.
5. CI validates full checkout depth, all new group registrations, portable
   missing-bundle diagnostics, static-link/no-DSO audit, and the SDK-free
   regression path.
6. All bundle/license manifests, scripts, workflows, and source changes pass
   secret scans, `git diff --check`, and independent code review.

## Migration and Release Policy

`PROXYSQLAWSIAM=1` changes from an external-host prerequisite to an in-tree
vendor prerequisite. Operators no longer install AWS SDK C++ development
packages; release packaging carries the committed SDK/CRT attribution files
with the ProxySQL source and records the bundle manifest version and SHA-256.

The operator guide and CI documentation will be revised to remove
`AWS_SDK_CPP_ROOT`, system-package installation instructions, and the prior
package-owned-notice release block. They will describe the pinned
`1.11.869` bundle, static-link audit, standard AWS credential-provider chain,
and unchanged IAM database-user/RDS TLS requirements.
