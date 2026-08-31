# OpenSSL Vendoring and FIPS Roadmap

## Purpose

Track the ordering between two distinct ProxySQL projects without combining
their deliverables or acceptance criteria.

Parent issue: <https://github.com/sysown/proxysql/issues/6114>

## Projects

### 1. Mandatory vendored OpenSSL

Issue: <https://github.com/sysown/proxysql/issues/6115>

Specification:
[2026-08-19-vendored-openssl-design.md](2026-08-19-vendored-openssl-design.md)

This project restores OpenSSL 3.5 LTS as a mandatory source-vendored
dependency, statically links a single OpenSSL core into ProxySQL on Linux,
macOS, and FreeBSD, removes system OpenSSL build/runtime assumptions, and
proves the result through the build and packaging matrix.

Its completion does not deliver FIPS mode or make ProxySQL FIPS compliant.

### 2. Future OpenSSL FIPS provider mode

Issue: <https://github.com/sysown/proxysql/issues/6116>

Specification:
[2026-08-19-openssl-fips-provider-design.md](2026-08-19-openssl-fips-provider-design.md)

This project adds an explicit, fail-closed operating mode around a shipped and
qualified OpenSSL FIPS provider. It owns the cryptographic API migration,
protocol restrictions, validated-module packaging, installation procedure,
runtime enforcement, operational-environment qualification, and compliance
review.

## Dependency

The FIPS project depends on the static-core architecture delivered by the
vendoring project. That dependency does not make the projects one unit of
work. The vendoring issue can close independently once its own acceptance
criteria pass. The FIPS issue remains open until its separate implementation
and qualification are complete.

## Acceptance

This roadmap closes only when both child issues close. No parent or child issue
may represent completion of vendoring alone as FIPS compliance.
