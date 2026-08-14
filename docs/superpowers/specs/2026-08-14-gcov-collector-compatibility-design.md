# GCOV collector compatibility

## Problem

The coverage build runs with GCC 11.4, so its `.gcno` and `.gcda` files must
be read by the matching GCOV 11 tool. The Ubuntu 24 CI-base image currently
provides GCOV 13 only. Fastcov therefore discovers the data files but cannot
convert them, producing an empty LCOV report while the TAP tests themselves
pass and exercise the implementation.

## Design

Keep the coverage build toolchain unchanged. Install `gcc-11`, which provides
the `gcov-11` executable, in the CI-base image and use that executable
explicitly for every fastcov invocation that converts raw GCOV files. The two
conversion paths are the standalone test-runner exit trap and the multi-group
per-group collector. Combining existing LCOV files does not need GCOV and
remains unchanged.

Before conversion, each path will check that `gcov-11` is available and fail
with an actionable error if it is not. This prevents a successful TAP job from
silently uploading an empty coverage report.

## Verification

Add a regression check for the collector contract: the CI-base Dockerfile
must install `gcc-11`, and raw-data fastcov calls must use `-g gcov-11`.
Then run the existing `test_ffto_mysql-t` through the normal isolated runner
with coverage enabled. The test must pass and its LCOV output must include
nonzero coverage for `lib/MySQLFFTO.cpp`.
