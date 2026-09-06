#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
VERIFY_COMMAND='test/infra/control/verify-package-install.bash "binaries/'

ci_output=$(GITHUB_ACTIONS=true make -n -C "$ROOT_DIR" almalinux8)
ci_count=$(grep -Fc "$VERIFY_COMMAND" <<<"$ci_output" || true)
if [[ "$ci_count" -ne 1 ]]; then
    echo "expected one package verification in a CI package build; found $ci_count" >&2
    exit 1
fi

local_output=$(env -u GITHUB_ACTIONS make -n -C "$ROOT_DIR" almalinux8)
if grep -Fq "$VERIFY_COMMAND" <<<"$local_output"; then
    echo "local package builds must not run the CI verification hook" >&2
    exit 1
fi

tarball_output=$(GITHUB_ACTIONS=true make -n -C "$ROOT_DIR" tarball-almalinux9)
if grep -Fq "$VERIFY_COMMAND" <<<"$tarball_output"; then
    echo "tarballs must remain on their dedicated runtime test" >&2
    exit 1
fi

asan_output=$(GITHUB_ACTIONS=true WITHASAN=1 make -n -C "$ROOT_DIR" ubuntu24-tap)
if grep -Fq "$VERIFY_COMMAND" <<<"$asan_output"; then
    echo "ASAN test builds must not run the clean-install verification hook" >&2
    exit 1
fi

tsan_output=$(GITHUB_ACTIONS=true WITHTSAN=1 make -n -C "$ROOT_DIR" ubuntu24-tap)
if grep -Fq "$VERIFY_COMMAND" <<<"$tsan_output"; then
    echo "TSAN test builds must not run the clean-install verification hook" >&2
    exit 1
fi

echo 'package CI verification hook test: PASS'
