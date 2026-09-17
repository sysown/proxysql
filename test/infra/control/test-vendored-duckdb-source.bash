#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
verifier="${repo_root}/deps/duckdb/verify-source.bash"
tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT

fail=0
check() {
	local desc=$1; shift
	if "$@" >/dev/null 2>&1; then
		echo "ok - ${desc}"
	else
		echo "not ok - ${desc}"; fail=1
	fi
}
check_fails() {
	local desc=$1; shift
	if "$@" >/dev/null 2>&1; then
		echo "not ok - ${desc} (expected non-zero exit)"; fail=1
	else
		echo "ok - ${desc}"
	fi
}

# 1. The committed archive verifies.
check "committed archive passes verification" bash "${verifier}"

# 2. An unfetched LFS pointer is detected as such, not as a corrupt archive.
printf 'version https://git-lfs.github.com/spec/v1\noid sha256:deadbeef\nsize 1\n' \
	> "${tmp}/pointer.tar.gz"
echo "0000000000000000000000000000000000000000000000000000000000000000  pointer.tar.gz" \
	> "${tmp}/pointer.tar.gz.sha256"
check_fails "LFS pointer file is rejected" bash "${verifier}" "${tmp}/pointer.tar.gz"
# Captured (not piped) so pipefail can't surface the verifier's intentional
# non-zero exit as the check's own failure regardless of what grep finds.
pointer_output=$(bash "${verifier}" "${tmp}/pointer.tar.gz" 2>&1 || true)
if echo "${pointer_output}" | grep -qi "git lfs"; then
	echo "ok - pointer rejection mentions git lfs"
else
	echo "not ok - pointer rejection must name git lfs"; fail=1
fi

# 3. A checksum mismatch is rejected.
head -c 1024 /dev/urandom > "${tmp}/bad.tar.gz"
echo "0000000000000000000000000000000000000000000000000000000000000000  bad.tar.gz" \
	> "${tmp}/bad.tar.gz.sha256"
check_fails "checksum mismatch is rejected" bash "${verifier}" "${tmp}/bad.tar.gz"

exit "${fail}"
