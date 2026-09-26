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

# 2. A small text file with a matching checksum is rejected as corrupt, not
# silently accepted.
printf 'not a gzip archive\n' > "${tmp}/text.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum "${tmp}/text.tar.gz" | awk '{print $1"  text.tar.gz"}' \
		> "${tmp}/text.tar.gz.sha256"
else
	shasum -a 256 "${tmp}/text.tar.gz" | awk '{print $1"  text.tar.gz"}' \
		> "${tmp}/text.tar.gz.sha256"
fi
check_fails "non-archive file is rejected" bash "${verifier}" "${tmp}/text.tar.gz"

# 3. A checksum mismatch is rejected.
head -c 1024 /dev/urandom > "${tmp}/bad.tar.gz"
echo "0000000000000000000000000000000000000000000000000000000000000000  bad.tar.gz" \
	> "${tmp}/bad.tar.gz.sha256"
check_fails "checksum mismatch is rejected" bash "${verifier}" "${tmp}/bad.tar.gz"

exit "${fail}"
