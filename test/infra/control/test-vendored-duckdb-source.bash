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
write_checksum() {
	local archive=$1
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "${archive}" > "${archive}.sha256"
	else
		shasum -a 256 "${archive}" > "${archive}.sha256"
	fi
}

# 1. The committed archive verifies.
check "committed archive passes verification" bash "${verifier}"

# 2. A small text file with a matching checksum is rejected as corrupt, not
# silently accepted.
printf 'not an xz archive\n' > "${tmp}/text.tar.xz"
write_checksum "${tmp}/text.tar.xz"
check_fails "non-archive file is rejected" bash "${verifier}" "${tmp}/text.tar.xz"

# 3. A checksum mismatch is rejected.
head -c 1024 /dev/urandom > "${tmp}/bad.tar.xz"
echo "0000000000000000000000000000000000000000000000000000000000000000  bad.tar.xz" \
	> "${tmp}/bad.tar.xz.sha256"
check_fails "checksum mismatch is rejected" bash "${verifier}" "${tmp}/bad.tar.xz"

# A readable first member must not hide a truncated xz stream.
mkdir "${tmp}/duckdb-2.0.0"
printf 'source fixture\n' > "${tmp}/duckdb-2.0.0/source.txt"
tar -cJf "${tmp}/complete.tar.xz" -C "${tmp}" duckdb-2.0.0
write_checksum "${tmp}/complete.tar.xz"
check "complete xz fixture passes verification" bash "${verifier}" "${tmp}/complete.tar.xz"
size=$(wc -c < "${tmp}/complete.tar.xz")
dd if="${tmp}/complete.tar.xz" of="${tmp}/truncated.tar.xz" bs=1 count=$((size - 12)) 2>/dev/null
write_checksum "${tmp}/truncated.tar.xz"
check_fails "truncated xz with matching checksum is rejected" bash "${verifier}" "${tmp}/truncated.tar.xz"

mkdir "${tmp}/wrong-root"
tar -cJf "${tmp}/wrong-root.tar.xz" -C "${tmp}" wrong-root
write_checksum "${tmp}/wrong-root.tar.xz"
check_fails "xz archive with wrong root is rejected" bash "${verifier}" "${tmp}/wrong-root.tar.xz"

exit "${fail}"
