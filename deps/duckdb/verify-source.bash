#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
archive=${1:-"${script_dir}/duckdb-1.4.5.tar.gz"}
checksum_file=${2:-"${archive}.sha256"}
required_root=duckdb-1.4.5
lfs_path=deps/duckdb/duckdb-1.4.5.tar.gz

fail() { echo "ERROR: $*" >&2; exit 1; }

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	elif command -v shasum   >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
	elif command -v sha256   >/dev/null 2>&1; then sha256 -q "$1"
	else fail "no SHA-256 tool found; install sha256sum, shasum, or sha256"; fi
}

[[ -f "${archive}" ]] || fail "DuckDB source archive is missing: ${archive}"

first_line=
IFS= read -r first_line < "${archive}" || true
if [[ "${first_line}" == 'version https://git-lfs.github.com/spec/v1' ]]; then
	cat >&2 <<EOF
ERROR: ${archive} is an unfetched git LFS pointer, not the source archive.

This tree stores the DuckDB source via git LFS. Install git-lfs and fetch it:

    git lfs install
    git lfs pull --include "${lfs_path}"

In CI, add 'lfs: true' to the actions/checkout step of the workflow.
EOF
	exit 1
fi

[[ -f "${checksum_file}" ]] || fail "checksum file is missing: ${checksum_file}"
expected=$(awk '{print $1; exit}' "${checksum_file}")
actual=$(sha256_file "${archive}")
[[ "${expected}" == "${actual}" ]] || \
	fail "SHA-256 mismatch for ${archive}: expected ${expected}, got ${actual}"

# awk waits for the complete listing before printing the first entry's root.
# This keeps tar's exit status meaningful: truncated or otherwise corrupt
# streams must fail verification even if their first member was readable.
if ! root=$(tar -tzf "${archive}" | awk -F/ 'NR == 1 { root = $1 } END { print root }'); then
	fail "cannot read complete archive listing: ${archive}"
fi
[[ "${root}" == "${required_root}" ]] || \
	fail "unexpected archive root '${root}', expected '${required_root}'"

echo "OK: ${archive} verified (sha256 ${actual}, root ${root}/)"
