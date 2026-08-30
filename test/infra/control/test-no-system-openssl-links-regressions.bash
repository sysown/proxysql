#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
audit_script="${script_dir}/test-no-system-openssl-links.bash"
tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

assert_rejected() {
	local name=$1
	local contents=$2
	local fixture="${tmp_dir}/${name}"

	mkdir -p "${fixture}"
	printf '%s\n' "${contents}" > "${fixture}/build.mk"
	git -C "${fixture}" init -q
	git -C "${fixture}" add build.mk
	git -C "${fixture}" -c user.email=test@example.invalid -c user.name=test commit -qm fixture

	if OPENSSL_AUDIT_ROOT="${fixture}" "${audit_script}" >/dev/null 2>&1; then
		fail "audit accepted ${name}"
	fi
}

assert_rejected compact_assignment 'OPENSSL_LIBS=-lssl -lcrypto'
assert_rejected forwarded_selector 'LDFLAGS=-Wl,-z,defs,-lssl'
assert_rejected forwarded_filename 'LDFLAGS=-Wl,-l:libssl.a'
assert_rejected linker_filename 'LDLIBS=-l:libcrypto.a'
assert_rejected system_library_path 'OPENSSL_LIB=/usr/lib/x86_64-linux-gnu/libssl.so.3'

echo "System OpenSSL audit regression tests passed"
