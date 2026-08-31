#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
consumer_test="${script_dir}/test-vendored-openssl-consumers.bash"
fake_make="${script_dir}/fixtures/mark-consumer-stub-and-fail-make.bash"
tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

build_contract="${script_dir}/test-vendored-openssl-build-contract.bash"
contract_fixture="${tmp_dir}/build-contract-fixture"
mkdir -p \
	"${contract_fixture}/common_mk" \
	"${contract_fixture}/deps/libssl" \
	"${contract_fixture}/include" \
	"${contract_fixture}/src" \
	"${contract_fixture}/test/deps/mariadb-connector-c"
cp "${repo_root}/common_mk/openssl_flags.mk" "${contract_fixture}/common_mk/"
cp "${repo_root}/deps/Makefile" "${contract_fixture}/deps/"
cp "${repo_root}/include/makefiles_vars.mk" \
	"${repo_root}/include/makefiles_paths.mk" "${contract_fixture}/include/"
cp "${repo_root}/test/deps/Makefile" "${contract_fixture}/test/deps/"
: > "${contract_fixture}/src/proxysql_global.cpp"
: > "${contract_fixture}/deps/libssl/openssl-3.5.7.tar.gz"
: > "${contract_fixture}/deps/libssl/openssl-3.5.7.tar.gz.sha256"
: > "${contract_fixture}/deps/libssl/verify-source.bash"
ln -s openssl-3.5.7 "${contract_fixture}/deps/libssl/openssl"
ln -s mariadb-connector-c-3.1.9 \
	"${contract_fixture}/test/deps/mariadb-connector-c/mariadb-connector-c"

if ! contract_output=$(OPENSSL_BUILD_CONTRACT_ROOT="${contract_fixture}" \
		"${build_contract}" 2>&1); then
	printf '%s\n' "${contract_output}" >&2
	fail "build contract failed against a fresh checkout with dangling dependency symlinks"
fi

fixture_script="${tmp_dir}/test/infra/control/test-vendored-openssl-consumers.bash"
mkdir -p "$(dirname -- "${fixture_script}")" "${tmp_dir}/bin"
cp "${consumer_test}" "${fixture_script}"

marker="${tmp_dir}/test/deps/mariadb-connector-c/mariadb-connector-c-3.1.9/.keep"
cp "${fake_make}" "${tmp_dir}/bin/make"

if PATH="${tmp_dir}/bin:${PATH}" CONSUMER_STUB_MARKER="${marker}" \
	"${fixture_script}" >/dev/null 2>&1; then
	fail "consumer contract fixture unexpectedly passed"
fi

[[ -f "${marker}" ]] || fail "consumer stub cleanup removed a non-empty test directory"

echo "Vendored OpenSSL consumer stub cleanup regression tests passed"
