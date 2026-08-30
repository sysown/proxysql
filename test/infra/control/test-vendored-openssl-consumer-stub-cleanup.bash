#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
consumer_test="${script_dir}/test-vendored-openssl-consumers.bash"
fake_make="${script_dir}/fixtures/mark-consumer-stub-and-fail-make.bash"
tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

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
