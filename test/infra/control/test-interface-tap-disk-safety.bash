#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
validator="${repo_root}/test/infra/control/validate-interface-tap-disk-safety.bash"

fail() {
	echo "interface TAP disk-safety contract: FAIL: $*" >&2
	exit 1
}

[[ -x "${validator}" ]] || fail "${validator} must exist and be executable"

fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT
mkdir -p "${fixture}/bin" "${fixture}/test/infra/control"
cp "${validator}" "${fixture}/test/infra/control/validate-interface-tap-disk-safety.bash"

for command in env bash dirname grep; do
	ln -s "$(command -v "${command}")" "${fixture}/bin/${command}"
done

# Deliberately omit the TAP source. A missing input is an operational error,
# not evidence that the source contains no forbidden command.
if PATH="${fixture}/bin" "${fixture}/test/infra/control/validate-interface-tap-disk-safety.bash" \
	>"${fixture}/stdout" 2>"${fixture}/stderr"; then
	fail "validator must fail when the TAP source is missing"
fi

grep -Fq "unable to read" "${fixture}/stderr" \
	|| fail "missing TAP source must be reported as unreadable"

mkdir -p "${fixture}/test/tap/tests"
printf '%s\n' 'SELECT 1;' > "${fixture}/test/tap/tests/mysql-server_version_by_interface-t.cpp"
if ! PATH="${fixture}/bin" "${fixture}/test/infra/control/validate-interface-tap-disk-safety.bash" \
	>"${fixture}/stdout" 2>"${fixture}/stderr"; then
	fail "validator must accept a clean TAP source without rg installed"
fi
[[ ! -s "${fixture}/stderr" ]] \
	|| fail "validator must not require rg"

echo "interface TAP disk-safety contract: OK"
