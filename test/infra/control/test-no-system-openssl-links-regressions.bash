#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
audit_script=${OPENSSL_AUDIT_SCRIPT:-${script_dir}/test-no-system-openssl-links.bash}

# Git hooks in linked worktrees export GIT_DIR for the caller repository.
# Clear every repository-local Git variable before creating fixture repositories,
# otherwise `git -C "${fixture}"` can commit to the branch being pushed.
while IFS= read -r git_local_env; do
	unset "${git_local_env}"
done < <(git rev-parse --local-env-vars)

tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

audit_path="${tmp_dir}/audit-bin"
mkdir -p "${audit_path}"
for tool in bash dirname git grep mktemp rm sort; do
	tool_path=$(command -v "${tool}") || fail "required test tool is unavailable: ${tool}"
	ln -s "${tool_path}" "${audit_path}/${tool}"
done

assert_rejected() {
	local name=$1
	local contents=$2
	local fixture="${tmp_dir}/${name}"

	mkdir -p "${fixture}"
	printf '%s\n' "${contents}" > "${fixture}/build.mk"
	git -C "${fixture}" init -q
	git -C "${fixture}" add build.mk
	git -C "${fixture}" -c user.email=test@example.invalid -c user.name=test commit -qm fixture

	if PATH="${audit_path}" OPENSSL_AUDIT_ROOT="${fixture}" \
		"${audit_script}" >/dev/null 2>&1; then
		fail "audit accepted ${name}"
	fi
}

assert_accepted() {
	local name=$1
	local contents=$2
	local fixture="${tmp_dir}/${name}"

	mkdir -p "${fixture}"
	printf '%s\n' "${contents}" > "${fixture}/build.mk"
	git -C "${fixture}" init -q
	git -C "${fixture}" add build.mk
	git -C "${fixture}" -c user.email=test@example.invalid -c user.name=test commit -qm fixture

	if ! PATH="${audit_path}" OPENSSL_AUDIT_ROOT="${fixture}" \
		"${audit_script}" >/dev/null 2>&1; then
		fail "audit rejected ${name}"
	fi
}

assert_rejected compact_assignment 'OPENSSL_LIBS=-lssl -lcrypto'
assert_rejected forwarded_selector 'LDFLAGS=-Wl,-z,defs,-lssl'
assert_rejected forwarded_filename 'LDFLAGS=-Wl,-l:libssl.a'
assert_rejected forwarded_split_ssl 'LDFLAGS=-Wl,-l,ssl'
assert_rejected forwarded_split_crypto 'LDFLAGS=-Wl,-l,crypto'
assert_rejected xlinker_split_ssl 'LDFLAGS=-Xlinker -l -Xlinker ssl'
assert_rejected xlinker_split_crypto_equals 'LDFLAGS=-Xlinker=-l -Xlinker=crypto'
assert_rejected linker_filename 'LDLIBS=-l:libcrypto.a'
assert_rejected system_library_path 'OPENSSL_LIB=/usr/lib/x86_64-linux-gnu/libssl.so.3'
assert_rejected lib64_ssl_archive_path 'OPENSSL_LIB=/lib64/libssl.a'
assert_rejected lib64_crypto_shared_path 'OPENSSL_LIB=/lib64/libcrypto.so.3'
assert_rejected triplet_ssl_shared_path 'OPENSSL_LIB=/lib/x86_64-linux-gnu/libssl.so'
assert_rejected triplet_crypto_archive_path 'OPENSSL_LIB=/lib/aarch64-linux-gnu/libcrypto.a'
assert_rejected darwin_system_library_path 'OPENSSL_LIB=/usr/lib/libssl.dylib'
assert_rejected homebrew_system_library_path 'OPENSSL_LIB=/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib'
assert_rejected intel_homebrew_opt_path 'OPENSSL_LIB=/usr/local/opt/openssl@3/lib/libssl.dylib'
assert_rejected intel_homebrew_cellar_path 'OPENSSL_LIB=/usr/local/Cellar/openssl@3/3.5.7/lib/libcrypto.dylib'
assert_rejected arm_homebrew_cellar_ssl_path 'OPENSSL_LIB=/opt/homebrew/Cellar/openssl@3/3.5.7/lib/libssl.dylib'
assert_rejected arm_homebrew_cellar_crypto_path 'OPENSSL_LIB=/opt/homebrew/Cellar/openssl@3/3.5.7/lib/libcrypto.dylib'
assert_rejected intel_homebrew_opt_versioned_path 'OPENSSL_LIB=/usr/local/opt/openssl@3/lib/libssl.3.dylib'
assert_rejected arm_homebrew_cellar_versioned_path 'OPENSSL_LIB=/opt/homebrew/Cellar/openssl@3/3.5.7/lib/libcrypto.3.dylib'
assert_rejected darwin_system_versioned_path 'OPENSSL_LIB=/usr/lib/libssl.3.dylib'

# Fixtures intentionally contain Make expressions.
# shellcheck disable=SC2016
assert_accepted vendored_archive_paths \
	'OPENSSL_LIBS=$(THIRD_PARTY)/libssl/openssl/libssl.a $(THIRD_PARTY)/libssl/openssl/libcrypto.a'
# shellcheck disable=SC2016
assert_accepted vendored_search_path \
	'LDFLAGS=-L$(THIRD_PARTY)/libssl/openssl'

if [[ -z ${OPENSSL_AUDIT_MUTATION_CHECK:-} ]]; then
	mutated_audit="${tmp_dir}/overbroad-openssl-audit.bash"
	cp "${audit_script}" "${mutated_audit}"
	python3 - "${mutated_audit}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
needle = 'pattern="'
if needle not in text:
    raise SystemExit("audit pattern assignment was not found")
path.write_text(text.replace(needle, 'pattern="libssl[.]a|', 1))
PY
	if OPENSSL_AUDIT_SCRIPT="${mutated_audit}" OPENSSL_AUDIT_MUTATION_CHECK=1 \
			"${BASH_SOURCE[0]}" >/dev/null 2>&1; then
		fail "positive fixtures did not reject an over-broad audit pattern"
	fi
fi

echo "System OpenSSL audit regression tests passed"
