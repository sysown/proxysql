#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

assert_match() {
	local file=$1
	local pattern=$2
	local description=$3

	rg -q -- "${pattern}" "${repo_root}/${file}" || \
		fail "${description}: expected pattern '${pattern}' in ${file}"
}

assert_no_match() {
	local file=$1
	local pattern=$2
	local description=$3

	if rg -n -- "${pattern}" "${repo_root}/${file}"; then
		fail "${description}: forbidden pattern '${pattern}' in ${file}"
	fi
}

deb_control=docker/images/proxysql/deb-compliant/ctl/proxysql.ctl
rhel_spec=docker/images/proxysql/rhel-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec
suse_spec=docker/images/proxysql/suse-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec
tarball_entrypoint=docker/images/proxysql/tarball-compliant/entrypoint/entrypoint.bash
tarball_test=tools/test-tarball-runtime.sh

assert_match "${deb_control}" '^Depends:.*libgnutls' \
	'Debian package must retain its GnuTLS runtime dependency'
assert_no_match "${deb_control}" '(^|[[:space:],|])libssl([[:space:],|(]|$)' \
	'Debian package must not require shared OpenSSL'

for spec in "${rhel_spec}" "${suse_spec}"; do
	assert_match "${spec}" '^Requires:[[:space:]]+gnutls([[:space:]]|$)' \
		'RPM package must retain its GnuTLS runtime dependency'
	assert_no_match "${spec}" '^Requires:.*openssl' \
		'RPM package must not require shared OpenSSL'
done

assert_no_match "${tarball_entrypoint}" \
	'bundle_runtime_library[[:space:]]+lib(ssl|crypto)' \
	'tarball assembly must not bundle OpenSSL shared libraries'
assert_no_match "${tarball_entrypoint}" 'lib(ssl|crypto)\.so' \
	'tarball assembly must not name OpenSSL shared libraries'

assert_match "${tarball_test}" 'check_runtime_linkage' \
	'tarball smoke test must inspect executable and plugin linkage'
assert_match "${tarball_test}" 'forbidden OpenSSL runtime dependency' \
	'tarball smoke test must reject dynamic OpenSSL'
assert_match "${tarball_test}" 'lib/proxysql' \
	'tarball smoke test must inspect packaged plugins'
assert_no_match "${tarball_test}" 'did not resolve from the tarball' \
	'tarball smoke test must not expect bundled OpenSSL'

echo 'OpenSSL package contract passed'
