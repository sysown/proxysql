#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
archive=${1:-"${script_dir}/openssl-3.5.7.tar.gz"}
if [[ $# -ge 2 ]]; then
	checksum_file=$2
elif [[ $# -eq 1 ]]; then
	checksum_file="${archive}.sha256"
else
	checksum_file="${script_dir}/openssl-3.5.7.tar.gz.sha256"
fi
archive_name=$(basename -- "${archive}")
required_root=openssl-3.5.7
lfs_path=deps/libssl/openssl-3.5.7.tar.gz

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

sha256_file() {
	local path=$1
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "${path}" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "${path}" | awk '{print $1}'
	elif command -v sha256 >/dev/null 2>&1; then
		sha256 -q "${path}"
	else
		fail "no SHA-256 tool found; install sha256sum, shasum, or sha256"
	fi
}

[[ -f "${archive}" ]] || fail "OpenSSL source archive is missing: ${archive}"

first_line=
IFS= read -r first_line < "${archive}" || true
if [[ "${first_line}" == 'version https://git-lfs.github.com/spec/v1' ]]; then
	cat >&2 <<EOF
ERROR: OpenSSL source archive is an unhydrated Git LFS pointer: ${archive}
Hydrate the vendored source with:
  git lfs pull --include=${lfs_path}
EOF
	exit 1
fi

[[ -f "${checksum_file}" ]] || fail "OpenSSL checksum file is missing: ${checksum_file}"

checksum_entries=$(awk 'NF { count++ } END { print count + 0 }' "${checksum_file}")
[[ "${checksum_entries}" == 1 ]] || \
	fail "checksum file must contain exactly one non-empty entry: ${checksum_file}"

expected=
recorded_name=
extra=
while read -r expected recorded_name extra; do
	[[ -n "${expected}" ]] || continue
	break
done < "${checksum_file}"

[[ "${expected}" =~ ^[[:xdigit:]]{64}$ ]] || \
	fail "checksum file does not start with a 64-character SHA-256: ${checksum_file}"
recorded_name=${recorded_name#\*}
[[ -n "${recorded_name}" ]] || fail "checksum file does not name an archive: ${checksum_file}"
[[ -z "${extra}" ]] || fail "checksum file entry has unexpected fields: ${checksum_file}"
[[ "${recorded_name}" == "${archive_name}" ]] || \
	fail "checksum entry names '${recorded_name}', expected '${archive_name}'"

actual=$(sha256_file "${archive}")
actual=$(printf '%s' "${actual}" | tr '[:upper:]' '[:lower:]')
expected=$(printf '%s' "${expected}" | tr '[:upper:]' '[:lower:]')
if [[ "${actual}" != "${expected}" ]]; then
	cat >&2 <<EOF
ERROR: OpenSSL source archive SHA-256 mismatch: ${archive}
Expected: ${expected}
Actual:   ${actual}
EOF
	exit 1
fi

gzip -t "${archive}" 2>/dev/null || fail "OpenSSL source archive is not valid gzip data: ${archive}"

if ! members=$(tar -tzf "${archive}" 2>/dev/null); then
	fail "OpenSSL source archive cannot be listed: ${archive}"
fi

found_configure=0
while IFS= read -r member; do
	[[ -n "${member}" ]] || continue
	case "${member}" in
		/*|../*|*/../*|*/..)
			fail "unsafe archive member '${member}'"
			;;
	esac
	case "${member}" in
		"${required_root}"|"${required_root}/"|"${required_root}/"*)
			;;
		*)
			fail "archive member '${member}' is outside required root '${required_root}/'"
			;;
	esac
	if [[ "${member}" == "${required_root}/Configure" ]]; then
		found_configure=1
	fi
done <<< "${members}"

[[ "${found_configure}" == 1 ]] || \
	fail "OpenSSL source archive does not contain ${required_root}/Configure"

echo "Verified ${archive_name}: ${actual}"
