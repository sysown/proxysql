#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
subject="${repo_root}/deps/libssl/verify-source.bash"
production_archive="${repo_root}/deps/libssl/openssl-3.5.7.tar.gz"
production_checksum="${production_archive}.sha256"

if [[ ! -x "${subject}" ]]; then
	echo "ERROR: vendored OpenSSL source verifier is missing or not executable: ${subject}" >&2
	exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

tests_run=0

sha256_file() {
	local path=$1
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "${path}" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "${path}" | awk '{print $1}'
	else
		sha256 -q "${path}"
	fi
}

write_checksum() {
	local archive=$1
	local checksum=$2
	local recorded_name=${3:-$(basename -- "${archive}")}
	printf '%s  %s\n' "$(sha256_file "${archive}")" "${recorded_name}" > "${checksum}"
}

make_fixture_archive() {
	local case_dir=$1
	local root_name=$2
	mkdir -p "${case_dir}/source/${root_name}"
	printf '%s\n' '#!/usr/bin/env perl' > "${case_dir}/source/${root_name}/Configure"
	tar -C "${case_dir}/source" -czf "${case_dir}/openssl-3.5.7.tar.gz" "${root_name}"
	write_checksum \
		"${case_dir}/openssl-3.5.7.tar.gz" \
		"${case_dir}/openssl-3.5.7.tar.gz.sha256"
}

make_unsafe_archive() {
	local case_dir=$1
	local member_name=$2
	mkdir -p "${case_dir}"
	python3 - "${case_dir}/openssl-3.5.7.tar.gz" "${member_name}" <<'PY'
import io
import sys
import tarfile

archive, member_name = sys.argv[1:]
payload = b"unsafe fixture\n"
with tarfile.open(archive, "w:gz") as output:
    member = tarfile.TarInfo(member_name)
    member.size = len(payload)
    output.addfile(member, io.BytesIO(payload))
PY
	write_checksum \
		"${case_dir}/openssl-3.5.7.tar.gz" \
		"${case_dir}/openssl-3.5.7.tar.gz.sha256"
}

expect_failure() {
	local name=$1
	local expected=$2
	shift 2
	local output

	tests_run=$((tests_run + 1))
	if output=$("${subject}" "$@" 2>&1); then
		echo "not ok ${tests_run} - ${name}: verifier unexpectedly succeeded" >&2
		exit 1
	fi
	if [[ "${output}" != *"${expected}"* ]]; then
		echo "not ok ${tests_run} - ${name}: expected diagnostic containing '${expected}'" >&2
		printf '%s\n' "${output}" >&2
		exit 1
	fi
	echo "ok ${tests_run} - ${name}"
}

expect_success() {
	local name=$1
	shift
	local output

	tests_run=$((tests_run + 1))
	if ! output=$("${subject}" "$@" 2>&1); then
		echo "not ok ${tests_run} - ${name}: verifier failed" >&2
		printf '%s\n' "${output}" >&2
		exit 1
	fi
	echo "ok ${tests_run} - ${name}"
}

missing_dir="${tmp_dir}/missing"
mkdir -p "${missing_dir}"
expect_failure \
	"missing archive is rejected" \
	"source archive is missing" \
	"${missing_dir}/openssl-3.5.7.tar.gz" \
	"${missing_dir}/openssl-3.5.7.tar.gz.sha256"

pointer_dir="${tmp_dir}/pointer"
mkdir -p "${pointer_dir}"
printf '%s\n' \
	'version https://git-lfs.github.com/spec/v1' \
	'oid sha256:a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8' \
	'size 53800000' \
	> "${pointer_dir}/openssl-3.5.7.tar.gz"
printf '%s  %s\n' \
	a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8 \
	openssl-3.5.7.tar.gz \
	> "${pointer_dir}/openssl-3.5.7.tar.gz.sha256"
expect_failure \
	"unhydrated LFS pointer is rejected with recovery" \
	"git lfs pull --include=deps/libssl/openssl-3.5.7.tar.gz" \
	"${pointer_dir}/openssl-3.5.7.tar.gz" \
	"${pointer_dir}/openssl-3.5.7.tar.gz.sha256"

missing_checksum_dir="${tmp_dir}/missing-checksum"
make_fixture_archive "${missing_checksum_dir}" openssl-3.5.7
rm "${missing_checksum_dir}/openssl-3.5.7.tar.gz.sha256"
expect_failure \
	"missing checksum file is rejected" \
	"checksum file is missing" \
	"${missing_checksum_dir}/openssl-3.5.7.tar.gz" \
	"${missing_checksum_dir}/openssl-3.5.7.tar.gz.sha256"

corrupt_dir="${tmp_dir}/corrupt"
make_fixture_archive "${corrupt_dir}" openssl-3.5.7
printf '%s\n' 'corruption' >> "${corrupt_dir}/openssl-3.5.7.tar.gz"
expect_failure \
	"corrupt archive is rejected before extraction" \
	"SHA-256 mismatch" \
	"${corrupt_dir}/openssl-3.5.7.tar.gz" \
	"${corrupt_dir}/openssl-3.5.7.tar.gz.sha256"

invalid_gzip_dir="${tmp_dir}/invalid-gzip"
mkdir -p "${invalid_gzip_dir}"
printf '%s\n' 'not gzip data' > "${invalid_gzip_dir}/openssl-3.5.7.tar.gz"
write_checksum \
	"${invalid_gzip_dir}/openssl-3.5.7.tar.gz" \
	"${invalid_gzip_dir}/openssl-3.5.7.tar.gz.sha256"
expect_failure \
	"invalid gzip with a matching checksum is rejected" \
	"not valid gzip data" \
	"${invalid_gzip_dir}/openssl-3.5.7.tar.gz" \
	"${invalid_gzip_dir}/openssl-3.5.7.tar.gz.sha256"

wrong_name_dir="${tmp_dir}/wrong-checksum-name"
make_fixture_archive "${wrong_name_dir}" openssl-3.5.7
write_checksum \
	"${wrong_name_dir}/openssl-3.5.7.tar.gz" \
	"${wrong_name_dir}/openssl-3.5.7.tar.gz.sha256" \
	wrong-source.tar.gz
expect_failure \
	"checksum filename mismatch is rejected" \
	"checksum entry names 'wrong-source.tar.gz'" \
	"${wrong_name_dir}/openssl-3.5.7.tar.gz" \
	"${wrong_name_dir}/openssl-3.5.7.tar.gz.sha256"

traversal_dir="${tmp_dir}/traversal"
make_unsafe_archive "${traversal_dir}" ../escape
expect_failure \
	"parent traversal archive member is rejected" \
	"unsafe archive member '../escape'" \
	"${traversal_dir}/openssl-3.5.7.tar.gz" \
	"${traversal_dir}/openssl-3.5.7.tar.gz.sha256"

absolute_dir="${tmp_dir}/absolute"
make_unsafe_archive "${absolute_dir}" /absolute/escape
expect_failure \
	"absolute archive member is rejected" \
	"unsafe archive member '/absolute/escape'" \
	"${absolute_dir}/openssl-3.5.7.tar.gz" \
	"${absolute_dir}/openssl-3.5.7.tar.gz.sha256"

wrong_root_dir="${tmp_dir}/wrong-root"
make_fixture_archive "${wrong_root_dir}" openssl-wrong-root
expect_failure \
	"wrong top-level directory is rejected" \
	"outside required root 'openssl-3.5.7/'" \
	"${wrong_root_dir}/openssl-3.5.7.tar.gz" \
	"${wrong_root_dir}/openssl-3.5.7.tar.gz.sha256"

missing_configure_dir="${tmp_dir}/missing-configure"
mkdir -p "${missing_configure_dir}/source/openssl-3.5.7"
printf '%s\n' 'fixture without Configure' \
	> "${missing_configure_dir}/source/openssl-3.5.7/README.md"
tar -C "${missing_configure_dir}/source" \
	-czf "${missing_configure_dir}/openssl-3.5.7.tar.gz" openssl-3.5.7
write_checksum \
	"${missing_configure_dir}/openssl-3.5.7.tar.gz" \
	"${missing_configure_dir}/openssl-3.5.7.tar.gz.sha256"
expect_failure \
	"archive without Configure is rejected" \
	"does not contain openssl-3.5.7/Configure" \
	"${missing_configure_dir}/openssl-3.5.7.tar.gz" \
	"${missing_configure_dir}/openssl-3.5.7.tar.gz.sha256"

valid_dir="${tmp_dir}/valid"
make_fixture_archive "${valid_dir}" openssl-3.5.7
expect_success \
	"valid fixture archive is accepted" \
	"${valid_dir}/openssl-3.5.7.tar.gz" \
	"${valid_dir}/openssl-3.5.7.tar.gz.sha256"

expect_success \
	"one-argument mode uses the adjacent checksum file" \
	"${valid_dir}/openssl-3.5.7.tar.gz"

expect_success \
	"production OpenSSL archive is accepted" \
	"${production_archive}" \
	"${production_checksum}"

printf '1..%d\n' "${tests_run}"
