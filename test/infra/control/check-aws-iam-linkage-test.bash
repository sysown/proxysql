#!/usr/bin/env bash
# The single-quoted command bodies below are source for fake executables.
# shellcheck disable=SC2016

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
checker_source="$repo_root/test/infra/control/check-aws-iam-linkage.bash"
temporary_root=$(mktemp -d)
trap 'rm -rf -- "$temporary_root"' EXIT

pass_count=0

fail() {
	printf 'not ok - %s\n' "$*" >&2
	exit 1
}

pass() {
	pass_count=$((pass_count + 1))
	printf 'ok %d - %s\n' "$pass_count" "$1"
}

assert_contains() {
	local text=$1
	local expected=$2
	local description=$3
	if [[ $text != *"$expected"* ]]; then
		printf 'missing text: %s\noutput:\n%s\n' "$expected" "$text" >&2
		fail "$description"
	fi
}

assert_not_contains() {
	local text=$1
	local unexpected=$2
	local description=$3
	if [[ $text == *"$unexpected"* ]]; then
		printf 'unexpected text: %s\noutput:\n%s\n' "$unexpected" "$text" >&2
		fail "$description"
	fi
}

write_executable() {
	local path=$1
	shift
	printf '%s\n' "$@" >"$path"
	chmod +x "$path"
}

new_fixture() {
	local name=$1
	LINKAGE_TEST_PLATFORM=Linux
	LINKAGE_TEST_LINKS=required
	LINKAGE_TEST_SYMBOL=present
	LINKAGE_TEST_LICENSES=present
	LINKAGE_TEST_OWNERS=all
	LINKAGE_TEST_LINK_PREFIX=
	fixture="$temporary_root/$name/repository with spaces"
	fake_bin="$temporary_root/$name/fake tools"
	minimal_bin="$temporary_root/$name/minimal tools"
	license_file="$temporary_root/$name/package docs/LICENSE.txt"
	notice_file="$temporary_root/$name/package docs/NOTICE.txt"
	fixture_binary="$fixture/bin/proxysql feature \$(not executed) -- binary"
	mkdir -p "$fixture/test/infra/control" "$fixture/build/aws-sdk-cpp" "$fixture/bin" \
		"$fake_bin" "$minimal_bin" "$(dirname "$license_file")"
	for tool in bash dirname grep sed tr; do
		ln -s "$(command -v "$tool")" "$minimal_bin/$tool"
	done
	cp "$checker_source" "$fixture/test/infra/control/check-aws-iam-linkage.bash"
	chmod +x "$fixture/test/infra/control/check-aws-iam-linkage.bash"
	printf 'Apache License\nVersion 2.0, January 2004\n' >"$license_file"
	printf 'AWS SDK for C++\nCopyright Amazon.com, Inc. or its affiliates.\n' >"$notice_file"
	printf '#!/usr/bin/env bash\nexit 0\n' >"$fixture_binary"
	chmod +x "$fixture_binary"

	write_executable "$fake_bin/uname" \
		'#!/usr/bin/env bash' \
		'printf "%s\\n" "${LINKAGE_TEST_PLATFORM:-Linux}"'
	write_executable "$fake_bin/ldd" \
		'#!/usr/bin/env bash' \
		'case ${LINKAGE_TEST_LINKS:-required} in' \
		'  required) printf "%s\\n" "libaws-cpp-sdk-rds.so => /system/lib/libaws-cpp-sdk-rds.so" "libaws-cpp-sdk-core.so => /system/lib/libaws-cpp-sdk-core.so" ;;' \
		'  unrelated) printf "%s\\n" "libaws-cpp-sdk-rds.so => /system/lib/libaws-cpp-sdk-rds.so" "libaws-cpp-sdk-core.so => /system/lib/libaws-cpp-sdk-core.so" "libaws-cpp-sdk-s3.so => /system/lib/libaws-cpp-sdk-s3.so" ;;' \
		'  none) printf "%s\\n" "libpthread.so => /system/lib/libpthread.so" ;;' \
		'  unresolved) printf "%s\\n" "libaws-cpp-sdk-rds.so => not found" "libaws-cpp-sdk-core.so => /system/lib/libaws-cpp-sdk-core.so" ;;' \
		'esac'
	write_executable "$fake_bin/otool" \
		'#!/usr/bin/env bash' \
		'prefix=${LINKAGE_TEST_LINK_PREFIX:-/system/lib}' \
		'printf "%s\\n" "$2:" "$prefix/libaws-cpp-sdk-rds.dylib" "$prefix/libaws-cpp-sdk-core.dylib"'
	write_executable "$fake_bin/nm" \
		'#!/usr/bin/env bash' \
		'if [[ ${LINKAGE_TEST_SYMBOL:-present} == present ]]; then' \
		'  printf "%s\\n" "00000000 T Aws::RDS::RDSClient::GenerateConnectAuthToken(char const*, char const*, unsigned int, char const*)"' \
		'fi'
	write_executable "$fake_bin/dpkg-query" \
		'#!/usr/bin/env bash' \
		'case $1 in' \
		'  -S) if [[ ${LINKAGE_TEST_OWNERS:-all} == all || $3 == *core* ]]; then printf "%s\\n" "libaws-sdk-cpp-dev: $3"; fi ;;' \
		'  -L) if [[ ${LINKAGE_TEST_LICENSES:-present} == present ]]; then printf "%s\\n" "$LINKAGE_TEST_LICENSE_FILE" "$LINKAGE_TEST_NOTICE_FILE"; fi ;;' \
		'  -W) printf "%s\\n" "libaws-sdk-cpp-dev" ;;' \
		'  *) exit 2 ;;' \
		'esac'
}

write_metadata() {
	local shared=$1
	local version=${2:-1.11.321}
	local libraries=${3:-"'-laws-cpp-sdk-rds' '-laws-cpp-sdk-core'"}
	printf '%s\n' \
		"AWS_IAM_CPPFLAGS := '-I/system/include'" \
		"AWS_IAM_LDFLAGS := '-L/system/lib'" \
		"AWS_IAM_LIBS := $libraries" \
		"AWS_IAM_SDK_VERSION := \"$version\"" \
		"AWS_IAM_SDK_SHARED := \"$shared\"" \
		'AWS_IAM_DISCOVERY_ID := fixture' \
		>"$fixture/build/aws-sdk-cpp/aws-sdk-cpp.mk"
	printf '%s\n' 'enabled:fixture' >"$fixture/build/aws-sdk-cpp/build-mode"
	touch "$fixture_binary"
}

run_checker() {
	PATH="$fake_bin:$minimal_bin" \
	LINKAGE_TEST_PLATFORM=${LINKAGE_TEST_PLATFORM:-Linux} \
	LINKAGE_TEST_LINKS=${LINKAGE_TEST_LINKS:-required} \
	LINKAGE_TEST_SYMBOL=${LINKAGE_TEST_SYMBOL:-present} \
	LINKAGE_TEST_LICENSES=${LINKAGE_TEST_LICENSES:-present} \
	LINKAGE_TEST_OWNERS=${LINKAGE_TEST_OWNERS:-all} \
	LINKAGE_TEST_LINK_PREFIX=${LINKAGE_TEST_LINK_PREFIX:-} \
	LINKAGE_TEST_LICENSE_FILE="$license_file" \
	LINKAGE_TEST_NOTICE_FILE="$notice_file" \
	AWS_SECRET_ACCESS_KEY='must-not-appear-in-linkage-output' \
		"$fixture/test/infra/control/check-aws-iam-linkage.bash" \
		"$fixture_binary" 2>&1
}

printf '1..25\n'

new_fixture shared_linux
write_metadata 1
output=$(run_checker) || fail 'shared Linux release linkage is accepted'
assert_contains "$output" 'AWS SDK for C++ version: 1.11.321' 'shared Linux reports the discovered SDK version'
assert_contains "$output" 'shared release linkage: verified' 'shared Linux release linkage is accepted'
assert_not_contains "$output" 'must-not-appear-in-linkage-output' 'shared Linux output never dumps credential environment values'
pass 'shared Linux linkage, package ownership, and redacted output'

new_fixture shared_darwin
write_metadata 1
LINKAGE_TEST_PLATFORM=Darwin output=$(run_checker) || fail 'shared Darwin release linkage is accepted'
assert_contains "$output" 'shared release linkage: verified' 'otool shared branch succeeds'
pass 'Darwin otool linkage branch'

new_fixture static_linux
write_metadata 0
output=$(run_checker) || fail 'static development linkage is accepted'
assert_contains "$output" 'static development linkage: verified' 'static branch verifies the final symbol'
assert_contains "$output" 'dynamic linkage remains required for the release-package job' 'static branch preserves the release warning'
pass 'static metadata and final-symbol branch'

new_fixture unexpected_metadata_service
write_metadata 0 1.11.321 "'-laws-cpp-sdk-rds' '-laws-cpp-sdk-core' '-laws-cpp-sdk-s3'"
if output=$(run_checker); then fail 'unrelated metadata service library is rejected'; fi
assert_contains "$output" 'unexpected AWS service library: aws-cpp-sdk-s3' 'unrelated metadata library diagnostic is precise'
pass 'unrelated metadata service rejection'

new_fixture unexpected_dynamic_service
write_metadata 1
LINKAGE_TEST_LINKS=unrelated
if output=$(run_checker); then fail 'unrelated dynamic service library is rejected'; fi
assert_contains "$output" 'unexpected AWS service library: aws-cpp-sdk-s3' 'unrelated dynamic library diagnostic is precise'
pass 'unrelated dynamic service rejection'

new_fixture old_sdk
write_metadata 1 1.8.999
if output=$(run_checker); then fail 'AWS SDK older than 1.9 is rejected'; fi
assert_contains "$output" 'AWS SDK for C++ 1.9 or newer is required' 'minimum SDK diagnostic is precise'
pass 'minimum AWS SDK version gate'

new_fixture minimum_sdk
write_metadata 1 1.9.0
output=$(run_checker) || fail 'minimum AWS SDK version is accepted'
assert_contains "$output" 'AWS SDK for C++ version: 1.9.0' 'minimum version is reported'
pass 'minimum accepted SDK version'

new_fixture next_major_sdk
write_metadata 1 2.0.0
output=$(run_checker) || fail 'a newer AWS SDK major version is accepted'
assert_contains "$output" 'AWS SDK for C++ version: 2.0.0' 'newer major version is reported'
pass 'newer SDK major version'

new_fixture semver_build_suffix
write_metadata 1 1.11.862+system.1
output=$(run_checker) || fail 'a valid SemVer build suffix is accepted'
assert_contains "$output" 'AWS SDK for C++ version: 1.11.862+system.1' 'SemVer build suffix is reported'
pass 'SDK SemVer build suffix'

new_fixture malformed_sdk
write_metadata 1 latest
if output=$(run_checker); then fail 'malformed SDK version is rejected'; fi
assert_contains "$output" 'invalid AWS SDK version in discovery metadata' 'malformed version diagnostic is precise'
pass 'malformed SDK version rejection'

new_fixture no_dynamic_aws
write_metadata 1
LINKAGE_TEST_LINKS=none
if output=$(run_checker); then fail 'shared metadata without linked SDK DSOs is rejected'; fi
assert_contains "$output" 'required shared AWS SDK libraries were not both linked' 'missing DSO diagnostic is precise'
pass 'feature-off/shared-link mismatch rejection'

new_fixture unresolved_dynamic_aws
write_metadata 1
LINKAGE_TEST_LINKS=unresolved
if output=$(run_checker); then fail 'an unresolved required AWS DSO is rejected'; fi
assert_contains "$output" 'AWS SDK shared library was not resolved' 'unresolved DSO diagnostic is precise'
pass 'unresolved shared-library rejection'

new_fixture partially_owned_dynamic_aws
write_metadata 1
LINKAGE_TEST_OWNERS=core-only
if output=$(run_checker); then fail 'one owned and one unowned AWS DSO is rejected'; fi
assert_contains "$output" 'resolved AWS SDK shared library has no system package owner' 'every linked DSO requires package ownership'
pass 'per-DSO package ownership gate'

new_fixture missing_license
write_metadata 1
LINKAGE_TEST_LICENSES=missing
if output=$(run_checker); then fail 'missing package license material is rejected'; fi
assert_contains "$output" 'package-owned Apache-2.0 LICENSE and NOTICE material was not found' 'license diagnostic is precise'
pass 'package license and notice gate'

new_fixture unrelated_package_material
write_metadata 1
write_executable "$fake_bin/dpkg-query" \
	'#!/usr/bin/env bash' \
	'case $1 in' \
	'  -S) printf "%s\\n" "aws-sdk-cpp-linked: $3" ;;' \
	'  -L) if [[ $2 == aws-sdk-cpp-unrelated ]]; then printf "%s\\n" "$LINKAGE_TEST_LICENSE_FILE" "$LINKAGE_TEST_NOTICE_FILE"; fi ;;' \
	'  -W) printf "%s\\n" aws-sdk-cpp-unrelated ;;' \
	'  *) exit 2 ;;' \
	'esac'
if output=$(run_checker); then fail 'legal files from an unrelated installed SDK package are rejected'; fi
assert_contains "$output" 'package-owned Apache-2.0 LICENSE and NOTICE material was not found' 'only linked-package ownership can satisfy the legal gate'
pass 'linked-package legal ownership binding'

new_fixture combined_legal_material
write_metadata 1
license_file="$temporary_root/combined_legal_material/package docs/LICENSE-NOTICE.txt"
printf 'Apache License\nVersion 2.0\nAWS SDK for C++\nCopyright Amazon.com, Inc.\n' >"$license_file"
write_executable "$fake_bin/dpkg-query" \
	'#!/usr/bin/env bash' \
	'case $1 in' \
	'  -S) printf "%s\\n" "libaws-sdk-cpp-dev: $3" ;;' \
	'  -L) printf "%s\\n" "$LINKAGE_TEST_LICENSE_FILE" ;;' \
	'  -W) printf "%s\\n" libaws-sdk-cpp-dev ;;' \
	'  *) exit 2 ;;' \
	'esac'
if output=$(run_checker); then fail 'one combined file cannot satisfy both legal-material records'; fi
assert_contains "$output" 'distinct package-owned Apache-2.0 LICENSE and NOTICE material was not found' 'LICENSE and NOTICE records must be distinct'
pass 'distinct LICENSE and NOTICE material gate'

new_fixture missing_static_symbol
write_metadata 0
LINKAGE_TEST_SYMBOL=missing
if output=$(run_checker); then fail 'missing static SDK symbol is rejected'; fi
assert_contains "$output" 'GenerateConnectAuthToken symbol was not found' 'static symbol diagnostic is precise'
pass 'static final-symbol gate'

new_fixture missing_metadata
if output=$(run_checker); then fail 'binary without IAM discovery metadata is rejected'; fi
assert_contains "$output" 'binary is not an AWS IAM-enabled build' 'SDK-free rejection is explicit'
pass 'SDK-free build rejection'

new_fixture outside_repository
write_metadata 1
outside_binary="$temporary_root/outside repository/proxysql"
mkdir -p "$(dirname "$outside_binary")"
printf '#!/usr/bin/env bash\nexit 0\n' >"$outside_binary"
chmod +x "$outside_binary"
fixture_binary=$outside_binary
if output=$(run_checker); then fail 'binary outside the metadata repository is rejected'; fi
assert_contains "$output" 'binary must be inside the repository being inspected' 'metadata cannot certify an unrelated binary'
pass 'binary and metadata repository binding'

new_fixture stale_feature_metadata
write_metadata 1
printf '%s\n' disabled >"$fixture/build/aws-sdk-cpp/build-mode"
if output=$(run_checker); then fail 'feature-off build with stale discovery metadata is rejected'; fi
assert_contains "$output" 'binary is not an AWS IAM-enabled build' 'feature-off mode stamp overrides stale metadata'
pass 'feature-off build with stale metadata rejection'

new_fixture older_binary
write_metadata 1
touch -t 202001010000 "$fixture_binary"
touch -t 202001010001 "$fixture/build/aws-sdk-cpp/aws-sdk-cpp.mk" \
	"$fixture/build/aws-sdk-cpp/build-mode"
if output=$(run_checker); then fail 'binary older than enabled discovery state is rejected'; fi
assert_contains "$output" 'binary predates the AWS IAM build metadata' 'enabled metadata cannot certify an older binary'
pass 'binary freshness binding'

new_fixture rpm_inventory
write_metadata 1
rm "$fake_bin/dpkg-query"
write_executable "$fake_bin/rpm" \
	'#!/usr/bin/env bash' \
	'if [[ $1 == -qf ]]; then printf "%s\\n" aws-sdk-cpp-libs; exit 0; fi' \
	'if [[ $1 == -qa ]]; then printf "%s\\n" aws-sdk-cpp-libs aws-sdk-cpp-devel unrelated-package; exit 0; fi' \
	'if [[ $1 == -ql ]]; then printf "%s\\n" "$LINKAGE_TEST_LICENSE_FILE" "$LINKAGE_TEST_NOTICE_FILE"; exit 0; fi' \
	'exit 2'
output=$(run_checker) || fail 'RPM-owned license and notice material is accepted'
assert_contains "$output" '(package aws-sdk-cpp-libs)' 'RPM package ownership is reported'
pass 'RPM ownership branch'

new_fixture brew_inventory
write_metadata 1
LINKAGE_TEST_PLATFORM=Darwin
LINKAGE_TEST_LINK_PREFIX=/opt/homebrew/opt/aws-sdk-cpp/lib
rm "$fake_bin/dpkg-query"
write_executable "$fake_bin/brew" \
	'#!/usr/bin/env bash' \
	'if [[ $1 == --prefix ]]; then printf "%s\\n" /opt/homebrew/opt/aws-sdk-cpp; exit 0; fi' \
	'if [[ $1 == list && ${2:-} == --versions ]]; then printf "%s\\n" "aws-sdk-cpp 1.11.321"; exit 0; fi' \
	'if [[ $1 == list ]]; then printf "%s\\n" "$LINKAGE_TEST_LICENSE_FILE" "$LINKAGE_TEST_NOTICE_FILE"; exit 0; fi' \
	'exit 2'
output=$(run_checker) || fail 'Homebrew-owned linkage and legal material are accepted'
assert_contains "$output" '(package aws-sdk-cpp)' 'Homebrew package ownership is reported'
pass 'Homebrew ownership branch'

new_fixture unrelated_brew_linkage
write_metadata 1
LINKAGE_TEST_PLATFORM=Darwin
LINKAGE_TEST_LINK_PREFIX=/unrelated/lib
rm "$fake_bin/dpkg-query"
write_executable "$fake_bin/brew" \
	'#!/usr/bin/env bash' \
	'if [[ $1 == --prefix ]]; then printf "%s\\n" /opt/homebrew/opt/aws-sdk-cpp; exit 0; fi' \
	'if [[ $1 == list && ${2:-} == --versions ]]; then printf "%s\\n" "aws-sdk-cpp 1.11.321"; exit 0; fi' \
	'if [[ $1 == list ]]; then printf "%s\\n" "$LINKAGE_TEST_LICENSE_FILE" "$LINKAGE_TEST_NOTICE_FILE"; exit 0; fi' \
	'exit 2'
if output=$(run_checker); then fail 'AWS dylibs outside the Homebrew formula prefix are rejected'; fi
assert_contains "$output" 'resolved AWS SDK shared library is not owned by Homebrew aws-sdk-cpp' 'Homebrew linkage must belong to the audited formula'
pass 'unrelated Homebrew linkage rejection'

new_fixture apk_inventory
write_metadata 1
rm "$fake_bin/dpkg-query"
write_executable "$fake_bin/apk" \
	'#!/usr/bin/env bash' \
	'if [[ $1 == info && $# == 1 ]]; then printf "%s\\n" aws-sdk-cpp-dev; exit 0; fi' \
	'if [[ $1 == info && ${2:-} == --who-owns ]]; then printf "%s\\n" "$3 is owned by aws-sdk-cpp-dev"; exit 0; fi' \
	'if [[ $1 == info && ${2:-} == -L ]]; then printf "%s\\n" "aws-sdk-cpp-dev contains:" "${LINKAGE_TEST_LICENSE_FILE#/}" "${LINKAGE_TEST_NOTICE_FILE#/}"; exit 0; fi' \
	'exit 2'
output=$(run_checker) || fail 'APK-owned license and notice material is accepted'
assert_contains "$output" '(package aws-sdk-cpp-dev)' 'APK package ownership is reported'
pass 'Alpine APK ownership branch'
