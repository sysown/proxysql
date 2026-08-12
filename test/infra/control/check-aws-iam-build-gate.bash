#!/usr/bin/env bash

set -euo pipefail

proxysql_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
real_sdk_root=${AWS_SDK_CPP_ROOT:-}
temporary_directories=()

cleanup() {
	if ((${#temporary_directories[@]})); then
		rm -rf -- "${temporary_directories[@]}"
	fi
}
trap cleanup EXIT

assert_no_aws_symbols() {
	local archive=$1
	local symbols
	symbols=$(nm -C "$archive")
	if grep -F 'Aws::' <<<"$symbols" >/dev/null; then
		return 1
	fi
}

contains_build_command() {
	grep -E '(^g\+\+ .* (-(c|o))($| ))|(^clang\+\+ .* (-(c|o))($| ))|(^ar rcs )'
}

write_fake_sdk_config() {
	local sdk_root=$1
	local version=$2
	local shared=$3
	local config_dir="$sdk_root/lib/cmake/AWSSDK"
	mkdir -p "$config_dir"
	# The single-quoted strings below are CMake source, not shell expressions.
	# shellcheck disable=SC2016
	printf '%s\n' \
		"set(PACKAGE_VERSION \"$version\")" \
		'set(PACKAGE_VERSION_COMPATIBLE TRUE)' \
		'if(PACKAGE_FIND_VERSION VERSION_GREATER PACKAGE_VERSION)' \
		'  set(PACKAGE_VERSION_COMPATIBLE FALSE)' \
		'endif()' >"$config_dir/AWSSDKConfigVersion.cmake"
	# The single-quoted strings below are CMake source, not shell expressions.
	# shellcheck disable=SC2016
	printf '%s\n' \
		"set(AWSSDK_VERSION \"$version\")" \
		"set(PACKAGE_VERSION \"$version\")" \
		'get_filename_component(_aws_fixture_root "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)' \
		'set(AWSSDK_INCLUDE_DIRS "${_aws_fixture_root}/include $cash #hash '\''quote")' \
		'set(AWSSDK_LIB_DIR "${_aws_fixture_root}/lib $cash #hash '\''quote")' \
		"set(AWSSDK_INSTALL_AS_SHARED_LIBS $shared)" \
		'set(AWSSDK_LINK_LIBRARIES aws-cpp-sdk-rds aws-cpp-sdk-core "${_aws_fixture_root}/dependency $cash #hash '\''quote.a")' \
		'set(AWSSDK_core_FOUND TRUE)' \
		'set(AWSSDK_rds_FOUND TRUE)' \
		'macro(AWSSDK_DETERMINE_LIBS_TO_LINK SERVICE_LIST OUTPUT_VAR)' \
		'  set(${OUTPUT_VAR} aws-cpp-sdk-rds aws-cpp-sdk-core aws-c-common pthread)' \
		'endmacro()' >"$config_dir/AWSSDKConfig.cmake"
}

cd "$proxysql_root"

sdk_source="$proxysql_root/lib/Aws_Iam_Sdk.cpp"
grep -F 'class AwsIamSensitiveStringCleanup final' "$sdk_source"
grep -F 'explicit AwsIamSensitiveStringCleanup(Aws::String& value)' "$sdk_source"
grep -F '~AwsIamSensitiveStringCleanup() noexcept' "$sdk_source"
grep -F 'if (!value_.empty()) {' "$sdk_source"
grep -F 'OPENSSL_cleanse(&value_[0], value_.size());' "$sdk_source"
grep -F 'Aws::String token = rds_client.GenerateConnectAuthToken(' "$sdk_source"
grep -F 'AwsIamSensitiveStringCleanup token_cleanup(token);' "$sdk_source"
if grep -F 'const auto token = rds_client.GenerateConnectAuthToken(' "$sdk_source" >/dev/null; then
	echo 'AWS SDK token buffer is immutable and cannot be cleansed' >&2
	exit 1
fi

symbol_fixture=$(mktemp -d)
temporary_directories+=("$symbol_fixture")
printf '%s\n' 'namespace Aws { void matching_symbol() {} }' \
	| g++ -x c++ -c -o "$symbol_fixture/aws-symbol.o" -
awk 'BEGIN { for (i = 0; i < 2000; ++i) printf "void filler_%d() {}\n", i }' \
	| g++ -x c++ -c -o "$symbol_fixture/filler.o" -
ar rcs "$symbol_fixture/aws-symbol.a" \
	"$symbol_fixture/aws-symbol.o" "$symbol_fixture/filler.o"
if assert_no_aws_symbols "$symbol_fixture/aws-symbol.a"; then
	echo 'AWS symbol gate accepted a matching symbol fixture' >&2
	exit 1
fi

make -C lib clean
make -C lib -j2
noop_output=$(make -C lib -j2)
if contains_build_command <<<"$noop_output" >/dev/null; then
	echo 'unchanged AWS IAM build mode rebuilt an archive or object' >&2
	exit 1
fi
noop_dry_run=$(make -C lib -n -j2)
if contains_build_command <<<"$noop_dry_run" >/dev/null; then
	echo 'unchanged AWS IAM build mode scheduled a rebuild' >&2
	exit 1
fi
assert_no_aws_symbols lib/libproxysql.a

fake_root=$(mktemp -d)
temporary_directories+=("$fake_root")
if PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$fake_root" make -C lib 2>"$fake_root/error"; then
	exit 1
fi
grep -F 'AWS SDK for C++ 1.9 or newer with core and rds is required' "$fake_root/error"

metadata_parent=$(mktemp -d)
temporary_directories+=("$metadata_parent")
hostile_sdk_root="$metadata_parent/sdk root \$cash #hash 'quote"
write_fake_sdk_config "$hostile_sdk_root" 1.9.111 ON

metadata_makefile="$metadata_parent/metadata.mk"
metadata_artifact="$metadata_parent/artifact"
metadata_count="$metadata_parent/rebuild-count"
# The single-quoted strings below are Make source, not shell expressions.
# shellcheck disable=SC2016
printf '%s\n' \
	"PROXYSQL_PATH := $proxysql_root" \
	'.RECIPEPREFIX := >' \
	'include $(PROXYSQL_PATH)/common_mk/aws_sdk_cpp_flags.mk' \
	"artifact := $metadata_artifact" \
	"count := $metadata_count" \
	'all: $(AWS_IAM_MODE_STAMP) $(artifact)' \
	'$(artifact): $(AWS_IAM_MODE_STAMP)' \
	">@printf '%s\\n' rebuilt >> \"\$(count)\"" \
	">@touch \"\$@\"" \
	'print-flags:' \
	'>@for value in $(AWS_IAM_CPPFLAGS) $(AWS_IAM_LDFLAGS) $(AWS_IAM_LIBS); do printf '\''<%s>\n'\'' "$$value"; done' \
		>"$metadata_makefile"

PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$hostile_sdk_root" make -s -f "$metadata_makefile"
PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$hostile_sdk_root" make -s -f "$metadata_makefile"
[[ $(wc -l <"$metadata_count") -eq 1 ]]

flag_output=$(PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$hostile_sdk_root" \
	make -s -f "$metadata_makefile" print-flags)
grep -Fx -- "<-I$hostile_sdk_root/include \$cash #hash 'quote>" <<<"$flag_output"
grep -Fx -- "<-L$hostile_sdk_root/lib \$cash #hash 'quote>" <<<"$flag_output"
grep -Fx -- "<$hostile_sdk_root/dependency \$cash #hash 'quote.a>" <<<"$flag_output"

write_fake_sdk_config "$hostile_sdk_root" 1.10.222 OFF
PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$hostile_sdk_root" make -s -f "$metadata_makefile"
[[ $(wc -l <"$metadata_count") -eq 2 ]]
grep -F "AWS_IAM_SDK_VERSION := \"1.10.222\"" build/aws-sdk-cpp/aws-sdk-cpp.mk
grep -F 'AWS_IAM_SDK_SHARED := "0"' build/aws-sdk-cpp/aws-sdk-cpp.mk
grep -F 'aws-c-common' build/aws-sdk-cpp/aws-sdk-cpp.mk
grep -F 'pthread' build/aws-sdk-cpp/aws-sdk-cpp.mk

alternate_sdk_root="$metadata_parent/alternate sdk root \$cash #hash 'quote"
write_fake_sdk_config "$alternate_sdk_root" 1.10.222 OFF
PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$alternate_sdk_root" make -s -f "$metadata_makefile"
PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$alternate_sdk_root" make -s -f "$metadata_makefile"
[[ $(wc -l <"$metadata_count") -eq 3 ]]

make -s -f "$metadata_makefile"
make -s -f "$metadata_makefile"
[[ $(wc -l <"$metadata_count") -eq 4 ]]

if [[ -n "$real_sdk_root" ]]; then
	PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$real_sdk_root" make -C lib clean
	PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$real_sdk_root" make -C lib -j2

	flags_file=build/aws-sdk-cpp/aws-sdk-cpp.mk
	grep -F 'aws-cpp-sdk-rds' "$flags_file"
	grep -F 'aws-cpp-sdk-core' "$flags_file"
	grep -E '^AWS_IAM_SDK_VERSION := ".+"$' "$flags_file"
	if grep -E 'aws-cpp-sdk-(s3|sts|ec2|secretsmanager)' "$flags_file"; then
		exit 1
	fi
fi
