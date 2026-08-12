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

cd "$proxysql_root"

make -C lib clean
make -C lib -j2
if nm -C lib/libproxysql.a | grep -q 'Aws::'; then
	exit 1
fi

fake_root=$(mktemp -d)
temporary_directories+=("$fake_root")
if PROXYSQLAWSIAM=1 AWS_SDK_CPP_ROOT="$fake_root" make -C lib 2>"$fake_root/error"; then
	exit 1
fi
grep -F 'AWS SDK for C++ 1.9 or newer with core and rds is required' "$fake_root/error"

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
