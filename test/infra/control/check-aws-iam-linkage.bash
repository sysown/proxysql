#!/usr/bin/env bash

set -euo pipefail

die() {
	printf 'AWS IAM linkage check failed: %s\n' "$*" >&2
	exit 1
}

usage() {
	printf 'Usage: %s <proxysql-binary>\n' "${0##*/}" >&2
	exit 2
}

[[ $# -eq 1 ]] || usage

binary=$1
[[ -f $binary ]] || die "binary does not exist: $binary"
if [[ $binary != /* ]]; then
	binary=$PWD/$binary
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
case $binary in
	"$repo_root"/*) ;;
	*) die 'binary must be inside the repository being inspected' ;;
esac
metadata="$repo_root/build/aws-sdk-cpp/aws-sdk-cpp.mk"
[[ -f $metadata ]] || die 'binary is not an AWS IAM-enabled build (discovery metadata is absent)'
mode_stamp="$repo_root/build/aws-sdk-cpp/build-mode"
[[ -f $mode_stamp ]] || die 'binary is not an AWS IAM-enabled build (build-mode stamp is absent)'
build_mode=$(sed -n '1p' "$mode_stamp")
[[ $build_mode == enabled:* ]] || die 'binary is not an AWS IAM-enabled build (feature is disabled)'

metadata_value() {
	local key=$1
	local line value
	line=$(sed -n "s/^${key}[[:space:]]*:=[[:space:]]*//p" "$metadata")
	[[ -n $line ]] || die "discovery metadata is missing $key"
	value=$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"$line")
	if [[ $value == \"*\" && $value == *\" ]]; then
		value=${value#\"}
		value=${value%\"}
	fi
	printf '%s' "$value"
}

extract_aws_services() {
	local text=$1
	local match
	while [[ $text =~ (aws-cpp-sdk-[[:alnum:]_-]+) ]]; do
		match=${BASH_REMATCH[1]}
		printf '%s\n' "$match"
		text=${text#*"$match"}
	done
}

validate_service_set() {
	local text=$1
	local context=$2
	local service
	local have_core=0
	local have_rds=0
	local services
	services=$(extract_aws_services "$text")
	while IFS= read -r service; do
		[[ -n $service ]] || continue
		case $service in
			aws-cpp-sdk-core) have_core=1 ;;
			aws-cpp-sdk-rds) have_rds=1 ;;
			*) die "unexpected AWS service library: $service ($context)" ;;
		esac
	done <<<"$services"
	if ((have_core == 0 || have_rds == 0)); then
		die "required AWS SDK core and rds libraries are missing from $context"
	fi
}

sdk_version=$(metadata_value AWS_IAM_SDK_VERSION)
sdk_shared=$(metadata_value AWS_IAM_SDK_SHARED)
sdk_libraries=$(metadata_value AWS_IAM_LIBS)
sdk_discovery_id=$(metadata_value AWS_IAM_DISCOVERY_ID)

[[ $build_mode == "enabled:$sdk_discovery_id" ]] || \
	die 'AWS IAM build-mode stamp does not match the discovery metadata'
if [[ $metadata -nt $binary || $mode_stamp -nt $binary ]]; then
	die 'binary predates the AWS IAM build metadata'
fi

if [[ ! $sdk_version =~ ^([0-9]+)\.([0-9]+)(\.[0-9]+)*([+-][0-9A-Za-z.-]+)?$ ]]; then
	die "invalid AWS SDK version in discovery metadata: $sdk_version"
fi
sdk_major=$((10#${BASH_REMATCH[1]}))
sdk_minor=$((10#${BASH_REMATCH[2]}))
if ((sdk_major < 1 || (sdk_major == 1 && sdk_minor < 9))); then
	die "AWS SDK for C++ 1.9 or newer is required (discovered $sdk_version)"
fi
[[ $sdk_shared == 0 || $sdk_shared == 1 ]] || die "invalid AWS_IAM_SDK_SHARED value: $sdk_shared"
validate_service_set "$sdk_libraries" 'generated AWS_IAM_LIBS'

platform=$(uname -s)
linkage_output=''
declare -a linked_sdk_paths=()

if [[ $sdk_shared == 1 ]]; then
	case $platform in
		Linux)
			command -v ldd >/dev/null 2>&1 || die 'ldd is required for a shared Linux release check'
			if ! linkage_output=$(ldd "$binary" 2>&1); then
				die 'ldd could not inspect the requested feature-on binary'
			fi
			;;
		Darwin)
			command -v otool >/dev/null 2>&1 || die 'otool is required for a shared macOS release check'
			if ! linkage_output=$(otool -L "$binary" 2>&1); then
				die 'otool could not inspect the requested feature-on binary'
			fi
			;;
		*) die "shared release linkage inspection is unsupported on $platform" ;;
	esac

	if [[ $platform == Linux ]]; then
		while IFS= read -r line; do
			if [[ $line == *aws-cpp-sdk-* && $line == *"=>"[[:space:]]*"not found"* ]]; then
				die "AWS SDK shared library was not resolved: ${line%%=>*}"
			fi
		done <<<"$linkage_output"
	fi

	linked_services=$(extract_aws_services "$linkage_output")
	linked_core=0
	linked_rds=0
	while IFS= read -r service; do
		[[ -n $service ]] || continue
		case $service in
			aws-cpp-sdk-core) linked_core=1 ;;
			aws-cpp-sdk-rds) linked_rds=1 ;;
			*) die "unexpected AWS service library: $service (final dynamic linkage)" ;;
		esac
	done <<<"$linked_services"
	if ((linked_core == 0 || linked_rds == 0)); then
		die 'required shared AWS SDK libraries were not both linked'
	fi

	while IFS= read -r line; do
		[[ $line == *aws-cpp-sdk-* ]] || continue
		if [[ $line =~ (/[[:graph:]]*aws-cpp-sdk-[[:alnum:]_.-]+) ]]; then
			linked_sdk_paths+=("${BASH_REMATCH[1]}")
		fi
	done <<<"$linkage_output"
	if ((${#linked_sdk_paths[@]} < 2)); then
		die 'resolved absolute paths for both AWS SDK shared libraries were not found'
	fi
else
	command -v nm >/dev/null 2>&1 || die 'nm is required for a static development check'
	if ! symbol_output=$(nm -C "$binary" 2>&1); then
		die 'nm could not inspect the requested feature-on binary'
	fi
	if [[ $symbol_output != *'Aws::RDS::RDSClient::GenerateConnectAuthToken'* ]]; then
		die 'Aws::RDS::RDSClient::GenerateConnectAuthToken symbol was not found in the final binary'
	fi
fi

declare -a package_names=()
declare -a package_files=()

append_unique_package() {
	local candidate=$1
	local existing
	[[ -n $candidate ]] || return
	for existing in "${package_names[@]:-}"; do
		[[ $existing == "$candidate" ]] && return
	done
	package_names+=("$candidate")
}

if command -v dpkg-query >/dev/null 2>&1; then
	for path in "${linked_sdk_paths[@]:-}"; do
		[[ -n $path ]] || continue
		owner_output=$(dpkg-query -S -- "$path" 2>/dev/null || true)
		path_owned=0
		while IFS= read -r owner_line; do
			[[ $owner_line == *:* ]] || continue
			append_unique_package "${owner_line%%:*}"
			path_owned=1
		done <<<"$owner_output"
		((path_owned == 1)) || die "resolved AWS SDK shared library has no system package owner: $path"
	done
	if [[ $sdk_shared == 0 ]]; then
		installed_output=$(dpkg-query -W -f='${binary:Package}\n' '*aws-sdk-cpp*' 2>/dev/null || true)
		while IFS= read -r package; do append_unique_package "$package"; done <<<"$installed_output"
	fi
	for package in "${package_names[@]:-}"; do
		[[ -n $package ]] || continue
		files=$(dpkg-query -L "$package" 2>/dev/null || true)
		while IFS= read -r path; do [[ -n $path ]] && package_files+=("$package|$path"); done <<<"$files"
	done
elif command -v apk >/dev/null 2>&1; then
	for path in "${linked_sdk_paths[@]:-}"; do
		[[ -n $path ]] || continue
		owner=$(apk info --who-owns "$path" 2>/dev/null | sed -n 's/.* is owned by \([^ ]*\).*/\1/p')
		[[ -n $owner ]] || die "resolved AWS SDK shared library has no system package owner: $path"
		append_unique_package "$owner"
	done
	if [[ $sdk_shared == 0 ]]; then
		installed_output=$(apk info 2>/dev/null | sed -n '/^aws-sdk-cpp-/p')
		while IFS= read -r package; do append_unique_package "$package"; done <<<"$installed_output"
	fi
	for package in "${package_names[@]:-}"; do
		[[ -n $package ]] || continue
		files=$(apk info -L "$package" 2>/dev/null || true)
		while IFS= read -r path; do
			[[ -n $path && $path != *:* ]] || continue
			[[ $path == /* ]] || path="/$path"
			package_files+=("$package|$path")
			done <<<"$files"
	done
elif command -v rpm >/dev/null 2>&1; then
	for path in "${linked_sdk_paths[@]:-}"; do
		[[ -n $path ]] || continue
		owner_output=$(rpm -qf --qf '%{NAME}\n' "$path" 2>/dev/null || true)
		path_owned=0
		while IFS= read -r package; do
			[[ -n $package ]] || continue
			append_unique_package "$package"
			path_owned=1
		done <<<"$owner_output"
		((path_owned == 1)) || die "resolved AWS SDK shared library has no system package owner: $path"
	done
	if [[ $sdk_shared == 0 ]]; then
		installed_output=$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | sed -n '/^aws-sdk-cpp/p' || true)
		while IFS= read -r package; do append_unique_package "$package"; done <<<"$installed_output"
	fi
	for package in "${package_names[@]:-}"; do
		[[ -n $package ]] || continue
		files=$(rpm -ql "$package" 2>/dev/null || true)
		while IFS= read -r path; do [[ -n $path ]] && package_files+=("$package|$path"); done <<<"$files"
	done
elif [[ $platform == Darwin ]] && command -v brew >/dev/null 2>&1; then
	brew_prefix=$(brew --prefix aws-sdk-cpp 2>/dev/null || true)
	[[ $brew_prefix == /* ]] || die 'Homebrew aws-sdk-cpp formula prefix was not found'
	for path in "${linked_sdk_paths[@]:-}"; do
		[[ -n $path ]] || continue
		case $path in
			"$brew_prefix"/*) ;;
			*) die "resolved AWS SDK shared library is not owned by Homebrew aws-sdk-cpp: $path" ;;
		esac
	done
	append_unique_package aws-sdk-cpp
	files=$(brew list aws-sdk-cpp 2>/dev/null || true)
	while IFS= read -r path; do [[ -n $path ]] && package_files+=("aws-sdk-cpp|$path"); done <<<"$files"
else
	die 'no supported system package inventory tool was found for AWS SDK license verification'
fi

license_record=''
notice_record=''
for record in "${package_files[@]:-}"; do
	[[ -n $record ]] || continue
	package=${record%%|*}
	path=${record#*|}
	[[ -f $path ]] || continue
	basename_lower=$(printf '%s' "${path##*/}" | tr '[:upper:]' '[:lower:]')
	if [[ -z $license_record && $basename_lower == *license* ]]; then
		if grep -Eiq 'Apache License|Apache-2\.0' "$path" && grep -Eiq 'Version[[:space:]]+2\.0|Apache-2\.0' "$path"; then
			license_record="$package|$path"
		fi
	fi
	if [[ -z $notice_record && $basename_lower == *notice* ]]; then
		if grep -Eiq 'AWS SDK for C\+\+|Amazon( Web Services|\.com)' "$path"; then
			notice_record="$package|$path"
		fi
	fi
done

if [[ -z $license_record || -z $notice_record ]]; then
	die 'package-owned Apache-2.0 LICENSE and NOTICE material was not found'
fi
if [[ ${license_record#*|} == "${notice_record#*|}" ]]; then
	die 'distinct package-owned Apache-2.0 LICENSE and NOTICE material was not found'
fi

printf 'AWS IAM binary: %s\n' "$binary"
printf 'AWS SDK discovery metadata: %s\n' "$metadata"
printf 'AWS SDK for C++ version: %s\n' "$sdk_version"
printf 'AWS SDK license: %s (package %s)\n' "${license_record#*|}" "${license_record%%|*}"
printf 'AWS SDK notice: %s (package %s)\n' "${notice_record#*|}" "${notice_record%%|*}"
if [[ $sdk_shared == 1 ]]; then
	printf 'AWS SDK shared release linkage: verified (core and rds only)\n'
else
	printf 'AWS SDK static development linkage: verified (core and rds only)\n'
	printf 'AWS SDK dynamic linkage remains required for the release-package job\n'
fi
