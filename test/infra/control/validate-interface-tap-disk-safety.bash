#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
tap_source="${repo_root}/test/tap/tests/mysql-server_version_by_interface-t.cpp"

forbidden_pattern='SAVE[[:space:]].*TO[[:space:]]+DISK|LOAD[[:space:]].*FROM[[:space:]]+DISK'

if matches="$(grep -Eni -- "${forbidden_pattern}" "${tap_source}")"; then
	echo "interface TAP disk-safety contract: FAIL" >&2
	echo "${matches}" >&2
	exit 1
else
	status=$?
	if (( status != 1 )); then
		echo "interface TAP disk-safety contract: unable to read ${tap_source}" >&2
		exit "${status}"
	fi
fi

echo "interface TAP disk-safety contract: OK"
