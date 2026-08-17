#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
subject="${script_dir}/asan-detection.bash"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

printf '%s\n' 'int main() { return 0; }' > "${tmp_dir}/main.cpp"
"${CXX:-c++}" "${tmp_dir}/main.cpp" -o "${tmp_dir}/plain"
"${CXX:-c++}" -fsanitize=address "${tmp_dir}/main.cpp" -o "${tmp_dir}/asan"

source "${subject}"

if proxysql_binary_uses_asan "${tmp_dir}/plain"; then
	echo "plain binary incorrectly detected as ASAN" >&2
	exit 1
fi
if ! proxysql_binary_uses_asan "${tmp_dir}/asan"; then
	echo "ASAN binary was not detected" >&2
	exit 1
fi
if proxysql_binary_uses_asan "${tmp_dir}/missing"; then
	echo "missing binary incorrectly detected as ASAN" >&2
	exit 1
fi

echo "ASAN binary detection tests passed"
