#!/bin/bash

# Return success only when the supplied ELF binary has a dynamic dependency on
# libasan. The central build hands binaries to separate TAP workflows, so build
# flags are no longer available when the test infrastructure starts.
proxysql_binary_uses_asan() {
	local binary="${1:-}"
	local dynamic_section

	[ -r "${binary}" ] || return 1

	if command -v readelf >/dev/null 2>&1; then
		dynamic_section="$(LC_ALL=C readelf --dynamic "${binary}" 2>/dev/null)" || return 1
		grep -Eq '\(NEEDED\).*\[libasan\.so(\.[^]]*)?\]' <<< "${dynamic_section}"
	else
		# proxysql's GCC ASAN build links libasan dynamically. Keep a
		# dependency-free fallback for minimal runner hosts without binutils.
		LC_ALL=C grep -aEq 'libasan\.so(\.[0-9]+)+' "${binary}"
	fi
}
