#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=${OPENSSL_AUDIT_ROOT:-$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)}
tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

candidate_list="${tmp_dir}/candidates"
violations="${tmp_dir}/violations"

git -C "${repo_root}" ls-files -z -- \
	'*Makefile*' '*.mk' '*.bash' '*.sh' > "${candidate_list}"

pattern="(^|[[:space:]\"'=])(-lssl|-lcrypto)([[:space:]\"'=]|$)|-Wl,[^[:space:]]*-l(ssl|crypto)(,|[[:space:]]|$)|-Wl,[^[:space:]]*-l,(ssl|crypto)(,|[[:space:]]|$)|-Xlinker([[:space:]]|=)+-l(ssl|crypto)([[:space:]\"'=]|$)|-Xlinker([[:space:]]|=)+-l([[:space:]]|=)+-Xlinker([[:space:]]|=)+(ssl|crypto)([[:space:]\"'=]|$)|-l:(libssl|libcrypto)([.[:space:]\"'=]|$)|brew --prefix openssl|CUSTOM_OPENSSL_PATH|OPENSSL_ROOT_DIR[[:space:]]*[:?+]?=[[:space:]]*(/usr|/opt)|/usr/include/openssl|/(usr|lib|opt)/(local/)?lib[^[:space:]\"']*/lib(ssl|crypto)[.](a|so([.][0-9]+)*|dylib|[0-9]+[.]dylib)|/lib64/lib(ssl|crypto)[.](a|so([.][0-9]+)*)|/lib/[^/[:space:]\"']+/lib(ssl|crypto)[.](a|so([.][0-9]+)*)|/(usr/local|opt/homebrew)/(opt|Cellar)/openssl[^[:space:]\"']*/lib/lib(ssl|crypto)[.](a|so([.][0-9]+)*|dylib|[0-9]+[.]dylib)"

while IFS= read -r -d '' file; do
	case ${file} in
		docs/*|test/infra/control/test-*)
			continue
			;;
	esac

	if matches=$(rg -n --no-heading -- "${pattern}" "${repo_root}/${file}"); then
		while IFS= read -r match; do
			printf '%s:%s\n' "${file}" "${match}" >> "${violations}"
		done <<< "${matches}"
	fi
done < "${candidate_list}"

if [[ -s "${violations}" ]]; then
	echo "ERROR: active build files contain system OpenSSL link selectors:" >&2
	sort -u "${violations}" >&2
	exit 1
fi

echo "No active build file links against system OpenSSL"
