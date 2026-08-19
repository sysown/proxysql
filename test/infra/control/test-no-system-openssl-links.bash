#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

candidate_list="${tmp_dir}/candidates"
violations="${tmp_dir}/violations"

git -C "${repo_root}" ls-files -z -- \
	'*Makefile*' '*.mk' '*.bash' '*.sh' > "${candidate_list}"

pattern="(^|[[:space:]\"'])(-lssl|-lcrypto)([[:space:]\"']|$)|brew --prefix openssl|CUSTOM_OPENSSL_PATH|OPENSSL_ROOT_DIR=(/usr|/opt)|/usr/include/openssl"

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
