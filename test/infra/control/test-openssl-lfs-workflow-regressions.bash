#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
validator="${script_dir}/validate-openssl-lfs-workflows.bash"
tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

cp -a "${repo_root}/.github" "${tmp_dir}/.github"
workflow="${tmp_dir}/.github/workflows/CI-cluster-simulator.yml"
checkout='actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4'

python3 - "${workflow}" "${checkout}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
checkout = sys.argv[2]
text = path.read_text()
old = f'''    - name: Checkout
      uses: {checkout}
      with:
        fetch-depth: 0
        lfs: true
        persist-credentials: false
'''
new = f'''    - uses: {checkout}
      with:
        lfs: true
'''
if old not in text:
    raise SystemExit("build checkout fixture was not found")
path.write_text(text.replace(old, new, 1))
PY

if OPENSSL_LFS_WORKFLOW_DIR="${tmp_dir}/.github/workflows" "${validator}" >/dev/null 2>&1; then
	fail "validator accepted a single-line build checkout without persist-credentials: false"
fi

python3 - "${workflow}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
old = '      lfs: true\n'
if old not in text:
    raise SystemExit("single-line checkout fixture was not found")
path.write_text(text.replace(old, old + '      persist-credentials: false\n', 1))
PY
if ! OPENSSL_LFS_WORKFLOW_DIR="${tmp_dir}/.github/workflows" "${validator}" >/dev/null 2>&1; then
	fail "validator rejected a single-line build checkout with both required settings"
fi

echo "OpenSSL LFS workflow regression tests passed"
