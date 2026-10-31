#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../../.." && pwd)
validator="${script_dir}/validate-openssl-checkout-workflows.bash"
tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

cp -a "${repo_root}/.github" "${tmp_dir}/.github"
workflow="${tmp_dir}/.github/workflows/CI-cluster-simulator.yml"
checkout='actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4'

run_validator() {
	OPENSSL_WORKFLOW_DIR="${tmp_dir}/.github/workflows" "${validator}" >/dev/null 2>&1
}

# Baseline: the migrated tree (no lfs: keys) must validate.
run_validator || fail "validator rejected the LFS-free tree"

# 1. Reintroducing lfs: true on a build checkout must be rejected.
python3 - "${workflow}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
old = '''      with:
        fetch-depth: 0
        persist-credentials: false
'''
new = '''      with:
        fetch-depth: 0
        lfs: true
        persist-credentials: false
'''
if old not in text:
    raise SystemExit("build checkout fixture was not found")
path.write_text(text.replace(old, new, 1))
PY
if run_validator; then
	fail "validator accepted a build checkout with lfs: true"
fi

# 2. Removing the reintroduced key restores validity.
python3 - "${workflow}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
old = '        lfs: true\n'
if old not in text:
    raise SystemExit("reintroduced lfs fixture was not found")
path.write_text(text.replace(old, '', 1))
PY
run_validator || fail "validator rejected the tree after removing lfs: true"

# 3. Dropping persist-credentials: false must still be rejected.
python3 - "${workflow}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
old = '        persist-credentials: false\n'
if old not in text:
    raise SystemExit("persist-credentials fixture was not found")
path.write_text(text.replace(old, '', 1))
PY
if run_validator; then
	fail "validator accepted a build checkout without persist-credentials: false"
fi

valid_workflow="${tmp_dir}/valid-CI-cluster-simulator.yml"
cp "${repo_root}/.github/workflows/CI-cluster-simulator.yml" "${valid_workflow}"
cp "${valid_workflow}" "${workflow}"

assert_misplaced_settings_rejected() {
	local name=$1
	if run_validator; then
		fail "validator accepted checkout settings misplaced under ${name}"
	fi
	cp "${valid_workflow}" "${workflow}"
}

python3 - "${workflow}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
old = '''      with:
        fetch-depth: 0
        persist-credentials: false
'''
new = '''      with:
        fetch-depth: |
          persist-credentials: false
'''
if old not in text:
    raise SystemExit("valid checkout settings fixture was not found")
path.write_text(text.replace(old, new, 1))
PY
assert_misplaced_settings_rejected 'a block scalar'

python3 - "${workflow}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
old = '''      with:
        fetch-depth: 0
        persist-credentials: false
'''
new = '''      env:
        persist-credentials: false
'''
if old not in text:
    raise SystemExit("valid checkout settings fixture was not found")
path.write_text(text.replace(old, new, 1))
PY
assert_misplaced_settings_rejected 'env'

echo "OpenSSL checkout workflow regression tests passed"
