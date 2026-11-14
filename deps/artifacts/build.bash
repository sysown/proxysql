#!/usr/bin/env bash
# Runs inside the actual package environment, or natively on the selected Mac.
set -euo pipefail
profile=${1:?profile}
dependency=${2:?dependency}
output=${3:?output directory}
repository=${4:?repository}
tag=${5:?release tag}
repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"
if [[ "$profile" == *-clang ]]; then
    default_cc=clang
    default_cxx=clang++
else
    default_cc=cc
    default_cxx=g++
fi
export CC=${CC:-$default_cc} CXX=${CXX:-$default_cxx}
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$repo_root"
export GIT_VERSION=$(git describe --long --abbrev=7 --tags)
jobs=${DEPS_BUILD_JOBS:-2}
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid DEPS_BUILD_JOBS' >&2; exit 1; }
case "$dependency" in openssl) target=libssl;; duckdb) target=duckdb;; *) exit 1;; esac
for compiler_variable in CC CXX; do
    read -r -a compiler_command <<< "${!compiler_variable}"
    language=c
    if [[ "$compiler_variable" == CXX ]]; then language=c++; fi
    macros=$("${compiler_command[@]}" -dM -E -x "$language" /dev/null)
    if [[ "$profile" == *-clang ]]; then
        [[ "$macros" == *'__clang__'* ]] || { echo "Profile requires Clang for $compiler_variable" >&2; exit 1; }
    else
        [[ "$macros" != *'__clang__'* && "$macros" == *'__GNUC__'* ]] || { echo "Profile requires GCC for $compiler_variable" >&2; exit 1; }
    fi
done
mkdir -p "$output"
make -j"$jobs" -C deps NPROCS="$jobs" DEPS_MODE=source "$target"
key=$(python3 "$repo_root/deps/artifacts/manage.py" identity --dependency "$dependency" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["fingerprint"])')
archive="$output/$dependency-$key.tar.gz"
entry="$output/$profile-$dependency.entry.json"
python3 "$repo_root/deps/artifacts/manage.py" package --dependency "$dependency" --output "$archive" \
    --url "https://github.com/$repository/releases/download/$tag/$(basename -- "$archive")" > "$entry"
chmod 644 "$archive"
python3 - "$entry" "$profile" <<'PY'
import json,sys
from pathlib import Path
path=Path(sys.argv[1]); entry=json.loads(path.read_text())
entry['provenance']['profile']=sys.argv[2]
path.write_text(json.dumps(entry,sort_keys=True)+'\n')
PY
relocated=$(mktemp -d)
trap 'rm -rf "$relocated"' EXIT
python3 - "$repo_root" "$archive" "$entry" "$relocated/tree" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[1])/'deps/artifacts'))
from bundles import restore_bundle
from identity import load_json
restore_bundle(Path(sys.argv[2]),load_json(sys.argv[3]),Path(sys.argv[4]))
PY
bash "$repo_root/test/infra/control/dependency-artifacts-smoke.bash" "$dependency" "$relocated/tree"
