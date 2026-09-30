#!/usr/bin/env bash
# Delete *-t test binaries that the running ProxySQL feature tier can never
# select.
#
# Why this exists
# ---------------
# test/infra/control/run-tests-isolated.bash selects a group's binaries with a
# @proxysql_min_version filter read off the *built binary's own* version
# (`proxysql --version`). The Makefile bumps that version per tier
# (Makefile:82-92: minor+1 for PROXYSQL31, major+1 for PROXYSQL40), so a
# downgrade build reports 3.0.x / 3.1.x and the harness already refuses to
# SELECT anything newer.
#
# The binaries it will not select are still sitting in the tree, and each is
# ~170 MB because the unit tests statically link libproxysql.a in debug mode.
# Dropping them:
#   1. shrinks the CI-builds handoff artifact, and
#   2. makes a "binary not found" false-red structurally impossible --
#      run-tests-isolated.bash:256-262 counts a missing binary as a FAILURE.
#
# The keep-rule below must stay byte-for-byte equivalent to the filter in
# run-tests-isolated.bash. If you change one, change the other.
#
# Usage:
#   prune-tier-handoff.bash --binary <path/to/proxysql> --groups <path/to/groups.json>
#
# Runs on the HOST (not inside the build container), so deletions need sudo:
# the binaries are created by the container running as root, and unlink needs
# write access to the parent directory, which the runner user does not have.
# This is the same constraint that forces sudo for the test/deps prune in
# ci-builds.yml.
set -euo pipefail

# NOTE: do not name this variable GROUPS -- bash reserves that as a builtin
# array holding the caller's group IDs, and assigning to it here is silently
# clobbered (it came back as a GID in testing, which then failed the
# "not found" check with a baffling message).
BINARY=""
GROUPS_JSON=""

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="${2:-}"; shift 2 ;;
    --groups) GROUPS_JSON="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "ERROR: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

if [ -z "${BINARY}" ] || [ -z "${GROUPS_JSON}" ]; then
  echo "ERROR: both --binary and --groups are required" >&2
  exit 2
fi
if [ ! -x "${BINARY}" ]; then
  echo "ERROR: ${BINARY} is not an executable file" >&2
  exit 1
fi
if [ ! -f "${GROUPS_JSON}" ]; then
  echo "ERROR: ${GROUPS_JSON} not found" >&2
  exit 1
fi

# Use the shared host/build-container probe: the host may lack the ABI used
# to build src/proxysql. Refuse to delete anything if neither probe succeeds.
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if ! version_output="$(python3 - "$script_dir" "$BINARY" <<'PY_VERSION'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from ci_tier_artifacts import binary_version
try:
    print(binary_version(Path.cwd(), sys.argv[2]), end='')
except (OSError, ValueError, RuntimeError) as error:
    print(error, file=sys.stderr)
    sys.exit(1)
PY_VERSION
)"; then
  echo "ERROR: could not determine the ProxySQL version from ${BINARY}; refusing to prune" >&2
  exit 1
fi
# Same extraction as the test selector; metadata never substitutes for a probe.
version_line="$(printf '%s\n' "$version_output" | grep -oP 'ProxySQL version \K[0-9]+\.[0-9]+\.[0-9]+' || true)"
if [ -z "${version_line}" ]; then
  echo "ERROR: could not determine the ProxySQL version from ${BINARY}" >&2
  echo "       Refusing to prune: a wrong guess silently deletes the wrong binaries." >&2
  exit 1
fi
echo ">>> ProxySQL version under test: ${version_line}"

# Emit the basenames to KEEP. A test with no @proxysql_min_version tag is
# always kept (that is how run-tests-isolated.bash treats it too).
#
# `packaging.version` is what the harness imports, but it is only guaranteed
# present inside the TAP container -- this script runs on the runner host. So
# compare dotted triples numerically ourselves and do NOT pip-install anything.
# Build the deduplicated list of candidate binaries FIRST, then hand the whole
# decision to one python pass.
#
# Two things this deliberately avoids:
#   1. `printf ... | grep -q` under `set -o pipefail`. grep -q exits on the
#      first match, printf takes SIGPIPE, the pipeline reports 141, and an
#      `if !` around it silently inverts -- which produced spurious "not
#      registered" warnings on a *different* file on every run.
#   2. One grep per file over a ~600-line set.
SEARCH_PATHS=(test/tap/tests test/tap/tests_with_deps test/tap/tests/unit)
existing=()
for d in "${SEARCH_PATHS[@]}"; do
  [ -d "${d}" ] || continue
  while IFS= read -r b; do
    [ -n "${b}" ] && existing+=("${b}")
  done < <(find "${d}" -type f -name '*-t' -executable 2>/dev/null || true)
done

# test/tap/tests CONTAINS test/tap/tests/unit, so searching both visits every
# unit binary twice. Sort -u on the path list is the cheap, obviously-correct
# fix, and keeps this resilient if the layout changes again.
if [ "${#existing[@]}" -gt 0 ]; then
  mapfile -t existing < <(printf '%s\n' "${existing[@]}" | sort -u)
fi

if [ "${#existing[@]}" -lt 1 ]; then
  echo "ERROR: no *-t binaries found under ${SEARCH_PATHS[*]}" >&2
  echo "       This normally means the TAP build did not run; refusing to prune." >&2
  exit 1
fi

# stdout -> one path per line, to be deleted.
# stderr -> warnings and the summary.
#
# The candidate list is passed as a FILE, not on stdin: python reads its own
# program from the heredoc, so stdin cannot also carry the data.
PRUNE_LIST="$(mktemp)"
PRUNE_OUT="$(mktemp)"
PRUNE_ERR="$(mktemp)"
trap 'rm -f "${PRUNE_LIST}" "${PRUNE_OUT}" "${PRUNE_ERR}"' EXIT
printf '%s\n' "${existing[@]}" > "${PRUNE_LIST}"

PROXYSQL_VER="${version_line}" python3 - "${GROUPS_JSON}" "${PRUNE_LIST}" \
  >"${PRUNE_OUT}" 2>"${PRUNE_ERR}" <<'PY'
import json
import os
import sys

groups_path = sys.argv[1]
list_path = sys.argv[2]


def parse(v):
    """'3.1.11' -> (3, 1, 11). Numeric, so 3.10 > 3.9 (unlike a string compare)."""
    parts = []
    for chunk in v.strip().split('.'):
        digits = ''.join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


have = parse(os.environ['PROXYSQL_VER'])

with open(groups_path) as f:
    groups = json.load(f)

selectable = set()
gated_out = set()
for name, entries in groups.items():
    required = (0, 0, 0)
    for entry in entries:
        if isinstance(entry, str) and entry.startswith('@proxysql_min_version:'):
            required = parse(entry.split(':', 1)[1])
            break
    # No tag means required == (0,0,0), which is always <= have, i.e. kept --
    # matching run-tests-isolated.bash, where an untagged test is never skipped.
    if required <= have:
        selectable.add(name)
    else:
        gated_out.add(name)

kept = dropped = unregistered = 0
with open(list_path) as f:
    for line in f:
        path = line.rstrip('\n')
        if not path:
            continue
        base = os.path.basename(path)
        if base in gated_out:
            # Version-gated out for this tier: unreachable by the version
            # filter, and a big chunk of the artifact. Safe to drop.
            print(path)
            dropped += 1
            continue
        if base not in selectable:
            # Not something this script understands. It can never be selected,
            # but deleting data we cannot reason about is how you hide a real
            # "built but never registered in groups.json" bug. Leave it, shout.
            print('    WARNING: %s is not registered in groups.json; leaving it in place'
                  % base, file=sys.stderr)
            unregistered += 1
        kept += 1

if kept == 0:
    print('ERROR: not a single registered test is selectable at %s'
          % os.environ['PROXYSQL_VER'], file=sys.stderr)
    print('       Refusing to prune: the version filter and this script disagree.',
          file=sys.stderr)
    sys.exit(1)

print('>>> kept %d, dropped %d, unregistered %d' % (kept, dropped, unregistered),
      file=sys.stderr)
PY

cat "${PRUNE_ERR}"

if ! grep -q . "${PRUNE_OUT}"; then
  echo ">>> nothing to prune: every binary present is selectable at ${version_line}"
  exit 0
fi

mapfile -t to_delete < "${PRUNE_OUT}"
for b in "${to_delete[@]}"; do
  echo "    dropped ${b} (needs a newer ProxySQL than ${version_line})"
  sudo rm -f -- "${b}"
done

# Belt and braces: whatever the keep-rule says, never let a bug here empty the
# whole tree -- the handoff would upload successfully and every consumer would
# then fail with a confusing "No tests found" or a wall of not-found reds.
left=0
for b in "${existing[@]}"; do
  [ -e "${b}" ] && left=$((left + 1))
done
if [ "${left}" -lt 1 ]; then
  echo "ERROR: pruning removed every test binary; refusing to continue" >&2
  exit 1
fi
echo ">>> ${left} binaries remain in the handoff tree"
