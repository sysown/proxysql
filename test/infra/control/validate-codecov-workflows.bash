#!/usr/bin/env bash
set -euo pipefail

WORKFLOW_ROOT="${1:-.github/workflows}"
EXPECTED_CONFIG="${2:-codecov.yml}"
if [ "$#" -ge 3 ]; then
    EXPECTED_COMMIT="$3"
else
    EXPECTED_COMMIT='${{ env.SHA }}'
fi

mapfile -t WORKFLOWS < <(
    rg -l --glob '*.yml' --glob '*.yaml' \
        '^[[:space:]]*uses:[[:space:]]*codecov/codecov-action@v4' \
        "${WORKFLOW_ROOT}" | sort
)

if [ "${#WORKFLOWS[@]}" -eq 0 ]; then
    echo "ERROR: no Codecov workflows found under ${WORKFLOW_ROOT}" >&2
    exit 1
fi

for workflow in "${WORKFLOWS[@]}"; do
    awk -v file="${workflow}" \
        -v expected="${EXPECTED_CONFIG}" \
        -v expected_commit="${EXPECTED_COMMIT}" '
        function mapping_value(key, line,   prefix, value) {
            prefix = "^[[:space:]]*" key ":[[:space:]]*"
            if (line !~ prefix) {
                return ""
            }
            value = line
            sub(prefix, "", value)
            sub(/[[:space:]]*$/, "", value)
            return value
        }

        function finish_step() {
            if (!has_codecov) {
                return
            }
            if (!has_config) {
                printf "%s: missing codecov_yml_path: %s\n", file, expected > "/dev/stderr"
                bad = 1
            }
            if (!has_override_commit) {
                printf "%s: missing override_commit: %s\n", file, expected_commit > "/dev/stderr"
                bad = 1
            }
            if (!has_nonblocking) {
                printf "%s: Codecov upload must keep fail_ci_if_error: false\n", file > "/dev/stderr"
                bad = 1
            }
        }

        /^[[:space:]]*-[[:space:]]/ {
            if (in_step) {
                finish_step()
            }
            in_step = 1
            has_codecov = 0
            has_config = 0
            has_override_commit = 0
            has_nonblocking = 0
        }

        /^[[:space:]]*uses:[[:space:]]*codecov\/codecov-action@v4[[:space:]]*$/ {
            has_codecov = 1
        }
        /^[[:space:]]*with:[[:space:]]*$/ {
            in_with = 1
            next
        }
        in_with {
            if (mapping_value("codecov_yml_path", $0) == expected) {
                has_config = 1
            }
            if (mapping_value("override_commit", $0) == expected_commit) {
                has_override_commit = 1
            }
            if (mapping_value("fail_ci_if_error", $0) == "false") {
                has_nonblocking = 1
            }
        }

        END {
            if (in_step) {
                finish_step()
            }
            exit bad
        }
    ' "${workflow}"
done

echo "Codecov workflow contract OK: ${#WORKFLOWS[@]} workflow(s), config=${EXPECTED_CONFIG}, commit=${EXPECTED_COMMIT}"
