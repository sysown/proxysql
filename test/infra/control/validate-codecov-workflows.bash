#!/usr/bin/env bash
set -euo pipefail

WORKFLOW_ROOT="${1:-.github/workflows}"
EXPECTED_CONFIG="${2:-codecov.yml}"

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
    awk -v file="${workflow}" -v expected="${EXPECTED_CONFIG}" '
        function finish_step() {
            if (!has_codecov) {
                return
            }
            if (!has_config) {
                printf "%s: missing codecov_yml_path: %s\n", file, expected > "/dev/stderr"
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
            has_nonblocking = 0
        }

        /uses:[[:space:]]*codecov\/codecov-action@v4/ {
            has_codecov = 1
        }
        /codecov_yml_path:/ && index($0, expected) {
            has_config = 1
        }
        /fail_ci_if_error:[[:space:]]*false/ {
            has_nonblocking = 1
        }

        END {
            if (in_step) {
                finish_step()
            }
            exit bad
        }
    ' "${workflow}"
done

echo "Codecov workflow contract OK: ${#WORKFLOWS[@]} workflow(s), config=${EXPECTED_CONFIG}"
