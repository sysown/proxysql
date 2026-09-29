#!/usr/bin/env bash
# Select data for paired lint; never execute code from the selected engine ref.
set -euo pipefail
if [[ -n "${CI_ENGINE_REF:-}" ]]; then
    printf '%s\n' "${CI_ENGINE_REF}"
elif git cat-file -e origin/GH-Actions:.github/ci-tier-consumers.json 2>/dev/null; then
    printf '%s\n' origin/GH-Actions
elif [[ -f .github/ci-tier-engine-ref ]]; then
    candidate_sha="$(cat .github/ci-tier-engine-ref)"
    if [[ ! "${candidate_sha}" =~ ^[0-9a-f]{40}$ ]]; then
        echo 'Invalid paired CI engine pin: expected a full commit SHA' >&2
        exit 1
    fi
    printf '%s\n' "${candidate_sha}"
elif git rev-parse --verify --quiet origin/GH-Actions >/dev/null; then
    echo 'Paired CI engine lacks the tier catalogue and no .github/ci-tier-engine-ref pin exists; restore the companion pin or select a compatible CI_ENGINE_REF.' >&2
    exit 1
else
    printf '%s\n' origin/GH-Actions
fi
