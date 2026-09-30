#!/usr/bin/env bash
# Select data for paired lint; never execute code from the selected engine ref.
set -euo pipefail
if [[ -n "${CI_ENGINE_REF:-}" ]]; then
    printf '%s\n' "${CI_ENGINE_REF}"
    exit 0
fi
# A missing ref/catalogue is expected before the paired engine is available.
# Once present, malformed data must not silently fall back to the companion pin.
if catalogue="$(git show origin/GH-Actions:.github/ci-tier-consumers.json 2>/dev/null)"; then
    compatible="$(python3 -c '
import json, sys
try:
    catalogue = json.load(sys.stdin)
    if not isinstance(catalogue, dict):
        raise ValueError("expected an object")
    schema = catalogue.get("schema", 0)
    if type(schema) is not int:
        raise ValueError("schema must be an integer")
except ValueError as error:
    print("Invalid CI engine catalogue at origin/GH-Actions: " + str(error), file=sys.stderr)
    sys.exit(2)
print("yes" if schema >= 2 else "no")
' <<< "${catalogue}")"
    if [[ "${compatible}" == yes ]]; then
        printf '%s\n' origin/GH-Actions
        exit 0
    fi
fi
if [[ -f .github/ci-tier-engine-ref ]]; then
    candidate_sha="$(cat .github/ci-tier-engine-ref)"
    if [[ ! "${candidate_sha}" =~ ^[0-9a-f]{40}$ ]]; then
        echo 'Invalid paired CI engine pin: expected a full commit SHA' >&2
        exit 1
    fi
    printf '%s\n' "${candidate_sha}"
elif git rev-parse --verify --quiet origin/GH-Actions >/dev/null; then
    echo 'Paired CI engine lacks a compatible shared-execution catalogue and no .github/ci-tier-engine-ref pin exists; restore the companion pin or select a compatible CI_ENGINE_REF.' >&2
    exit 1
else
    printf '%s\n' origin/GH-Actions
fi
