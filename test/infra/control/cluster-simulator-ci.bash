#!/usr/bin/env bash
#
# Centralizes cluster simulation workflow operations so build and runtime
# packaging behavior is readable, reusable locally, and kept out of YAML.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../.." && pwd -P)"
GROUPS_FILE="${REPO_ROOT}/test/tap/groups/groups.json"
SIMULATOR_BINARIES_FILE="${REPO_ROOT}/.cluster-simulator-binaries"
RUNTIME_CACHE_DIR_VALUE="${RUNTIME_CACHE_DIR:-.cluster-simulator-runtime}"

if [[ "${RUNTIME_CACHE_DIR_VALUE}" = /* ]]; then
    RUNTIME_CACHE_PATH="$(realpath -m -- "${RUNTIME_CACHE_DIR_VALUE}")"
else
    RUNTIME_CACHE_PATH="$(realpath -m -- "${REPO_ROOT}/${RUNTIME_CACHE_DIR_VALUE}")"
fi

case "${RUNTIME_CACHE_PATH}" in
    "${REPO_ROOT}/"*) ;;
    *)
        echo "ERROR: RUNTIME_CACHE_DIR must resolve inside ${REPO_ROOT}." >&2
        exit 1
        ;;
esac

STAGE_TEMP_DIR=""

die() {
    echo "ERROR: $*" >&2
    exit 1
}

usage_error() {
    echo "ERROR: $*" >&2
    echo "Run '$0 help' for usage." >&2
    exit 2
}

expect_no_arguments() {
    local command="${1}"
    local argument_count="${2}"

    [[ "${argument_count}" -eq 0 ]] ||
        usage_error "'${command}' does not accept arguments."
}

require_command() {
    command -v "${1}" >/dev/null 2>&1 ||
        die "Required command '${1}' was not found."
}

require_executable() {
    [[ -x "${1}" ]] || die "Required executable is missing: ${1}"
}

require_directory() {
    [[ -d "${1}" ]] || die "Required directory is missing: ${1}"
}

discover_groups_json() {
    jq -ce '
        [.[] | .[] | select(type == "string" and startswith("cluster_sim_"))]
        | unique
        | if length > 0 then . else error("no cluster simulation groups found") end
    ' "${GROUPS_FILE}"
}

refresh_binaries_manifest() {
    local temporary_manifest

    temporary_manifest="$(mktemp "${SIMULATOR_BINARIES_FILE}.tmp.XXXXXX")"
    if ! jq -er '
        [
            to_entries[]
            | select(any(.value[]; type == "string" and startswith("cluster_sim_")))
            | .key
        ]
        | unique
        | if length > 0 then .[] else error("no cluster simulation TAP binaries found") end
    ' "${GROUPS_FILE}" > "${temporary_manifest}"; then
        rm -f -- "${temporary_manifest}"
        die "Failed to discover cluster simulation TAP binaries from ${GROUPS_FILE}."
    fi

    mv -- "${temporary_manifest}" "${SIMULATOR_BINARIES_FILE}"
}

load_manifest_binaries() {
    [[ -s "${SIMULATOR_BINARIES_FILE}" ]] ||
        die "Simulation binary manifest is missing: ${SIMULATOR_BINARIES_FILE}"
    mapfile -t SIMULATOR_BINARIES < "${SIMULATOR_BINARIES_FILE}"
    [[ "${#SIMULATOR_BINARIES[@]}" -gt 0 ]] ||
        die "No TAP binaries were written to ${SIMULATOR_BINARIES_FILE}."
}

load_group_binaries() {
    local group="${1}"
    local binaries_json

    [[ "${group}" == cluster_sim_* ]] ||
        die "'${group}' is not a cluster simulation group."

    binaries_json="$(jq -ce --arg group "${group}" '
        [
            to_entries[]
            | select(.value | index($group))
            | .key
        ]
        | unique
        | if length > 0 then . else error("group is not registered") end
    ' "${GROUPS_FILE}")" ||
        die "Cluster simulation group '${group}' is not registered in ${GROUPS_FILE}."

    mapfile -t SIMULATOR_BINARIES < <(jq -r '.[]' <<< "${binaries_json}")
}

verify_runtime_paths() {
    local root="${1}"
    shift
    local binary

    require_executable "${root}/src/proxysql"
    require_executable "${root}/test/deps/cluster_simulator/cluster_simulator"
    require_directory "${root}/test/tap/tap"

    for binary in "$@"; do
        require_executable "${root}/test/tap/tests/${binary}"
    done
}

cleanup_stage_temp() {
    if [[ -n "${STAGE_TEMP_DIR}" && -d "${STAGE_TEMP_DIR}" ]]; then
        rm -rf -- "${STAGE_TEMP_DIR}"
    fi
}

trap cleanup_stage_temp EXIT

# discover
# Purpose: Generate the matrix group JSON and the TAP-binary build manifest.
# Local use: Run `cluster-simulator-ci.bash discover` to inspect registry output.
# GitHub use: Supplies the build job's matrix output before cache restoration.
handle_discover() {
    expect_no_arguments "discover" "$#"
    require_command jq

    local groups_json
    local group_count
    local binary_count

    groups_json="$(discover_groups_json)" ||
        die "Failed to discover cluster simulation groups from ${GROUPS_FILE}."
    refresh_binaries_manifest

    group_count="$(jq 'length' <<< "${groups_json}")"
    binary_count="$(wc -l < "${SIMULATOR_BINARIES_FILE}")"

    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        printf 'groups=%s\n' "${groups_json}" >> "${GITHUB_OUTPUT}"
    fi

    printf 'Discovered %s simulation groups and %s TAP binaries.\n' \
        "${group_count}" "${binary_count}"
    jq -r '.[] | "  group: \(.)"' <<< "${groups_json}"
    sed 's/^/  binary: /' "${SIMULATOR_BINARIES_FILE}"
}

# build
# Purpose: Build ProxySQL runtime with all simulation flags and every registered TAP binary.
# Local use: Run `cluster-simulator-ci.bash build` to reproduce the CI build.
# GitHub use: Invoked on an exact-SHA cache miss in the build job.
handle_build() {
    expect_no_arguments "build" "$#"
    require_command docker
    require_command git
    require_command jq
    refresh_binaries_manifest

    local git_version
    git_version="$(git -C "${REPO_ROOT}" describe --long --abbrev=7 2>/dev/null ||
        git -C "${REPO_ROOT}" describe --long --abbrev=7 --always)" ||
        die "Failed to derive the ProxySQL build version from Git."

    (
        cd "${REPO_ROOT}"
        docker compose run --rm --no-deps \
            --env "GIT_VERSION_BASE=${git_version}" \
            --entrypoint /opt/proxysql/test/infra/control/cluster-simulator-ci.bash \
            --workdir /opt/proxysql \
            ubuntu24_build _build
    )
}

# _build
# Purpose: Execute the compiler commands inside the Ubuntu 24 packaging image.
# Local use: Internal only; use the public `build` command from the host.
# GitHub use: Called by `build` as the packaging container entrypoint.
handle_internal_build() {
    expect_no_arguments "_build" "$#"
    load_manifest_binaries
    [[ -n "${GIT_VERSION_BASE:-}" ]] ||
        die "GIT_VERSION_BASE was not provided by the host build command."

    cd "${REPO_ROOT}"
    make -j"$(nproc)" WITHGCOV=1 \
        GIT_VERSION_BASE="${GIT_VERSION_BASE}" testall
    make -j"$(nproc)" WITHGCOV=1 \
        GIT_VERSION_BASE="${GIT_VERSION_BASE}" build_cluster_simulator
    make -C test/deps/cluster_simulator -j"$(nproc)" WITHGCOV=1 check
    make -C test/tap -j"$(nproc)" WITHGCOV=1 \
        GIT_VERSION="${GIT_VERSION_BASE}" tap
    make -C test/tap/tests -j"$(nproc)" WITHGCOV=1 \
        GIT_VERSION="${GIT_VERSION_BASE}" "${SIMULATOR_BINARIES[@]}"
}

# verify
# Purpose: Check the complete runtime, or only the TAP binaries for one group.
# Local use: Run `verify` after a build, optionally with a cluster_sim_* group.
# GitHub use: Checks the build job runtime and each restored matrix-job runtime.
handle_verify() {
    [[ "$#" -le 1 ]] ||
        usage_error "'verify' accepts at most one simulation group."
    require_command jq

    local group="${1:-}"

    if [[ -n "${group}" ]]; then
        load_group_binaries "${group}"
    else
        refresh_binaries_manifest
        load_manifest_binaries
    fi

    verify_runtime_paths "${REPO_ROOT}" "${SIMULATOR_BINARIES[@]}"

    if [[ -n "${group}" ]]; then
        printf 'Verified simulation runtime for %s.\n' "${group}"
    else
        printf 'Verified simulation runtime for all registered groups.\n'
    fi
}

# stage
# Purpose: Assemble only the runtime files that matrix jobs need in the cache.
# Local use: Optional; run after `build` to inspect the cache payload locally.
# GitHub use: Creates the exact-SHA cache payload after a successful build.
handle_stage() {
    expect_no_arguments "stage" "$#"
    require_command jq
    handle_verify

    local binary
    local runtime_parent

    runtime_parent="$(dirname -- "${RUNTIME_CACHE_PATH}")"
    mkdir -p -- "${runtime_parent}"
    STAGE_TEMP_DIR="$(mktemp -d "${RUNTIME_CACHE_PATH}.tmp.XXXXXX")"

    install -D -m 0755 \
        "${REPO_ROOT}/src/proxysql" \
        "${STAGE_TEMP_DIR}/src/proxysql"
    install -d \
        "${STAGE_TEMP_DIR}/lib/obj" \
        "${STAGE_TEMP_DIR}/src/obj"
    cp -a "${REPO_ROOT}"/lib/obj/*.gcno \
        "${STAGE_TEMP_DIR}/lib/obj/"
    cp -a "${REPO_ROOT}"/src/obj/*.gcno \
        "${STAGE_TEMP_DIR}/src/obj/"
    install -D -m 0755 \
        "${REPO_ROOT}/test/deps/cluster_simulator/cluster_simulator" \
        "${STAGE_TEMP_DIR}/test/deps/cluster_simulator/cluster_simulator"
    install -d "${STAGE_TEMP_DIR}/test/deps/cluster_simulator/obj"
    cp -a "${REPO_ROOT}"/test/deps/cluster_simulator/*.gcno \
        "${STAGE_TEMP_DIR}/test/deps/cluster_simulator/"
    cp -a "${REPO_ROOT}"/test/deps/cluster_simulator/obj/*.gcno \
        "${STAGE_TEMP_DIR}/test/deps/cluster_simulator/obj/"
    install -d "${STAGE_TEMP_DIR}/test/tap"
    cp -a "${REPO_ROOT}/test/tap/tap" "${STAGE_TEMP_DIR}/test/tap/"

    for binary in "${SIMULATOR_BINARIES[@]}"; do
        install -D -m 0755 \
            "${REPO_ROOT}/test/tap/tests/${binary}" \
            "${STAGE_TEMP_DIR}/test/tap/tests/${binary}"
    done

    if [[ -e "${RUNTIME_CACHE_PATH}" || -L "${RUNTIME_CACHE_PATH}" ]]; then
        rm -rf -- "${RUNTIME_CACHE_PATH}"
    fi
    mv -- "${STAGE_TEMP_DIR}" "${RUNTIME_CACHE_PATH}"
    STAGE_TEMP_DIR=""

    printf 'Staged simulation runtime in %s.\n' "${RUNTIME_CACHE_PATH}"
}

# install
# Purpose: Restore a staged simulation runtime into the current checkout.
# Local use: Usually unnecessary; use it only to validate a staged cache payload.
# GitHub use: Installs files immediately after actions/cache restores the payload.
handle_install() {
    expect_no_arguments "install" "$#"
    require_command jq
    require_directory "${RUNTIME_CACHE_PATH}"
    refresh_binaries_manifest
    load_manifest_binaries
    verify_runtime_paths "${RUNTIME_CACHE_PATH}" "${SIMULATOR_BINARIES[@]}"

    cp -a "${RUNTIME_CACHE_PATH}/." "${REPO_ROOT}/"
    printf 'Installed simulation runtime from %s.\n' "${RUNTIME_CACHE_PATH}"
}

# help
# Purpose: Document the command interface, generated files, and common examples.
# Local use: Run `cluster-simulator-ci.bash help` when reproducing workflow steps.
# GitHub use: Not called by the workflow; it is maintainer-facing documentation.
handle_help() {
    expect_no_arguments "help" "$#"

    cat <<EOF
Usage: $0 <command> [arguments]

Commands:
  discover              Print registered simulation groups and write:
                          ${SIMULATOR_BINARIES_FILE}
  build                 Build ProxySQL with simulation support in ubuntu22_build.
  verify [group]        Verify all runtime files, or one matrix group.
  stage                 Create the cache payload at:
                          ${RUNTIME_CACHE_PATH}
  install               Restore that cache payload into the checkout.
  help                  Show this help.

Examples:
  $0 discover
  $0 build
  $0 verify
  $0 verify cluster_sim_galera-g1
EOF
}

command_name="${1:-help}"
if [[ "$#" -gt 0 ]]; then
    shift
fi

case "${command_name}" in
    discover) handle_discover "$@" ;;
    build) handle_build "$@" ;;
    _build) handle_internal_build "$@" ;;
    verify) handle_verify "$@" ;;
    stage) handle_stage "$@" ;;
    install) handle_install "$@" ;;
    help|-h|--help) handle_help "$@" ;;
    *) usage_error "Unknown command '${command_name}'." ;;
esac
