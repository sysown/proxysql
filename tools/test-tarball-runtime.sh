#!/usr/bin/env bash
set -euo pipefail

shopt -s nullglob
archives=(binaries/proxysql-*.tar.gz)
if [[ ${#archives[@]} -ne 1 ]]; then
    echo "ERROR: expected exactly one tarball in binaries/, found ${#archives[@]}" >&2
    printf '  %s\n' "${archives[@]:-<none>}" >&2
    exit 1
fi

archive_path=$(readlink -f "${archives[0]}")
archive_dir=$(dirname "${archive_path}")
archive_name=$(basename "${archive_path}")
read -r -a images <<< "${TARBALL_TEST_IMAGES:-almalinux:9 debian:12 ubuntu:22.04}"

for image in "${images[@]}"; do
    echo "==> Testing ${archive_name} on ${image}"
    docker run --rm \
        --mount "type=bind,src=${archive_dir},dst=/artifacts,readonly" \
        --entrypoint /bin/sh \
        "${image}" \
        -eu -c '
            archive="/artifacts/$1"
            workdir=$(mktemp -d)
            trap "rm -rf \"${workdir}\"" EXIT
            tar -xzf "${archive}" -C "${workdir}"

            launcher=$(find "${workdir}" -type f -path "*/bin/proxysql" -print -quit)
            [ -n "${launcher}" ] || { echo "ERROR: tarball launcher is missing" >&2; exit 1; }
            root_dir=$(dirname "$(dirname "${launcher}")")
            binary="${root_dir}/bin/proxysql.bin"
            [ -x "${binary}" ] || { echo "ERROR: tarball binary is missing" >&2; exit 1; }

            export LD_LIBRARY_PATH="${root_dir}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
            check_runtime_linkage() {
                candidate=$1
                ldd_output=$(ldd "${candidate}")
                printf "%s\\n" "${ldd_output}"

                if printf "%s\\n" "${ldd_output}" | grep -q "not found"; then
                    echo "ERROR: unresolved runtime dependency in ${candidate}" >&2
                    exit 1
                fi
                if printf "%s\\n" "${ldd_output}" | grep -Eq "lib(ssl|crypto)\\.so"; then
                    echo "ERROR: forbidden OpenSSL runtime dependency in ${candidate}" >&2
                    exit 1
                fi
            }

            check_runtime_linkage "${binary}"

            plugin_dir="${root_dir}/lib/proxysql"
            if [ -d "${plugin_dir}" ]; then
                for plugin in "${plugin_dir}"/*.so; do
                    [ -f "${plugin}" ] || continue
                    check_runtime_linkage "${plugin}"
                done
            fi
            "${launcher}" --version
        ' sh "${archive_name}"
done
