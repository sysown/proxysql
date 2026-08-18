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
            ldd_output=$(ldd "${binary}")
            printf "%s\\n" "${ldd_output}"
            ! printf "%s\\n" "${ldd_output}" | grep -q "not found"
            for library in libssl.so.3 libcrypto.so.3; do
                resolved_path=
                while IFS= read -r dependency; do
                    case "${dependency}" in
                        *"${library} => "*)
                            resolved_path=${dependency#*=> }
                            resolved_path=${resolved_path%% *}
                            break
                            ;;
                    esac
                done <<EOF
${ldd_output}
EOF
                case "${resolved_path}" in
                    "${root_dir}"/lib/*) ;;
                    *)
                        echo "ERROR: ${library} did not resolve from the tarball" >&2
                        exit 1
                        ;;
                esac
            done
            "${launcher}" --version
        ' sh "${archive_name}"
done
