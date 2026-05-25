#!/bin/bash

# docker_fs_exec <command> <path>
# Run a command against a host path through a temporary container.
# Use this for host-mounted files/directories whose ownership was set by container users and
# cannot be reliably modified from the host user context.
# Example: docker_fs_exec "rm -f proxysql/proxysql.db" "${INFRA_LOGS_PATH}/${INFRA_ID}"
docker_fs_exec() {
    local fs_command="$1"
    local target_path="$2"

    if [ -z "${fs_command}" ] || [ -z "${target_path}" ]; then
        echo "docker_fs_exec requires a command and a path" >&2
        return 1
    fi

    # Work around host-mounted paths owned by container users different from the host user.
    # Alpine/busybox would also work here, but proxysql-ci-base:latest is already pulled in this workflow.
    docker run --rm \
        -v "${target_path}:/target" \
        proxysql-ci-base:latest \
        /bin/sh -ec "cd /target && ${fs_command}"
}
