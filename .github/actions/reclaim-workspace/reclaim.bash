#!/usr/bin/env bash
set -euo pipefail

# Hosted runners are disposable. Only persistent self-hosted workspaces need
# privileged ownership repair after a container writes into a bind mount.
if [[ "${RUNNER_ENVIRONMENT:-}" != self-hosted ]]; then
    exit 0
fi

workspace="${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is not set}"
if [[ "${workspace}" != /* || -L "${workspace}" || ! -d "${workspace}" ]]; then
    echo '::error::refusing to reclaim an invalid workspace path' >&2
    exit 1
fi
workspace="$(realpath -e -- "${workspace}")"
if [[ "${workspace}" == / ]]; then
    echo '::error::refusing to reclaim the filesystem root' >&2
    exit 1
fi

runner_uid="$(id -u)"
runner_gid="$(id -g)"
echo ">>> reclaiming self-hosted workspace ownership: ${workspace}"
# -h keeps links from changing ownership of targets outside the workspace.
sudo -n chown -hR "${runner_uid}:${runner_gid}" "${workspace}"
sudo -n chmod -R u+rwX "${workspace}"
remaining="$(find "${workspace}" ! -uid "${runner_uid}" -print -quit)"
if [[ -n "${remaining}" ]]; then
    echo "::error::workspace still contains a foreign-owned path: ${remaining}" >&2
    exit 1
fi
