#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_BIN="$TMP_DIR/bin"
DOCKER_PULL_LOG="$TMP_DIR/docker-pulls"
ZYPPER_ARGS_LOG="$TMP_DIR/zypper-args"
mkdir -p "$FAKE_BIN"

cat >"$FAKE_BIN/rpm" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$FAKE_BIN/dpkg" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$FAKE_BIN/docker" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == pull ]]; then
  printf '%s\n' "$2" >>"$DOCKER_PULL_LOG"
fi
if [[ "${FAKE_DOCKER_FAIL_COMMAND:-}" == "$1" ]]; then
  exit 1
fi
case "$1" in
  pull|run|cp|kill|rm)
    exit 0
    ;;
  exec)
    shift
    [[ "${1:-}" == "-i" ]] && shift
    shift
    PATH="$FAKE_CONTAINER_BIN:/usr/bin:/bin" "$@"
    ;;
  *)
    echo "unexpected docker command: $*" >&2
    exit 1
    ;;
esac
EOF

cat >"$FAKE_BIN/apt-get" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$FAKE_BIN/zypper" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >"$ZYPPER_ARGS_LOG"
[[ " $* " == *" --no-gpg-checks "* ]]
EOF

cat >"$FAKE_BIN/proxysql" <<'EOF'
#!/usr/bin/env bash
echo 'ProxySQL version 3.1.11'
EOF

cat >"$FAKE_BIN/od" <<'EOF'
#!/usr/bin/env bash
echo ' 7f 45 4c 46'
EOF

chmod +x "$FAKE_BIN"/*

export DOCKER_PULL_LOG
export FAKE_CONTAINER_BIN="$FAKE_BIN"
export ZYPPER_ARGS_LOG

cases=(
  'proxysql_3.1.11-ubuntu24_arm64.deb|ubuntu:24.04'
  'proxysql_3.1.11-dbg-debian12_amd64.deb|debian:bookworm-slim'
  'proxysql_3.1.11-ubuntu22-clang_amd64.deb|ubuntu:22.04'
  'proxysql-3.1.11-1-almalinux9.aarch64.rpm|almalinux:9'
  'proxysql-3.1.11-1-dbg-centos9.x86_64.rpm|quay.io/centos/centos:stream9'
  'proxysql-3.1.11-1-opensuse15-clang.x86_64.rpm|opensuse/leap:15.6'
)

for test_case in "${cases[@]}"; do
  package=${test_case%%|*}
  expected_image=${test_case#*|}
  package_path="$TMP_DIR/$package"
  touch "$package_path"

  PATH="$FAKE_BIN:$PATH" \
    "$ROOT_DIR/test/infra/control/verify-package-install.bash" "$package_path" \
    >/dev/null

  actual_image=$(tail -1 "$DOCKER_PULL_LOG")
  if [[ "$actual_image" != "$expected_image" ]]; then
    echo "$package: expected image $expected_image, got $actual_image" >&2
    exit 1
  fi
done

expected_zypper='--non-interactive --no-gpg-checks install -y /tmp/pkg.rpm'
actual_zypper=$(<"$ZYPPER_ARGS_LOG")
if [[ "$actual_zypper" != "$expected_zypper" ]]; then
  echo "expected zypper arguments: $expected_zypper" >&2
  echo "actual zypper arguments:   $actual_zypper" >&2
  exit 1
fi

failure_package="$TMP_DIR/proxysql-3.1.11-1-opensuse15-clang.x86_64.rpm"
for failed_command in pull run; do
  if PATH="$FAKE_BIN:$PATH" FAKE_DOCKER_FAIL_COMMAND="$failed_command" \
    "$ROOT_DIR/test/infra/control/verify-package-install.bash" "$failure_package" \
    >/dev/null 2>&1; then
    echo "docker $failed_command failure must fail package verification" >&2
    exit 1
  fi
done

echo 'package filename, unsigned RPM, and fail-closed tests: PASS'
