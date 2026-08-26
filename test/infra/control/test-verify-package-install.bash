#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_BIN="$TMP_DIR/bin"
ZYPPER_ARGS_LOG="$TMP_DIR/zypper-args"
mkdir -p "$FAKE_BIN"
touch "$TMP_DIR/proxysql-3.1.11-1-opensuse15.x86_64.rpm"

cat >"$FAKE_BIN/rpm" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$FAKE_BIN/docker" <<'EOF'
#!/usr/bin/env bash
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

export FAKE_CONTAINER_BIN="$FAKE_BIN"
export ZYPPER_ARGS_LOG

PATH="$FAKE_BIN:$PATH" \
  "$ROOT_DIR/test/infra/control/verify-package-install.bash" \
  "$TMP_DIR/proxysql-3.1.11-1-opensuse15.x86_64.rpm"

expected='--non-interactive --no-gpg-checks install -y /tmp/pkg.rpm'
actual=$(<"$ZYPPER_ARGS_LOG")
if [[ "$actual" != "$expected" ]]; then
  echo "expected zypper arguments: $expected" >&2
  echo "actual zypper arguments:   $actual" >&2
  exit 1
fi

echo 'verify-package-install openSUSE unsigned-RPM test: PASS'
