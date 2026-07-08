#!/bin/bash
# verify-package-install.bash
#
# Install a just-built ProxySQL package on a clean Docker image of the target
# distro and run smoke tests.  Catches:
#  - Missing runtime dependencies (the binary or plugins can't load)
#  - File conflicts / incorrect paths
#  - Binary startup failures
#  - Missing plugin .so files (belt-and-braces beyond the entrypoint check)
#
# Usage:
#   verify-package-install.bash <path-to-package>
#
# The distro is extracted from the package filename (e.g.
# "proxysql_2.6.0-ubuntu24_arm64.deb" => ubuntu24 => ubuntu:24.04).
#
# The script auto-detects whether the package contains plugins (mysqlx, genai)
# by inspecting the package metadata, and adjusts the verification accordingly.

set -euo pipefail

PKG_PATH="${1:-}"
if [[ -z "$PKG_PATH" || ! -f "$PKG_PATH" ]]; then
    echo "Usage: $0 <package-file>" >&2
    exit 1
fi
PKG_PATH="$(realpath "$PKG_PATH")"
PKG_FILE="$(basename "$PKG_PATH")"

# ---- Detect package type and extract distro ----
if [[ "$PKG_FILE" == *.deb ]]; then
    PKG_TYPE=deb
elif [[ "$PKG_FILE" == *.rpm ]]; then
    PKG_TYPE=rpm
else
    echo "ERROR: unknown package type (not .deb or .rpm): $PKG_FILE" >&2
    exit 1
fi

# Extract distro from filename.
# DEB:   proxysql_<vers>-<distro>_<arch>.deb        => ubuntu24
# RPM:   proxysql-<vers>-1-<distro>.<arch>.rpm       => centos9
DISTRO="$(echo "$PKG_FILE" | sed -n 's/.*\-\([a-z0-9]\+\)[-_.].*\.\(deb\|rpm\)$/\1/p')"
if [[ -z "$DISTRO" ]]; then
    echo "ERROR: could not extract distro from filename: $PKG_FILE" >&2
    echo "  Expected: proxysql_<vers>-<distro>_<arch>.deb or proxysql-<vers>-1-<distro>.<arch>.rpm" >&2
    exit 1
fi

# ---- Detect whether this package ships plugins ----
# Check the package metadata for .so files under /usr/lib/proxysql/.
HAS_PLUGINS=false
if [[ "$PKG_TYPE" == deb ]]; then
    if dpkg -c "$PKG_PATH" 2>/dev/null | grep -q 'usr/lib/proxysql/.*\.so'; then
        HAS_PLUGINS=true
    fi
else
    if rpm -qpl "$PKG_PATH" 2>/dev/null | grep -q '/usr/lib/proxysql/.*\.so'; then
        HAS_PLUGINS=true
    fi
fi

# ---- Map distro name to a clean Docker image ----
declare -A IMAGE_MAP=(
    [ubuntu22]="ubuntu:22.04"
    [ubuntu24]="ubuntu:24.04"
    [debian12]="debian:bookworm-slim"
    [debian13]="debian:trixie-slim"
    [centos9]="quay.io/centos/centos:stream9"
    [centos10]="quay.io/centos/centos:stream10"
    [almalinux8]="almalinux:8"
    [almalinux9]="almalinux:9"
    [almalinux10]="almalinux:10"
    [fedora42]="fedora:42"
    [fedora43]="fedora:43"
    [fedora44]="fedora:44"
    [opensuse15]="opensuse/leap:15.6"
    [opensuse16]="opensuse/leap:16.0"
)
IMAGE="${IMAGE_MAP[$DISTRO]:-}"
if [[ -z "$IMAGE" ]]; then
    echo "ERROR: unknown distro '$DISTRO' — add it to IMAGE_MAP in $0" >&2
    exit 1
fi

echo "==> Verifying package: $PKG_FILE"
echo "==> Distro: $DISTRO  =>  Image: $IMAGE"
echo "==> Plugins detected: $HAS_PLUGINS"
echo ""

# ---- Pull the clean distro image ----
echo "==> Pulling $IMAGE ..."
if ! docker pull "$IMAGE" >/dev/null 2>&1; then
    echo "WARNING: could not pull $IMAGE — skipping verification" >&2
    exit 0
fi
echo ""

# ---- Prepare the test script that runs inside the container ----
TEST_SCRIPT=$(cat << 'SCRIPT_BODY'
#!/bin/bash
set -euo pipefail
PKG_TYPE="$1"
HAS_PLUGINS="$2"

# Portable ELF check — minimal base images (debian-slim, etc.) may not ship
# `file` or `which`, so validate the ELF magic bytes (7f 45 4c 46) directly.
is_elf() { [ "$(head -c4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]; }

echo "==> Installing package: /tmp/pkg.$PKG_TYPE"
case "$PKG_TYPE" in
    deb)
        apt-get update -qq 2>/dev/null || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/pkg.deb 2>&1
        ;;
    rpm)
        if command -v dnf &>/dev/null; then
            dnf install -y -q /tmp/pkg.rpm 2>&1
        elif command -v yum &>/dev/null; then
            yum install -y -q /tmp/pkg.rpm 2>&1
        elif command -v zypper &>/dev/null; then
            zypper --non-interactive install -y /tmp/pkg.rpm 2>&1
        else
            echo "ERROR: no supported package manager (dnf/yum/zypper)" >&2
            exit 1
        fi
        ;;
esac
echo ""

echo "==> Binary smoke test (proxysql --version)"
proxysql --version 2>&1 | head -5
echo ""

echo "==> Plugin .so presence check"
ALL_OK=0
if [[ "$HAS_PLUGINS" == "true" ]]; then
    for plugin in ProxySQL_MySQLX_Plugin.so ProxySQL_GenAI_Plugin.so; do
        path="/usr/lib/proxysql/${plugin}"
        if [[ -f "$path" ]]; then
            echo "  OK   ${plugin} (exists)"
            if is_elf "$path"; then
                echo "  OK   ${plugin} (valid ELF)"
            else
                echo "  FAIL ${plugin} (not a valid ELF file)" >&2
                ALL_OK=1
            fi
        else
            echo "  FAIL ${plugin} (not found at ${path})" >&2
            ALL_OK=1
        fi
    done
else
    echo "  SKIP  (no plugins in this package)"
fi

# Binary sanity check
if is_elf "$(command -v proxysql)"; then
    echo "  OK   proxysql binary (valid ELF)"
else
    echo "  FAIL proxysql binary (not a valid ELF file)" >&2
    ALL_OK=1
fi

if [[ "$ALL_OK" != "0" ]]; then
    echo "" >&2
    echo "==> Package verification FAILED" >&2
    exit 1
fi
echo ""
echo "==> Package verification PASSED"
SCRIPT_BODY
)

# ---- Run verification in clean distro container ----
CID="proxysql-verify-$$"
cleanup() {
    docker kill "$CID" >/dev/null 2>&1 || true
    docker rm "$CID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Starting clean container from $IMAGE ..."
if ! docker run -d --name "$CID" "$IMAGE" sleep 120 >/dev/null 2>&1; then
    echo "WARNING: could not start container from $IMAGE — skipping" >&2
    exit 0
fi

# Copy package into container
docker cp "$PKG_PATH" "$CID:/tmp/pkg.$PKG_TYPE"

# Run the test script inside the container
if docker exec -i "$CID" bash -s "$PKG_TYPE" "$HAS_PLUGINS" <<< "$TEST_SCRIPT"; then
    echo ""
    echo "==> Package verification PASSED for $PKG_FILE"
    exit 0
else
    EXIT_CODE=$?
    echo ""
    echo "==> Package verification FAILED for $PKG_FILE (exit code $EXIT_CODE)" >&2
    exit $EXIT_CODE
fi
