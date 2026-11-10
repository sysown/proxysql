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

# Extract distro from filename after removing the extension, architecture,
# and optional compiler suffix.
# DEB: proxysql_<vers>-<distro>[-clang]_<arch>.deb  => ubuntu24
# RPM: proxysql-<vers>-1-<distro>[-clang].<arch>.rpm => centos9
PKG_STEM="${PKG_FILE%.deb}"
PKG_STEM="${PKG_STEM%.rpm}"
PKG_STEM="${PKG_STEM%_amd64}"
PKG_STEM="${PKG_STEM%_arm64}"
PKG_STEM="${PKG_STEM%.x86_64}"
PKG_STEM="${PKG_STEM%.aarch64}"
PKG_STEM="${PKG_STEM%-clang}"
DISTRO="${PKG_STEM##*-}"
if [[ -z "$DISTRO" ]]; then
    echo "ERROR: could not extract distro from filename: $PKG_FILE" >&2
    echo "  Expected: proxysql_<vers>-<distro>[-clang]_<arch>.deb or proxysql-<vers>-1-<distro>[-clang].<arch>.rpm" >&2
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
# A case table also works with macOS's /bin/bash 3.2 (no associative arrays).
case "$DISTRO" in
    ubuntu22) IMAGE="ubuntu:22.04" ;;
    ubuntu24) IMAGE="ubuntu:24.04" ;;
    ubuntu26) IMAGE="ubuntu:26.04" ;;
    debian12) IMAGE="debian:bookworm-slim" ;;
    debian13) IMAGE="debian:trixie-slim" ;;
    centos9) IMAGE="quay.io/centos/centos:stream9" ;;
    centos10) IMAGE="quay.io/centos/centos:stream10" ;;
    almalinux8) IMAGE="almalinux:8" ;;
    almalinux9) IMAGE="almalinux:9" ;;
    almalinux10) IMAGE="almalinux:10" ;;
    fedora42) IMAGE="fedora:42" ;;
    fedora43) IMAGE="fedora:43" ;;
    fedora44) IMAGE="fedora:44" ;;
    opensuse16) IMAGE="opensuse/leap:16.0" ;;
    *) IMAGE="" ;;
esac
if [[ -z "$IMAGE" ]]; then
    echo "ERROR: unknown distro '$DISTRO' — add it to the image mapping in $0" >&2
    exit 1
fi

echo "==> Verifying package: $PKG_FILE"
echo "==> Distro: $DISTRO  =>  Image: $IMAGE"
echo "==> Plugins detected: $HAS_PLUGINS"
echo ""

# ---- Pull the clean distro image ----
echo "==> Pulling $IMAGE ..."
if ! docker pull "$IMAGE" >/dev/null 2>&1; then
    echo "ERROR: could not pull $IMAGE" >&2
    exit 1
fi
echo ""

# ---- Prepare the test script that runs inside the container ----
# read avoids Bash 3.2's command-substitution/heredoc parser limitations.
IFS= read -r -d '' TEST_SCRIPT << 'SCRIPT_BODY' || true
#!/bin/bash
set -euo pipefail
PKG_TYPE="$1"
HAS_PLUGINS="$2"
DIAG="${3:-0}"

# Forensic phase markers only; never alter a package-command exit status.
diag_now() {
    local up="" whole frac
    if [[ "$(uname -s 2>/dev/null)" == "Linux" ]] && read -r up _ </proc/uptime 2>/dev/null && [[ "$up" == *.* ]]; then
        whole="${up%%.*}"
        frac="${up#*.}00"
        printf '%s.%s' "$whole" "${frac:0:2}"
    else
        printf 'UNAVAILABLE'
    fi
}
diag_begin() {
    [[ "$DIAG" == "1" ]] || return 0
    printf 'DIAG PHASE BEGIN %s BOOTTIME=%ss\n' "$1" "$(diag_now)" || true
}
diag_end() {
    [[ "$DIAG" == "1" ]] || return 0
    printf 'DIAG PHASE END %s RC=%s BOOTTIME=%ss\n' "$1" "$2" "$(diag_now)" || true
}

# Portable ELF check — minimal base images (debian-slim, etc.) may not ship
# `file` or `which`, so validate the ELF magic bytes (7f 45 4c 46) directly.
is_elf() { [ "$(head -c4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]; }

echo "==> Installing package: /tmp/pkg.$PKG_TYPE"
case "$PKG_TYPE" in
    deb)
        diag_begin apt_update
        rc=0
        if [[ "$DIAG" == "1" ]]; then
            apt-get update -qq 2>&1 || rc=$?
        else
            apt-get update -qq 2>/dev/null || rc=$?
        fi
        diag_end apt_update "$rc"
        diag_begin apt_install
        rc=0
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/pkg.deb 2>&1 || rc=$?
        diag_end apt_install "$rc"
        [[ "$rc" == "0" ]] || exit "$rc"
        ;;
    rpm)
        diag_begin rpm_install
        rc=0
        if command -v dnf &>/dev/null; then
            dnf install -y -q /tmp/pkg.rpm 2>&1 || rc=$?
        elif command -v yum &>/dev/null; then
            yum install -y -q /tmp/pkg.rpm 2>&1 || rc=$?
        elif command -v zypper &>/dev/null; then
            # Release-build RPMs are intentionally unsigned until the
            # release-kraken signing step.  Keep dependency resolution and
            # installation strict while deferring only the signature gate.
            zypper --non-interactive --no-gpg-checks install -y /tmp/pkg.rpm 2>&1 || rc=$?
        else
            echo "ERROR: no supported package manager (dnf/yum/zypper)" >&2
            exit 1
        fi
        diag_end rpm_install "$rc"
        [[ "$rc" == "0" ]] || exit "$rc"
        ;;
esac
echo ""

echo "==> Binary smoke test (proxysql --version)"
diag_begin proxysql_version
rc=0
proxysql --version 2>&1 | head -5 || rc=$?
diag_end proxysql_version "$rc"
[[ "$rc" == "0" ]] || exit "$rc"
echo ""

echo "==> Plugin .so presence check"
diag_begin plugin_checks
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

diag_end plugin_checks "$ALL_OK"
if [[ "$ALL_OK" != "0" ]]; then
    echo "" >&2
    echo "==> Package verification FAILED" >&2
    exit 1
fi
echo ""
echo "==> Package verification PASSED"
SCRIPT_BODY

# ---- Run verification in clean distro container ----
CID="proxysql-verify-$$"

# CI-Linux bounded failure snapshot (measurement only; never gates cleanup).
DIAG=0
if [[ "${GITHUB_ACTIONS:-}" == "true" && "$(uname -s 2>/dev/null)" == "Linux" ]]; then
    DIAG=1
fi

diag_container_state() {
    local rc=0 out=""
    if ! timeout --version 2>/dev/null | grep -q GNU; then
        printf 'DIAGNOSTIC_UNAVAILABLE: GNU timeout missing; container metadata skipped\n'
        return 0
    fi
    printf '==> DIAG container state for %s (bounded)\n' "$CID"
    out="$(timeout --kill-after=1s 4s docker inspect --format '{{.State.Status}} running={{.State.Running}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} started={{.State.StartedAt}} finished={{.State.FinishedAt}}' "$CID" 2>&1)" || rc=$?
    printf 'DIAG inspect rc=%s %s\n' "$rc" "$out"
    [[ "$rc" == "0" ]] || printf 'DIAGNOSTIC_UNAVAILABLE: docker inspect rc=%s\n' "$rc"
    rc=0
    out="$(timeout --kill-after=1s 4s docker top "$CID" -eo pid,comm 2>&1 | sed -n '1,40p')" || rc=$?
    printf 'DIAG top rc=%s\n%s\n' "$rc" "$out"
    [[ "$rc" == "0" ]] || printf 'DIAGNOSTIC_UNAVAILABLE: docker top rc=%s\n' "$rc"
    return 0
}

cleanup() {
    local rc=$?
    if [[ "$DIAG" == "1" && "$rc" != "0" ]]; then
        diag_container_state || true
    fi
    docker kill "$CID" >/dev/null 2>&1 || true
    docker rm "$CID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Starting clean container from $IMAGE ..."
if ! docker run -d --name "$CID" "$IMAGE" sleep 120 >/dev/null 2>&1; then
    echo "ERROR: could not start container from $IMAGE" >&2
    exit 1
fi

# Copy package into container
docker cp "$PKG_PATH" "$CID:/tmp/pkg.$PKG_TYPE"

# Run the test script inside the container
if docker exec -i "$CID" bash -s "$PKG_TYPE" "$HAS_PLUGINS" "$DIAG" <<< "$TEST_SCRIPT"; then
    echo ""
    echo "==> Package verification PASSED for $PKG_FILE"
    exit 0
else
    EXIT_CODE=$?
    echo ""
    echo "==> Package verification FAILED for $PKG_FILE (exit code $EXIT_CODE)" >&2
    exit $EXIT_CODE
fi
