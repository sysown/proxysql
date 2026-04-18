#!/usr/bin/env bash
set -e
set -o pipefail

echo "=== mysqlx-e2e: Provisioning MySQL 8.4 sandbox with dbdeployer ==="

# Install dbdeployer if not already present
if ! command -v dbdeployer &>/dev/null; then
    echo "Installing dbdeployer..."
    curl -s https://raw.githubusercontent.com/ProxySQL/dbdeployer/master/scripts/dbdeployer-install.sh | bash
fi

# Download MySQL 8.4 (cached by dbdeployer)
echo "Downloading MySQL 8.4..."
dbdeployer downloads get-by-version 8.4 --newest --minimal --verbosity=0 || true

# Find the downloaded tarball
TARBALL=$(ls -t $HOME/opt/mysql/8.4.*.tar.xz 2>/dev/null | head -1)
if [ -z "$TARBALL" ]; then
    TARBALL=$(ls -t mysql-8.4.*.tar.xz 2>/dev/null | head -1)
fi
if [ -z "$TARBALL" ]; then
    echo "ERROR: MySQL 8.4 tarball not found"
    exit 1
fi

# Unpack if not already unpacked
VERSION=$(basename "$TARBALL" | sed 's/\.tar\.\(xz\|gz\|bz2\)//' | sed 's/mysql-//')
if [ ! -d "$HOME/opt/mysql/$VERSION" ]; then
    echo "Unpacking $TARBALL..."
    dbdeployer unpack "$TARBALL"
fi

# Deploy single sandbox if not already running
SANDBOX_DIR="$HOME/sandboxes/msb_${VERSION//./_}"
if [ ! -d "$SANDBOX_DIR" ]; then
    echo "Deploying MySQL $VERSION sandbox..."
    dbdeployer deploy single "$VERSION" --port=13306
fi

# Start the sandbox if not running
if [ -f "$SANDBOX_DIR/start" ]; then
    "$SANDBOX_DIR/start" || true
fi

# Wait for MySQL to be ready
echo "Waiting for MySQL sandbox to be ready..."
for i in $(seq 1 30); do
    if "$SANDBOX_DIR/use" -e "SELECT 1" &>/dev/null; then
        echo "MySQL sandbox is ready"
        break
    fi
    sleep 2
done

# Create test user (mysqlx_test)
"$SANDBOX_DIR/use" -e "
    CREATE USER IF NOT EXISTS 'mysqlx_test'@'%' IDENTIFIED WITH mysql_native_password BY 'mysqlx_test';
    GRANT ALL PRIVILEGES ON *.* TO 'mysqlx_test'@'%';
    FLUSH PRIVILEGES;
" || true

# Verify X Protocol is listening
echo "Verifying X Protocol on port 33060..."
for i in $(seq 1 30); do
    if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/33060" 2>/dev/null; then
        echo "X Protocol is listening on port 33060"
        exit 0
    fi
    sleep 2
done

echo "WARNING: X Protocol not detected on port 33060 after 60s"
echo "Attempting to enable mysqlx plugin..."
"$SANDBOX_DIR/use" -e "INSTALL PLUGIN mysqlx SONAME 'mysqlx.so';" 2>/dev/null || true
sleep 5

# Final check
if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/33060" 2>/dev/null; then
    echo "X Protocol is now available on port 33060"
    exit 0
fi

echo "ERROR: X Protocol not available on port 33060 — failing fast."
echo "Tests would otherwise pass spuriously against a missing infra."
exit 1
