#!/bin/bash
#
# setup_test_db.sh - Create/setup a test MySQL database with sample data
#
# Usage:
#   ./setup_test_db.sh [options] <command>
#   ./setup_test_db.sh <command> [options]
#
# Commands:
#   start               Setup/start test database
#   stop                Stop test database (Docker only)
#   status              Check status
#   connect             Connect to test database shell
#   reset               Drop/recreate test database
#
# Options:
#   --mode MODE         Mode: docker or native (default: auto-detect)
#   --host HOST         MySQL host (native mode, default: 127.0.0.1)
#   --port PORT         MySQL port (native mode, default: 3306)
#   --user USER         MySQL user (native mode, default: root)
#   --password PASS     MySQL password
#   --database DB       Database name (default: testdb)
#   -h, --help          Show help
#

set -e

# Default Docker configuration
CONTAINER_NAME="proxysql_mcp_test_mysql"
DOCKER_PORT="3307"
DOCKER_ROOT_PASSWORD="test123"
DOCKER_DATABASE="testdb"
DOCKER_VERSION="8.4"

# Default native MySQL configuration
NATIVE_HOST="127.0.0.1"
NATIVE_PORT="3306"
NATIVE_USER="root"
NATIVE_PASSWORD=""
DATABASE_NAME="testdb"

# Mode: auto, docker, or native
MODE="auto"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Detect which mode to use
detect_mode() {
    if [ "${MODE}" != "auto" ]; then
        echo "${MODE}"
        return 0
    fi

    # Check if Docker is available
    if command -v docker &> /dev/null; then
        # Check if user can run docker
        if docker info &> /dev/null; then
            echo "docker"
            return 0
        fi
    fi

    # Check if mysql client can connect locally
    if command -v mysql &> /dev/null; then
        # Try to connect with default credentials
        if MYSQL_PWD="" mysql -h "${NATIVE_HOST}" -P "${NATIVE_PORT}" -u "${NATIVE_USER}" -e "SELECT 1" &> /dev/null; then
            echo "native"
            return 0
        fi
    fi

    # Fall back to Docker
    echo "docker"
    return 0
}

# Execute MySQL command (native mode)
exec_mysql_native() {
    local sql="$1"
    local db="${2:-mysql}"

    if [ -z "${NATIVE_PASSWORD}" ]; then
        mysql -h "${NATIVE_HOST}" -P "${NATIVE_PORT}" -u "${NATIVE_USER}" "${db}" -e "${sql}"
    else
        MYSQL_PWD="${NATIVE_PASSWORD}" mysql -h "${NATIVE_HOST}" -P "${NATIVE_PORT}" -u "${NATIVE_USER}" "${db}" -e "${sql}"
    fi
}

# Create init SQL file
create_init_sql() {
    cat > "${SCRIPT_DIR}/init_testdb.sql" <<'EOSQL'
-- Test Database Schema for MCP Testing

CREATE DATABASE IF NOT EXISTS testdb;
USE testdb;

CREATE TABLE IF NOT EXISTS customers (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(100),
  email VARCHAR(100),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_email (email)
);

CREATE TABLE IF NOT EXISTS orders (
  id INT PRIMARY KEY AUTO_INCREMENT,
  customer_id INT NOT NULL,
  order_date DATE,
  total DECIMAL(10,2),
  status VARCHAR(20),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (customer_id) REFERENCES customers(id),
  INDEX idx_customer (customer_id),
  INDEX idx_status (status)
);

CREATE TABLE IF NOT EXISTS products (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(200),
  category VARCHAR(50),
  price DECIMAL(10,2),
  stock INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_category (category)
);

CREATE TABLE IF NOT EXISTS order_items (
  id INT PRIMARY KEY AUTO_INCREMENT,
  order_id INT NOT NULL,
  product_id INT NOT NULL,
  quantity INT DEFAULT 1,
  price DECIMAL(10,2),
  FOREIGN KEY (order_id) REFERENCES orders(id),
  FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Insert sample customers
INSERT INTO customers (name, email) VALUES
  ('Alice Johnson', 'alice@example.com'),
  ('Bob Smith', 'bob@example.com'),
  ('Charlie Brown', 'charlie@example.com'),
  ('Diana Prince', 'diana@example.com'),
  ('Eve Davis', 'eve@example.com');

-- Insert sample products
INSERT INTO products (name, category, price, stock) VALUES
  ('Laptop', 'Electronics', 999.99, 50),
  ('Mouse', 'Electronics', 29.99, 200),
  ('Keyboard', 'Electronics', 79.99, 150),
  ('Desk Chair', 'Furniture', 199.99, 75),
  ('Coffee Mug', 'Kitchen', 12.99, 500);

-- Insert sample orders
INSERT INTO orders (customer_id, order_date, total, status) VALUES
  (1, '2024-01-15', 1029.98, 'completed'),
  (2, '2024-01-16', 79.99, 'shipped'),
  (1, '2024-01-17', 212.98, 'pending'),
  (3, '2024-01-18', 199.99, 'completed'),
  (4, '2024-01-19', 1099.98, 'shipped');

-- Insert sample order items
INSERT INTO order_items (order_id, product_id, quantity, price) VALUES
  (1, 1, 1, 999.99),
  (1, 2, 1, 29.99),
  (2, 3, 1, 79.99),
  (3, 1, 1, 999.99),
  (3, 3, 1, 79.99),
  (3, 5, 3, 38.97),
  (4, 4, 1, 199.99),
  (5, 1, 1, 999.99),
  (5, 4, 1, 199.99);

-- Create a view
CREATE OR REPLACE VIEW customer_orders AS
SELECT
  c.id AS customer_id,
  c.name AS customer_name,
  COUNT(o.id) AS order_count,
  SUM(o.total) AS total_spent
FROM customers c
LEFT JOIN orders o ON c.id = o.customer_id
GROUP BY c.id, c.name;

-- Create a stored procedure
DELIMITER //
CREATE PROCEDURE get_customer_stats(IN customer_id INT)
BEGIN
  SELECT
    c.name,
    COUNT(o.id) AS order_count,
    COALESCE(SUM(o.total), 0) AS total_spent
  FROM customers c
  LEFT JOIN orders o ON c.id = o.customer_id
  WHERE c.id = customer_id;
END //
DELIMITER ;
EOSQL

    log_info "Created ${SCRIPT_DIR}/init_testdb.sql"
}

# ========== Docker Mode Functions ==========

start_docker() {
    log_step "Starting Docker MySQL container..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    # Check if container already exists
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_warn "Container '${CONTAINER_NAME}' already exists"
        read -p "Remove and recreate? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            docker rm -f "${CONTAINER_NAME}" > /dev/null 2>&1 || true
        else
            log_info "Starting existing container..."
            docker start "${CONTAINER_NAME}"
            return 0
        fi
    fi

    # Create init SQL if needed
    if [ ! -f "${SCRIPT_DIR}/init_testdb.sql" ]; then
        create_init_sql
    fi

    # Create and start container
    docker run -d \
        --name "${CONTAINER_NAME}" \
        -p "${DOCKER_PORT}:3306" \
        -e MYSQL_ROOT_PASSWORD="${DOCKER_ROOT_PASSWORD}" \
        -e MYSQL_DATABASE="${DOCKER_DATABASE}" \
        -v "${SCRIPT_DIR}/init_testdb.sql:/docker-entrypoint-initdb.d/01-init.sql:ro" \
        mysql:${DOCKER_VERSION} \
        --default-authentication-plugin=mysql_native_password

    log_info "Waiting for MySQL to be ready..."
    for i in {1..30}; do
        if docker exec "${CONTAINER_NAME}" mysqladmin ping -h localhost --silent 2>/dev/null; then
            log_info "MySQL is ready!"
            break
        fi
        sleep 1
    done

    show_docker_info
}

stop_docker() {
    log_step "Stopping Docker MySQL container..."

    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        docker stop "${CONTAINER_NAME}"
        log_info "Container stopped"
    else
        log_warn "Container '${CONTAINER_NAME}' is not running"
    fi

    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        read -p "Remove container '${CONTAINER_NAME}'? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            docker rm "${CONTAINER_NAME}"
            log_info "Container removed"
        fi
    fi
}

status_docker() {
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "${GREEN}●${NC} Docker container '${CONTAINER_NAME}' is ${GREEN}running${NC}"
        show_docker_info
        show_docker_tables
    elif docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "${YELLOW}○${NC} Docker container '${CONTAINER_NAME}' exists but is ${YELLOW}stopped${NC}"
        echo "Start with: $0 start --mode docker"
    else
        echo -e "${RED}✗${NC} Docker container '${CONTAINER_NAME}' does not exist"
        echo "Create with: $0 start --mode docker"
    fi
}

connect_docker() {
    if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_error "Container '${CONTAINER_NAME}' is not running"
        exit 1
    fi
    docker exec -it "${CONTAINER_NAME}" mysql -uroot -p"${DOCKER_ROOT_PASSWORD}" "${DOCKER_DATABASE}"
}

reset_docker() {
    log_step "Resetting Docker MySQL database..."
    if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_error "Container '${CONTAINER_NAME}' is not running"
        exit 1
    fi

    docker exec -i "${CONTAINER_NAME}" mysql -uroot -p"${DOCKER_ROOT_PASSWORD}" <<'EOSQL'
DROP DATABASE IF EXISTS testdb;
CREATE DATABASE testdb;
EOSQL

    # Re-run init script
    if [ -f "${SCRIPT_DIR}/init_testdb.sql" ]; then
        docker exec -i "${CONTAINER_NAME}" mysql -uroot -p"${DOCKER_ROOT_PASSWORD}" "${DOCKER_DATABASE}" < "${SCRIPT_DIR}/init_testdb.sql"
    fi

    log_info "Database reset complete"
}

show_docker_info() {
    echo ""
    echo "Connection Details:"
    echo "  Host: 127.0.0.1"
    echo "  Port: ${DOCKER_PORT}"
    echo "  User: root"
    echo "  Password: ${DOCKER_ROOT_PASSWORD}"
    echo "  Database: ${DOCKER_DATABASE}"
    echo ""
    echo "To configure ProxySQL MCP:"
    echo "  ./configure_mcp.sh --host 127.0.0.1 --port ${DOCKER_PORT}"
}

show_docker_tables() {
    echo "Database Info:"
    docker exec "${CONTAINER_NAME}" mysql -uroot -p"${DOCKER_ROOT_PASSWORD}" -e "
        SELECT
            table_name AS 'Table',
            table_rows AS 'Rows',
            ROUND((data_length + index_length) / 1024, 2) AS 'Size (KB)'
        FROM information_schema.tables
        WHERE table_schema = '${DOCKER_DATABASE}'
        ORDER BY table_name;
    " 2>/dev/null | column -t
}

# ========== Native Mode Functions ==========

start_native() {
    log_step "Setting up native MySQL database..."

    if ! command -v mysql &> /dev/null; then
        log_error "mysql client is not installed"
        exit 1
    fi

    # Test connection
    if ! test_native_connection; then
        log_error "Cannot connect to MySQL server"
        log_error "Please ensure MySQL is running and credentials are correct"
        log_error "  Host: ${NATIVE_HOST}"
        log_error "  Port: ${NATIVE_PORT}"
        log_error "  User: ${NATIVE_USER}"
        exit 1
    fi

    # Create init SQL and run it
    create_init_sql

    log_info "Creating database and tables..."
    if [ -z "${NATIVE_PASSWORD}" ]; then
        mysql -h "${NATIVE_HOST}" -P "${NATIVE_PORT}" -u "${NATIVE_USER}" < "${SCRIPT_DIR}/init_testdb.sql"
    else
        MYSQL_PWD="${NATIVE_PASSWORD}" mysql -h "${NATIVE_HOST}" -P "${NATIVE_PORT}" -u "${NATIVE_USER}" < "${SCRIPT_DIR}/init_testdb.sql"
    fi

    show_native_info
}

stop_native() {
    log_warn "Native mode: Database is not stopped (it's managed by MySQL server)"
    log_info "To remove the test database, use: $0 reset --mode native"
}

status_native() {
    if test_native_connection; then
        echo -e "${GREEN}●${NC} Native MySQL connection ${GREEN}successful${NC}"
        show_native_info
        show_native_tables
    else
        echo -e "${RED}✗${NC} Cannot connect to MySQL at ${NATIVE_HOST}:${NATIVE_PORT}"
        echo "  Host: ${NATIVE_HOST}"
        echo "  Port: ${NATIVE_PORT}"
        echo "  User: ${NATIVE_USER}"
    fi
}

connect_native() {
    local db="${DATABASE_NAME}"

    if [ -z "${NATIVE_PASSWORD}" ]; then
        mysql -h "${NATIVE_HOST}" -P "${NATIVE_PORT}" -u "${NATIVE_USER}" "${db}"
    else
        MYSQL_PWD="${NATIVE_PASSWORD}" mysql -h "${NATIVE_HOST}" -P "${NATIVE_PORT}" -u "${NATIVE_USER}" "${db}"
    fi
}

reset_native() {
    log_step "Resetting native MySQL database..."

    if ! test_native_connection; then
        log_error "Cannot connect to MySQL server"
        exit 1
    fi

    read -p "Drop database '${DATABASE_NAME}'? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Aborted"
        return 0
    fi

    exec_mysql_native "DROP DATABASE IF EXISTS ${DATABASE_NAME};"

    log_info "Database dropped. Recreate with: $0 start --mode native"
}

test_native_connection() {
    if [ -z "${NATIVE_PASSWORD}" ]; then
        MYSQL_PWD="" mysql -h "${NATIVE_HOST}" -P "${NATIVE_PORT}" -u "${NATIVE_USER}" -e "SELECT 1" &> /dev/null
    else
        MYSQL_PWD="${NATIVE_PASSWORD}" mysql -h "${NATIVE_HOST}" -P "${NATIVE_PORT}" -u "${NATIVE_USER}" -e "SELECT 1" &> /dev/null
    fi
}

show_native_info() {
    echo ""
    echo "Connection Details:"
    echo "  Host: ${NATIVE_HOST}"
    echo "  Port: ${NATIVE_PORT}"
    echo "  User: ${NATIVE_USER}"
    echo "  Password: ${NATIVE_PASSWORD:-<empty>}"
    echo "  Database: ${DATABASE_NAME}"
    echo ""
    echo "To configure ProxySQL MCP:"
    echo "  ./configure_mcp.sh --host ${NATIVE_HOST} --port ${NATIVE_PORT}"
}

show_native_tables() {
    echo "Database Info:"
    exec_mysql_native "
        SELECT
            table_name AS 'Table',
            table_rows AS 'Rows',
            ROUND((data_length + index_length) / 1024, 2) AS 'Size (KB)'
        FROM information_schema.tables
        WHERE table_schema = '${DATABASE_NAME}'
        ORDER BY table_name;
    " 2>/dev/null | column -t
}

# ========== Main Functions ==========

show_usage() {
    cat <<EOF
Usage: $0 [options] <command>

Commands:
  start               Setup/start test database
  stop                Stop test database (Docker only)
  status              Check status
  connect             Connect to test database shell
  reset               Drop/recreate test database
  create-sql          Create init_testdb.sql file

Options:
  --mode MODE         Mode: docker, native, or auto (default: auto)
  --host HOST         MySQL host for native mode (default: 127.0.0.1)
  --port PORT         MySQL port (default: 3306)
  --user USER         MySQL user (default: root)
  --password PASS     MySQL password
  --database DB       Database name (default: testdb)
  -h, --help          Show this help

Environment Variables:
  MYSQL_HOST          MySQL host (native mode)
  MYSQL_PORT          MySQL port (native mode)
  MYSQL_USER          MySQL user
  MYSQL_PASSWORD      MySQL password
  TEST_DB_NAME        Test database name

Examples:
  # Auto-detect mode and setup
  $0 start

  # Use native MySQL explicitly
  $0 start --mode native
  $0 start --mode native --host localhost --port 3306

  # Check status
  $0 status

  # Connect to test database
  $0 connect

  # Drop and recreate test database
  $0 reset

  # Stop Docker container
  $0 stop --mode docker
EOF
}

# Main script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load environment variables if set
[ -n "${MYSQL_HOST}" ] && NATIVE_HOST="${MYSQL_HOST}"
[ -n "${MYSQL_PORT}" ] && NATIVE_PORT="${MYSQL_PORT}"
[ -n "${MYSQL_USER}" ] && NATIVE_USER="${MYSQL_USER}"
[ -n "${MYSQL_PASSWORD}" ] && NATIVE_PASSWORD="${MYSQL_PASSWORD}"
[ -n "${TEST_DB_NAME}" ] && DATABASE_NAME="${TEST_DB_NAME}"

# Print environment variables
log_info "Environment Variables:"
echo "  MYSQL_HOST=${MYSQL_HOST:-<not set>}"
echo "  MYSQL_PORT=${MYSQL_PORT:-<not set>}"
echo "  MYSQL_USER=${MYSQL_USER:-<not set>}"
echo "  MYSQL_PASSWORD=${MYSQL_PASSWORD:-<not set>}"
echo "  TEST_DB_NAME=${TEST_DB_NAME:-<not set>}"
echo ""

# Parse arguments
COMMAND=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        --mode)
            MODE="$2"
            shift 2
            ;;
        --host)
            NATIVE_HOST="$2"
            shift 2
            ;;
        --port)
            if [ "$2" = "3307" ]; then
                DOCKER_PORT="$2"
            else
                NATIVE_PORT="$2"
            fi
            shift 2
            ;;
        --user)
            NATIVE_USER="$2"
            shift 2
            ;;
        --password)
            NATIVE_PASSWORD="$2"
            shift 2
            ;;
        --database)
            DATABASE_NAME="$2"
            DOCKER_DATABASE="$2"
            shift 2
            ;;
        start|stop|status|connect|reset|create-sql)
            COMMAND="$1"
            shift
            # Continue parsing options after command
            while [[ $# -gt 0 ]]; do
                case $1 in
                    --mode)
                        MODE="$2"
                        shift 2
                        ;;
                    --host)
                        NATIVE_HOST="$2"
                        shift 2
                        ;;
                    --port)
                        if [ "$2" = "3307" ]; then
                            DOCKER_PORT="$2"
                        else
                            NATIVE_PORT="$2"
                        fi
                        shift 2
                        ;;
                    --user)
                        NATIVE_USER="$2"
                        shift 2
                        ;;
                    --password)
                        NATIVE_PASSWORD="$2"
                        shift 2
                        ;;
                    --database)
                        DATABASE_NAME="$2"
                        DOCKER_DATABASE="$2"
                        shift 2
                        ;;
                    *)
                        log_error "Unknown option: $1"
                        show_usage
                        exit 1
                        ;;
                esac
            done
            break
            ;;
        *)
            log_error "Unknown option or command: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Check if command was provided
if [ -z "${COMMAND}" ]; then
    show_usage
    exit 1
fi

# Detect mode if auto
DETECTED_MODE=$(detect_mode)
if [ "${MODE}" = "auto" ]; then
    MODE="${DETECTED_MODE}"
fi

# Execute command based on mode
case "${COMMAND}" in
    start)
        if [ "${MODE}" = "docker" ]; then
            start_docker
        else
            start_native
        fi
        ;;
    stop)
        if [ "${MODE}" = "docker" ]; then
            stop_docker
        else
            stop_native
        fi
        ;;
    status)
        if [ "${MODE}" = "docker" ]; then
            status_docker
        else
            status_native
        fi
        ;;
    connect)
        if [ "${MODE}" = "docker" ]; then
            connect_docker
        else
            connect_native
        fi
        ;;
    reset)
        if [ "${MODE}" = "docker" ]; then
            reset_docker
        else
            reset_native
        fi
        ;;
    create-sql)
        create_init_sql
        ;;
esac
