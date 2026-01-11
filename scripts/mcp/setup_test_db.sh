#!/bin/bash
#
# setup_test_db.sh - Create/start a test MySQL database with sample data
#
# Usage:
#   ./setup_test_db.sh start    # Start test MySQL container
#   ./setup_test_db.sh stop     # Stop and remove test MySQL container
#   ./setup_test_db.sh status   # Check status of test MySQL
#   ./setup_test_db.sh connect  # Connect to test MySQL
#

set -e

# Configuration
CONTAINER_NAME="proxysql_mcp_test_mysql"
MYSQL_PORT="3307"
MYSQL_ROOT_PASSWORD="test123"
MYSQL_DATABASE="testdb"
MYSQL_VERSION="8.4"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is available
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        log_info "Please install Docker or use an existing MySQL server"
        exit 1
    fi
}

# Start test MySQL container
start_mysql() {
    log_info "Starting test MySQL container..."

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

    # Create and start container
    docker run -d \
        --name "${CONTAINER_NAME}" \
        -p "${MYSQL_PORT}:3306" \
        -e MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD}" \
        -e MYSQL_DATABASE="${MYSQL_DATABASE}" \
        -v "${SCRIPT_DIR}/init_testdb.sql:/docker-entrypoint-initdb.d/01-init.sql:ro" \
        mysql:${MYSQL_VERSION} \
        --default-authentication-plugin=mysql_native_password

    log_info "Waiting for MySQL to be ready..."
    for i in {1..30}; do
        if docker exec "${CONTAINER_NAME}" mysqladmin ping -h localhost --silent 2>/dev/null; then
            log_info "MySQL is ready!"
            break
        fi
        sleep 1
    done

    # Run initialization script if not via volume
    if [ ! -f "${SCRIPT_DIR}/init_testdb.sql" ]; then
        log_info "Creating test schema and data..."
        sleep 5  # Give MySQL extra time to fully start
        docker exec -i "${CONTAINER_NAME}" mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" "${MYSQL_DATABASE}" <<'EOSQL'
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
    fi

    log_info "Test MySQL database is ready!"
    log_info "  Host: 127.0.0.1"
    log_info "  Port: ${MYSQL_PORT}"
    log_info "  User: root"
    log_info "  Password: ${MYSQL_ROOT_PASSWORD}"
    log_info "  Database: ${MYSQL_DATABASE}"
}

# Stop and remove test MySQL container
stop_mysql() {
    log_info "Stopping test MySQL container..."
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

# Check status of test MySQL
status_mysql() {
    log_info "Checking test MySQL status..."

    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "${GREEN}●${NC} Container '${CONTAINER_NAME}' is ${GREEN}running${NC}"

        # Show connection details
        echo ""
        echo "Connection Details:"
        echo "  Host: 127.0.0.1"
        echo "  Port: ${MYSQL_PORT}"
        echo "  User: root"
        echo "  Password: ${MYSQL_ROOT_PASSWORD}"
        echo "  Database: ${MYSQL_DATABASE}"

        # Test connection
        if docker exec "${CONTAINER_NAME}" mysqladmin ping -h localhost --silent 2>/dev/null; then
            echo -e "  Status: ${GREEN}Accepting connections${NC}"
        else
            echo -e "  Status: ${RED}Not responding${NC}"
        fi

        # Show database info
        echo ""
        echo "Database Info:"
        docker exec "${CONTAINER_NAME}" mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -e "
            SELECT
                table_name AS 'Table',
                table_rows AS 'Rows',
                ROUND((data_length + index_length) / 1024, 2) AS 'Size (KB)'
            FROM information_schema.tables
            WHERE table_schema = '${MYSQL_DATABASE}'
            ORDER BY table_name;
        " 2>/dev/null | column -t
    elif docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "${YELLOW}○${NC} Container '${CONTAINER_NAME}' exists but is ${YELLOW}stopped${NC}"
        echo "Start with: $0 start"
    else
        echo -e "${RED}✗${NC} Container '${CONTAINER_NAME}' does not exist"
        echo "Create with: $0 start"
    fi
}

# Connect to test MySQL
connect_mysql() {
    log_info "Connecting to test MySQL..."
    if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_error "Container '${CONTAINER_NAME}' is not running"
        exit 1
    fi

    docker exec -it "${CONTAINER_NAME}" mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" "${MYSQL_DATABASE}"
}

# Create initialization SQL file
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
EOSQL

    log_info "Created ${SCRIPT_DIR}/init_testdb.sql"
}

# Main script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "${1:-start}" in
    start)
        check_docker
        start_mysql
        ;;
    stop)
        check_docker
        stop_mysql
        ;;
    status)
        check_docker
        status_mysql
        ;;
    connect)
        check_docker
        connect_mysql
        ;;
    create-sql)
        create_init_sql
        ;;
    *)
        echo "Usage: $0 {start|stop|status|connect|create-sql}"
        echo ""
        echo "Commands:"
        echo "  start      - Start test MySQL container"
        echo "  stop       - Stop test MySQL container"
        echo "  status     - Check status of test MySQL"
        echo "  connect    - Connect to test MySQL shell"
        echo "  create-sql - Create init_testdb.sql file"
        exit 1
        ;;
esac
