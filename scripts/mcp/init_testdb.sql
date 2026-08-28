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
