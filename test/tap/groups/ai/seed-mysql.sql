-- AI Group MySQL Test Data Seeding
-- Creates tables needed by AI/MCP tests
-- This is executed by setup-infras.bash as part of AI group infrastructure setup

CREATE DATABASE IF NOT EXISTS test;
USE test;

CREATE TABLE IF NOT EXISTS tap_mysql_static_customers (
  customer_id INT PRIMARY KEY,
  email VARCHAR(128) NOT NULL UNIQUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tap_mysql_static_orders (
  order_id INT PRIMARY KEY,
  customer_id INT NOT NULL,
  total_amount DECIMAL(10,2) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_tap_mysql_orders_customer
    FOREIGN KEY (customer_id) REFERENCES tap_mysql_static_customers(customer_id)
);

INSERT INTO tap_mysql_static_customers(customer_id, email) VALUES
  (1, 'seed-mysql-a@example.com'),
  (2, 'seed-mysql-b@example.com')
ON DUPLICATE KEY UPDATE email=VALUES(email);

INSERT INTO tap_mysql_static_orders(order_id, customer_id, total_amount) VALUES
  (101, 1, 42.50),
  (102, 2, 18.99)
ON DUPLICATE KEY UPDATE total_amount=VALUES(total_amount);

FLUSH TABLES;
