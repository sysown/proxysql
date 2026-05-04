# ProxySQL SQLite3 Server

## Overview

ProxySQL provides a built-in SQLite3 server that acts as a MySQL-to-SQLite gateway. When started with the `--sqlite3-server` option, it listens on port 6030 (by default) and translates MySQL protocol queries into SQLite commands, converting the responses back to MySQL format for the client.

This is the magic of the feature: MySQL clients can use standard MySQL commands to interact with a full SQLite database, with ProxySQL handling all the protocol translation behind the scenes.

## Important Distinction

- **Admin Interface**: Always enabled, listens on port 6032, provides access to config/stats/monitor databases
- **SQLite3 Server**: Optional, requires `--sqlite3-server`, listens on port 6030, provides access to empty `main` schema

## Usage

### Starting ProxySQL

```bash
# Start with SQLite3 server on default port 6030
proxysql --sqlite3-server
```

### Connecting

```bash
# Connect using standard mysql client with valid MySQL credentials
mysql -h 127.0.0.1 -P 6030 -u your_mysql_user -p
```

Authentication uses the `mysql_users` table in ProxySQL's configuration.

## What You Get

The SQLite3 server provides:
- **Single Schema**: `main` (initially empty)
- **Full SQLite Capabilities**: All SQLite features are available
- **MySQL Protocol**: Standard MySQL client compatibility
- **Translation Layer**: Automatic MySQL-to-SQLite conversion

## Common Operations

### Basic SQL

```sql
-- Check current database
SELECT database();

-- Create tables
CREATE TABLE users (id INT, name TEXT);

-- Insert data
INSERT INTO users VALUES (1, 'john');

-- Query data
SELECT * FROM users;
```

### Vector Search (with sqlite-vec)

```sql
-- Create vector table
CREATE VECTOR TABLE vec_data (vector float[128]);

-- Insert vector
INSERT INTO vec_data(rowid, vector) VALUES (1, json('[0.1, 0.2, 0.3,...,0.128]'));

-- Search similar vectors
SELECT rowid, distance FROM vec_data
WHERE vector MATCH json('[0.1, 0.2, 0.3,...,0.128]');
```

### Available Databases

```sql
-- Show available databases
SHOW DATABASES;

-- Results:
+----------+
| database |
+----------+
| main     |
+----------+
```

### Use Cases

1. **Data Analysis**: Store and analyze temporary data
2. **Vector Search**: Perform similarity searches with sqlite-vec
3. **Testing**: Test SQLite features with MySQL clients
4. **Prototyping**: Quick data storage and retrieval
5. **Custom Applications**: Build applications using SQLite with MySQL tools

## Limitations

- Only one database: `main`
- No access to ProxySQL's internal databases (config, stats, monitor)
- Tables and data are temporary (unless you create external databases)

## Security

- Bind to localhost for security
- Use proper MySQL user authentication
- Consider firewall restrictions
- Configure appropriate user permissions in `mysql_users` table

## Examples

### Simple Analytics

```sql
CREATE TABLE events (
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT,
    metrics JSON
);

INSERT INTO events (event_type, metrics)
VALUES ('login', json('{"user_id": 123, "success": true}'));

SELECT event_type,
       json_extract(metrics, '$.user_id') as user_id
FROM events;
```

### Time Series Data

```sql
CREATE TABLE metrics (
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    cpu_usage REAL,
    memory_usage REAL
);

-- Insert time series data
INSERT INTO metrics (cpu_usage, memory_usage) VALUES (45.2, 78.5);

-- Query recent data
SELECT * FROM metrics
WHERE timestamp > datetime('now', '-1 hour');
```

## Connection Testing

```bash
# Test connection
mysql -h 127.0.0.1 -P 6030 -u your_mysql_user -p -e "SELECT 1"

# Expected output
+---+
| 1 |
+---+
| 1 |
+---+
```