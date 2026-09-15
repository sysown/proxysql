# Troubleshooting `runtime_mysql_users` Desynchronization and Access Denied Errors

## Problem Overview

In production environments running connection pooling libraries (such as Spring Boot HikariCP), client applications may suddenly fail to establish connections to ProxySQL with authentication errors:

```text
ProxySQL Error: Access denied for user 'app-svc'@'10.x.x.x' (using password: YES)
This error often occurs even when:
1. The user exists in the backend MySQL mysql.user table.
2. Direct connection to the backend database succeeds with the same credentials.
3. The row appears to exist in mysql_users inside ProxySQL's Admin interface.
```

## Root Cause
ProxySQL operates as an authenticating reverse proxy:

1. Frontend Authentication: Incoming client handshakes on port 6033 are authenticated at the ProxySQL memory layer using runtime_mysql_users before any query is routed or multiplexed to backend hostgroups.
2. Hash Table Divergence: Partial configuration reloads or updating rows directly in mysql_users without an explicit purge can leave stale or duplicate password hashes inside ProxySQL's in-memory authentication hash tables.
3. Simply running LOAD MYSQL USERS TO RUNTIME; without first clearing stale user entries can retain conflicted in-memory references.


## Production-Safe Recovery Flow

To resolve stale user authentication entries without restarting ProxySQL or dropping connections for other active users, follow this atomic purge and reload procedure:

## 1. In-Memory & Physical Backup (Recommended)
Before modifying user tables, create a snapshot of the current configuration:


-- Connect to ProxySQL Admin Interface (Port 6032)
```
SQL
CREATE TABLE mysql_users_backup_recovery AS SELECT * FROM mysql_users;
```
Optionally back up the physical SQLite configuration file on the host:


```
Bash
sudo cp /var/lib/proxysql/proxysql.db /var/lib/proxysql/proxysql.db.bak
```


## 2. Atomic Purge, Re-Insert, and Reload
Execute the following sequence in the Admin interface (Port 6032):

```
SQL
-- Step A: Purge the target user from mysql_users and runtime memory
DELETE FROM mysql_users WHERE username = 'target_service_user';
LOAD MYSQL USERS TO RUNTIME;
```

-- Step B: Re-insert clean user configuration mapped to the target hostgroup


```
SQL

INSERT INTO mysql_users (username, password, default_hostgroup, active, transaction_persistent) 
VALUES ('target_service_user', 'CLEAN_PLAINTEXT_OR_HASH_PASSWORD', 0, 1, 1);
```
-- Step C: Atomically load clean state to runtime memory and persist to disk
```
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;
```

## 3. Verification
Verify that the runtime memory structure contains exactly one clean entry:

```
SQL
SELECT username, active, default_hostgroup, transaction_persistent 
FROM runtime_mysql_users 
WHERE username = 'target_service_user';
```


Test application pool connectivity. HikariCP / Spring Boot connection handshakes will now succeed immediately.
