# PostgreSQL Configuration

## Initial Configuration

**Introduction:**

ProxySQL now supports the PostgreSQL protocol, enabling you to leverage its powerful features like connection
pooling, query routing, and monitoring for your PostgreSQL deployments.

This guide provides a step-by-step walkthrough for configuring ProxySQL to work with PostgreSQL. It assumes
you are already familiar with the basic ProxySQL configuration process. If you're completely new to ProxySQL,
we strongly recommend first reading our guide on [How to configure ProxySQL for MySQL][1].

This PostgreSQL guide focuses on the necessary modifications and differences, it also assumes you have
ProxySQL and a PostgreSQL client installed, and your PostgreSQL servers are running and accessible.

**Prerequisites:**

- ProxySQL installed and running.
- A PostgreSQL client installed on your system.
- Your PostgreSQL servers are running and accessible from the ProxySQL server.

This guide walks you through the initial configuration of ProxySQL for PostgreSQL. We'll configure ProxySQL to
connect to your PostgreSQL instances, set up monitoring, create PostgreSQL users, and, optionally, define
query rules.

**Explanation:**

The ProxySQL configuration for PostgreSQL mirrors the MySQL setup in many ways, but utilizes different tables
and variables tailored to the PostgreSQL protocol. Instead of `mysql_servers`, `mysql_users`, and
`mysql_query_rules`, we'll use `pgsql_servers`, `pgsql_users`, and `pgsql_query_rules`. The basic process
involves:

1. **Adding PostgreSQL Backends:** Define your PostgreSQL servers in the `pgsql_servers` table.
2. **Configuring Monitoring:** Set up monitoring credentials in PostgreSQL and configure them within ProxySQL.
   This allows ProxySQL to track the health of your backend servers.
3. **Creating PostgreSQL Users:** Create users in ProxySQL's administration interface to manage access
   control.
4. **Defining Query Rules (Optional):** Implement advanced routing logic using `pgsql_query_rules` to direct
   specific queries to particular PostgreSQL instances.

**Key Differences from MySQL Configuration:**

The core configuration process for PostgreSQL is similar to MySQL, but with some key differences:

- **Table Names:** All `mysql_*` tables (e.g., `mysql_servers`, `mysql_users`, `mysql_query_rules`) are
  replaced with their PostgreSQL counterparts: `pgsql_*` (e.g., `pgsql_servers`, `pgsql_users`,
  `pgsql_query_rules`).
- **Variable Names:** Global variables related to MySQL monitoring (e.g., `mysql-monitor_username`) are
  changed to `pgsql-` prefixed equivalents (e.g., `pgsql-monitor_username`).
- **Commands:** The `LOAD MYSQL ... TO RUNTIME` and `SAVE MYSQL ... TO DISK` commands become
  `LOAD PGSQL ... TO RUNTIME` and `SAVE PGSQL ... TO DISK`.

**Example:**

Let's assume we have three PostgreSQL backend servers: `10.0.0.1`, `10.0.0.2`, and `10.0.0.3`, all running on
the default PostgreSQL port (5432). We'll use the ProxySQL admin interface (accessible via
`psql -h 127.0.0.1 -p6132 -U admin -d admin`) to configure it.

1. **Add PostgreSQL Backends:**

```sql
psql (ProxySQL Admin)> INSERT INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (1, '10.0.0.1', 5432);
psql (ProxySQL Admin)> INSERT INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (1, '10.0.0.2', 5432);
psql (ProxySQL Admin)> INSERT INTO pgsql_servers (hostgroup_id, hostname, port) VALUES (1, '10.0.0.3', 5432);
```

2. **Configure Monitoring:**

First, create a monitoring user in your _primary_ PostgreSQL server:

```sql
psql (PostgreSQL)> CREATE USER monitor WITH PASSWORD 'monitor';
psql (PostgreSQL)> GRANT CONNECT ON DATABASE postgres TO monitor; -- Adjust privileges as needed
```

Then, configure the monitoring user in ProxySQL:

```sql
psql (ProxySQL Admin)> UPDATE global_variables SET variable_value = 'monitor' WHERE variable_name = 'pgsql-monitor_username';
psql (ProxySQL Admin)> UPDATE global_variables SET variable_value = 'monitor' WHERE variable_name = 'pgsql-monitor_password';
psql (ProxySQL Admin)> UPDATE global_variables SET variable_value = '2000' WHERE variable_name IN ('pgsql-monitor_connect_interval', 'pgsql-monitor_ping_interval');
psql (ProxySQL Admin)> LOAD PGSQL VARIABLES TO RUNTIME;
psql (ProxySQL Admin)> SAVE PGSQL VARIABLES TO DISK;
```

3. **PostgreSQL Users:**

Create a PostgreSQL user (`appuser`) in your primary PostgreSQL server:

```sql
psql (PostgreSQL)> CREATE USER appuser WITH PASSWORD 'appuser';
psql (PostgreSQL)> GRANT ALL PRIVILEGES ON DATABASE mydatabase TO appuser; -- Replace 'mydatabase'
```

and then add the user to ProxySQL:

```sql
psql (ProxySQL Admin)> INSERT INTO pgsql_users (username, password, default_hostgroup) VALUES ('appuser', 'appuser', 1);
psql (ProxySQL Admin)> LOAD PGSQL USERS TO RUNTIME;
psql (ProxySQL Admin)> SAVE PGSQL USERS TO DISK;
```

4. **Connect and Test:**

You can now connect to your PostgreSQL servers through ProxySQL:

```bash
psql -h 127.0.0.1 -p6133 -U appuser -d mydatabase
```

**Benefits:**

- **Connection Pooling:** ProxySQL efficiently manages connections, reducing the overhead on your PostgreSQL
  servers.
- **Load Balancing:** Distributes read traffic across multiple PostgreSQL instances.
- **High Availability:** Provides redundancy and failover capabilities.
- **Query Routing:** Allows for advanced traffic management based on various criteria.
- **Monitoring and Statistics:** Offers real-time insights into the performance and health of your PostgreSQL
  infrastructure.

**Best Practices and Tips:**

- **Use a dedicated monitoring user:** Avoid using your application users for monitoring.
- **Regularly backup your ProxySQL configuration.**
- **Monitor ProxySQL's performance:** Track metrics like connection usage, query latency, and error rates.
- **Start with a simple configuration:** Add features gradually as needed.
- **Test thoroughly:** Before deploying to production, test your ProxySQL configuration in a staging
  environment.
- **Implement high availability:** Use ProxySQL clustering to avoid single points of failure.

[1]: https://proxysql.com/proxysql-configuration/
