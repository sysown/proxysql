Configuring ProxySQL
====================

First of all, bear in mind that the best way to configure ProxySQL is through its admin interface. This lends itself to online configuration (without having to restart the proxy) via SQL queries to its admin database. It's an effective way to configure it both manually and in an automated fashion.

As a secondary way to configure it, we have the configuration file. 

Configuring ProxySQL through the admin interface
------------------------------------------------

In order to connect to the admin interface, you will have to use the credentials and `(interface, port)` pair specified in the global variables. Relevant global variables:
* [`admin-admin_credentials`](https://github.com/sysown/proxysql/blob/master/doc/global_variables.md#admin-admin_credentials)
* [`admin-stats_credentials`](https://github.com/sysown/proxysql/blob/master/doc/global_variables.md#admin-stats_credentials)
* [`admin-mysql_ifaces`](https://github.com/sysown/proxysql/blob/master/doc/global_variables.md#admin-mysql_ifaces)

Once connected to the admin interface, you will have a [list of databases and tables](https://github.com/sysown/proxysql/blob/master/doc/admin_tables.md) at your disposal that can be queried using the SQL language. This will allow you to control the list of the backend servers, how traffic is routed to them, and other important settings (such as caching, access control, etc.)

Once you do modifications to the in-memory data structure, you can load the new configuration to the runtime, or persist the new settings to disk (so that they are still there after a restart of the proxy). See the [configuration system](https://github.com/sysown/proxysql/blob/master/doc/configuration_system.md) document to understand the 3-tier model of the configuration and how they all blend together.

Configuring ProxySQL through the config file
--------------------------------------------

Even though the config file should only be regarded as a secondary way to configure the proxy, we must not discard its value as a valid way to bootstrap a fresh ProxySQL install. You can find some example configuration files in here: TODO

Let's discuss very quickly the main sections of the configuration file.

Top-level sections:
* `admin_variables`: contains global variables that control the functionality of the admin interface. [Here](https://github.com/sysown/proxysql/blob/master/doc/global_variables.md#admin-admin_credentials) is the full list of the available variables and their semantics (the ones that start with `admin-`)
* `mysql_variables`: contains global variables that control the functionality for handling the incoming MySQL traffic. [Here](https://github.com/sysown/proxysql/blob/master/doc/global_variables.md#mysql-commands_stats) is the full list of the available variables and their semantics (the ones that start with `mysql-`)
* `mysql_servers`: contains rows for the `mysql_servers` table from the admin interface. Basically, these define the backend servers towards which the incoming MySQL traffic is routed. Rows are encoded as per the `.cfg` file format, here is an example:
	```bash
	mysql_servers =
	(
		{
			address="127.0.0.1"
			port=3306
			hostgroup=0
			max_connections=200
		}
	)
	```
	For the available columns of the `mysql_servers` table and their semantics, please check the [associated documentation](https://github.com/sysown/proxysql/blob/master/doc/admin_tables.md#mysql_servers).
* `mysql_users`: contains rows for the `mysql_users` table from the admin interface. Basically, these define the users which can connect to the proxy, and the users with which the proxy can connect to the backend servers. Rows are encoded as per the `.cfg` file format, here is an example:
	```bash
	mysql_users:
	(
		{
			username = "root"
			password = "root"
			default_hostgroup = 0
			max_connections=1000
			default_schema="information_schema"
			active = 1
		}
	)
	```
	For the available columns of the `mysql_users` table and their semantics, please check the [associated documentation](https://github.com/sysown/proxysql/blob/master/doc/admin_tables.md#mysql_users).
* `mysql_query_rules`: contains rows for the `mysql_query_rules` table from the admin interface. Basically, these define the rules used to classify and route the incoming MySQL traffic, according to various criteria (patterns matched, user used to run the query, etc.). Rows are encoded as per the `.cfg` file format, here is an example:
	```bash
	mysql_query_rules:
	(
		{
			rule_id=1
			active=1
			match_pattern="^SELECT .* FOR UPDATE$"
			destination_hostgroup=0
			apply=1
		},
		{
			rule_id=2
			active=1
			match_pattern="^SELECT"
			destination_hostgroup=1
			apply=1
		}
	)
	```
	For the available columns of the `mysql_query_rules` table and their semantics, please check the [associated documentation](https://github.com/sysown/proxysql/blob/master/doc/admin_tables.md#mysql_query_rules).
* top-level configuration item: `datadir`, as a string, to point to the data dir.