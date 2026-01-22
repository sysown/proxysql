# Bootstrap Mode

This mode allows the user to easily configure ProxySQL against a 'Group Replication Cluster', automating many
of the regular configuration steps, that otherwise would need to be performed manually. Also provides multiple
command line options that allows to customize this process.

## Automatic configuration overview

This is the configuration that is automatically performed when using `--bootstrap` mode:

- `mysql-server_version`: Fetched from the MySQL server used to bootstrap.
- `mysql-default_charset`: Fetched from the MySQL server used to bootstrap.
- `mysql-default_collation_connection`: Fetched from the MySQL server used to bootstrap.
- `mysql_servers`: Fetched from the MySQL server used to bootstrap.
- `mysql_users`: Fetched from the MySQL server used to bootstrap.
- `mysql-have_ssl`: Always set to `yes` when starting in `bootstrap` mode.
- `mysql-interfaces`: Configured with the same defaults ports as MySQL router (RW:6446,RO:6447);
- `mysql-monitor_username`: Dependent on command lines arguments, but randomly created by default.
- `mysql-monitor_password`: Dependent on command lines arguments, but randomly created by default.
- `mysql_group_replication_hostgroups`: Entry is created with similar configuration to MySQL router.
- `mysql_hostgroup_attributes`: Two entries are created, for RW and RO hostgroups, with same defaults that
  MySQL router uses for servers.
- `mysql_query_rules`: Simple port based _RW Split_ with RW, and RO ports. Similar to MySQL Router one.

### Notes

**`mysql_users`**:

During `bootstrap`, ProxySQL fetches the configured servers from the target server, but for security reasons,
excludes users with the following patterns:

- `mysql.%`
- `root`
- `bt_proxysql_%`

Users matching pattern `bt_proxysql_%` are considered ProxySQL users created during the `bootstrap` process.
See [command line options][4] for more details.

**`mysql_query_rules`**:

Please note that the default _RW Split_ is a very simplistic setup, which shouldn't be recommended for many
scenarios, and that ProxySQL allows for a much fine degree of control for routing. The default _RW Split_ is
provided as it's for compatibility reasons and as a starting point for configuration. For more information on
how to configure your own query rules with `--bootstrap`, please refer to section [configuration
precedence][8].

## Command line options

This information could also be check via `--help` command:

```
-B, --bootstrap ARG          Start ProxySQL in Group Replication bootstrap mode.
                             An URI needs to be specified for creating a
                             connection to the bootstrap server, if no URI is
                             provided, a connection to the default local socket
                             will be attempted.
-d, --directory ARG          Datadir
--account ARG                Account to use by monitoring after bootstrap,
                             either reuses a specify account or creates a new
                             one; this behavior is controlled by related option
                             '--acount-create'. When used, a password must be
                             provided.
--account-create ARG         Account creation policy for bootstrap. Possible
                             values are:
                             - if-not-exists (default): If the account doesn't
                             exist, create it, otherwise reuse it.
                             - always: Only bootstrap if the account isn't
                             present and can be created.
                             - never: Only bootstrap if the account is already
                             present.
--account-host ARG           Host pattern to be used for accounts created during
                             bootstrap (Not implemented).
--conf-base-port ARG         Sets the default base port ('mysql-interfaces') for
                             the default R/W split port based configuration
--conf-bind-address ARG      Sets the default bind address ('mysql-interfaces').
                             Used in combination with '--conf-bind-port'
--conf-skip-tcp ARG          Sets the default base port for the default R/W
                             split port based configuration
--conf-use-sockets ARG       bootstrap option, configures two Unix sockets with
                             names 'mysql.sock' and 'mysqlro.sock'
--password-retries ARG       Number of attempts for generating a password when
                             creating an account during bootstrap
--ssl-ca ARG                 The path name of the Certificate Authority (CA)
                             certificate file. Must specify the same certificate
                             used by the server
--ssl-capath arg             the path name of the directory that contains
                             trusted ssl ca certificate files
--ssl-cert arg               the path name of the client public key certificate
                             file
--ssl-cipher arg             the list of permissible ciphers for ssl encryption
--ssl-crl arg                the path name of the file containing certificate
                             revocation lists
--ssl-crlpath arg            the path name of the directory that contains
                             certificate revocation list files
--ssl-key arg                the path name of the client private key file
--ssl-mode arg               ssl connection mode for using during bootstrap
                             during normal operation with the backend servers.
                             Only PREFERRED, and DISABLED are supported.
```

Extra clarifications on several config options:

**`-B, --bootstrap ARG`**:

The URI that is supplied for this config option, needs to fulfill the following expression:

```
[scheme://][user[:[password]]@]host[:port]
```

The original expression, as stated in MySQL documentation for the supported URI formats is:

```
[scheme://][user[:[password]]@]host[:port][/schema][?attribute1=value1&attribute2=value2...
```

Further documentation on how the URI with which we should offer compatibility can be check [here][1]. There
are parts of this specification that are not covered, this is intentional, as for now we only cover the
previously described URI format. Some examples of supported connections strings are:

```
mysql://username@localhost:3333
mysql://username:password@example.com:8042
mysqlx://username:password@:19391
mysqlx://username:password@[2001:0db8:85a3:0000:0000:8a2e:037:8123]:3306/
```

The protocol specification is **ignored** as we don't support X protocol.

**`Default values`**:

If no URI is provided, a connection to a local default socket will be attempted. The default values used when
no URI is provided or provided one has missing parts are:

- `username`: If no _username_ or _password_ is specified, default username value is `root`.
- `password`: If no _password_ is specified, user input will be required for specifying one.
- `address`: If no address is specified, `localhost` will be assumed.
- `port`: If no port is specified, `3306` will be assumed.

Optional fields, can be supplied as the URI format specifies, as an example, here is a valid URI that doesn't
specify address or port:

```
mysql://username:password@
```

**`-d, --directory ARG`**:

This option is equivalent to the classic `--datadir`, it has been introduced just for compatibility reasons,
may be removed.

**`--conf-base-port ARG`**:

If no port is specified, the default ports used are the sames as for MySQL Router:

- RW: 6446
- RO: 6447

**`--ssl-mode ARG`**:

One of the following values:

- `DISABLED`: When disabled, **only** backend connections will be configured with `use_ssl=0`. Frontend
  connections will still **support** SSL via `mysql-have_ssl=true`. This way, clients still can decide to
  fully disable SSL on demand, while supporting SSL just on frontend when ProxySQL is situated near the
  backend servers, and SSL isn't a requirement.
- `PREFERRED`: Default mode, SSL is enabled for frontend and backend connections via `use_ssl=1` for all
  backend servers and `have_ssl=1` for frontend connections.

**`--account`**:

Specifies the account that is going to be used by ProxySQL for monitoring after the bootstrapping process.
When provided, the user is required to supply a password. If not provided, ProxySQL will create a random user
and password. These values will be stored under `disk.bootstrap_variables`, once ProxySQL is running, this
values will be used for the monitoring account, so they can also be check via: `mysql-monitor_username` and
`mysql-monitor_password`. When creating this account, ProxySQL will grant it with the following set of
permissions:

```
GRANT USAGE ON *.* TO `%s`@`%%`
GRANT SELECT ON `performance_schema`.`global_variables` TO `%s`@`%%`
GRANT SELECT ON `performance_schema`.`replication_group_member_stats` TO `%s`@`%%`
GRANT SELECT ON `performance_schema`.`replication_group_members` TO `%s`@`%%`"
```

These are the minimum set of permissions a monitoring account should have for ProxySQL being able to monitor a
Group Replication cluster, for more info check [MySQL Group Replication Support][7].

By default, this account is reused, to avoid unnecessary user creation during different `--bootstrap`
operations, this behavior can be changed via `--account-create`. The created account, for now, always matches
the pattern `bt_proxysql_%`, this could change in the future with support for `--acount-host`.

## Configuration precedence

In general, configuration precedence still works the same as expected for first boot:

- Command line arguments.
- Configuration file.

If a previously created `configdb` is present, `configdb` doesn't take precedence over certain config
variables that modify the bootstrap process itself, when ProxySQL is executed again in `bootstrap` mode:

- `mysql-%`: The following previously defined `mysql-%` variables:
  - `mysql-server_version`: Obtained from the MySQL server used to bootstrap.
  - `mysql-default_charset`: Obtained from the MySQL server used to bootstrap.
  - `mysql-default_collation_connection`: Obtained from the MySQL server used to bootstrap.
  - `mysql-interfaces`: Dependent on `--conf-bind-address` and `--conf-base-port`.
  - `mysql-monitor_username`: Dependent on `--account`, `--account-create`.
  - `mysql-monitor_password`: Dependent on `--account`, `--account-create`.
  - `mysql-have_ssl`: Always set to `yes` when starting in `bootstrap` mode.
  - `mysql-ssl_p2s_ca`: Dependent on `--ssl-ca`, and config file. Used for bootstrap connection itself.
  - `mysql-ssl_p2s_capath`: Dependent on `--ssl-capath`, and config file. Used for bootstrap connection
    itself.
  - `mysql-ssl_p2s_cert`: Dependent on `--ssl-cert`, and config file. Used for bootstrap connection itself.
  - `mysql-ssl_p2s_cipher`: Dependent on `--ssl-cipher`, and config file. Used for bootstrap connection
    itself.
  - `mysql-ssl_p2s_crl`: Dependent on `--ssl-crl`, and config file. Used for bootstrap connection itself.
  - `mysql-ssl_p2s_crlpath`: Dependent on `--ssl-crlpath`, and config file. Used for bootstrap connection
    itself.
  - `mysql-ssl_p2s_key`: Dependent on `--ssl-key`, and config file. Used for bootstrap connection itself.
- `admin-%`: The following previously defined `admin-%` variables:
  - `admin-hash_passwords`: Always set to `false`. This variable will be deprecated and disappear.
- `mysql_servers`: Obtained from the MySQL server used to bootstrap. Core bootstrapping functionality.
- `mysql_users`: Obtained from the MySQL server used to bootstrap. Core bootstrapping functionality.

For other previous user config, `configdb` takes precedence as usual, it's worth mentioning:

**`mysql_group_replication_hostgroups`**:

Allows the user to have custom bootstrapping hostgroups for the fetched servers. Default table entries created
by the bootstrapping process are:

- `writer_hostgroup`: 0
- `backup_writer_hostgroup`: 2
- `reader_hostgroup`: 1
- `offline_hostgroup`: 3
- `active`: 1
- `max_writers`: 9
- `writer_is_also_reader`: 0
- `max_transactions_behind`: 0

If preserving the default `RW Split` is intended, the user providing a custom entry **should always honor**
the hostgroups numbers from the default `mysql_query_rules` configuration. This is, hostgroup `0` for
`writer_hostgroup` and `1` for `reader_hostgroup`.

**`mysql_hostgroup_attributes`**:

Allows the user to have custom `mysql_hostgroup_attributes`, with custom defaults for the auto discovered
servers. For example, this allows a user to impose custom weights on this autodiscovered instances, for more
information see [mysql_hostgroup_attributes][2]. Default table entries created by the bootstrapping process
are:

- Hostgroup `0` - RW:
  - `hostgroup_id`: 0
  - `servers_defaults`: `'{"weight": 1, "max_connections": 512, "use_ssl": 1}'`
- Hostgroup `1` - RO:
  - `hostgroup_id`: 1
  - `servers_defaults`: `'{"weight": 1, "max_connections": 512, "use_ssl": 1}'`

**Important**: Since this table **isn't rebuilt** when `configdb` is present, discovered backend servers will
still preserve the SSL configuration due to the `use_ssl` field on `servers_defaults`. Even if a user specify
other value in the command line for `--ssl-mode`. This is expected behavior.

**`mysql_query_rules`**:

Allows the user to have their own rules instead of the simple default port based RW. By default the table
entries created by the bootstrapping process are:

- `rule_id`: 0, `active`: 1, `proxy_port`: _RW_PORT_, `destination_hostgroup`: 0, `apply`: 1
- `rule_id`: 1, `active`: 1, `proxy_port`: _RO_PORT_, `destination_hostgroup`: 1, `apply`: 1

`RW_PORT` is the port configured by user via `--conf-base-port`, or if not, default `6446`. `RO_PORT` is
`RW_PORT` + 1.

## MySQL Router differences

MySQL Router also offers a bootstrap mode, and while the initial configuration steps are pretty similar, and
the end configuration should also be compatible, operationally there are some differences of which a user
should be aware of.

### InnoDB Cluster dependence

MySQL Router requires of InnoDB Cluster, it's even defined [as part of it][3]. In this sense, MySQL Router is
only aware of the servers that are configured (promoted) to be part of InnoDB Cluster, this configuration is
typically performed via MySQL Shell.

ProxySQL on the other hand doesn't rely on InnoDB Cluster, it operates in terms off it's configuration and the
MySQL Group Replication cluster that is monitoring. When the cluster status itself changes, ProxySQL
automatically handles this new status, this includes:

- Cluster resizing.
- Server state changes.

### Configuration precedence

MySQL Router recreates all it's configuration during `--bootstrap`, with the exception of `router_id`, which
is reused. All changes present made to an existing configuration file are discarded, the way to supply extra
configuration after the bootstrapping process, would be to split the config into multiple files and make use
of the `--extra-config` command line option, supplying extra config file that would be applied **after** the
main one (generated during _bootstrap_).

ProxySQL takes a different approach, one that more closely matches it's original configuration philosophy. The
initial configuration via `--bootstrap` accomplishes the same goal as the MySQL Router one, creating a fresh
`configdb`. Bu contrary to MySQL Router behavior, subsequent `--bootstrap` initializations won't discard the
current `configdb`, some sections of the current `configdb` will be preserve, allowing users to customize the
expected configuration. For more info, see main section [configuration precedence][8].

### RW Split - Routing

By default, the _bootstrap_ configuration provides a _RW Split_, please remember that this is a very
simplistic setup, which shouldn't be recommended for many scenarios, and that ProxySQL allows for a much fine
degree of control for routing. See [mysql_query_rules][5] for more details.

#### Single-Primary

When _InnoDB Cluster_ is configured in _Single-Primary_ mode, and there is more than one server in the
Cluster, the default `bootstrap` configuration produces a compatible setup between ProxySQL and MySQL Router:

- Primary server is target by RW port.
- Replica servers are target by the RO port, load is balanced between the servers.

For MySQL Router this means that by default the ports are configured under the following modes:

- `RW` port operates under `read-write` config.
- `RO` port operates under `read-only` config mode.

These modes operate with different routing strategies, which is the main difference with ProxySQL, we will
elaborate on this on `Multi-Primary` section. For more information, you can refer to [mysql_router_mode][6].

For ProxySQL instead, this means that the servers are going to be automatically placed into two different
hostgroups:

- `RW` is going to be represented with hostgroup `0`: This hostgroup will contain the amount of servers
  specified in configuration that are in _PRIMARY_ mode, by default, `bootstrap` will set
  `mysql_group_replication_hostgroups` to allow just one server in this hostgroup. Since we are in
  `Single Primary` mode, the number of `PRIMARY` servers will always match this given config.
- `RO` is going to be represented with hostgroup `1`: This hostgroup will contain all the servers which are
  not present in hostgroup `0`, but are part of the `Group Replication` cluster.

#### Multi-Primary

When operation in `Multi-Primary` mode, MySQL Cluster has, _by default_, the same configuration as for
`Single-Primary` mode. This is, the port configuration is again:

- `RW` port operates under `read-write` config.
- `RO` port operates under `read-only` config mode.

It's important to note that the routing strategy that it's used _by default_ for `read-write` in both,
`Single-Primary` and `Multi-Primary` modes is the same, which is `first-available`. So in essence the same
behavior is exhibit for routing when the cluster is working in `Single-Primary`, and `Multi-Primary` modes.

For ProxySQL routing behavior will be the same with the default config, **but** if
`mysql_group_replication_hostgroups` is changed, allowing a bigger number of writers via `max_writers` then
more than one server will be present in the hostgroup `0`, which will make ProxySQL balance the queries
between all the servers present in this hostgroup. In this scenario, behavior from MySQL Router and ProxySQL
will defer, as MySQL Router will use _by default_ the strategy `first-available`, effectively sending all the
traffic to one server, while ProxySQL will balance the load between all available writers.

This a subtle but worth mentioning difference.

#### Special Case - Single Server

We are going to use this special case, as an example for also illustrating MySQL Router dependency with InnoDB
Cluster, and the difference in behavior with ProxySQL. If a cluster has only one server, MySQL Router will
sends traffic from both ports to the same server:

```
mysql -c -uroot -proot -h127.0.0.1 -P6446 --protocol=TCP --verbose --table --ssl-mode=DISABLED -e"SELECT @@server_id"
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
SELECT @@server_id
--------------

+-------------+
| @@server_id |
+-------------+
|         111 |
+-------------+
mysql -c -uroot -proot -h127.0.0.1 -P6447 --protocol=TCP --verbose --table --ssl-mode=DISABLED -e"SELECT @@server_id"
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
SELECT @@server_id
--------------

+-------------+
| @@server_id |
+-------------+
|         111 |
+-------------+
```

At the moment another server is added to the GR cluster, Router stops accepting traffic in ANY port, until
_InnoDB Cluster_ status is updated:

```
mysql -c -uroot -proot -h127.0.0.1 -P6446 --protocol=TCP --verbose --table --ssl-mode=DISABLED -e"SELECT @@server_id"
mysql: [Warning] Using a password on the command line interface can be insecure.
ERROR 2003 (HY000): Can't connect to MySQL server on '127.0.0.1:6447' (111)
```

```
mysql -c -uroot -proot -h127.0.0.1 -P6447 --protocol=TCP --verbose --table --ssl-mode=DISABLED -e"SELECT @@server_id"
mysql: [Warning] Using a password on the command line interface can be insecure.
ERROR 2003 (HY000): Can't connect to MySQL server on '127.0.0.1:6447' (111)
```

After adding the new node to the InnoDB cluster:

```
MySQL  localhost  JS > var cluster = dba.getCluster()
MySQL  localhost  JS > cluster.rescan()

Result of the rescanning operation for the 'devCluster' cluster:
{
    "name": "devCluster",
    "newTopologyMode": null,
    "newlyDiscoveredInstances": [
        {
            "host": "172.20.0.3:3306",
            "member_id": "8cdc9dc3-fb1b-11ed-bbea-0242ac140003",
            "name": null,
            "version": "8.0.33"
        }
    ],
    "unavailableInstances": [],
    "updatedInstances": []
}
...
```

MySQL Router now starts accepting traffic again to both ports. This time with a working RW split.

```
mysql -c -uroot -proot -h127.0.0.1 -P6447 --protocol=TCP --ssl-mode=DISABLED -e"SELECT @@server_id"
+-------------+
| @@server_id |
+-------------+
|         333 |
+-------------+
```

Meanwhile, by default in ProxySQL a read-write split will be setup for the same default ports as MySQL router.
Two hostgroups can be expected, `0` and `1`:

- Hostgroup `0` will contains the servers marked as PRIMARY.
- Hostgroup `1` will contains non PRIMARY servers.

Variable `writer_is_also_reader` will be `0`, so for properly serving RW and RO traffic on the designated
ports, both hostgroups should have at least one healthy server.

Summarizing, while MySQL Router will server traffic from both ports two just one server in case of InnoDB
Cluster just having one member, ProxySQL will expect two healthy servers, one in which hostgroup for the RW to
be functional.

### SSL mode:

The behavior for SSL is different for ProxySQL and MySQL Router:

- MySQL Router takes the default mode supplied by this option and uses it for the bootstrap connection and
  later monitoring connections. SSL mode is forwarded for user connections at a per-connection bases, this
  means, that if a particular client connects with `--ssl-mode=DISABLED` in the frontend, it will connect with
  that very same mode against the backend MYSQL server.
- ProxySQL keeps both worlds separated, client connections can only decided how they want to connect to
  frontend connections. The SSL mode for connections between ProxySQL and backend servers is determined by
  `mysql_servers` configuration. For knowing how `--bootstrap` affects this configuration by default, check
  section [command line options][4].

## Bootstrap Example Commands

This section describe with several examples how to make use of several command line options for tunning the
resulting _bootstrap_ configuration.

### SSL:

As a minimal config, provide the required CA cert, toguether with client's key and cert:

```
proxysql -f --bootstrap root:root@172.20.0.2:3306 \
    --ssl-mode REQUIRED --ssl-ca '/tmp/server_certs/ca.pem' \
    --ssl-cert '/tmp/server_certs/client-cert.pem' \
    --ssl-key '/tmp/server_certs/client-key.pem' \
    -d bootstrap_datadir
```

In the same fashion we can specify the rest of `SSL` related variables:

```
--ssl-capath arg
--ssl-cert arg
--ssl-cipher arg
--ssl-crl arg
--ssl-crlpath arg
```

### RW Split port config:

Perform a regular bootstrap in a clean datadir:

```
proxysql -f --bootstrap root:root@172.20.0.2:3306 --conf-bind-address "127.0.0.1" \
    --conf-base-port 6448 -d bootstrap_datadir
```

ProxySQL should have created two query rules for hostgroup `0` and hostgroup `1`, and should redirect incoming
traffic in port `6448` to hostgroup `0` and traffic to port `6449` to hostgroup `1`.

**Important**: If ProxySQL is started again in bootstrap mode in the same datadir, the RW split rules wont be
updated, because of the reasons described in section [configuration precedence][8]. This is expected behavior.

### Accounts creation

Here we present some examples on account creation, using the command line arguments `--account` and
`--account-create`.

Simple `bootstrapping` ProxySQL will either create a new account, or reuse a previous one if found:

```
proxysql -f --bootstrap root:root@172.20.0.2:3306 -d bootstrap_datadir
```

Don't create account, ProxySQL will ask for password for already existing account, will abort if account
doesn't exists:

```
proxysql -f --bootstrap root:root@172.20.0.2:3306 \
    --account bt_proxysql_DUKRhvf8Hl8N --account-create never -d bootstrap_datadir
```

Always create the account, ProxySQL will ask for password, will abort if account already exists:

```
proxysql -f --bootstrap root:root@172.20.0.2:3306 \
    --account bt_proxysql_DUKRhvf8Hl8N --account-create always -d bootstrap_datadir
```

[1]: https://dev.mysql.com/doc/refman/8.0/en/connecting-using-uri-or-key-value-pairs.html#connecting-using-uri
[2]: https://proxysql.com/main-runtime#mysql_hostgroup_attributes
[3]: https://dev.mysql.com/doc/mysql-router/8.0/en/mysql-router-innodb-cluster.html
[5]: https://proxysql.com/main-runtime/#mysql_query_rules
[6]: https://dev.mysql.com/doc/mysql-router/8.0/en/mysql-router-conf-options.html#option_mysqlrouter_mode
[7]: https://proxysql.com/group-replication-configuration/
[4]: #command-line-options
[8]: #configuration-precedence
