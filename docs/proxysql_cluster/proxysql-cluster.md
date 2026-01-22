# Preface

ProxySQL is a decentralized proxy, and it is normally advised to deploy it on the same server as the
application if possible. This approach scales well up to hundred(s) of nodes and was designed to be easily
reconfigurable at runtime. In order to administer a group of ProxySQL instances you would need to configure
each host individually, use a configuration management tool such as Ansible/Chef/Puppet/Salt (in alphabetical
order) or alternatively a service discovery tool like Consul/ZooKeeper. So while ProxySQL is highly
customizable and can be deployed and managed in any environment using any of the already implemented
configuration management tools technologies this approach has some drawbacks:

- It requires and relies on external software (the configuration management software itself)
- The previous point implies that such an approach is not natively supported
- Converge time is not predictable
- There is no protection against network split

<!-- -->

For this reason, starting from ProxySQL 1.4.x configuration clustering is natively supported. Currently there
are two main components in the ProxySQL clustering solution:

- Monitoring
- Re-configuration

<!-- -->

Both components (monitoring and remote reconfiguration) are available for the following tables:

- `global_variables (Supported from ProxySQL 2.1.x)`
- `mysql_query_rules`
- `mysql_servers`
- `mysql_replication_hostgroups`
- `mysql_group_replication_hostgroups`
- `mysql_galera_hostgroups`
- `mysql_aws_aurora_hostgroups`
- `mysql_hostgroup_attributes`
- `mysql_users`
- `proxysql_servers`

<!-- -->

Also, there are a couple of worth mentioning global features:

- *SSL support*: All connections between peer nodes use SSL.
- *Prevention of unnecessary reconfigurations*: Protections against fetching of transient states.
- *Circular fetching prevention*: Several counter measures, enhanced in `v2.6.0`.
- *Peer version verification*: Since `v2.1.0`, nodes check their peer versions and only pairs with the ones
  sharing the same versions.

## Key concepts

### Cluster members

A ProxySQL cluster is form by multiple ProxySQL nodes acting as one of two roles:

- **Core**: Primary nodes of the cluster, they share and propagate the configuration.
- **Satellites**: Replica nodes of the cluster, they fetch the configuration from the `Core` nodes.

By definition, a node member of a ProxySQL cluster is considered as a `Core` node if:

* It's present in its `proxysql_servers` table together with the other `Core` members.
* It's present in the `proxysql_servers` table of other `Core` nodes of the cluster.

These nodes together constitute the `source of truth` of the Cluster. Meanwhile, a `Satellite` node is by
definition a node that:

* It's **not** present in its `proxysql_servers` table.
* It's **not** present in the `proxysql_servers` table of other `Core` nodes of the cluster.

Because this member isn't present in the `proxysql_servers` table of the other nodes, it will never be part of
the nodes promoting new configuration into the cluster, its role will be to pull new configuration when
detected.

### Supported Topologies

These two types of nodes are the base for all the supported topologies, which essentially differ in the number
of `Core` and `Satellite` nodes in them:

* Single `Core` node with/without `Satellite` nodes.
* Multiple `Core` nodes with/without `Satellite` nodes.

These architectures are supported even without the notion of a single `leader|primary` node. ProxySQL has
multiple builtin protections to prevent circular fetching and propagation of transient states between `Core`
nodes. From `v2.6.0` these features got enhanced by allowing users to select from different configuration
fetching strategies depending on the requirements of their setup, more on section [Configuration Fetching
Strategies](#configuration-fetching-strategies).

### Source of truth selection

A ProxySQL cluster is defined by the entries present in the `proxysql_servers` tables from its members. Based
on the contents of this table the members have one or other role within the cluster. We are going to split the
flow for creating a cluster into two steps, the first one being booting and configuring the `Core` nodes:

1. Start the ProxySQL instances that are going to be the `Core` nodes of this cluster.
2. Insert the `Core` nodes into the `proxysql_servers` table from the cluster members. Only the `Cores` node
   will be present in this table, since the satellite nodes don't propagate configuration.
3. Load this configuration to runtime, via `LOAD PROXYSQL SERVERS TO RUNTIME`.

These previous steps can of course be replaced by booting three ProxySQL instances with its peers already
configured. At this stage, no source of truth has been configured in the cluster, this means that in case of
checksum mismatch, i.e. differences in the configuration between the nodes, ProxySQL should be notifying us
via error log that cluster synchronization **can't** start:

```
Cluster: detected a peer %s with **module_name** version 1, epoch %d, diff_check %d. Own version: 1, epoch: %d. diff_check is increasing, but version 1 doesn't allow sync
```

This message will keep repeating until a suitable source of truth is selected. For this, we need to increase
this `version` number for one of the `Core` nodes, this can be done by issuing the corresponding:

```
LOAD **MODULE_NAME** TO RUNTIME
```

After this, `version` number should be increased to `2`, and the other ProxySQL instances will consider this
instance as the source of truth, in case of a checksum mismatch, it will be selected for syncing. Propagating
its configuration to the other `Core` nodes of the cluster.

# Monitoring

To support Cluster Monitoring, several new tables, commands and variables were introduced.

## Admin variables

Several new variables were added related to the Cluster solution. They are all Admin's variables, which means
that to load them the command `LOAD ADMIN VARIABLES TO RUNTIME` is needed.

<!-- -->

### Credentials

Variables that define credentials:

- `admin-cluster_username`
- `admin-cluster_password`

To monitor other ProxySQL instances this credential is used. Note that the pair username/password should also
be present in `admin-admin_credentials`, or the connection will fail. If `admin-cluster_username` is not
defined, Clustering doesn't perform any check.

<!-- -->

### Checks Frequency

Variables that define checks interval/frequency:

- `admin-cluster_check_interval_ms`: Interval between checksums checks. Default: 1000, Min: 10, Max: 300000
- `admin-cluster_check_status_frequency`: If greater than 0, this variable defines after how many checksums
  checks a `status check` is performed. Default: 10, Min: 0, Max: 10000

A `status check` is a check performed from a node to another node, issuing query `SHOW MYSQL STATUS`, every
status check updates the table `stats_proxysql_servers_metrics`. For more info check section
[stats\_proxysql\_servers\_metrics](#table-stats_proxysql_servers_metrics).

<!-- -->

#### Diffs before sync

Defines how many mismatching checks are required for triggering the synchronization of a particular module:

- `admin-cluster_mysql_query_rules_diffs_before_sync`
- `admin-cluster_mysql_servers_diffs_before_sync`
- `admin-cluster_mysql_users_diffs_before_sync`
- `admin-cluster_proxysql_servers_diffs_before_sync`
- `admin-cluster_mysql_variables_diffs_before_sync`
- `admin-cluster_admin_variables_diffs_before_sync`
- `admin-cluster_ldap_variables_diffs_before_sync`

All hold the same value range:

- Default: 3
- Min: 0 (*Never sync*)
- Max: 1000

**Motivation:**

These variables bring two different functionalities:

1. Protection against unnecessary reconfigurations.
2. Ability to disable module synchronization.

These reconfigurations normally have two different sources:

1. New user promoted configuration.
2. Servers state change detection by Monitor.

To understand the first point, we need to think that it's possible for multiple ProxySQL instances to be
reconfigured at the same time by these previously mentioned events. Also, these reconfiguration could even
have transient states, meaning that the first configuration change, may not be the final one. In this
scenario, the most sensible thing the cluster nodes can do, is to have a grace period, expecting that it will:

* Minimize the reactions (reconfigurations) due to transient states.
* Allow the cluster nodes to converge, avoiding the need of fetching, when reacting to monitoring events.

A couple of examples of the previously mentioned scenarios are:

* Each ProxySQL instance is monitoring a MySQL replication topology and automatically detecting a failover,
  and within a short period of time (probably less than a second) they will all converge to the same
  configuration without the need to synchronize with each other.
* Similarly, a temporary network issue or a slow MySQL instance is detected by all proxies that will
  automatically shun the node. All proxies will take the same action without the need to synchronize with each
  other.

**Not syncing scenarios:**

If `diff_check` increases a lot without triggering a synchronization it means that the remote peer is not a
reliable source of truth, for example if `version=1`. On the other hand, if the remote peer doesn't sync with
the rest of the cluster it means that the cluster doesn't have a reliable source of truth. This happens when
all the proxies in a cluster start with a different configuration, and they can't automatically decide which
is the correct configuration. Running `LOAD module TO RUNTIME` on one of the nodes will automatically "elect"
it to become the source of truth for that specific module.

<!-- -->

### Configuration Persistence

After a remote sync, it is normally a good idea to immediately save to disk the new changes. In this way,
after a restart the configuration will be already in sync.

Variables for specific kinds of global variables:

- `admin-cluster_mysql_variables_save_to_disk`
- `admin-cluster_admin_variables_save_to_disk`
- `admin-cluster_ldap_variables_save_to_disk`

Variables for modules:

- `admin-cluster_mysql_query_rules_save_to_disk`
- `admin-cluster_mysql_servers_save_to_disk`
    + `mysql_servers`
    + `mysql_replication_hostgroups`
    + `mysql_group_replication_hostgroups`
    + `mysql_galera_hostgroups`
    + `mysql_aws_aurora_hostgroups`
    + `mysql_hostgroup_attributes`
- `admin-cluster_mysql_users_save_to_disk`
- `admin-cluster_proxysql_servers_save_to_disk`

All of these are `boolean` variables, when `true` (default) after a remote sync and the corresponding load to
runtime, the new values for the sync module are `saved to disk`.

<!-- -->

### Disabling modules sync

Prior to version `v2.5.2` module synchronization could be disabled via variables:

- `admin-checksum_$\{module_name\}`
- `admin-cluster_$\{module_name\}_diffs_before_sync`

Since version `v2.5.2`, variables `admin-checksum_$\{module_name\}` got **deprecated**, the way to disable
module synchronization is now via `admin-cluster_$\{module_name\}_diffs_before_sync` variable.

### Configuration Fetching Strategies

Introduced via `admin-cluster_mysql_servers_sync_algorithm` in `v2.6.0`. Allows users to define which fetching
strategy should be use for syncing of `runtime_mysql_servers` configuration. This is achieved by the addition
of an extra table called `mysql_servers_v2`. In essence we can define these tables as:

- `runtime_mysql_servers`: Table containing the current state of the servers configured by the user and
  monitored by ProxySQL. This table entries, and consequently the module checksum, can change due to
  monitoring actions performed over the servers.
- `mysql_servers_v2`: Contains the latest `mysql_servers` configuration promoted to `runtime` by the user.
  This table, and its checksum is only modified by user actions, and consequently its checksum never change
  until the user promotes new configuration.

Variable `admin-cluster_mysql_servers_sync_algorithm` allows the user to select which tables should become the
pulling endpoint for the instance `mysql_servers` module. Can be set to:

* **1**: Sync both tables, in this mode, both tables `runtime_mysql_servers` and `mysql_server_v2` will be
  fetched from the peer. This means, that both monitoring actions and user promoted configuration will trigger
  the computation of a new module checksum, that in case of not matching with the local ones will translate in a
  fetch by other cluster peers.
* **2**: Sync only `mysql_server_v2` table. This means, that only a user promoting new configuration will
  trigger a new checksum computation of the module, and potential fetching from cluster peers.
* **3**: Fetching mode is dependent on `-M` flag. If `-M` flag isn't present `1` is selected, otherwise `2` is
  chosen.

Mode **1** exhibits the classic fetching behavior for `mysql_servers` module. But modes **2** and **3** offer
increased reliability for other scenarios:

* **2**: This mode should be considered for topologies holding multiple `Core` nodes. Since **only** promoted
  user configuration is fetched when operating in this mode, this prevents two things; first eliminates
  unnecessary reconfigurations for `Core` nodes during transient Monitoring states, given that the nodes are
  no longer "competing" exposing their current `runtime` state to the other nodes, their convergence rate is
  much less relevant at cluster level, and second prevents continuous circular fetching scenarios. While the
  first is a enhancement, and it's beneficial during regular operation, the second one, is a contention
  mechanism for an already serious infrastructure issue that could be affecting traffic, and that should be
  fixed. Let's elaborate on this second potential situation, one of the core nodes suffers from network
  issues against the backend servers, while the others node **doesn't**, this will trigger monitor
  reconfigurations in just this server with network issues, and will create a mismatch between the
  `runtime_mysql_servers` tables on the different `Core` nodes. This will lead to an inconsistent state, in
  which servers continuously try to fetch data from their peers with the newer checksum, for later,
  reconfiguring their servers again because their Monitoring doesn't match the state reported by their peers,
  thus generating a new checksum in the process and continue the cycle. This scenario **isn't** possible when
  operating in this mode, in which only the latest user promoted configuration is fetched.
* **3**: This is a mode specially created for clusters with `Satellites` nodes, since it allows the `Core`
  nodes to operate with **2** as fetching strategy while allowing satellite nodes started with `-M` (disabled
  monitoring) to fetch both, the `runtime_mysql_servers` and the user promoted configuration. This allows for
  setups in which `Satellites` don't contribute to Monitoring load, since they rely in the monitoring of the
  `Core` nodes, while the `Core` nodes only fetch the latest user promoted configuration, and individually
  converge to their own `runtime` monitoring state, this achieves the best of both worlds for `Core` and
  `Satellite` nodes.

### Checksum computation - Deprecated since v2.5.2

This variables enables or disables the checksum computation for the specific modules:

- `admin-checksum_mysql_query_rules`: When `true` (default) a new configuration checksum is generated every
  time `LOAD MYSQL QUERY RULES TO RUNTIME` is executed.
- `admin-checksum_mysql_servers`: When `true` (default) a new configuration checksum is generated every
  time `LOAD MYSQL SERVERS TO RUNTIME` is executed.
- `admin-checksum_mysql_users`: When `true` (default) a new configuration checksum is generated every
  time `LOAD MYSQL USERS TO RUNTIME` is executed.
- `admin-checksum_mysql_variables`: When `true` (default) a new configuration is generated everytime `LOAD
  MYSQL VARIABLES TO RUNTIME` is executed.
- `admin-checksum_admin_variables`: When `true` (default) a new configuration is generated everytime `LOAD
  ADMIN VARIABLES TO RUNTIME` is executed.
- `admin-checksum_ldap_variables`: When `true` (default) a new configuration is generated everytime `LOAD
  LDAP VARIABLES TO RUNTIME` is executed.

These are `boolean` variables. When set to `false`, the new configuration isn't automatically propagated,
since no new checksum was created for the module, which renders the changes invisible for the other cluster
members, and also prevents configuration from being synced from a remote node.

These variables were **deprecated** in version `v2.5.2`. Checksum computation is **always** performed, for
more details on how to disable modules sync check section [disabling modules sync](#disabling-modules-sync).

The motivation for this deprecation is that the ability to disable checksum computation supposed a challenge
for implementing new cluster resiliency features, while its main feature was duplicated by
`admin-cluster_$\{module_name\}_diffs_before_sync` variables.

## Configuration tables

### Table `proxysql_servers`

Table definition:

```
CREATE TABLE proxysql_servers (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 6032,
    weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0,
    comment VARCHAR NOT NULL DEFAULT '',
    PRIMARY KEY (hostname, port) )
```

 This table is a configuration table, and defines a list of ProxySQL peers.

- `hostname`: Peer's hostname/IP.
- `port`: Peer's port.
- `weight`: Currently unused, but in the roadmap for future enhancements.
- `comment`: Free form comment field.

<!-- -->

Commands to promote table configuration:

- `LOAD PROXYSQL SERVERS FROM MEMORY` / `LOAD PROXYSQL SERVERS TO RUNTIME` loads ProxySQL servers from the
  in-memory database to the runtime data structures.
- `SAVE PROXYSQL SERVERS TO MEMORY` / `SAVE PROXYSQL SERVERS FROM RUNTIME` persists the ProxySQL Servers from
  the runtime data structures to the in-memory database.
- `LOAD PROXYSQL SERVERS TO MEMORY` / `LOAD PROXYSQL SERVERS FROM DISK` loads ProxySQL Servers from the
  on-disk database to the in-memory database.
- `LOAD PROXYSQL SERVERS FROM CONFIG` loads ProxySQL Servers from configuration file to the in-memory
  database.
- `SAVE PROXYSQL SERVERS FROM MEMORY` / `SAVE PROXYSQL SERVERS TO DISK` persists the ProxySQL Servers from the
  in-memory database to the on-disk database.

When the configuration from this table is promoted to runtime, ProxySQL will start monitoring the configured
nodes, joining as cluster member, the role the node will have as a member will be defined by its presence or
not in the other nodes `proxysql_servers` table. See section [Cluster members](#cluster-members) for more
details.

#### Support for config file

Entries for `proxysql_servers` can be loaded from the configuration file. Below is an example of how to
configure `proxysql_servers` from config file:

```
proxysql_servers =
(
    \{
        hostname="172.16.0.101"
        port=6032
        weight=0
        comment="proxysql1"
    \},
    \{
        hostname="172.16.0.102"
        port=6032
        weight=0
        comment="proxysql2"
    \}
)
```

### Table `runtime_checksums_values`

Table definition:

```
CREATE TABLE runtime_checksums_values (
    name VARCHAR NOT NULL,
    version INT NOT NULL,
    epoch INT NOT NULL,
    checksum VARCHAR NOT NULL,
    PRIMARY KEY (name))
```

Table `runtime_checksums_values` is the first `runtime_` table that is not the runtime representation of a
base table. Table `runtime_checksums_values` shows information of when a `LOAD TO RUNTIME` command was
executed:

- `name`: Name of the module.
- `version`: How many times `LOAD TO RUNTIME` was executed, either explicitly or not (executed internally due
  to some other event). All modules start with `version 1`. This version has special meaning, since cluster
  members don't sync from modules with `version 1`. See section [Source of truth
  selection](#source-of-truth-selection).
- `epoch`: Timestamp of when `LOAD TO RUNTIME` was executed.
- `checksum`: The checksum of the internal memory structure resulting from `LOAD TO RUNTIME`.

<!-- -->

Example:

```
admin> SELECT * FROM runtime_checksums_values;
+-------------------+---------+------------+--------------------+
| name              | version | epoch      | checksum           |
+-------------------+---------+------------+--------------------+
| admin_variables   | 1       | 1692021362 | 0x2220DDA8D0DB12D0 |
| mysql_query_rules | 1       | 1692021362 | 0x0000000000000000 |
| mysql_servers     | 1       | 1692021363 | 0xC2AAFF69CB9C34FD |
| mysql_users       | 1       | 1692021362 | 0xAC3B2F84B00375F3 |
| mysql_variables   | 1       | 1692021362 | 0x852768C4FB43CD68 |
| proxysql_servers  | 1       | 1692021362 | 0x0000000000000000 |
| mysql_servers_v2  | 1       | 1692021362 | 0xF39D99F43BAA6855 |
+-------------------+---------+------------+--------------------+
7 rows in set (0.00 sec)
```

- `LOAD MYSQL QUERY RULES TO RUNTIME`
- `LOAD MYSQL SERVERS TO RUNTIME`
- `LOAD MYSQL USERS TO RUNTIME`
- `LOAD PROXYSQL SERVERS TO RUNTIME`
- `LOAD ADMIN VARIABLES TO RUNTIME`
- `LOAD MYSQL VARIABLES TO RUNTIME`

All module commands promoting configuration to runtime generate a new checksum for the module. In versions
older than `v2.5.2` this behavior was conditional to the `admin-checksum_$\{module_name\}`.

<!-- -->

## Stats tables

The following tables are present in the `stats` schema:

### Table `stats_proxysql_servers_checksums`

 Table definition:

```
Admin> SHOW CREATE TABLE stats.stats_proxysql_servers_checksums\G
*************************** 1. row ***************************
       table: stats_proxysql_servers_checksums
Create Table: CREATE TABLE stats_proxysql_servers_checksums (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 6032,
    name VARCHAR NOT NULL,
    version INT NOT NULL,
    epoch INT NOT NULL,
    checksum VARCHAR NOT NULL,
    changed_at INT NOT NULL,
    updated_at INT NOT NULL,
    diff_check INT NOT NULL,
    PRIMARY KEY (hostname, port, name) )
1 row in set (0,00 sec)
```

This table shows the checksum of other proxies, and their status:

- `hostname`: Hostname of the peer.
- `port`: Port of the peer.
- `name`: Name of the module as reported in peer's `runtime_checksums_values`
- `version`: Version of checksum's module as reported in peer's `runtime_checksums_values`. Note that a
  ProxySQL Instance just started will have `version=1`: for this reason, a ProxySQL instance will never sync
  from another instance having `version=1`, because it is unlikely that a ProxyQL instance just started is the
  source of truth. This prevents a new joining node to corrupt the current Cluster configuration.
- `epoch`: epoch of the checksum's module as reported in peer's `runtime_checksums_values`
- `checksum`: The checksum's module as reported in peer's `runtime_checksums_values`
- `changed_at`: The timestamp of when a checksum change was detected.
- `updated_at`: The timestamp of when this entry was last refreshed.
- `diff_check`: A counter that defines for how many checks the checksum of the remote peer's was different
  than the local checksum, this value will continue growing until a defined threshold is reached, at which
  point a reconfiguration will be triggered, and the value reset. The value could keep growing if no
  reliable source of truth is found. E.g. peer having `version=1`. For more info please refer to [diffs
  before sync](#diffs-before-sync).

This is useful in case the same configuration is applied to multiple proxies
at the same time, or when proxies are reconfiguring themselves in case of a failover and they will likely
converge without the need of resync. See also variables `cluster_*_diffs_before_sync`

<!-- -->

### Table `stats_proxysql_servers_metrics`

Table definition:

```
Admin> SHOW CREATE TABLE stats.stats_proxysql_servers_metrics\G
*************************** 1. row ***************************
       table: stats_proxysql_servers_metrics
Create Table: CREATE TABLE stats_proxysql_servers_metrics (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 6032,
    weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0,
    comment VARCHAR NOT NULL DEFAULT '',
    response_time_ms INT NOT NULL,
    Uptime_s INT NOT NULL,
    last_check_ms INT NOT NULL,
    Queries INT NOT NULL,
    Client_Connections_connected INT NOT NULL,
    Client_Connections_created INT NOT NULL,
    PRIMARY KEY (hostname, port) )
1 row in set (0,00 sec)
```

This table shows some of the metrics that are retrieved when the clustering module executes `SHOW MYSQL
STATUS` in its peers. Columns:

- `hostname`: Hostname of the peer.
- `port`: Port of the peer.
- `weight`: Same as reported in `proxysql_servers`.`weight`.
- `comment`: Same as reported in `proxysql_servers`.`comment`.
- `response_time_ms`: Response time while running `SHOW MYSQL STATUS`, in millisecond.
- `Uptime_s`: Peer's uptime in second.
- `last_check_ms`: Age of the last time a check was executed, in millisecond.
- `Queries`: Number of queries executed by the peer.
- `Client_Connections_connected`: Number of client's connections connected.
- `Client_Connections_created`: Number of client's connections created.

<!-- -->

Note: All the status variables are retrieved by the peers, but only few are monitored to be able to check if
the peer is up and running and processing traffic. Currently this feature is useful only for debugging
purposes, but maybe future versions will use these metrics to understand the health of remote peers.

### Table `stats_proxysql_servers_clients_status`

Table definition:

```
admin> SHOW CREATE TABLE stats.stats_proxysql_servers_clients_status\G
*************************** 1. row ***************************
       table: stats_proxysql_servers_clients_status
Create Table: CREATE TABLE stats_proxysql_servers_clients_status (
    uuid VARCHAR NOT NULL,
    hostname VARCHAR NOT NULL,
    port INT NOT NULL,
    admin_mysql_ifaces VARCHAR NOT NULL,
    last_seen_at INT NOT NULL,
    PRIMARY KEY (uuid, hostname, port) )
1 row in set (0.00 sec)
```

This table shows the information advertised by peer nodes from the cluster when connecting to this instance.
This communication is performed via the command `PROXYSQL CLUSTER_NODE_UUID`, the following information is
extracted by the receving instance during the command processing. The fields have the following semantics:

- `uuid`: The connecting peer `UUID`.
- `hostname`: Hostname of the client peer node as seen by the receiving instance.
- `port`: Port of the client peer node as seen by the receiving instance.
- `admin_mysql_ifaces`: Admin interfaces of the client node.
- `last_seen_at`: The time, *seconds since Epoch*, at the moment of the command reception.

This table is populated in the following way. When a cluster node (client) connects to another cluster node,
it advertises its UUID but also exports its `admin-mysql_ifaces`, this is done via the previously mentioned
command `PROXYSQL CLUSTER_NODE_UUID`. This information can later be used by the receiving cluster node, for
example, for guessing hot to connect to the nodes initializing connections, to collect metrics from them.

### Table `stats_proxysql_servers_status`

 Currently unused

## Bandwidth considerations

As described above, architectures where all nodes monitor all the other nodes are possible. A fully mesh
peer-to-peer network. To reduce network usage, nodes do not always exchange the whole list of checksums;
instead they exchange a single checksum resulting from combining all the versions and all the checksums. If
this *global checksum* has changed, a detailed list of checksums is retrieved. Using this technique, a 200
nodes cluster monitoring each other every 1000ms, requires a bandwidth of 50KBps in/out to/from each node.

This optimization only takes place for *changes detection*. For the actual data being propagated between
nodes, ProxySQL doesn't perform any form of compression or delta detection. This means, that evaluating if the
amount of data being transfer is something acceptable or not, is up to the user to determine. This is
specially relevant for modules that can hold *hundreds of thousands*, or even *millions* of entries, like
`mysql_users` or `mysql_query_rules`. For more details check [Re-configuration](#re-configuration)

# Re-configuration


This section tries to cover several topics on the fetching procedure itself. We will try to answer the
following questions:

- How it's decided that new configuration is available in one peer to be fetched?
- How much data it's sent between peers?
- Does data generation affects the sending ProxySQL instance?
- Does data reception and configuration load affect the receiving ProxySQL instance?

There are two phases concerning configuration propagation when a module is updated in one ProxySQL instance:

1. Data ('resultset') generation for configuration propagation, and checksums update.
2. Fetching operation from peer nodes when checksum update is detected.

## Data generation

The first phase is triggered when the user updates the configuration and promotes it to runtime. Since version
`v2.4.3` ProxySQL performs an optimization at this stage, it generates `resultsets` with the configuration
being promoted, these are later being used by `Admin` module when replying to another cluster nodes requests,
this way, there is **no penalty** when replying to the cluster peers fetching requests, since the response has
been already pre-computed. Please note, that currently there is no `configuration delta` being computed, this
means that the full configuration applied to each module is being fetch by the other peer nodes. This is
something to take into account mostly because of the network load that could generate, specially for modules
that could potentially hold hundred of thousands of entries, like `mysql_query_rules` or `mysql_users`. Even
with this number of entries, the processing of the fetch request should be relatively fast for both nodes
involved:

* Sending node: Request is precomputed and served by Admin, so it will be a *light* operation, which will only
  lock the Admin interface (as any other Admin interface request).
* Receiving node: The operation (reconfiguration) should be very fast even with really big number of entries
  for the sync modules, but several optimizations are in place, like bulk inserting, that help speeding this
  process, the operation is of course less lighter than for the *Sending* node, since data is required to be
  processed.

Checksum computation is performed and updated after this new configuration is applied, and this new data is
created.

## Fetching procedure

The second part of configuration propagation, concerns the fetching phase. Because proxies monitor each other,
they can immediately know when a checksum of a configuration changed, which means that the configuration
itself have changed. The full checking and sync procedure can be summarized in the following steps:

1. Check the peers `global_checksum`, this global checksum minimize the network load required for checking
   that no changes took place in any module of the peer instance.
2. If some peer `gobal_checksum` changes, is indicative that one or more modules configuration has been
   modified. A query like `SELECT * FROM runtime_checksums_values ORDER BY name` is sent to the remote peer in
   order to fetch the latest checksums for all modules, including epoch and version.
3. When the module checksums from the peer are received, they are checked against the instance own
   configuration. This is done because it is possible that the remote peer's configuration and its own
   configuration have changed at the same time, or within a short period of time. The action been taken now is
   dependent on own module version number:
      - If own `version` is `1`, find a peer with `version > 1` and the highest epoch and sync
        immediately. Jump to step `5`.
      - If own `version` is greater than `1`, then we follow on step `4`.
4. There is now a grace period phase, determined primarily by
   [admin-*module\_name*\_diffs\_before_sync](#diffs-before-sync) variables, each check increases `diff_check`
   value from [stats\_proxysql\_servers\_checksums](#table-stats_proxysql_servers_checksums). When the
   threshold imposed by the variable is exceeded, the fetching starts.
5. Data fetching is performed as a series of `SELECT` statements performed in the same connections used for
   performing the health checks. These statements are of the form `SELECT _list_of_columns_ FROM
   runtime_module`.
6. After receiving the data, ProxySQL ensures that the received data matches the pre-fetched checksum,
   ensuring this way that the module from the peer wasn't reconfigured between the checksum change detection
   and the fetching operation.
7. If everything holds, the local configuration tables are deleted, via statements of the form `DELETE FROM
   module_name`. Fetched data is then inserted into the module tables. The configuration is then promoted to
   runtime via `LOAD module_name TO RUNTIME` commands. This will increase the version number of the module and
   create a new checksum.
8. Finally configuration is conditionally saved to disk based on the value of per-module variables
   `cluster_module_name_save_to_disk`, if `true` configuration will be save to disk via `SAVE module_name TO
   DISK` commands.

**NOTES:**

It is possible that a different is detected against a node, but the sync is performed against a
different node. Because the sync is done with the node with the highest epoch, it is expected that all the
nodes will converge.

Up to ProxySQL `v2.1.0`, cluster members with different ProxySQL version numbers were allowed to
sync, this behavior got changed in `v2.1.0`. ProxySQL versions `v2.1.0` and newer **do not** allow cluster
members with different versions to sync anymore (i.e. every member of a ProxySQL Cluster has to share the
exact version of ProxySQL). The reasons behind this change were to prevent possible inconsistencies between
different versions of ProxySQL and to reduce the complexity of the logic involved.

<!-- -->

# Configuration Example

As a way of guiding through multiple concepts, we are going to setup a ProxySQL cluster with two `Core` nodes
and one `Satellite` node. First we would like to have different ProxySQL interfaces for our instances, since
this will be a local example, we will take a look to our instances configuration files. We will assume a
simple local setup, in which each node of the ProxySQL cluster is listening to different ports, other setups
may share `mysql-interfaces`, since ProxySQL has the ability of sharing ports with other instances.  Let's
start with the `Core` nodes configuration files:

`proxysql-01.cfg`:
```
// Avoid syncing the interfaces since our setup is local
cluster_sync_interfaces=false

// Setup the minimal variables for having
// - Admin credentials.
// - Admin interface.
// - Cluster monitoring credentials.
admin_variables=
\{
	admin_credentials="radmin:radmin;cluster_user:cluster_pass"
	mysql_ifaces="0.0.0.0:26001"
	cluster_username="cluster_user"
	cluster_password="cluster_pass"
\}

mysql_variables=
\{
	// Setup the local mysql-interface:
	interfaces="0.0.0.0:36001"
	// Different from default to experience 'version 1' warning
	monitor_ping_timeout=999
\}

// Setup the Core nodes of our cluster
proxysql_servers =
(
	\{
		hostname="127.0.0.1"
		port=26001
		weight=0
		comment="proxysql01"
	\},
	\{
		hostname="127.0.0.1"
		port=26002
		weight=0
		comment="proxysql02"
	\}
)
```

For our second core node, we are just required to update the interfaces being used, all the other variables
should remain with the same values as in the previous template:

`proxysql-02.cfg`:
```
...

admin_variables=
\{
...
	mysql_ifaces="0.0.0.0:26002"
	monitor_ping_timeout=1000 // Default value
...
\}

mysql_variables=
\{
	interfaces="0.0.0.0:36002"
\}

...
```

Now, let's launch both nodes, and connect to the first one:

```
mysql --prompt="admin> " -uradmin -pradmin -h0.0.0.0 -P26001
```

Now let's check the current checksum values:

```
admin> SELECT * FROM runtime_checksums_values;
+-------------------+---------+------------+--------------------+
| name              | version | epoch      | checksum           |
+-------------------+---------+------------+--------------------+
| admin_variables   | 1       | 1692376589 | 0xC5FA911349ED496B |
| mysql_query_rules | 1       | 1692376589 | 0x0000000000000000 |
| mysql_servers     | 1       | 1692376589 | 0x0000000000000000 |
| mysql_users       | 1       | 1692376589 | 0x0000000000000000 |
| mysql_variables   | 1       | 1692376589 | 0xDE4864841AE32D5D |
| proxysql_servers  | 1       | 1692376589 | 0x10C33098743C7705 |
+-------------------+---------+------------+--------------------+
6 rows in set (0.00 sec)
```

We can see that all our modules are initialized with some checksum, some of them, having `0` as checksum, as
they having been yet configured. Let's check the checksums of the other known cluster instances (peers):

```
admin> SELECT * FROM stats_proxysql_servers_checksums;
+-----------+-------+-------------------+---------+------------+--------------------+------------+------------+------------+
| hostname  | port  | name              | version | epoch      | checksum           | changed_at | updated_at | diff_check |
+-----------+-------+-------------------+---------+------------+--------------------+------------+------------+------------+
| 127.0.0.1 | 26002 | admin_variables   | 1       | 1692376590 | 0xC5FA911349ED496B | 1692376591 | 1692376659 | 0          |
| 127.0.0.1 | 26002 | mysql_query_rules | 1       | 1692376590 | 0x0000000000000000 | 1692376591 | 1692376659 | 0          |
| 127.0.0.1 | 26002 | mysql_servers     | 1       | 1692376590 | 0x0000000000000000 | 1692376591 | 1692376659 | 0          |
| 127.0.0.1 | 26002 | mysql_users       | 1       | 1692376590 | 0x0000000000000000 | 1692376591 | 1692376659 | 0          |
| 127.0.0.1 | 26002 | mysql_variables   | 1       | 1692376590 | 0x84895A2188043C77 | 1692376591 | 1692376659 | 69         |
| 127.0.0.1 | 26002 | proxysql_servers  | 1       | 1692376590 | 0x10C33098743C7705 | 1692376591 | 1692376659 | 0          |
| 127.0.0.1 | 26001 | admin_variables   | 1       | 1692376589 | 0xC5FA911349ED496B | 1692376590 | 1692376659 | 0          |
| 127.0.0.1 | 26001 | mysql_query_rules | 1       | 1692376589 | 0x0000000000000000 | 1692376590 | 1692376659 | 0          |
| 127.0.0.1 | 26001 | mysql_servers     | 1       | 1692376589 | 0x0000000000000000 | 1692376590 | 1692376659 | 0          |
| 127.0.0.1 | 26001 | mysql_users       | 1       | 1692376589 | 0x0000000000000000 | 1692376590 | 1692376659 | 0          |
| 127.0.0.1 | 26001 | mysql_variables   | 1       | 1692376589 | 0xDE4864841AE32D5D | 1692376590 | 1692376659 | 0          |
| 127.0.0.1 | 26001 | proxysql_servers  | 1       | 1692376589 | 0x10C33098743C7705 | 1692376590 | 1692376659 | 0          |
+-----------+-------+-------------------+---------+------------+--------------------+------------+------------+------------+
12 rows in set (0.01 sec)
```

This way we can see not only our current checksums, but also the ones from the other instances we are fetching
from. For example, we can spot our intentional mismatch placed in the configuration file for variable
`mysql-monitor_ping_timeout`, we can see a mismatch between the checksums for module `mysql_variables`,
this difference is also flagged by the field `diff_check`, that stands above our current configured threshold
`admin-cluster_mysql_variables_diffs_before_sync`. This is expected, since we are dealing with `version 1`
right now, ProxySQL will report the situation to the user in both ProxySQL instances through error log:

*proxysql-01*:

```
2023-08-18 18:37:00 ProxySQL_Cluster.cpp:870:set_checksums(): [WARNING] Cluster: detected a peer 127.0.0.1:26002 with mysql_variables version 1, epoch 1692376590, diff_check 30. Own version: 1, epoch: 1692376589. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every 30 checks until LOAD MYSQL VARIABLES TO RUNTIME is executed on candidate master.
```

*proxysql-02*:

```
2023-08-18 18:36:59 ProxySQL_Cluster.cpp:870:set_checksums(): [WARNING] Cluster: detected a peer 127.0.0.1:26001 with mysql_variables version 1, epoch 1692376589, diff_check 30. Own version: 1, epoch: 1692376590. diff_check is increasing, but version 1 doesn't allow sync. This message will be repeated every 30 checks until LOAD MYSQL VARIABLES TO RUNTIME is executed on candidate master.
```

As the message says, this will be repeating with each periodic check, this is due to a mismatch with the
special version number `1`. Since both ProxySQL instances are freshly started, and both hold `version 1` for
all the configuration in their modules, there is no promoted `source of truth` in the cluster yet. Because of
this, the instances hold the synchronization until a instance is selected by the user via:

```
LOAD *MODULE_NAME* TO RUNTIME;
```

In this case, we are going to execute the following command in instance `proxysql-01`:

```
LOAD MYSQL VARIABLES TO RUNTIME;
```

After this command, we can check that our version for `mysql_variables` module has been increased, and that
the other instance `proxysql-02` detected this change and performed a configuration sync:

```
admin> SELECT * FROM stats_proxysql_servers_checksums;
+-----------+-------+-------------------+---------+------------+--------------------+------------+------------+------------+
| hostname  | port  | name              | version | epoch      | checksum           | changed_at | updated_at | diff_check |
+-----------+-------+-------------------+---------+------------+--------------------+------------+------------+------------+
| 127.0.0.1 | 26002 | admin_variables   | 1       | 1692376590 | 0xC5FA911349ED496B | 1692376591 | 1692377446 | 0          |
| 127.0.0.1 | 26002 | mysql_query_rules | 1       | 1692376590 | 0x0000000000000000 | 1692376591 | 1692377446 | 0          |
| 127.0.0.1 | 26002 | mysql_servers     | 1       | 1692376590 | 0x0000000000000000 | 1692376591 | 1692377446 | 0          |
| 127.0.0.1 | 26002 | mysql_users       | 1       | 1692376590 | 0x0000000000000000 | 1692376591 | 1692377446 | 0          |
| 127.0.0.1 | 26002 | mysql_variables   | 2       | 1692377444 | 0xDE4864841AE32D5D | 1692377446 | 1692377446 | 0          |
| 127.0.0.1 | 26002 | proxysql_servers  | 1       | 1692376590 | 0x10C33098743C7705 | 1692376591 | 1692377446 | 0          |
| 127.0.0.1 | 26001 | admin_variables   | 1       | 1692376589 | 0xC5FA911349ED496B | 1692376590 | 1692377446 | 0          |
| 127.0.0.1 | 26001 | mysql_query_rules | 1       | 1692376589 | 0x0000000000000000 | 1692376590 | 1692377446 | 0          |
| 127.0.0.1 | 26001 | mysql_servers     | 1       | 1692376589 | 0x0000000000000000 | 1692376590 | 1692377446 | 0          |
| 127.0.0.1 | 26001 | mysql_users       | 1       | 1692376589 | 0x0000000000000000 | 1692376590 | 1692377446 | 0          |
| 127.0.0.1 | 26001 | mysql_variables   | 2       | 1692377444 | 0xDE4864841AE32D5D | 1692376590 | 1692377446 | 0          |
| 127.0.0.1 | 26001 | proxysql_servers  | 1       | 1692376589 | 0x10C33098743C7705 | 1692376590 | 1692377446 | 0          |
+-----------+-------+-------------------+---------+------------+--------------------+------------+------------+------------+
12 rows in set (0.00 sec)
```

After the sync, we can see the newer epoch in the updated checksums, that their value changed, and that
`diff_check` is back being `0`. Normally, if for some reason, we start several instances with different
configurations, we want to configure one of them as the source of truth, as we have done in this example.

First, let's check the members stats that the instance is reporting about the other core nodes:

```
admin> SELECT * FROM stats_proxysql_servers_metrics;
+-----------+-------+--------+------------+------------------+----------+---------------+---------+------------------------------+----------------------------+
| hostname  | port  | weight | comment    | response_time_ms | Uptime_s | last_check_ms | Queries | Client_Connections_connected | Client_Connections_created |
+-----------+-------+--------+------------+------------------+----------+---------------+---------+------------------------------+----------------------------+
| 127.0.0.1 | 26002 | 0      | proxysql02 | 10               | 2412     | 6303          | 0       | 0                            | 0                          |
| 127.0.0.1 | 26001 | 0      | proxysql01 | 11               | 2411     | 8608          | 0       | 0                            | 0                          |
+-----------+-------+--------+------------+------------------+----------+---------------+---------+------------------------------+----------------------------+
2 rows in set (0.00 sec)
```

Lets now also check the current clients that instance `proxysql-01` acknowledges, before adding satellites
nodes to the cluster:

```
admin> SELECT * FROM stats_proxysql_servers_clients_status;
+--------------------------------------+-----------+-------+--------------------+--------------+
| uuid                                 | hostname  | port  | admin_mysql_ifaces | last_seen_at |
+--------------------------------------+-----------+-------+--------------------+--------------+
| 6cd51c3a-b32f-4758-99a5-6c156c2da99e | 127.0.0.1 | 54776 | 0.0.0.0:26001      | 1692378123   |
| ca2e1c4c-6e3f-46e5-a750-54ed57b528c3 | 127.0.0.1 | 54790 | 0.0.0.0:26002      | 1692378123   |
+--------------------------------------+-----------+-------+--------------------+--------------+
2 rows in set (0.01 sec)
```

Our two core nodes are the ones being reported by our instance, let's add a third node, which configuration
file will be just:

`proxysql-03.cfg`
```
cluster_sync_interfaces=false

admin_variables=
\{
	admin_credentials="radmin:radmin;cluster_user:cluster_pass"
	mysql_ifaces="0.0.0.0:26001"
	cluster_username="cluster_user"
	cluster_password="cluster_pass"
\}

mysql_variables=
\{
	// Setup the local mysql-interface:
	interfaces="0.0.0.0:36003"
\}

// Setup the Core nodes of our cluster
proxysql_servers =
(
	\{
		hostname="127.0.0.1"
		port=26001
		weight=0
		comment="proxysql01"
	\},
	\{
		hostname="127.0.0.1"
		port=26002
		weight=0
		comment="proxysql02"
	\}
)
```

Notice how the node itself isn't in the configured `proxysql_servers`. Only the `Core` nodes should be
configured in that table. After starting the instance, we can connect again to instance `proxysq-01`:

```
admin> SELECT * FROM stats_proxysql_servers_checksums;
+-----------+-------+-------------------+---------+------------+--------------------+------------+------------+------------+
| hostname  | port  | name              | version | epoch      | checksum           | changed_at | updated_at | diff_check |
+-----------+-------+-------------------+---------+------------+--------------------+------------+------------+------------+
| 127.0.0.1 | 26002 | admin_variables   | 1       | 1692376590 | 0xC5FA911349ED496B | 1692376591 | 1692378523 | 0          |
| 127.0.0.1 | 26002 | mysql_query_rules | 1       | 1692376590 | 0x0000000000000000 | 1692376591 | 1692378523 | 0          |
| 127.0.0.1 | 26002 | mysql_servers     | 1       | 1692376590 | 0x0000000000000000 | 1692376591 | 1692378523 | 0          |
| 127.0.0.1 | 26002 | mysql_users       | 1       | 1692376590 | 0x0000000000000000 | 1692376591 | 1692378523 | 0          |
| 127.0.0.1 | 26002 | mysql_variables   | 2       | 1692377444 | 0xDE4864841AE32D5D | 1692377446 | 1692378523 | 0          |
| 127.0.0.1 | 26002 | proxysql_servers  | 1       | 1692376590 | 0x10C33098743C7705 | 1692376591 | 1692378523 | 0          |
| 127.0.0.1 | 26001 | admin_variables   | 1       | 1692376589 | 0xC5FA911349ED496B | 1692376590 | 1692378523 | 0          |
| 127.0.0.1 | 26001 | mysql_query_rules | 1       | 1692376589 | 0x0000000000000000 | 1692376590 | 1692378523 | 0          |
| 127.0.0.1 | 26001 | mysql_servers     | 1       | 1692376589 | 0x0000000000000000 | 1692376590 | 1692378523 | 0          |
| 127.0.0.1 | 26001 | mysql_users       | 1       | 1692376589 | 0x0000000000000000 | 1692376590 | 1692378523 | 0          |
| 127.0.0.1 | 26001 | mysql_variables   | 2       | 1692377444 | 0xDE4864841AE32D5D | 1692376590 | 1692378523 | 0          |
| 127.0.0.1 | 26001 | proxysql_servers  | 1       | 1692376589 | 0x10C33098743C7705 | 1692376590 | 1692378523 | 0          |
+-----------+-------+-------------------+---------+------------+--------------------+------------+------------+------------+
12 rows in set (0.00 sec)
```

We can see that the list of servers checksums being monitored haven't changed, **but** instead the list of
clients includes the new member:

```
admin> SELECT * FROM stats_proxysql_servers_clients_status;
+--------------------------------------+-----------+-------+--------------------+--------------+
| uuid                                 | hostname  | port  | admin_mysql_ifaces | last_seen_at |
+--------------------------------------+-----------+-------+--------------------+--------------+
| 8c7c0e97-41ac-49e8-b901-09164ffec90c | 127.0.0.1 | 56596 | 0.0.0.0:26003      | 1692378525   |
| 6cd51c3a-b32f-4758-99a5-6c156c2da99e | 127.0.0.1 | 54776 | 0.0.0.0:26001      | 1692378525   |
| ca2e1c4c-6e3f-46e5-a750-54ed57b528c3 | 127.0.0.1 | 54790 | 0.0.0.0:26002      | 1692378525   |
+--------------------------------------+-----------+-------+--------------------+--------------+
3 rows in set (0.00 sec)
```

The same scenario will be seeing from instance `proxysql-02`. We have ourselves a ProxySQL cluster with three
nodes, two `Core` nodes and one `Satellite` node.

# Roadmap

This is an overview of the features related to clustering, and not a complete list. None the following is
implemented yet. Implementation may be different than what is listed right now:

- Add support for Scheduler.
- Support for master election: the word master was intentionally chosen instead of leader.
- Only master proxy is writable/configurable.
- Implementation of MySQL-like replication from master to slaves, allowing to push configuration in real-time
  instead of pulling it.
- Implementation of MySQL-like replication from master to candidate-masters.
- Implementation of MySQL-like replication from candidate-masters to slaves.
- Creation of a quorum with only candidate-masters: normal slaves are not part of the quorum.

<!-- -->

# Q&A

**What if a different configuration is loaded at the same time on each of the ProxySQL servers, which
configuration is the one that needs to be "propagated" to all other nodes? The last one?**

The concept of master and master election is not implemented yet. That means that a `LOAD` command can be
potentially executed on multiple nodes at the same time (multi-master, to make some analogy), and each will
trigger an automatic reconfiguration with timestamp-based conflict-resolution. If the same configuration is
loaded at the same time on multiple ProxySQL instances, they should automatically converge. If different
configurations are loaded on multiple ProxySQL instances at different times, the last one will win. If
different configurations are loaded on multiple ProxySQL instances at the same time, the two configurations
will start propagating till the point at which they won't converge as conflict resolution is not possible.
The good thing is that each ProxySQL knows the checksum of configuration of every other node, so mismatches
are easy to detect and monitor.

**Who is writing this configuration to all those nodes?**

Currently a pull mechanism is used, therefore the node that detects it needs to reconfigure itself and it
will pull the configuration from the node with the most up-to-date configuration and apply it locally.

**How are you going to implement election? Raft consensus protocol?**

Implementation of election is in the roadmap, but probably not Raft consensus protocol. ProxySQL uses tables
to store configuration, it uses the MySQL protocol to perform requests to its peers querying their health and
their configuration, it uses the MySQL protocol to implement heartbeat and much more: for these reasons, in
the case of ProxySQL, the MySQL protocol itself might be a more versatile solution compared to Raft protocol.

**What will happen if for some reason one of the nodes will be unable to grab the new configuration in an
event of re-configuration?**

Changes are propagated asynchronously. Therefore it is possible that one of the nodes is not able to grab the
new configuration, for example in case of network issues or ProxySQL being restarted. Yet, when a ProxySQL
instance detects that one of its peers has a newer configuration, it will automatically grab it.

**What about crossdc? What will be the best practice, having a cluster in each DC?**

Clusters do not have boundaries, therefore it is possible to have a single cluster across multiple DCs, or to
have multiple clusters in the same DC, or multiple clusters across multiple DCs. This really depends on the
specific use case. The only limitation is that each ProxySQL instance needs to belong to a single cluster.
Clusters do not have names, and to make sure that a node doesn't erroneously join the wrong cluster it is
important to ensure that each cluster uses different credentials. See `admin-admin_credentials`,
`admin-cluster_username` and `admin-cluster_password`.

**Could be a nice feature to somehow replicate the configuration crossdc but prefer traffic to the backend
server that is closest to the local ProxySQL server. I am doing it now using weight.**

For this specific case I think it makes more sense to create a different cluster for each DC, as the
configuration will be different.

**How is a new ProxySQL going to join the cluster?**

Bootstrap is very easy: starts with at least 1 peer in `proxysql_servers` .

**How will all other ProxySQL servers know there is a new node?**

They do not know it automatically, and this is intentional to prevent that a new node may corrupt the cluster.
In other words, a new node can pull the configuration as soon as it joins, but it cannot advertise itself as
the source of truth. To let the other ProxySQL instances know that there is a new node, it is enough to add
the new node in `proxysql_servers` of any node of the current cluster and issue `LOAD PROXYSQL SERVERS TO
RUNTIME`.
