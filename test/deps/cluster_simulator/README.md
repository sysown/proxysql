## ProxySQL Cluster Simulator

This is a simulator that makes use of ProxySQL hability to fake the status being
received from the configured servers through SQLite. When compiled in each of
the different testing modes, ProxySQL replaces the servers connections in
favor to local connections to an internal SQLite database, in which the data
for the servers is faked.

## Compilation

To be used the simulator needs ProxySQL to be compiled in each of the different
modes that support the server replacement through SQLite. For this purpose, ProxySQL needs to be
compiled for the correct testing mode that is going to be performed, currently supported modes are:
`GALERA, READONLY, GROUP_REPLICATION`.

### ProxySQL modes compilation

* Galera suport:

  ```
  make build_deps -j$(nproc) && make testgalera -j$(nproc) && make build_tap_test -j$(nproc)
  ```

* ReadOnly support:

  ```
  make build_deps -j$(nproc) && make testreadonly -j$(nproc) && make build_tap_test -j$(nproc)
  ```

* Group Replication support:

  ```
  make build_deps -j$(nproc) && make testgrouprep -j$(nproc) && make build_tap_test -j$(nproc)
  ```

* Replication Lag support:

  ```
  make build_deps -j$(nproc) && make testreplicationlag -j$(nproc) && make build_tap_test -j$(nproc)
  ```

### ClusterSimulator compilation

To compile the simulator it's just required to go to the 'cluster_simulator' root
folder and execute the following commands:

```
export WORKSPACE=path_to_proxysql_workspace
make debug -j$(nproc)
```

To compile simulator tests helper, it

### Galera compilation

## Usage

Once ProxySQL is compiled in the desired mode, launch it using one of the provided
configurations in the datadir directory:

```
./src/proxysql --sqlite3-server -f -c ${CLUSTER_SIM_DIR}/configs/galera_sim_conf.cnf -D ./galera_sim_datadir
```

Available configurations are: `galera_sim_conf.cnf`, `readonly_sim_conf.cnf` and
`grouprep_sim_conf.cnf`.

With ProxySQL running in the desired mode, we can now make use of the simulator to perform
any checks we want. To illustrate this, we will make use of sample payloads supplied
in the `example_payloads` directory. First it's required to source the some environmental
variables that are used to configure how the simulator perform the connections to Admin interface
and SQLite:

```
source constants
```

Then we simply execute the simulator, using one of the example payloads provided:

```
./cluster_simulator -v --mode verify -f example_payloads/simple_test_payload.json
```

### Simulator options

To check the simulator options, just use the `--help` command line argument:

```
$ ./cluster_simulator --help

Generic Cluster Simulator for ProxySQL

USAGE: cluster_simulator [OPTIONS]

OPTIONS:

-f, --file ARG               Specify input payload file
-h, -help, --help, --usage   Display usage instructions.
-m, --mode ARG               Operation mode
-v, --verbose                Enable verbose output
--stop-on-failure            Stop on failure


Have fun :)
```

Arguments:

* --help: Displays the help message.
* --file: Required argument specifying the input payload file.
* --mode: Selects the simulator operation mode. Simulator can operate in two different modes: 'simulate'
  and 'verify'. The 'simulate' mode is used to obtain both the 'initial state' and the 'final state'
  from a provided configuration, while the 'verify' mode is used to verify that both, the provided
  'initial state' and the 'final state' match the expected ones. Complete usage can be seeing in the later
  section 'Complete usage example'.
* --verbose: Controls whether the simulator outputs the whole input as a result when operating in 'verify'
  mode, or just outputs a result specifying that no error took place.
* --stop-on-failure: Since the input payload can contain *multiple* different tests, this parameter
  specifies whether the simulator should stop or not after a failed verification.

### Simulator Payload Format

Simulator payload is a JSON object holding the following members:

#### Generic members:

* "__comment__"(Optional): Optional comment specifying the purpose of the test, just for providing
  documentation.
* "cluster_type"(Required): Specifies the type of simulation the test is targeting. Current valid
  values are: `GALERA`, `READONLY`, `GROUP_REPLICATION`
* "mysql_servers": Array holding the 'mysql_servers' to be configured in ProxySQL for performing
  the test. Objects in the array are required to be JSON objects with the following members:
  `{hostgroup_id, hostname, port, status (optional) }`.
* "proxysql_init_state": Array holding the expected status of the 'mysql_servers' on ProxySQL after
  the initial configuration provided.

  Objects in the array are required to be JSON objects with the following members: `{hostgroup_id,
  hostname, port, status}`. They can also include `weight`, `max_connections`, `use_ssl`, and
  `comment`. An omitted optional member is not compared; an explicitly supplied member, including
  an empty `comment`, must match exactly.

  Status member should be an `string` of one of the following values:
  "SHUNNED|ONLINE|OFFLINE_SOFT|OFFLINE_HARD". NOTE: Since 'OFFLINE_HARD' status is a transitory
  state, which will eventually disappear from the 'mysql_servers' table, it's internally ignored by
  the simulator for deciding whether the cluster is in a proper state or not.
* "proxysql_final_state": Array holding the expected status of the 'mysql_servers' on ProxySQL after
  the 'new_state' has been applied to cluster servers and ProxySQL has reconfigured itself responding
  to this new cluster state. The objects inside this array are required to be of the same shape as
  the ones supplied for `proxysql_init_state`.

#### GALERA cluster specific members:

* "mysql_galera_hostgroups": Array holding JSON objects holding the values for configuring the
  'mysql_galera_hostgroups'.

  Objects need to hold the following members:

  `{"writer_hostgroup, "backup_writer_hostgroup, "reader_hostgroup,
  "offline_hostgroup, "active, "max_writers, "writer_is_also_reader, "max_transactions_behind, "comment" }`.

  Values in this objects have the same requisites as values for configuring
  `mysql_galera_hostgroups` table:

  ```
  mysql> SHOW CREATE TABLE mysql_galera_hostgroups\G
  *************************** 1. row ***************************
         table: mysql_galera_hostgroups
  Create Table: CREATE TABLE mysql_galera_hostgroups (
      writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY,
      backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL,
      reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND   reader_hostgroup>0),
      offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND   backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0),
      active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
      max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1,
      writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1,2)) NOT NULL DEFAULT 0,
      max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0,
      comment VARCHAR,
      UNIQUE (reader_hostgroup),
      UNIQUE (offline_hostgroup),
      UNIQUE (backup_writer_hostgroup))
  1 row in set (0.00 sec)
  ```

* "galera_servers_init_state": Array holding JSON objects specifying the initial state for 'GALERA'
  servers. Objects need to hold the following members:

  ```
  { "hostgroup_id, "hostname, "port, "wsrep_local_state, "read_only, "wsrep_local_recv_queue, "wsrep_desync,
   "wsrep_reject_queries, "wsrep_sst_donor_rejects_queries, "wsrep_cluster_status, "pxc_maint_mode"}
  ```

  Values in these objects have the same requisites as values for configuring `HOST_STATUS_GALERA`
  table:
  ```
  mysql> SHOW CREATE TABLE HOST_STATUS_GALERA\G
  *************************** 1. row ***************************
         table: HOST_STATUS_GALERA
  Create Table: CREATE TABLE HOST_STATUS_GALERA (
      hostgroup_id INT NOT NULL,
      hostname VARCHAR NOT NULL,
      port INT NOT NULL,
      wsrep_local_state VARCHAR,
      read_only VARCHAR,
      wsrep_local_recv_queue VARCHAR,
      wsrep_desync VARCHAR,
      wsrep_reject_queries VARCHAR,
      wsrep_sst_donor_rejects_queries VARCHAR,
      wsrep_cluster_status VARCHAR,
      pxc_maint_mode VARCHAR NOT NULL CHECK (pxc_maint_mode IN ('DISABLED', 'SHUTDOWN', 'MAINTENANCE')) DEFAULT 'DISABLED',
      PRIMARY KEY (hostgroup_id, hostname, port))
  1 row in set (0.00 sec)
  ```


* "galera_servers_new_state": Array holding JSON objects specifying the new state for 'GALERA'
  servers. Objects needs to be of the same shape as the described for `galera_servers_init_state`,
  but only the ones specifying changes for servers are required to be provided. This way if for
  example initial servers status definition was:

  ```
      "galera_servers_init_state": [
          {
              "hostgroup_id": 2271,
              "hostname": "127.1.1.11",
              "port": 3306,
              "wsrep_local_state": 4,
              "read_only": 0,
              "wsrep_local_recv_queue": 0,
              "wsrep_desync": 0,
              "wsrep_reject_queries": "NONE",
              "wsrep_sst_donor_rejects_queries": 0,
              "wsrep_cluster_status": "Primary",
              "pxc_maint_mode": "DISABLED"
          },
          {
              "hostgroup_id": 2271,
              "hostname": "127.1.1.12",
              "port": 3306,
              "wsrep_local_state": 4,
              "read_only": 0,
              "wsrep_local_recv_queue": 0,
              "wsrep_desync": 0,
              "wsrep_reject_queries": "NONE",
              "wsrep_sst_donor_rejects_queries": 0,
              "wsrep_cluster_status": "Primary",
              "pxc_maint_mode": "DISABLED"
          },
          {
              "hostgroup_id": 2271,
              "hostname": "127.1.1.13",
              "port": 3306,
              "wsrep_local_state": 4,
              "read_only": 0,
              "wsrep_local_recv_queue": 0,
              "wsrep_desync": 0,
              "wsrep_reject_queries": "NONE",
              "wsrep_sst_donor_rejects_queries": 0,
              "wsrep_cluster_status": "Primary",
              "pxc_maint_mode": "DISABLED"
          }
      ]
  ```

  And we only want to change the state of server: `127.1.1.13:3306`, we can only provide the
  following `galera_servers_new_state` array definition:

  ```
    "galera_servers_new_state": [
        {
            "hostgroup_id": 2271,
            "hostname": "127.1.1.13",
            "port": 3306,
            "wsrep_local_state": 4,
            "read_only": 0,
            "wsrep_local_recv_queue": 0,
            "wsrep_desync": 1,
            "wsrep_reject_queries": "NONE",
            "wsrep_sst_donor_rejects_queries": 0,
            "wsrep_cluster_status": "Primary",
            "pxc_maint_mode": "DISABLED"
        }
    ]
  ```

  Differences in state for server `127.1.1.13:3306` will be detected and changed.

#### READONLY specific members:

* "mysql_replication_hostgroups": Array holding JSON objects holding the values for configuring the
  'mysql_replication_hostgroups' to be used for the test. Objects need to hold the following members:

  ```
   { "writer_hostgroup", "reader_hostgroup", "check_type", "comment" }
  ```

  Values in this object have the same requisites as values for configuring
  `mysql_replication_hostgroups` table:

  ```
  mysql> SHOW CREATE TABLE mysql_replication_hostgroups\G
  *************************** 1. row ***************************
         table: mysql_replication_hostgroups
  Create Table: CREATE TABLE mysql_replication_hostgroups (
      writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY,
      reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>=0),
      check_type VARCHAR CHECK (LOWER(check_type) IN ('read_only','innodb_read_only','super_read_only','read_only|innodb_read_only','read_only&innodb_read_only')) NOT NULL DEFAULT 'read_only',
      comment VARCHAR NOT NULL DEFAULT '', UNIQUE (reader_hostgroup))
  ```

* "readonly_servers_init_state": Array holding the initial values to be configured for the
    `read_only` values for the servers being simulated. Object needs to hold the following
    members:

    ```
    { "hostname", "port", "read_only" }
    ```

    Values in these objects have the same requisites as values for configuring
    `READONLY_STATUS` table:

    ```
    mysql> SHOW CREATE TABLE READONLY_STATUS\G
    *************************** 1. row ***************************
           table: READONLY_STATUS
    Create Table: CREATE TABLE READONLY_STATUS (
        hostname VARCHAR NOT NULL,
        port INT NOT NULL,
        read_only INT NOT NULL CHECK (read_only IN (0, 1)) DEFAULT 1,
        PRIMARY KEY (hostname, port))
    ```

* "readonly_servers_new_state": Array holding JSON objects specifying the new values for
  `read_only` for the servers being simulated. Objects needs to be of the same shape as
  the described for `readonly_servers_init_state`, but only the ones specifying changes
  for servers are required to be provided.

#### REPLICATION LAG specific members:

* "replicationlag_servers_init_state": Array holding the initial values to be configured for the
    `seconds_behind_master` values for the servers being simulated. Object needs to hold the following
    members:

    ```
    { "hostname", "port", "seconds_behind_master" }
    ```

    Values in these objects have the same requisites as values for configuring
    `REPLICATIONLAG_HOST_STATUS` table:

    ```
    mysql> SHOW CREATE TABLE REPLICATIONLAG_HOST_STATUS\G
    *************************** 1. row ***************************
           table: REPLICATIONLAG_HOST_STATUS
    Create Table: CREATE TABLE REPLICATIONLAG_HOST_STATUS (
        hostname VARCHAR NOT NULL, 
        port INT NOT NULL, 
        seconds_behind_master INT DEFAULT NULL, 
        PRIMARY KEY (hostname, port))
    ```

* "replicationlag_servers_new_state": Array holding JSON objects specifying the new values for
  `seconds_behind_master` for the servers being simulated. Objects needs to be of the same shape as
  the described for `replicationlag_servers_init_state`, but only the ones specifying changes
  for servers are required to be provided.

#### GROUP REPLICATION specific members:

* "mysql_group_replication_hostgroups": Array holding JSON objects holding the values for
  configuring the `mysql_group_replication_hostgroups` to be used for the test. Objects need to hold
  the following members:

  ```
   { "writer_hostgroup", "reader_hostgroup", "backup_writer_hostgroup", "offline_hostgroup",
       "active", "max_writers", "writer_is_also_reader", "max_transactions_behind", "comment" }
  ```

  Values in this object have the same requisites as values for configuring
  `mysql_group_replication_hostgroups` table:

  ```
  mysql> SHOW CREATE TABLE mysql_group_replication_hostgroups\G
  *************************** 1. row ***************************
         table: mysql_group_replication_hostgroups
  Create Table: CREATE TABLE mysql_group_replication_hostgroups (
      writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY,
      backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL,
      reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0),
      offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0),
      active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1,
      max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1,
      writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1,2)) NOT NULL DEFAULT 0,
      max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0,
      comment VARCHAR,
      UNIQUE (reader_hostgroup),
      UNIQUE (offline_hostgroup),
      UNIQUE (backup_writer_hostgroup))
  1 row in set (0.01 sec)

  mysql>
  ```

* "grouprep_servers_init_state": Array holding the initial values to be configured for the
    `viable_candidate,read_only,transactions_behind` values for the servers being simulated.
   Object needs to hold the following members:

   ```
   { "hostname", "port", "viable_candidate", "read_only", "transactions_behind" }
   ```

   Values in these objects have the same requisites as values for configuring
   `GR_MEMBER_ROUTING_CANDIDATE_STATUS` table:

   ```
   mysql> SHOW CREATE TABLE GR_MEMBER_ROUTING_CANDIDATE_STATUS\G
   *************************** 1. row ***************************
          table: GR_MEMBER_ROUTING_CANDIDATE_STATUS
   Create Table: CREATE TABLE GR_MEMBER_ROUTING_CANDIDATE_STATUS (
       hostname VARCHAR NOT NULL, port INT NOT NULL, viable_candidate varchar not null, read_only varchar not null, transactions_behind int not null, PRIMARY KEY (hostname, port))
   1 row in set (0.00 sec)
   ```

* "grouprep_servers_new_state": Array holding JSON objects specifying the new values for
  `viable_candidate,read_only,transactions_behind` for the servers being simulated. Objects
  needs to be of the same shape as the described for `grouprep_servers_init_state`, but
  only the ones specifying changes for servers are required to be provided.

* "mysql_monitor_config": Array holding the JSON objects specifying the variables to be configured
  for monitor before performing the tests. The expected object format is:

  ```
  { "monitor_$rest_of_variable_name", $value }
  ```

  Notice that the `mysql-` variable start is not present, and should not be included, since all
  `monitor` variables are `mysql` variables. Allowed variables to configure for `GROUP_REPLICATION`
  payloads are:

  * "monitor_groupreplication_healthcheck_interval"
  * "monitor_groupreplication_healthcheck_timeout"
  * "monitor_groupreplication_max_transactions_behind_for_read_only"
  * "monitor_groupreplication_max_transactions_behind_count"

### Simulator Output Format

Simulator output can vary depending if simulation was successful, there was an input error, some
internal failure occurred, and the simulator mode specified. But there are some common values that a
valid formed output should always have, these are: `{ "err_type", "err_msg" }`.

```
{
    "err_type": "invalid_input|simulation_error|none",
    "err_msg": "_Message describing why the input was detected to be invalid_|'One or more of the requested simulations have failed'|''"
}
```

The first `err_type` describes if any of the operations performed by the simulator failed to
complete successfully, possible values for this are:

* 'invalid_input': Some of the parameters supplied to the simulator was detected to be invalid.
* 'simulation_error': Something failed during the requested simulation, the details of why the
  simulation failed will be present in the `results` array holding all the requested simulation results.
* 'none': Simulation was successfully completed without errors.

If `err_type` hold value is `simulation_error|none` another member `results` should be present in
the output result.

```
{
    "err_type": "simulation_error|none",
    "err_msg": "'One or more of the requested simulations have failed'|''",
    "results": [
        { object_holding_simulation_result }
    ]
}
```

The objects contained in the `results` array also can have different shapes, depending on whether
the particular test was successful or not, and the simulator mode, yet the member `err_type` is
always present:

```
{
    "err_type": "invalid_payload|internal_error|verification_error|none",
    "err_msg": "__Message describing the error__|''",
    "results": [
        { object_holding_simulation_result }
    ]
}
```

* 'invalid_payload': The extraction of the fields in the payload required to perform the tests has
  failed. The member `err_msg` should hold the description of why the extraction of the values failed.
* 'internal_error': Some unexpected error happened during an internal simulator operation, these
  errors should be reported for a possible bug fix. The member `err_msg` should hold the
  description with details about the internal error.
* 'verification_error': Some of the verifications that needed to be performed as part of the
   supplied tests failed. The member `err_msg` should hold the description of why the verification failed.
* 'none': The verification completed successfully.

```
{
    "err_type": "invalid_input|internal_error|verification_error|none",
    "err_msg": "Message describing why the input was detected to be invalid."
}
```

If `err_type` is `invalid_payload|internal_error`, the object just contains the two previously
described members. Otherwise, if `err_type` holds `verification_error`, the object contains the
following members:

```
{
    "err_type": "verification_error",
    "err_msg": "Expected 'proxysql_init_state' doesn't match actual cluster state",
    "cluster_state_diff": {
        "2271:127.1.1.12:3306": [
            [
                "wsrep_desync",
                "1"
            ]
        ]
    },
    "exp_proxysql_state": [
        { exp_server_state },
        {       ...        },
    ],
    "act_proxysql_state": [
        { act_server_state },
        {       ...        },
    ]
}
```

* `cluster_state_diff`: Object holding the changes that have been performed in the servers state.
  The changes are specified in a array which key is the `id` of the server, which is a string
  composed by `hostgroup_id:hostname:port`. The contents of this array are a pairs of kind `[ key,
  value ]` identifying the property being changed and the new value assigned to it.
* 'exp_proxysql_state': Array holding the servers in the expected state in which ProxySQL should
  have them configured.
* 'act_proxysql_state': Array holding the servers in the actual state in which ProxySQL has them
  configured.

#### Verify mode:

All the previous outputs can be found in either `verify` or `simulate` modes. However, the final
case of `err_type` holding `none`, the contents of the object depends on if `verbose` flag has been
specified for the simulator.  In case the `verbose` flag **was no specified** the object will simply
contains:

```
{
    "err_type": "none",
    "err_msg": ""
}
```

If the `verbose` flag **was specified** then the object will specify all the members from the input payload,
plus the previously specified objects `err_type` and `err_msg`.

## Simulation and Verification guide

This is minimal guide on how to use the simulator to perform and initial simulation for a cluster
configuration to determine the initial expected cluster state. For later simulating changes in the
cluster and using those simulations as new tests.

### 1. Initial cluster configuration

For creating a new test and using the simulator to verify it, let's first create a sample
configuration for which we want to simulate an initial state:

* File: `next_test_template.json`

```
[
    {
        "cluster_type": "GALERA",
        "mysql_servers": [
            { "hostgroup_id": 2271, "hostname": "127.1.1.11", "port": 3306 },
            { "hostgroup_id": 2273, "hostname": "127.1.1.12", "port": 3306 },
            { "hostgroup_id": 2273, "hostname": "127.1.1.13", "port": 3306 }
        ],
        "mysql_galera_hostgroups": [
            {
                "writer_hostgroup": 2271,
                "backup_writer_hostgroup": 2272,
                "reader_hostgroup": 2273,
                "offline_hostgroup": 2274,
                "active": 1,
                "max_writers": 1,
                "writer_is_also_reader": 1,
                "max_transactions_behind": 100,
                "comment": null
            }
        ],
        "galera_servers_init_state": [
            {
                "hostgroup_id": 2271,
                "hostname": "127.1.1.11",
                "port": 3306,
                "wsrep_local_state": 4,
                "read_only": 0,
                "wsrep_local_recv_queue": 0,
                "wsrep_desync": 0,
                "wsrep_reject_queries": "NONE",
                "wsrep_sst_donor_rejects_queries": 0,
                "wsrep_cluster_status": "Primary",
                "pxc_maint_mode": "DISABLED"
            },
            {
                "hostgroup_id": 2271,
                "hostname": "127.1.1.12",
                "port": 3306,
                "wsrep_local_state": 4,
                "read_only": 0,
                "wsrep_local_recv_queue": 0,
                "wsrep_desync": 0,
                "wsrep_reject_queries": "NONE",
                "wsrep_sst_donor_rejects_queries": 0,
                "wsrep_cluster_status": "Primary",
                "pxc_maint_mode": "DISABLED"
            },
            {
                "hostgroup_id": 2271,
                "hostname": "127.1.1.13",
                "port": 3306,
                "wsrep_local_state": 4,
                "read_only": 0,
                "wsrep_local_recv_queue": 0,
                "wsrep_desync": 0,
                "wsrep_reject_queries": "NONE",
                "wsrep_sst_donor_rejects_queries": 0,
                "wsrep_cluster_status": "Primary",
                "pxc_maint_mode": "DISABLED"
            }
        ],
        "galera_servers_new_state": [
            {
                "hostgroup_id": 2271,
                "hostname": "127.1.1.12",
                "port": 3306,
                "wsrep_local_state": 4,
                "read_only": 0,
                "wsrep_local_recv_queue": 0,
                "wsrep_desync": 1,
                "wsrep_reject_queries": "NONE",
                "wsrep_sst_donor_rejects_queries": 0,
                "wsrep_cluster_status": "Primary",
                "pxc_maint_mode": "DISABLED"
            }
        ],
        "proxysql_init_state": [
        ],
        "proxysql_final_state": [
        ]
    }
]
```

### 2. Obtaining `proxysql_init_state` and `proxysql_final_state`

So far we left both the `proxysql_init_state`, and `proxysql_final_state` empty, this is
intentional, as we are expecting to use the simulator to fill this fields for us to create the test.
Now we perform a simulation to get the initial state piping our `next_test.json` to the simulator:

```
./cluster_simulator --mode simulate -f tests/tests_payloads/next_test.json

```

We should get an error of the following kind as a result:

```
{
    "err_type": "simulation_error",
    "err_msg": "One or more of the requested simulations have failed",
    "results": [
        {
            "err_type": "verification_error",
            "err_msg": "Expected 'proxysql_init_state' doesn't match actual cluster state",
            "cluster_state_diff": {},
            "exp_proxysql_state": [],
            "act_proxysql_state": [
                { "hostgroup_id":2271,"hostname":"127.1.1.11","port":3306,"status":"SHUNNED" },
                { "hostgroup_id":2271,"hostname":"127.1.1.12","port":3306,"status":"SHUNNED" },
                { "hostgroup_id":2271,"hostname":"127.1.1.13","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2272,"hostname":"127.1.1.11","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2272,"hostname":"127.1.1.12","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2273,"hostname":"127.1.1.11","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2273,"hostname":"127.1.1.12","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2273,"hostname":"127.1.1.13","port":3306,"status":"ONLINE" }
            ]
        }
    ]
}
```

As the initial ProxySQL state was empty, the simulator fails to verify it and print us with the
current cluster state, this leave us with the current state ProxySQL has after applying the initial
configuration:

```
   "act_proxysql_state": [
       { "hostgroup_id":2271,"hostname":"127.1.1.11","port":3306,"status":"SHUNNED" },
       { "hostgroup_id":2271,"hostname":"127.1.1.12","port":3306,"status":"SHUNNED" },
       { "hostgroup_id":2271,"hostname":"127.1.1.13","port":3306,"status":"ONLINE" },
       { "hostgroup_id":2272,"hostname":"127.1.1.11","port":3306,"status":"ONLINE" },
       { "hostgroup_id":2272,"hostname":"127.1.1.12","port":3306,"status":"ONLINE" },
       { "hostgroup_id":2273,"hostname":"127.1.1.11","port":3306,"status":"ONLINE" },
       { "hostgroup_id":2273,"hostname":"127.1.1.12","port":3306,"status":"ONLINE" },
       { "hostgroup_id":2273,"hostname":"127.1.1.13","port":3306,"status":"ONLINE" }
   ]
```

Now we can verify that this is indeed the initial state that we were expecting after ProxySQL has
applied the supplied configuration. If it's, we just pipe it into the `proxysql_init_state` from our
`next_test.json` test file, leaving us with:

```
[
    {
        "cluster_type": "GALERA",
        "mysql_servers": [
            { "hostgroup_id": 2271, "hostname": "127.1.1.11", "port": 3306 },
            { "hostgroup_id": 2273, "hostname": "127.1.1.12", "port": 3306 },
            { "hostgroup_id": 2273, "hostname": "127.1.1.13", "port": 3306 }
        ],
        "mysql_galera_hostgroups": [
            {
                "writer_hostgroup": 2271,
                "backup_writer_hostgroup": 2272,
                "reader_hostgroup": 2273,
                "offline_hostgroup": 2274,
                "active": 1,
                "max_writers": 1,
                "writer_is_also_reader": 1,
                "max_transactions_behind": 100,
                "comment": null
            }
        ],
        "galera_servers_init_state": [
            {
                "hostgroup_id": 2271,
                "hostname": "127.1.1.11",
                "port": 3306,
                "wsrep_local_state": 4,
                "read_only": 0,
                "wsrep_local_recv_queue": 0,
                "wsrep_desync": 0,
                "wsrep_reject_queries": "NONE",
                "wsrep_sst_donor_rejects_queries": 0,
                "wsrep_cluster_status": "Primary",
                "pxc_maint_mode": "DISABLED"
            },
            {
                "hostgroup_id": 2271,
                "hostname": "127.1.1.12",
                "port": 3306,
                "wsrep_local_state": 4,
                "read_only": 0,
                "wsrep_local_recv_queue": 0,
                "wsrep_desync": 0,
                "wsrep_reject_queries": "NONE",
                "wsrep_sst_donor_rejects_queries": 0,
                "wsrep_cluster_status": "Primary",
                "pxc_maint_mode": "DISABLED"
            },
            {
                "hostgroup_id": 2271,
                "hostname": "127.1.1.13",
                "port": 3306,
                "wsrep_local_state": 4,
                "read_only": 0,
                "wsrep_local_recv_queue": 0,
                "wsrep_desync": 0,
                "wsrep_reject_queries": "NONE",
                "wsrep_sst_donor_rejects_queries": 0,
                "wsrep_cluster_status": "Primary",
                "pxc_maint_mode": "DISABLED"
            }
        ],
        "galera_servers_new_state": [
            {
                "hostgroup_id": 2271,
                "hostname": "127.1.1.12",
                "port": 3306,
                "wsrep_local_state": 4,
                "read_only": 0,
                "wsrep_local_recv_queue": 0,
                "wsrep_desync": 1,
                "wsrep_reject_queries": "NONE",
                "wsrep_sst_donor_rejects_queries": 0,
                "wsrep_cluster_status": "Primary",
                "pxc_maint_mode": "DISABLED"
            }
        ],
        "proxysql_init_state": [
            { "hostgroup_id":2271,"hostname":"127.1.1.11","port":3306,"status":"SHUNNED" },
            { "hostgroup_id":2271,"hostname":"127.1.1.12","port":3306,"status":"SHUNNED" },
            { "hostgroup_id":2271,"hostname":"127.1.1.13","port":3306,"status":"ONLINE" },
            { "hostgroup_id":2272,"hostname":"127.1.1.11","port":3306,"status":"ONLINE" },
            { "hostgroup_id":2272,"hostname":"127.1.1.12","port":3306,"status":"ONLINE" },
            { "hostgroup_id":2273,"hostname":"127.1.1.11","port":3306,"status":"ONLINE" },
            { "hostgroup_id":2273,"hostname":"127.1.1.12","port":3306,"status":"ONLINE" },
            { "hostgroup_id":2273,"hostname":"127.1.1.13","port":3306,"status":"ONLINE" }
        ],
        "proxysql_final_state": [
        ]
    }
]

```

Now we perform a simulation again to get the final state supplying our `next_test.json` to the
simulator:

```
./cluster_simulator --mode simulate -f tests/tests_payloads/next_test.json

```

Which should gives us a result like:

```
{
    "err_type": "none",
    "err_msg": "",
    "results": [
        {
            "cluster_type": "GALERA",
            "mysql_servers": [
                { "hostgroup_id":2271,"hostname":"127.1.1.11","port":3306 },
                { "hostgroup_id":2273,"hostname":"127.1.1.12","port":3306 },
                { "hostgroup_id":2273,"hostname":"127.1.1.13","port":3306 }
            ],
            "mysql_galera_hostgroups": [
                {
                    "active": 1,
                    "backup_writer_hostgroup": 2272,
                    "comment": null,
                    "max_transactions_behind": 100,
                    "max_writers": 1,
                    "offline_hostgroup": 2274,
                    "reader_hostgroup": 2273,
                    "writer_hostgroup": 2271,
                    "writer_is_also_reader": 1
                }
            ],
            "galera_servers_init_state": [
                {
                    "hostgroup_id": 2271,
                    "hostname": "127.1.1.11",
                    "port": 3306,
                    "pxc_maint_mode": "DISABLED",
                    "read_only": 0,
                    "wsrep_cluster_status": "Primary",
                    "wsrep_desync": 0,
                    "wsrep_local_recv_queue": 0,
                    "wsrep_local_state": 4,
                    "wsrep_reject_queries": "NONE",
                    "wsrep_sst_donor_rejects_queries": 0
                },
                {
                    "hostgroup_id": 2271,
                    "hostname": "127.1.1.12",
                    "port": 3306,
                    "pxc_maint_mode": "DISABLED",
                    "read_only": 0,
                    "wsrep_cluster_status": "Primary",
                    "wsrep_desync": 0,
                    "wsrep_local_recv_queue": 0,
                    "wsrep_local_state": 4,
                    "wsrep_reject_queries": "NONE",
                    "wsrep_sst_donor_rejects_queries": 0
                },
                {
                    "hostgroup_id": 2271,
                    "hostname": "127.1.1.13",
                    "port": 3306,
                    "pxc_maint_mode": "DISABLED",
                    "read_only": 0,
                    "wsrep_cluster_status": "Primary",
                    "wsrep_desync": 0,
                    "wsrep_local_recv_queue": 0,
                    "wsrep_local_state": 4,
                    "wsrep_reject_queries": "NONE",
                    "wsrep_sst_donor_rejects_queries": 0
                }
            ],
            "galera_servers_new_state": [
                {
                    "hostgroup_id": 2271,
                    "hostname": "127.1.1.12",
                    "port": 3306,
                    "pxc_maint_mode": "DISABLED",
                    "read_only": 0,
                    "wsrep_cluster_status": "Primary",
                    "wsrep_desync": 1,
                    "wsrep_local_recv_queue": 0,
                    "wsrep_local_state": 4,
                    "wsrep_reject_queries": "NONE",
                    "wsrep_sst_donor_rejects_queries": 0
                }
            ],
            "proxysql_init_state": [
                { "hostgroup_id":2271,"hostname":"127.1.1.11","port":3306,"status":"SHUNNED" },
                { "hostgroup_id":2271,"hostname":"127.1.1.12","port":3306,"status":"SHUNNED" },
                { "hostgroup_id":2271,"hostname":"127.1.1.13","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2272,"hostname":"127.1.1.11","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2272,"hostname":"127.1.1.12","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2273,"hostname":"127.1.1.11","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2273,"hostname":"127.1.1.12","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2273,"hostname":"127.1.1.13","port":3306,"status":"ONLINE" }
            ],
            "proxysql_final_state": [
                { "hostgroup_id":2271,"hostname":"127.1.1.11","port":3306,"status":"SHUNNED" },
                { "hostgroup_id":2271,"hostname":"127.1.1.13","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2272,"hostname":"127.1.1.11","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2273,"hostname":"127.1.1.11","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2273,"hostname":"127.1.1.13","port":3306,"status":"ONLINE" },
                { "hostgroup_id":2274,"hostname":"127.1.1.12","port":3306,"status":"ONLINE" }
            ]
        }
    ]
}
```

Since now the provided `proxysql_init_state` matches the found one during the first simulation step,
simulators continues and performs the changes to the clusters and outputs the final state computed
by ProxySQL in `proxysql_final_state`. Now we can manually verify that this final state is indeed
the state that ProxySQL should have for this cluster after applying the required changes to its
state.

If everything is correct, the result of this simulation is now a test itself that can be supplied
to the simulator in `verify` mode. So, we take the `results` array directly from the output
and place it in our `next_test.json`, and pass it to the simulator in the following way:

### 3. Verifying obtained 'initial' and 'final' states

```
./cluster_simulator --mode verify -f tests/tests_payloads/next_test.json
```

Which should give an output of the following kind:

```
{
    "err_type": "none",
    "err_msg": "",
    "results": [
        {
            "err_type": "none",
            "err_msg": ""
        }
    ]
}
```

Now a new test has been created successfully. After creating this test file, it can simply be drop
into `tests\tests_payload` folder. For being automatically executed via `simulator_wrapper-t` test.

## Project folder structure

+ configs: Base configurations to supply to ProxySQL when launched for interacting with the
    simulator.
+ deps: Development dependencies required by the simulator.
+ example_payloads: Example payloads serving as examples on how to work with the
    simulator.
+ lib: Main library folder with the utilities required by the simulator.
+ obj: Folder holding the output binaries from library building.
+ tests: Folder containing the 'simulator_wrapper' used to call the simulator
    with the proper tests payloads and verify its success, and unit tests for the
    utilities being developed for the simulator itself.

## Tests development

### General tests structure

The `tests` folder contains both, the unitary tests for verifying the tools
being written for the simulator itself, and the `simulator_wrapper-t` utility.
This utility is the one that should be used to supply multiple tests files to
the simulator for verifying it's integrity.

For making use of the `simulator_wrapper-t` it's required to modify and source both
`constants` files from:

+ Root `cluster_simulator` workspace folder: This `constants` file has the
    constants required by the `cluster_simulator` itself.
+ Tests folder: This `constants` file has the constants required for locating
    the `cluster_simulator` binary being launch and the location of the tests
    files to be run against the simulator.

### Compilation

To compile all the tests, including unit tests and `simulator_wrapper-t` testing
utility, it's enough to:

```
export WORKSPACE=path_to_proxysql_workspace
cd tests
make -j$(nproc)
```

### `simulator_wrapper-t` usage

For making use of the `simulator_wrapper-t` testing utility it's required to:

1. Have a running instance of ProxySQL compiled in the proper way to support the
   configuration of the internal `SQLite` server. E.g:

   ```
   make build_deps -j$(nproc) && make testgalera -j$(nproc)
   ```

2. Source both constant files from `workspace` root and from `tests` folder,
   after proper modifying their contents with the required paths.
3. Launch the simulator wrapper:

   ```
   ./tests/simulator_wrapper-t
   ```
