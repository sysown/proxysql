## Simulator Payload Creation

### Goals

When creating payloads for the simulator, the goal is always to cover all the possible scenarios and
configurations that ProxySQL can encounter when monitoring a group of servers, thus being able to predict any
outcome that Monitoring actions will perform over these servers.

While complete coverage is the main goal, we shouldn't try to achieve this with an unique payload. The explicit
format for state description of the test payloads offers several characteristics that we can use in our favor:

* Easy to reason about them when they are small.
* Easy to use to describe minimal behaviors that we want to test.
* Easy to compose bigger test scenarios from smaller previously described behaviors.

Further clarifying this latest point, since payloads allows us to configure an arbitrary number of servers,
and to apply individual state changes to these servers, we can merge in bigger payloads scenarios from
other smaller payloads which share monitoring config or for which config is orthogonal.

### General Payload Design Rules- READ_ONLY Example

For taking advantage of the previously described format characteristics and keep building trust in the feature
we are testing, we should always follow a bottom-up approach:

1. Ensure basic behavior - Single server, single `mysql_replication_hostgroups`

In this basic payload we can test all the hostgroups transitions holds for a single server:

Server configured in:

```
- `writer_hostgroup` -> Detected as `RO=0` with `writer_is_also_reader=0` -> Kept in `writer_hostgroup`
- `writer_hostgroup` -> Detected as `RO=0` with `writer_is_also_reader=1` -> Kept in `writer_hostgroup`
- `writer_hostgroup` -> Detected as `RO=1` with `writer_is_also_reader=0` -> Moved in `reader_hostgroup`
- `writer_hostgroup` -> Detected as `RO=1` with `writer_is_also_reader=1` -> Moved in `reader_hostgroup`

- `reader_hostgroup` -> Detected as `RO=0` with `writer_is_also_reader=0` -> Moved in `writer_hostgroup`
- `reader_hostgroup` -> Detected as `RO=0` with `writer_is_also_reader=1` -> Copied in `writer_hostgroup`, kept in `reader_hostgroup`
- `reader_hostgroup` -> Detected as `RO=1` with `writer_is_also_reader=0` -> Kept in `reader_hostgroup`
- `reader_hostgroup` -> Detected as `RO=1` with `writer_is_also_reader=1` -> Kept in `reader_hostgroup`
```

We can check an example of such payload in file `read_only_test_single_server_single_hostgroups.json`. Let's
dissect the first payload, and understand everything that is being tested in it:

```
{
    "__comment__": "Single server in two 'mysql_replication_hostgroup' - writer_is_also_reader: 1, RO: 0 -> 1",
    "cluster_type": "READ_ONLY",
    "mysql_servers": [
        { "hostgroup_id": 2271, "hostname": "127.1.1.11", "port": 3306, "comment": "mysql01" }
    ],
    "mysql_monitor_config": [ { "monitor_writer_is_also_reader": 1 } ],
    "mysql_replication_hostgroups": [
        { "writer_hostgroup": 2271, "reader_hostgroup": 2272, "check_type": "read_only", "comment": "" }
    ],
    "readonly_servers_init_state": [
        { "hostname": "127.1.1.11", "port": 3306, "read_only": 0 }
    ],
    "readonly_servers_new_state": [
        { "hostname": "127.1.1.11", "port": 3306, "read_only": 1 }
    ],
    ...
}
```

We see that the server is being configured in the `writer_hostgroup: 2271`. And from the comment we see that
we are going to test a transition from a detection of `RO:0 to -> RO:1`, all this for the case of
`monitor_writer_is_also_reader=1`. Let's inspect the init and final ProxySQL states:

```
{
    ...
    "readonly_servers_init_state": [
        { "hostname": "127.1.1.11", "port": 3306, "read_only": 0 }
    ],
    "proxysql_init_state": [
        { "hostgroup_id":2271,"hostname":"127.1.1.11","port":3306,"status":"ONLINE", "comment": "mysql01" }
    ],
    ...
}
```

Init states also contribute to the testing themselves, this is because they encode the whole transition
between the promoted user configuration (`LOAD MYSQL SERVERS TO RUNTIME`), and the first monitoring action,
after the detection of the specified `servers_init_state` allowing us to test:

1. Behavior when server isn't placed by the user in the final target hostgroup.
2. Retention of the server in the target hostgroup, when config matches computed via `init_state`.

In the particular case above, we are testing that the server was correctly kept by ProxySQL in the
`writer_hostgroup` due to a `RO:0` value, after being placed by the user in that hostgroup.

Now, with the `final` state we are able to test the state transition specified between the `init_state` and
the `new_state`:

```
{
    ...
    "readonly_servers_init_state": [
        { "hostname": "127.1.1.11", "port": 3306, "read_only": 0 }
    ],
    "readonly_servers_new_state": [
        { "hostname": "127.1.1.11", "port": 3306, "read_only": 1 }
    ],
    "proxysql_init_state": [
        { "hostgroup_id":2271,"hostname":"127.1.1.11","port":3306,"status":"ONLINE", "comment": "mysql01" }
    ],
    "proxysql_final_state": [
        { "hostgroup_id":2272,"hostname":"127.1.1.11","port":3306,"status":"ONLINE", "comment": "mysql01" }
    ]
    ...
}
```

In this part of the test, we ensure that the correct hostgroup movement of the server from `writer_hostgroup`
to `reader_hostgroup`. So, with this single payload, we have been able to test two of the previously mentioned
scenarios:

```
- `writer_hostgroup` -> Detected as `RO=0` with `writer_is_also_reader=0` -> Kept in `writer_hostgroup`
- `writer_hostgroup` -> Detected as `RO=1` with `writer_is_also_reader=1` -> Moved in `reader_hostgroup`
```

The next payloads can be check as examples of how to test the rest of the listed scenarios.

2. Multiple servers, single `mysql_replication_hostgroups`:

Now we are going to ensure previous behavior for multiple servers. The payload format allows us to reuse the
previous case as a template, and to include extra configuration in it for the extra servers, for this payload
we are going to check `read_only_test_two_server_single_hostgroup`:

```
{
    ...
    "__comment__": "All transitions for two servers, single 'mysql_replication_hostgroup' - writer_is_also_reader: 1",
    "cluster_type": "READ_ONLY",
    "mysql_servers": [
        { "hostgroup_id": 2271, "hostname": "127.1.1.11", "port": 3306 },
        { "hostgroup_id": 2272, "hostname": "127.1.1.12", "port": 3306 }
    ],
    "mysql_replication_hostgroups": [
        { "writer_hostgroup": 2271, "reader_hostgroup": 2272, "check_type": "read_only", "comment": "" }
    ],
    "mysql_monitor_config": [
        { "monitor_writer_is_also_reader": 1 }
    ],
    ...
}
```

As we can see, we have just added a new server to the previous defined payload, and we are going to check all
the transitions possible for this extra server in combination with the previous one. Since we are testing for
`writer_is_also_reader=1` we are going to place this new server in the `reader_hostgroup`:

```
    ...
    ],
    "readonly_servers_init_state": [
        { "hostname": "127.1.1.11", "port": 3306, "read_only": 0 },
        { "hostname": "127.1.1.12", "port": 3306, "read_only": 0 }
    ],
    "readonly_servers_new_state": [
        { "hostname": "127.1.1.11", "port": 3306, "read_only": 1 },
        { "hostname": "127.1.1.12", "port": 3306, "read_only": 1 }
    ],
    "proxysql_init_state": [
        { "hostgroup_id":2271,"hostname":"127.1.1.11","port":3306,"status":"ONLINE" },
        { "hostgroup_id":2272,"hostname":"127.1.1.12","port":3306,"status":"ONLINE" },
        { "hostgroup_id":2271,"hostname":"127.1.1.12","port":3306,"status":"ONLINE" }
    ],
    "proxysql_final_state": [
        { "hostgroup_id":2272,"hostname":"127.1.1.11","port":3306,"status":"ONLINE" },
        { "hostgroup_id":2272,"hostname":"127.1.1.12","port":3306,"status":"ONLINE" }
    ]
    ...
```

This way, we are also checking the expected transition for `reader_hostgroup` into both hostgroups,
`reader_hostgroup` and `writer_hostgroup` required by `writer_is_also_reader=1`. The next step will be to
place the server into multiple hostgroups, and mix the transitions of these servers for testing all
combinations. For an example of this final payloads check
`read_only_test_multiple_servers_single_hostgroup.json`.

3. Single server, multiple `mysql_replication_hostgroups`:

Servers can be placed into multiple hostgroups simultaneously. We are going to start with a simple case of
this, using just one server, and checking that the behavior we previously tested for one hostgroup correctly
translate to multiple hostgroups. For this we are going to check payload
`read_only_test_single_server_two_hostgroups.json`:

```
    ...
    "__comment__": "Single server in two 'mysql_replication_hostgroup' - writer_is_also_reader: 1, RO: 0 -> 1",
    "cluster_type": "READ_ONLY",
    "mysql_servers": [
        { "hostgroup_id": 2271, "hostname": "127.1.1.11", "port": 3306, "comment": "mysql01" },
        { "hostgroup_id": 2274, "hostname": "127.1.1.11", "port": 3306, "comment": "mysql01" }
    ],
    "mysql_replication_hostgroups": [
        { "writer_hostgroup": 2271, "reader_hostgroup": 2272, "check_type": "read_only", "comment": "" },
        { "writer_hostgroup": 2273, "reader_hostgroup": 2274, "check_type": "read_only", "comment": "" }
    ],
    "mysql_monitor_config": [
        { "monitor_writer_is_also_reader": 1 }
    ],
    ...
```

We have duplicated our server and placed it into two different hostgroups, in one as a writer, and in the
other one as a reader. Now, we are going to verify that the hostgroup movements for this server are correct
when we modify its reported status:

```
    ...
    "readonly_servers_init_state": [
        { "hostname": "127.1.1.11", "port": 3306, "read_only": 0 }
    ],
    "readonly_servers_new_state": [
        { "hostname": "127.1.1.11", "port": 3306, "read_only": 1 }
    ],
    "proxysql_init_state": [
        { "hostgroup_id":2271,"hostname":"127.1.1.11","port":3306,"status":"ONLINE", "comment": "mysql01" },
        { "hostgroup_id":2273,"hostname":"127.1.1.11","port":3306,"status":"ONLINE", "comment": "mysql01" },
        { "hostgroup_id":2274,"hostname":"127.1.1.11","port":3306,"status":"ONLINE", "comment": "mysql01" }
    ],
    "proxysql_final_state": [
        { "hostgroup_id":2272,"hostname":"127.1.1.11","port":3306,"status":"ONLINE", "comment": "mysql01" },
        { "hostgroup_id":2274,"hostname":"127.1.1.11","port":3306,"status":"ONLINE", "comment": "mysql01" }
    ]
    ...
```

Here, we are verifying that the behavior that we previously tested for one individual hostgroup still holds:

- Server is properly moved between the multiple target hostgroups.
- `monitor_writer_is_also_reader` is only honored when the server is moved from `reader_hostgroup` to
  `writer_hostgroup`, leaving other hostgroups the same.

Now, we can create a bigger payload that verifies the same previously tested behavior but against a higher
number of servers, for an example of this check `read_only_test_single_server_multiple_hostgroups.json`. This
payload also includes extra hostgroups, which **are not used** by the target servers, to ensure that they are
simply **ignored**.

3. Multiple servers, multiple 'mysql_replication_hostgroups'

Now we ensure previous behavior for multiple hostgroups and multiple servers. Combining all the previously
described scenarios into a single payload. For this final payload, check `read_only_test_multiple_servers_multiple_hostgroups.json`.

#### Final considerations

We have already mentioned some of the benefits of the previously described approach, to summarize:

- Bottom up approach, simpler payloads can help to isolate simple scenarios.
- Increase of confidence with each new added payload, expanding previously tested behavior.
- When base cases are clear, expanding them is a matter of composing.
