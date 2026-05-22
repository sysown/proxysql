### Description

Allows you to select the `reader` or `writer` hostgroups in which a particular server is found in either
`proxysql_init_state` or `proxysql_final_state`:

```
jq -c --arg hostname "127.1.1.11" --arg state proxysql_init_state --arg type reader_hostgroup -f docs/payloads_processing/jq_filters/hostgroups_by_type_by_hostname.jq tests/readonly_tests_payloads/read_only_test_multiple_servers_multiple_hostgroups.json
{"hostgroup_id":2274,"hostname":"127.1.1.11","port":3306,"status":"ONLINE","comment":"mysql01"}
{"hostgroup_id":2278,"hostname":"127.1.1.11","port":3306,"status":"ONLINE","comment":"mysql01"}

jq -c --arg hostname "127.1.1.11" --arg state proxysql_final_state --arg type reader_hostgroup -f docs/payloads_processing/jq_filters/hostgroups_by_type_by_hostname.jq tests/readonly_tests_payloads/read_only_test_multiple_servers_multiple_hostgroups.json
{"hostgroup_id":2272,"hostname":"127.1.1.11","port":3306,"status":"ONLINE","comment":"mysql01"}
{"hostgroup_id":2274,"hostname":"127.1.1.11","port":3306,"status":"ONLINE","comment":"mysql01"}
{"hostgroup_id":2276,"hostname":"127.1.1.11","port":3306,"status":"ONLINE","comment":"mysql01"}
{"hostgroup_id":2278,"hostname":"127.1.1.11","port":3306,"status":"ONLINE","comment":"mysql01"}
```

We can easily check for example the transition of the servers expected to left as `readers` for the `RO=0` for
later all being moved to `readers` when `RO` changes to `1`.
