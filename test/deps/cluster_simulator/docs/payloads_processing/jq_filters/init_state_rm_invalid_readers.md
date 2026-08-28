### Description

Remove servers that were not found defined as `readers` in `mysql_servers` but were misplaced as `readers` at
`proxysql_init_state`. Used to fix previous payloads like the example
`read_only_test_multiple_servers_multiple_hostgroups_invalid.json`:

```
jq -c -f jq_filters/init_state_rm_invalid_readers.jq examples/read_only_test_multiple_servers_multiple_hostgroups_invalid.json
{"hostgroup_id":2271,"hostname":"127.1.1.11","port":3306,"status":"ONLINE","comment":"mysql01"}
{"hostgroup_id":2273,"hostname":"127.1.1.11","port":3306,"status":"ONLINE","comment":"mysql01"}
{"hostgroup_id":2274,"hostname":"127.1.1.11","port":3306,"status":"ONLINE","comment":"mysql01"}
{"hostgroup_id":2275,"hostname":"127.1.1.11","port":3306,"status":"ONLINE","comment":"mysql01"}
{"hostgroup_id":2277,"hostname":"127.1.1.11","port":3306,"status":"ONLINE","comment":"mysql01"}
{"hostgroup_id":2278,"hostname":"127.1.1.11","port":3306,"status":"ONLINE","comment":"mysql01"}
{"hostgroup_id":2271,"hostname":"127.1.1.12","port":3306,"status":"ONLINE","comment":"mysql02"}
{"hostgroup_id":2273,"hostname":"127.1.1.12","port":3306,"status":"ONLINE","comment":"mysql02"}
{"hostgroup_id":2275,"hostname":"127.1.1.12","port":3306,"status":"ONLINE","comment":"mysql02"}
{"hostgroup_id":2277,"hostname":"127.1.1.12","port":3306,"status":"ONLINE","comment":"mysql02"}
{"hostgroup_id":2279,"hostname":"127.1.1.12","port":3306,"status":"ONLINE","comment":"mysql02"}
{"hostgroup_id":2271,"hostname":"127.1.1.13","port":3306,"status":"ONLINE","comment":"mysql03"}
{"hostgroup_id":2273,"hostname":"127.1.1.13","port":3306,"status":"ONLINE","comment":"mysql03"}
{"hostgroup_id":2274,"hostname":"127.1.1.13","port":3306,"status":"ONLINE","comment":"mysql03"}
{"hostgroup_id":2275,"hostname":"127.1.1.13","port":3306,"status":"ONLINE","comment":"mysql03"}
{"hostgroup_id":2279,"hostname":"127.1.1.13","port":3306,"status":"ONLINE","comment":"mysql03"}
```
