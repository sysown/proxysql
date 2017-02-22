# proxysql-admin v1.3.0 , v1.3.0a, v1.3.0b

## proxysql-admin v1.3.0b

Release date : Nov 17, 2016

### Usability improvement

* Added document updates for single write mode
* Packaging: Added version number

### New features

* Added PXC Maintenance Mode support
  * Percona Xtradb Cluster implemented a maintenance mode to reduce the abrupt failure of workload while the node is taken down.
    With this new change in PXC, ProxySQL galera checker willl continue to probe the state of individual node by checking for pxc_maint_mode (in addition to existing wsrep_local_state).
    If ProxySQL detects pxc_maint_mode = SHUTDOWN|MAINTENANCE then it marks the node as OFFLINE_SOFT. This will avoid creation of new connections (or workload) on said node.
    
## proxysql-admin v1.3.0a

Release date : Oct 20, 2016

### New features

* Added singlewrite mode in proxysql-admin
* Added proxysql-admin logrotate support

### Bug fixes

* FIXED BLD-524 - proxysql galera check log file warning messages for credentials
* Removed hardcoded hostgroup id from proxysql-admin script [#1](../../../../issues/1)
