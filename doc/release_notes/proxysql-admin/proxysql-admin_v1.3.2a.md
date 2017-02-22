# proxysql-admin v1.3.2a

Release date : Jan 12, 2017

### Usability improvement

* Changed proxysql-admin default mode from loadbal to singlewrite
* Modified proxysql-admion script to read configuration file by default.
* Improved proxysql-admin dsn connection error message.
* Changed PXC default port to 3306 in configuration file.
* Resolved mismatch between command line options and EXPORT variables.
* Added network restriction to ProxySQL users in PXC #16
* Renamed following parameter options
  * --proxysql-user to --proxysql-username
  * --cluster-user to --cluster-username
  * --monitor-user to --monitor-username
  * --galera-check-interval to --node-check-interval
  * --proxysql-host to --proxysql-hostname
  * --cluster-host to --cluster-hostname
* Repalaced following parameter options
  * --pxc-app-write-user to --cluster-app-username
  * --pxc-app-write-password to --cluster-app-password
* Reomoved following parameter options
  * --pxc-app-read-user
  * --pxc-app-read-password
  
  

### New features

* Modified proxysql-admin script to create single user for handling read write transactions. proxysql will manage traffic automatically and split read and write operations with the help of mysql query rule and hostgroups.

  All SELECT operations (except 'SELECT .. FOR UPDATE') will go to read nodes and all other transactions will go to writer node.
* Added __--quick-demo__ to setup dummy proxysql configuration

### Bug fixes

* Fixed .mylogin.cnf issue. Now proxysql-admin user configuration will not override with .mylogin.cnf variables. [#14](../../../../issues/14)
* Fixed BLD-600
