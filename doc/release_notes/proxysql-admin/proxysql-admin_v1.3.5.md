# proxysql-admin v1.3.5

Release date : Apr 14, 2017

### Usability improvement

* Merged upstream proxysql_galera_checker.sh changes to proxysql_galera_checker.
* Added proxysql_node_monitor inside proxysql_galera_checker script to avoid scheduler table conflict.

  Currently we have two different entry in scheduler table to check PXC node status (proxysql_node_monitor and proxysql_galera_checker ).
  These two scripts are independent but it uses same mysql_servers table to change the PXC node status. Sometime these scripts will run together and update mysql_servers table. As per proxysql, scheduler entries should not interfere with each other.
  To overcome this issue proxysql_galera_checker script should call proxysql_node_monitor script to check node monitoring independently.
  
* Added hostgroup info and date in proxysql node monitoring log.
