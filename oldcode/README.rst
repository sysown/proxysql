============
Introduction
============

ProxySQL is a high performance proxy, currently for MySQL and forks (like Percona Server and MariaDB) only.
Future versions of ProxySQL will support a variety database backends.

Its development is driven by the lack of open source proxies that provide high performance.
Benchmarks can be found at http://www.proxysql.com


Installation
============


Dependencies
~~~~~~~~~~~~
Other than standard libraries, required packages, libraries and header files are:

* cmake
* gcc
* glibc-devel
* glibc-headers
* openssl-devel
* openssl-static
* glib2-devel
* zlib-devel
* libffi-devel

ProxySQL also depends from few libraries that are statically linked.
To download and compile these libraries, run the follows::

  mkdir ProxySQL
  cd ProxySQL
  wget https://downloads.mariadb.org/interstitial/mariadb-native-client/Source/mariadb-native-client.tar.gz
  tar -zxf mariadb-native-client.tar.gz
  cd mariadb-native-client
  cmake .
  make -i
  cd ..
  wget http://0pointer.de/lennart/projects/libdaemon/libdaemon-0.14.tar.gz
  tar -zxf libdaemon-0.14.tar.gz 
  cd libdaemon-0.14
  ./configure && make
  cd ..
  wget http://www.canonware.com/download/jemalloc/jemalloc-3.6.0.tar.bz2
  tar -jxf jemalloc-3.6.0.tar.bz2
  cd jemalloc-3.6.0
  ./configure --enable-xmalloc --enable-prof && make
  cd ..
  wget http://ftp.gnome.org/pub/gnome/sources/glib/2.40/glib-2.40.0.tar.xz
  tar -xJf glib-2.40.0.tar.xz
  cd glib-2.40.0
  ./configure --enable-static
  make
  cd ..



Compiling
~~~~~~~~~

After compiling the libraries from the previous section, download and compile ProxySQL running the follows::
  
  wget https://github.com/renecannao/proxysql/archive/master.zip
  unzip master.zip
  cd proxysql-master/src
  make

Note that no configure is available yet. You must check for missing dependencies.


Install
~~~~~~~

**make install** is not available yet.

You can manually install proxysql running the follows::

  cp proxysql /usr/bin
  mkdir /var/run/proxysql


Interactive configuration
~~~~~~~~~~~~~~~~~~~~~~~~~

After compiling, run *./proxysql_interactive_config.pl* that will guide you in the creation of the first configuration file.
Once completed, copy the configuration file in /etc/proxysql.cnf .


Usage
~~~~~

Usage is the follow::

  $ ./proxysql --help
  Usage:
    proxysql [OPTION...] - High Performance Advanced Proxy for MySQL
  
  Help Options:
    -h, --help        Show help options
  
  Application Options:
    --admin-port      Administration port
    --mysql-port      MySQL proxy port
    -c, --config      Configuration file


proxysql listens on 3 different TCP ports: 2 of them are configurable via command line arguments:

* **--mysql-port** specifies the port that mysql clients should connect to
* **--admin-port** specifies the administration port

The 3rd port not configurable via command line is the monitoring port. Note that this module is not completely implemented yet.

Other option(s):

* **--config** specifies the configuration file

A configuration file is mandatory.
If not specified on the command line it defaults to *proxysql.cnf* in the current directory if present, or */etc/proxysql.cnf*.
Currently there is no strong input validation of the configuration file, and wrong parsing of it can cause proxysql to crash at startup.
If parsing of config file is successful, proxysql will daemonize


ProxySQL Configuration
======================

ProxySQL uses two source of configuration:

* a configuration file in key-value format
* a built-in database that stores more advanced configurations and uses tables to define multiple attributes and relations between them. Currently, this is implemented as an SQLite3 database



Configuration file
==================

Configuration file is key-value file , .ini-like config file ( see https://developer.gnome.org/glib/stable/glib-Key-value-file-parser.html for reference ).

Currently 7 groups are available:

* **[global]** : generic configuration
* **[admin]** : configuration options related to admin and monitoring interface
* **[http]** : configuration options related to HTTP servers . Feature not available yet
* **[mysql]** : configuration options related to handling of mysql connections
* **[fundadb]** : configuration options for the internal storage used for caching
* **[debug]** : configuration options related to debugging
* **[mysql users]** : specify a list of users and their passwords used to connect to mysql servers


[global] section
~~~~~~~~~~~~~~~~

* **stack_size**

	Specify the stack size used by every thread created in proxysql , in bytes . Default is 524288 ( 512KB ) , minimum is 65536 ( 64KB ) , and maximum is 33554432 (32MB).

	Latest versions of ProxySQL use threads pool instead of one thread per connection, therefore the stack size has little memory footprint.

* **net_buffer_size**

	Each connection to proxysql creates a so called MySQL data stream. Each MySQL data stream has 2 buffers for recv and send. *net_buffer_size* defines the size of each of these buffers. Each connection from proxysql to a mysql server needs a MySQL data stream. Each client connection can have a different number of MySQL data streams associated to it, that can range from just one data stream if no connections are established to mysql servers, to N+1 where N is the number of defined hostgroups.

	Default is 8192 (8KB), minimum is 1024 (1KB), and maximum is 16777216 (16MB). Increasing this variable can slighly boost performance in case of large dataset, at the cost of additional memory usage.

* **backlog**

	Defines the backlog argument of the listen() call. Default is 2000, minimum is 50

* **core_dump_file_size**

	Defines the maximum size of a core dump file, to be used to debug crashes. Default is 0 (no core dump).

* **datadir**

	Defines the datadir. Not absolute files paths are relative to *datadir* . Default is */var/run/proxysql* .

* **error_log**

	Path to error log . Default is *proxysql.log*

* **debug**

	Enable or disable debugging messages if ProxySQL was compiled with support for debug. Boolean parameter (0/1) , where 0 is the default (disabled).

* **debug_log**

	Path to debug log . Default is *debug.log*

* **pid_file**

	PID file . Default is *proxysql.pid*

* **restart_on_error**

	When proxysql is executed it forks in 2 processes: an angel process and the proxy itself. If *restart_on_error* is set to 1 , the angel process will restart the proxy if this one dies unexpectedly

* **restart_delay**

	If the proxy process dies unexpectedly and the angel process is configured to restart it (*restart_on_error=1*), this one pauses *restart_delay* seconds before restarting. Default is 5, minimum is 0 and maximum is 600 (10 minutes).
 

[admin] section
~~~~~~~~~~~~~~~

* **proxy_admin_pathdb**

	It defines the path of the built-in database that stores advanced configurations. Default is *proxysql.db*

* **proxy_admin_bind**

	It defines the IP address that the admin interface will bind to. Default is *0.0.0.0*

* **proxy_admin_port**

	It defines the administrative port for runtime configuration and statistics. Default is 6032

* **proxy_admin_user**

	It defines the user to connect to the admin interface . Default is *admin* 

* **proxy_admin_password**

	It defines the password to connect to the admin interface . Default is *admin* 

* **proxy_admin_refresh_status_interval**

	ProxySQL doesn't constantly update status variables/tables in the admin interface. These are updates only when read, and up to once every *proxy_admin_refresh_status_interval* seconds. Default is 600 (10 minutes), minimum is 0 and maximum is 3600 (1 hour). 

* **proxy_monitor_bind**

	It defines the IP address that the monitor interface will bind to. Default is *0.0.0.0*

* **proxy_monitor_port**

	It defines the monitoring port for runtime statistics. Default is 6031 . This module is not completely implemented yet

* **proxy_monitor_user**

	It defines the user to connect to the monitoring interface . Default is *monitor* . This module is not completely implemented yet

* **proxy_monitor_password**

	It defines the password to connect to the monitoring interface . Default is *monitor* . This module is not completely implemented yet

* **proxy_monitor_refresh_status_interval**

	ProxySQL doesn't constantly update status variables/tables in the monitoring interface. These are updates only when read, and up to once every *proxy_monitor_refresh_status_interval* seconds. Default is 10, minimum is 0 and maximum is 3600 (1 hour). This module is not completely implemented yet

* **sync_to_disk_on_flush_command**

	When sync_to_disk_on_flush_command=1 , in-memory configuration is automatically saved on disk after every FLUSH command. Boolean parameter (0/1) , where 1 is the default (enabled). 

* **sync_to_disk_on_shutdown**

	When sync_to_disk_on_shutdown=1 , in-memory configuration is automatically saved on disk when the SHUTDOWN command is executed in the admin interface. Boolean parameter (0/1) , where 1 is the default (enabled). 

[http] section
~~~~~~~~~~~~~~

This module is not implemented yet.


[mysql] section
~~~~~~~~~~~~~~~

* **mysql_threads**

	Early versions of ProxySQL used 1 thread per connection, while recent versions use a pool of threads that handle all the connections. Performance improved by 20% for certain workload and an optimized number of threads. This can also drastically reduces the amount of memory uses by ProxySQL. Further optimizations are expected. Default is *number-of-CPU-cores X 2* , minimum is 2 and maximum is 128 .

* **mysql_default_schema**

	Each connection *requires* a default schema (database). If a client connects without specifying a schema, mysql_default_schema is applied. It defaults to *information_schema*.

	If you're using mostly one database, specifying a default schema (database) *could* save a request for each new connection.

* **proxy_mysql_bind**

	It defines the IP address that the mysql interface will bind to. Default is *0.0.0.0*

* **proxy_mysql_port**

	Specifies the port that mysql clients should connect to. Default is 6033.

* **mysql_socket**

	ProxySQL can accept connection also through the Unix Domain socket specified in *mysql_socket* . This socket is usable only if the client and ProxySQL are running on the same server. Benchmark shows that with workloads where all the queries are served from the internal query cache (that is, very fast), Unix Domain socket provides 50% more throughput than TCP socket. Default is */tmp/proxysql.sock*


* **mysql_hostgroups**

	ProxySQL groups MySQL backends into hostgroups. *mysql_hostgroups* defines the maximum number of hostgroups. Default is 8, mimimum is 2 (enough for classic read/write split) and maximum is 64 .

* **mysql_poll_timeout**

	Each connection to proxysql is handled by a thread that call poll() on all the file descriptors opened. poll() is called with a timeout of *mysql_poll_timeout* milliseconds. Default is 10000 (10 seconds) and minimum is 100 (0.1 seconds). The same timeout is applied also in the admin interface and in the monitoring interface.

* **mysql_auto_reconnect_enabled**

	If a connection to mysql server is dropped because killed or timed out, it automatically reconnects. This feature is very unstable and should not be enabled. Default is 0 (disabled).

* **mysql_query_cache_enabled**

	Enable the internal query cache that can be used to cache SELECT statements. Boolean parameter (0/1) , and default is 1 (enabled).

* **mysql_query_cache_partitions**

	The internal query cache is divided in several partitions to reduce contentions. Default is 16, minimum is 1 and maximum is 128.

* **mysql_query_cache_size**

	It defines the size of the internal query cache, if enabled. Default is 1048576 (1MB), so is its minimum. There is no maximum defined.

* **mysql_query_cache_precheck**

	It this option is enabled, the internal query cache is checked for possible resultset for every query even if not configured to be cached. Enabling this option can improved performance if the query cache hit ratio is high, as it prevents the parsing of the queries. Boolean parameter (0/1) , and default is 1 (enabled).

* **mysql_max_query_size**

	A query received from a client can be of any length. Although, to optimize memory utilization and to improve performance, only queries with a length smaller than *mysql_max_query_size* are analyzed and processed. Any query longer than *mysql_max_query_size* is forwarded to a mysql servers without being processed. That also means that for large queries the query cache is disabled. Default value is 1048576 (1MB), and the maximum length is 16777210 (few bytes less than 16MB).

* **mysql_max_resultset_size**

	When the server sends a resultset to proxysql, the resultset is stored internally before being forwarded to the client. *mysql_max_resultset_size* defines the maximum size of a resultset for being buffered: once a resultset passes this threshold it stops the buffering and triggers a fast forward algorithm. Indirectly, it also defines also the maximum size of a cachable resultset. In future a separate option will be introduced. Default is 1048576 (1MB).

* **mysql_query_cache_default_timeout**

	Every cached resultset has a time to live . *mysql_query_cache_default_timeout* defines the default time to live (in second) for the predefined caching rules when the administrator didn't explicitly configure query rules. Default is 1 seconds.

* **mysql_server_version**

	When a client connects to ProxySQL , this introduces itself as mysql version *mysql_server_version* . The default is "5.1.30" ( first GA release of 5.1 ).

* **mysql_usage_user** and **mysql_usage_password**

	At startup (and in future releases also at regular interval), ProxySQL connects to all the MySQL servers configured to verify connectivity and the status of read_only (this option if used to determine if a server is a master or a slave only during the first automatic configuration: do not rely on this for advanced setup).  *mysql_usage_user* and *mysql_usage_password* define the username and password that ProxySQL uses to connect to MySQL server. As the name suggests, only USAGE privilege is required. Defaults are *mysql_usage_user=proxy* and *mysql_usage_password=proxy* .

* **mysql_servers**

	Defines a list of mysql servers to use as backend in the format of hostname:port , separated by ';' . Example : mysql_servers=192.168.1.2:3306;192.168.1.3:3306;192.168.1.4:3306 . No default applies.

	**Note** : this list is used only of the built-in database is not present yet. If the built-in database is already present, this option is ignored.

* **mysql_connection_pool_enabled**

	ProxySQL implements its own connection pool to MySQL backends. Boolean parameter (0/1) , where 1 is the default (enabled).

* **mysql_share_connections**

	When connection pool is enabled, it is also possible to share connections among clients. Boolean parameter (0/1) , where 0 is the default (disabled).

	When this feature is disabled (default) and a connection is assigned to a client, this connection will be used only by that specific client connection and will be never shared. That is: connections to MySQL servers are not shared among client connections . When this feature is enabled, multiple clients can use the same connection to a single backend. This feature is *experimental*. 

* **mysql_wait_timeout**

	If connection pool is enabled ( *mysql_connection_pool_enabled=1* ) , unused connection (not assigned to any client) are automatically dropped after *mysql_wait_timeout* seconds. Default is 28800 (8 hours) , minimum is 1 second and maximum is 604800 (1 week). This option *must* be smaller than mysql variable *wait_timeout* .

* **mysql_parse_trx_cmds**

	ProxySQL can filter unnecessary transaction commands if irrelevant. For example, if a connection sends BEGIN or COMMIT twice without any command in between, the second command is filtered. Boolean parameter (0/1) , where 0 is the default (disabled). This feature is absolutely *unstable*.

* **mysql_maintenance_timeout**

	When a backend server is disabled, only the idle connections are immediately terminated. All the other active connections have up to *mysql_maintenance_timeout* milliseconds to gracefully shutdown before being terminated. Default is 10000 (10 seconds), minimum is 1000 (1 second) and maximum is 60000 (1 minute).

* **mysql_poll_timeout_maintenance**

	When a backend server is disabled, poll() timeout is *mysql_poll_timeout_maintenance* instead of *mysql_poll_timeout*. Also this variable is in milliseconds. Default is 100 (0.1 second), minimum is 100 (0.1 second) and maximum is 1000 (1 second).

* **mysql_query_statistics_enabled**

	ProxySQL collects queries statistics when enabled. This option can affect performance. Boolean parameter (0/1) , where 0 is the default (disabled).

* **mysql_query_statistics_interval**

	This option specifies how often (in seconds) ProxySQL dumps query statistics. Default is 10 (seconds), minimum is 5 and maximum is 600 (10 minutes).


[mysql users] section
~~~~~~~~~~~~~~~~~~~~~

This section includes a list of users and relative password in the form **user=password** . Users without password are in the form **user=** . For example::

  root=secretpass
  webapp=$ecr3t
  guest=
  test=password


[fundadb] section
~~~~~~~~~~~~~~~~~

This section allows advenced tunings related to the thread responsible to purge the internal query cache. normally there is no need to tune it.

* **fundadb_hash_purge_time**

	Total time to purge a hash table, in millisecond. Default is 10000 (10 second), miminum is 100 (0.1 second) and maximum is 600000 (10 minutes)

* **fundadb_hash_purge_loop**

	The purge of a hash table is performed in small chunks of time, defined by *fundadb_hash_purge_loop* . Default is 100 (0.1 second), minimum is 100 (0.1 second) and maximum is 60000 (1 minute)

* **fundadb_hash_expire_default**

	fundadb hash default expire in second. This is not relevant as every entry in the internal query always have an explicit timeout.

* **fundadb_hash_purge_threshold_pct_min**

	Minimum percentage of memory usage that triggers normal purge. No purge is performed if memory usage is below this threshold. Default is 50 (%), minimum is 0, maximum is 90.

* **fundadb_hash_purge_threshold_pct_max**

	Maximum percentage of memory usage that triggers normal purge. Aggressive purging is performed if memory usage is above this threshold. Default is 90 (%), minimum is 50, maximum is 100.


Quick start Tutorial
====================

Download and compile
~~~~~~~~~~~~~~~~~~~~

See above for an example of how to download and compile ProxySQL


Create a small replication environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To try proxysql we can use a standalone mysqld instance, or a small replication cluster for better testing. To quickly create a small replication environment you can use MySQL Sandbox::
  
  rene@voyager:~$ make_replication_sandbox mysql_binaries/mysql-5.5.34-linux2.6-i686.tar.gz 
  installing and starting master
  installing slave 1
  installing slave 2
  starting slave 1
  .... sandbox server started
  starting slave 2
  .... sandbox server started
  initializing slave 1
  initializing slave 2
  replication directory installed in $HOME/sandboxes/rsandbox_mysql-5_5_34


Now that the cluster is installed, verify on which ports are listening the various mysqld processes::
  
  rene@voyager:~$ cd sandboxes/rsandbox_mysql-5_5_34
  rene@voyager:~/sandboxes/rsandbox_mysql-5_5_34$ cat default_connection.json 
  {
  "master":  
      {
          "host":     "127.0.0.1",
          "port":     "23389",
          "socket":   "/tmp/mysql_sandbox23389.sock",
          "username": "msandbox@127.%",
          "password": "msandbox"
      }
  ,
  "node1":  
      {
          "host":     "127.0.0.1",
          "port":     "23390",
          "socket":   "/tmp/mysql_sandbox23390.sock",
          "username": "msandbox@127.%",
          "password": "msandbox"
      }
  ,
  "node2":  
      {
          "host":     "127.0.0.1",
          "port":     "23391",
          "socket":   "/tmp/mysql_sandbox23391.sock",
          "username": "msandbox@127.%",
          "password": "msandbox"
      }
  }

The mysqld processes are listening on port 23389 (master) and 23390 and 23391 (slaves).

Configure ProxySQL
~~~~~~~~~~~~~~~~~~

ProxySQL doesn't have an example configuration file. Create a new one named *proxysql.cnf* using the follow sample::
  
  [global]
  datadir=/home/rene/ProxySQL/proxysql-master/src
  [mysql]
  mysql_usage_user=proxy
  mysql_usage_password=proxy
  mysql_servers=127.0.0.1:23389;127.0.0.1:23390;127.0.0.1:23391
  mysql_default_schema=information_schema
  mysql_connection_pool_enabled=1
  mysql_max_resultset_size=1048576
  mysql_max_query_size=1048576
  mysql_query_cache_enabled=1
  mysql_query_cache_partitions=16
  mysql_query_cache_default_timeout=30
  [mysql users]
  msandbox=msandbox
  test=password

Note the *[global]* section is mandatory even if unused.

Create users on MySQL
~~~~~~~~~~~~~~~~~~~~~

We configured ProxySQL to use 3 users:

* proxy : this user needs only USAGE privileges, and it is used to verify that the server is alive and the value of read_only
* msandbox and test : these are two normal users that application can use to connect to mysqld through the proxy

User msandbox is already there, so only users proxy and test needs to be created. For example::

  rene@voyager:~$ mysql -h 127.0.0.1 -u root -pmsandbox -P23389 -e "GRANT USAGE ON *.* TO 'proxy'@'127.0.0.1' IDENTIFIED BY 'proxy'";
  rene@voyager:~$ mysql -h 127.0.0.1 -u root -pmsandbox -P23389 -e "GRANT ALL PRIVILEGES ON *.* TO 'test'@'127.0.0.1' IDENTIFIED BY 'password'";


Configure the slaves with read_only=0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When ProxySQL is executed for the first time (or when there are no built-in database database available), ProxySQL distinguishes masters from slaves only checking the global variables read_only. This means that you *must* configure the slaves with read_only=ON or ProxySQL will send DML to them as well. Note that this make ProxySQL suitable for multi-master environments using clustering solution like NDB and Galera.

Verify the status of read_only on all servers::
  
  rene@voyager:~$ for p in 23389 23390 23391 ; do mysql -h 127.0.0.1 -u root -pmsandbox -P$p -B -N -e "SHOW VARIABLES LIKE 'read_only'" ; done
  read_only OFF
  read_only OFF
  read_only OFF

Change read_only on slaves::
  
  rene@voyager:~$ for p in 23390 23391 ; do mysql -h 127.0.0.1 -u root -pmsandbox -P$p -B -N -e "SET GLOBAL read_only=ON" ; done


Verify again the status of read_only on all servers::
  
  rene@voyager:~$ for p in 23389 23390 23391 ; do mysql -h 127.0.0.1 -u root -pmsandbox -P$p -B -N -e "SHOW VARIABLES LIKE 'read_only'" ; done
  read_only OFF
  read_only ON
  read_only ON


Start ProxySQL
~~~~~~~~~~~~~~

ProxySQL is now ready to be executed::
  
  rene@voyager:~/ProxySQL/proxysql-master/src$ ./proxysql 

Note that ProxySQL will run fork into 2 processes, an angel process and the proxy itself::
  
  rene@voyager:~/ProxySQL/proxysql-master/src$ ps aux | grep proxysql
  rene    31007  0.0  0.0  32072   904 ?        S    08:03   0:00 ./proxysql
  rene    31008  0.0  0.0 235964  2336 ?        Sl   08:03   0:00 ./proxysql


Connect to ProxySQL
~~~~~~~~~~~~~~~~~~~

You can now connect to ProxySQL running any mysql client. For example::
  
  rene@voyager:~$ mysql -u msandbox -pmsandbox -h 127.0.0.1 -P6033
  Welcome to the MySQL monitor.  Commands end with ; or \g.
  Your MySQL connection id is 3060194112
  Server version: 5.1.30 MySQL Community Server (GPL)
  
  Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.
  
  Oracle is a registered trademark of Oracle Corporation and/or its
  affiliates. Other names may be trademarks of their respective
  owners.
  
  Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
  
  mysql> 

An acute observer can immediately understand that we aren't connected directly to MySQL, but to ProxySQL . A less acute observer can probably understand it from the next output::
  
  mysql> \s
  --------------
  mysql  Ver 14.14 Distrib 5.5.34, for debian-linux-gnu (i686) using readline 6.2
  
  Connection id:		3060194112
  Current database:	information_schema
  Current user:		msandbox@localhost
  SSL:			Not in use
  Current pager:		stdout
  Using outfile:		''
  Using delimiter:	;
  Server version:		5.1.30 MySQL Community Server (GPL)
  Protocol version:	10
  Connection:		127.0.0.1 via TCP/IP
  Server characterset:	latin1
  Db     characterset:	utf8
  Client characterset:	latin1
  Conn.  characterset:	latin1
  TCP port:		6033
  Uptime:			51 min 56 sec
  
  Threads: 4  Questions: 342  Slow queries: 0  Opens: 70  Flush tables: 1  Open tables: 63  Queries per second avg: 0.109
  --------------
  
  mysql>

Did you notice it now? If not, note that line::
  
  Server version:       5.1.30 MySQL Community Server (GPL)

We installed MySQL 5.5.34 , but the client says 5.1.30 . This because during the authentication phase ProxySQL introduces itself as MySQL version 5.1.30 . This is configurable via parameter *mysql_server_version* . Note: ProxySQL doesn't use the real version of the backends because it is possible to run backends with different versions.

Additionally, mysql says that the current database is *information_schema* while we didn't specify any during the connection.

On which server are we connected now? Because of read/write split, it is not always possible to answer this question.
What we know is that:

* SELECT statements without FOR UPDATE are sent to the slaves ( and also to the master if *mysql_use_masters_for_reads=1* , by default ) ;
* SELECT statements with FOR UPDATE are sent to a master ;
* any other statement is sent to the master only ;
* SELECT statements without FOR UPDATE are cached .

Let try to understand to which server are we connected running the follow::
  
  mysql> SELECT @@port;
  +--------+
  | @@port |
  +--------+
  |  23391 |
  +--------+
  1 row in set (0.00 sec)

We are connected on server using port 23391 . This information is true only the *first* time we run it. In fact, if we run the same query from another connection we will get the same result because this query is cached.
Also, if we disconnect the client and reconnect again, the above query will return the same result also after the cache is invalidated. Why? ProxySQL implement connection pooling, and a if a client connection to the proxy is close the backend connection will be reused by the next client connection.

To verify the effect of the cache, it is enough to run the follow commands::
  
  mysql> SELECT NOW();
  +---------------------+
  | NOW()               |
  +---------------------+
  | 2013-11-20 17:55:25 |
  +---------------------+
  1 row in set (0.00 sec)
  
  mysql> SELECT @@port;
  +--------+
  | @@port |
  +--------+
  |  23391 |
  +--------+
  1 row in set (0.00 sec)
  
  mysql> SELECT NOW();
  +---------------------+
  | NOW()               |
  +---------------------+
  | 2013-11-20 17:55:25 |
  +---------------------+
  1 row in set (0.00 sec)

The resultset of "SELECT NOW()" doesn't change with time. Probably this is not what you want.

Testing R/W split
~~~~~~~~~~~~~~~~~

The follow is an example of how to test R/W split .

Write on master::
  
  mysql> show databases;
  +--------------------+
  | Database           |
  +--------------------+
  | information_schema |
  | mysql              |
  | performance_schema |
  | test               |
  +--------------------+
  4 rows in set (0.02 sec)
  
  mysql> use test
  Database changed
  mysql> CREATE table tbl1 (id int);
  Query OK, 0 rows affected (0.25 sec)
  
  mysql> insert into tbl1 values (1);
  Query OK, 1 row affected (0.03 sec)

Read from a slave::
 
  mysql> SELECT * FROM tbl1;
  +------+
  | id   |
  +------+
  |    1 |
  +------+
  1 row in set (0.00 sec)

The follow query retrieves also @@port, so we can verify it is executed on a slave::

  mysql> SELECT @@port, t.* FROM tbl1 t;
  +--------+------+
  | @@port | id   |
  +--------+------+
  |  23391 |    1 |
  +--------+------+
  1 row in set (0.00 sec)

To force a read from master, we must specify FOR UPDATE::

  mysql> SELECT @@port, t.* FROM tbl1 t FOR UPDATE;
  +--------+------+
  | @@port | id   |
  +--------+------+
  |  23389 |    1 |
  +--------+------+
  1 row in set (0.01 sec)



Default query rules
===================
