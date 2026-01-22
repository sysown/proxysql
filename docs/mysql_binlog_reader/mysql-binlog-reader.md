## Overview

Since the release 2.0 of ProxySQL it is possible to track executed GTID in real-time from all the MySQL
servers in a replication topology. Adaptive query routing based on GTID tracking allows to provide causal
reads, and ProxySQL can route reads to the slave where the needed GTID event was already executed.u

**MySQL Binlog Reader** allows ProxySQL to know in real time which GTID was been executed on every MySQL
server, slaves and master itself. Thanks to this, when a client executes a reads that needs to provide causal
consistency reads, ProxySQL immediately knows on which server the query can be executed. If for whatever
reason the writes was not executed on any slave yet, ProxySQL will know that the write was executed on master
and send the read there.

For best results, the MySQL Binlog Reader should be running as close as possible to the MySQL database its
reading from.

This solutions scales very well with limited network usage, and is being already tested in production
environments.

## Requirements

Casual reads using GTID is only possible if:

-   ProxySQL version 2.0+ is used (older versions do not support it)
-   the backend is MySQL version 5.7.5 or newer. Older versions of MySQL do not have capability to use this
    functionality.
-   replication binlog format is ROW
-   GTID is enabled (that sounds almost obvious).
-   backends are either Oracle’s or Percona’s MySQL Server: MariaDB Server does not support
    `session_track_gtids`, but I hope it will be available soon.

<!-- -->

## Setup

There are multiple options how to setup the MySQL Binlog Reader, each with its own applicability and
limitations

1. install a package
2. use the offical docker container
3. use the Amazon EC2 AMI
4. compile from source

<!-- -->

#### Install

Current version can be found at the GitHub release page:
[https://github.com/sysown/proxysql_mysqlbinlog/releases/latest][1] Packages for the following distros are
provided:

-   [CentOS 7][2]
-   [CentOS 8][3]
-   [Debian 9][4]
-   [Debian 10][5]
-   [Debian 11][6]
-   [Ubuntu 16 LTS][7]
-   [Ubuntu 18 LTS][8]
-   [Ubuntu 20 LTS][9]

<!-- -->

#### Docker image

A choice of multiple images can be found in the offcial [proxysql/proxysql-mysqlbinlog][10] DockerHub
repository

<pre>docker pull proxysql/proxysql-mysqlbinlog:latest</pre>

#### Amazon AMI

comming soon.

#### Compile

clone out the repository from github

<pre>git clone https://github.com/sysown/proxysql_mysqlbinlog.git
cd proxysql_mysqlbinlog &amp;&amp; make</pre>

## Configuration

#### MySQL Binlog config

configured via option arguments at startup

<pre>-h &lt;mysql host&gt;
-u &lt;mysql user&gt;
-p &lt;mysql password&gt;
-P &lt;mysql port&gt;
-l &lt;listen port&gt;
-L &lt;log file&gt;</pre>

example:

<pre>proxysql_binlog_reader -h 127.0.0.1 -u root -proot -P 3306 -l 3307 -L /var/log/proxysql_binlog_reader.log</pre>

#### MySQL config

these options need to be added to the configuration:

<pre>gtid_mode=ON
enforce_gtid_consistency
session_track_gtids=OWN_GTID</pre>

#### ProxySQL config

execute these commands on the admin interface:

<pre>UPDATE mysql_servers SET gtid_port = 3307;
LOAD MYSQL SERVERS TO RUNTIME; SAVE MYSQL SERVERS TO DISK;</pre>

[1]: https://github.com/sysown/proxysql_mysqlbinlog/releases/latest
[2]: https://github.com/sysown/proxysql_mysqlbinlog/releases/download/v2.1/proxysql-mysqlbinlog-2.1-5-g7f50bd0-centos7.x86_64.rpm
[3]: https://github.com/sysown/proxysql_mysqlbinlog/releases/download/v2.1/proxysql-mysqlbinlog-2.1-5-g7f50bd0-centos8.x86_64.rpm
[4]: https://github.com/sysown/proxysql_mysqlbinlog/releases/download/v2.1/proxysql-mysqlbinlog_2.1-5-g7f50bd0-debian9_amd64.deb
[5]: https://github.com/sysown/proxysql_mysqlbinlog/releases/download/v2.1/proxysql-mysqlbinlog_2.1-5-g7f50bd0-debian10_amd64.deb
[6]: https://github.com/sysown/proxysql_mysqlbinlog/releases/download/v2.1/proxysql-mysqlbinlog_2.1-5-g7f50bd0-debian11_amd64.deb
[7]: https://github.com/sysown/proxysql_mysqlbinlog/releases/download/v2.1/proxysql-mysqlbinlog_2.1-5-g7f50bd0-ubuntu16_amd64.deb
[8]: https://github.com/sysown/proxysql_mysqlbinlog/releases/download/v2.1/proxysql-mysqlbinlog_2.1-5-g7f50bd0-ubuntu18_amd64.deb
[9]: https://github.com/sysown/proxysql_mysqlbinlog/releases/download/v2.1/proxysql-mysqlbinlog_2.1-5-g7f50bd0-ubuntu20_amd64.deb
[10]: https://hub.docker.com/repository/docker/proxysql/proxysql-mysqlbinlog
