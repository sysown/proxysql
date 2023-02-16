<a><img src="https://i0.wp.com/proxysql.com/wp-content/uploads/2020/04/ProxySQL-Colour-Logo.png?fit=800%2C278&ssl=1" alt="ProxySQL"></a>

Introduction	
============	

ProxySQL is a high performance, high availability, protocol aware proxy for MySQL and forks (like Percona Server and MariaDB).	
All the while getting the unlimited freedom that comes with a GPL license.	

Its development is driven by the lack of open source proxies that provide high performance.  	

Useful links	
===============	

- [Official website](https://www.proxysql.com/)	
- [Subscriptions and Support](https://proxysql.com/services/support/) 
- [Documentation](https://www.proxysql.com/Documentation)
- [DockerHub Repository](https://hub.docker.com/r/proxysql/proxysql)
- [Benchmarks and blog posts](http://www.proxysql.blogspot.com/)	
- [Forum](https://groups.google.com/forum/#!forum/proxysql/)
- [Facebook](https://www.facebook.com/proxysql)	
- [Linkedin](https://www.linkedin.com/groups/13581070/)	
- [Twitter](https://twitter.com/proxysql)	

Getting started
===============

### Installation
Released packages can be found here: https://github.com/sysown/proxysql/releases

Just download a package and use your systems package manager to install it:
```bash
wget https://github.com/sysown/proxysql/releases/download/v2.4.2/proxysql_2.4.2-ubuntu20_amd64.deb
dpkg -i proxysql_2.4.2-ubuntu20_amd64.deb
```

Alternatively you can also use the available repositories:

#### Ubuntu / Debian:

Adding repository:
```bash
apt-get update && apt-get install -y --no-install-recommends lsb-release wget apt-transport-https ca-certificates
wget -nv -O /etc/apt/trusted.gpg.d/proxysql-2.4.x-keyring.gpg 'https://repo.proxysql.com/ProxySQL/proxysql-2.4.x/repo_pub_key.gpg'
echo "deb https://repo.proxysql.com/ProxySQL/proxysql-2.4.x/$(lsb_release -sc)/ ./" | tee /etc/apt/sources.list.d/proxysql.list
```

Installing:
```bash
apt-get update
apt-get install proxysql OR apt-get install proxysql=version
```

#### Red Hat / CentOS:

Adding repository:
```bash
cat > /etc/yum.repos.d/proxysql.repo << EOF
[proxysql]
name=ProxySQL YUM repository
baseurl=https://repo.proxysql.com/ProxySQL/proxysql-2.4.x/centos/\$releasever
gpgcheck=1
gpgkey=https://repo.proxysql.com/ProxySQL/proxysql-2.4.x/repo_pub_key
EOF
```

Installing:
```bash
yum install proxysql OR yum install proxysql-version
```

#### Amazon Linux:

Adding repository:
```bash
cat > /etc/yum.repos.d/proxysql.repo << EOF
[proxysql]
name=ProxySQL YUM repository
baseurl=https://repo.proxysql.com/ProxySQL/proxysql-2.4.x/centos/8
gpgcheck=1
gpgkey=https://repo.proxysql.com/ProxySQL/proxysql-2.4.x/repo_pub_key
EOF
```

Installing:
```bash
yum install proxysql OR yum install proxysql-version
```

#### Almalinux:

Adding repository:
```bash
cat > /etc/yum.repos.d/proxysql.repo << EOF
[proxysql]
name=ProxySQL YUM repository
baseurl=https://repo.proxysql.com/ProxySQL/proxysql-2.4.x/almalinux/\$releasever
gpgcheck=1
gpgkey=https://repo.proxysql.com/ProxySQL/proxysql-2.4.x/repo_pub_key
EOF
```

Installing:
```bash
yum install proxysql OR yum install proxysql-version
```

#### OpenSUSE:

Adding repository:
```bash
cat > /etc/zypp/repos.d/proxysql.repo << EOF
[proxysql]
name=ProxySQL Zypper repository
enabled=1
autorefresh=0
baseurl=https://repo.proxysql.com/ProxySQL/proxysql-2.4.x/opensuse/\$releasever_major
gpgcheck=1
EOF
```
or
```bash
zypper addrepo -g -n 'ProxySQL Zypper repository' 'https://repo.proxysql.com/ProxySQL/proxysql-2.4.x/opensuse/$releasever_major' proxysql
```

Installing:
```bash
yum install proxysql OR yum install proxysql-version
```

### Service management
Once the software is installed, you can use the `service` command to control the process:  

#### Starting ProxySQL:
```bash
service proxysql start
```
#### Stopping ProxySQL:
```bash
service proxysql stop
```

Or alternatively via the Admin interface:
```
$ mysql -u admin -padmin -h 127.0.0.1 -P6032 --prompt='Admin> '
Warning: Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 4
Server version: 5.5.30 (ProxySQL Admin Module)

Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

Admin> proxysql stop
```

#### Restarting ProxySQL:
```bash
service proxysql restart
```

Or alternatively via the Admin interface:
```
$ mysql -u admin -padmin -h 127.0.0.1 -P6032 --prompt='Admin> '
Warning: Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 4
Server version: 5.5.30 (ProxySQL Admin Module)

Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

Admin> proxysql restart
```

#### Reinitializing ProxySQL from the config file (after first startup the DB file is used instead of the config file):
```bash
# If you are using the init script run:
/etc/init.d/proxysql initial
# or
service proxysql initial
 
# If you are using the systemd unit file run:
systemctl start proxysql-initial
# or
service proxysql-initial start
```

### Upgrades
Just install the new package and restart ProxySQL:
```bash
wget https://github.com/sysown/proxysql/releases/download/v2.1.0/proxysql_2.1.0-ubuntu16_amd64.deb
dpkg -i proxysql_2.1.0-ubuntu16_amd64.deb
service proxysql restart
```

### How to check the ProxySQL version
```bash
$ proxysql --version
```
```bash
ProxySQL version 2.1.0-544-g17a4b4a7, codename Truls
```
A debug version has `_DEBUG` in its version string.
It is slower than non-debug version, but easier to debug in case of failures.
```bash
$ proxysql --version
```
```bash
Main init phase0 completed in 0.000146 secs.
ProxySQL version 2.1.0-544-g17a4b4a7_DEBUG, codename Truls
```

### Configuring ProxySQL via the `admin interface`

First of all, bear in mind that the best way to configure ProxySQL is through its admin interface. This lends itself to online configuration (without having to restart the proxy) via SQL queries to its admin database. It's an effective way to configure it both manually and in an automated fashion.

As a secondary way to configure it, we have the configuration file. 

#### Configuring ProxySQL through the admin interface

To log into the admin interface (with the default credentials) use a mysql client and connect using the following `admin` credentials locally on port (6032):
```bash
$ mysql -u admin -padmin -h 127.0.0.1 -P6032 --prompt='Admin> '
Warning: Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 4
Server version: 5.5.30 (ProxySQL Admin Module)

Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

Admin>
```

note: If your MySQL client version is version 8.04 or higher add `--default-auth=mysql_native_password` to the above command to connect to the admin interface.

Once connected to the admin interface, you will have a list of databases and tables at your disposal that can be queried using the SQL language:
```mysql
Admin> SHOW DATABASES;
+-----+---------+-------------------------------+
| seq | name    | file                          |
+-----+---------+-------------------------------+
| 0   | main    |                               |
| 2   | disk    | /var/lib/proxysql/proxysql.db |
| 3   | stats   |                               |
| 4   | monitor |                               |
+-----+---------+-------------------------------+
4 rows in set (0.00 sec)
```
This will allow you to control the list of the backend servers, how traffic is routed to them, and other important settings (such as caching, access control, etc). Once you've made modifications to the in-memory data structure, you must load the new configuration to the runtime, or persist the new settings to disk (so that they are still there after a restart of the proxy). A detailed tutorial on how to configure ProxySQL through the Admin interface is available [here](https://github.com/sysown/proxysql/wiki/ProxySQL-Configuration).

#### Configuring ProxySQL through the config file

Even though the config file should only be regarded as a secondary way to configure the proxy, we must not discard its value as a valid way to bootstrap a fresh ProxySQL install.

Let's quickly go over the main sections of the configuration file (this overview serves as a very high level overview of ProxySQL configuration).

Top-level sections:
* `admin_variables`: contains global variables that control the functionality of the admin interface.
* `mysql_variables`: contains global variables that control the functionality for handling the incoming MySQL traffic.
* `mysql_servers`: contains rows for the `mysql_servers` table from the admin interface. Basically, these define the backend servers towards which the incoming MySQL traffic is routed. Rows are encoded as per the `.cfg` file format, here is an example:
	
	```bash
	mysql_servers =
	(
		{
			address="127.0.0.1"
			port=3306
			hostgroup=0
			max_connections=200
		}
	)
	```
* `mysql_users`: contains rows for the `mysql_users` table from the admin interface. Basically, these define the users which can connect to the proxy, and the users with which the proxy can connect to the backend servers. Rows are encoded as per the `.cfg` file format, here is an example:
	
	```bash
	mysql_users:
	(
		{
			username = "root"
			password = "root"
			default_hostgroup = 0
			max_connections=1000
			default_schema="information_schema"
			active = 1
		}
	)
	```
* `mysql_query_rules`: contains rows for the `mysql_query_rules` table from the admin interface. Basically, these define the rules used to classify and route the incoming MySQL traffic, according to various criteria (patterns matched, user used to run the query, etc.). Rows are encoded as per the `.cfg` file format, here is an example (Note: the example is a very generic query routing rule and it is recommended to create specific rules for queries rather than using a generic rule such as this):
	
	```bash
	mysql_query_rules:
	(
		{
			rule_id=1
			active=1
			match_pattern="^SELECT .* FOR UPDATE$"
			destination_hostgroup=0
			apply=1
		},
		{
			rule_id=2
			active=1
			match_pattern="^SELECT"
			destination_hostgroup=1
			apply=1
		}
	)
	```
* top-level configuration item: `datadir`, as a string, to point to the data dir.
