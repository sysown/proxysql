# Diamond collector for ProxySQL

## Installation

* Install `python2-PyMySQL` package
* Copy `proxysqlstat.py` to `/usr/share/diamond/collectors/proxysql/
* Copy `ProxySQLCollector.conf` to `/etc/diamond/collectors/`
  * Edit and adjust credentials and mysql admin host/port
* Restart diamond
