How to install ProxySQL
=======================

ProxySQL offers 2 types of releases:
- pre-packaged versions of the __last stable version__ (periodically updated at `https://github.com/sysown/proxysql/releases`).
The list of currently supported operating systems for binary packaging is:
 - [Ubuntu 14](https://github.com/sysown/proxysql/releases/download/v1.3.4/proxysql_1.3.4-ubuntu14_amd64.deb)
 - [Ubuntu 12](https://github.com/sysown/proxysql/releases/download/v1.3.4/proxysql_1.3.4-ubuntu12_amd64.deb)
 - [CentOS 7](https://github.com/sysown/proxysql/releases/download/v1.3.4/proxysql-1.3.4-1-centos7.x86_64.rpm)

Installing from source
----------------------
Make sure you have installed the equivalent for each of these packages for your operating system:
- automake
- bzip2
- cmake
- make
- g++
- gcc
- git
- patch
- openssl
- openssl-devel   # RHEL based
- libssl-dev      # Debian based

Go to the directory where you cloned the repo (or unpacked the tarball) and run:

```bash
make
sudo make install
```

Compilation time should be around a couple of minutes for the first time around. The configuration file will be found at `/etc/proxysql.cnf` afterwards.

Once you have installed it, please take a look at the document about [running and operating the proxy](https://github.com/sysown/proxysql/blob/master/RUNNING.md).
