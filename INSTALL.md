How to install ProxySQL
=======================

ProxySQL offers 2 types of releases:
- pre-packaged versions of the __last stable version__ - periodically updated at [ProxySQL](https://github.com/sysown/proxysql/releases/latest)
 
The list of currently supported operating systems for binary packaging is:
 - Ubuntu 14
 - Ubuntu 12
 - Debian 7
 - Debian 8
 - CentOS 6.7
 - Centos 7

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
- openssl
- openssl-devel
- patch

Go to the directory where you cloned the repo (or unpacked the tarball) and run:

```bash
make
sudo make install
```

Compilation time should be around a couple of minutes for the first time around. The configuration file will be found at `/etc/proxysql.cnf` afterwards.

Once you have installed it, please take a look at the document about [running and operating the proxy](https://github.com/sysown/proxysql/blob/master/RUNNING.md).
