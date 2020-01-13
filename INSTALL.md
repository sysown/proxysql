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
- openssl-devel   # Only for RHEL / CentOS based
- libssl-dev      # Only for Debian / Ubuntu based

Shortcut commands for installing pre-requisites:
```
# RHEL / CentOS < 7:
yum install -y automake bzip2 cmake make g++ gcc git openssl openssl-devel gnutls libtool patch

# CentOS 7.4+ / Fedora 28+:
yum install -y automake bzip2 cmake make gcc-c++ gcc git openssl openssl-devel gnutls gnutls-devel libtool patch

# Debian / Ubuntu Based:
apt-get install -y automake bzip2 cmake make g++ gcc git openssl libssl-dev libgnutls28-dev libtool patch
```

On Mac OSX, Proxysql's dependencies are not fully satisfied by the tools included with the XCode/clang toolkit. The Proxysql build system needs to be told where to find non-system `curl` (and possibly `openssl`) libraries. Using the [Homebrew](https://brew.sh/) OSX package manager, dependencies can be installed and located on OSX like this:

```bash
brew install automake bzip2 cmake make git gpatch openssl curl
export OPENSSL_ROOT_DIR="$(brew --prefix openssl)"
export CXXFLAGS="${CXXFLAGS:-} -I$(brew --prefix openssl)/include -I$(brew --prefix curl)/include"
export LDFLAGS="${LDFLAGS:-} -L$(brew --prefix openssl)/lib"
```

Go to the directory where you cloned the repo (or unpacked the tarball) and run:

```bash
make
sudo make install
```

Compilation time should be around a couple of minutes for the first time around. The configuration file will be found at `/etc/proxysql.cnf` afterwards.

Once you have installed it, please take a look at the document about [running and operating the proxy](https://github.com/sysown/proxysql/blob/master/RUNNING.md).
