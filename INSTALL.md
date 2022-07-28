How to install ProxySQL
=======================

ProxySQL offers 3 types of releases:
- rpm and deb packages
  https://github.com/sysown/proxysql/releases
- git repo with taged versions
  https://github.com/sysown/proxysql.git
- source code archives - tar.gz or zip
  https://github.com/sysown/proxysql/releases

The list of currently supported operating systems for binary packaging is:
 - CentOS 6,7,8
 - Debian 8,9,0,11
 - Ubuntu 14,16,18,20,22
 - Fedora 27,28,34,38
 - OpenSUSE 15
 - AlmaLinux 8,9

Installing from git repo using docker
-------------------------------------
This is the recommended way of building as it provides a reproducible environment.

Make sure you have docker installed, best from upstream docker.io
```
git clone https://github.com/sysown/proxysql.git
cd proxysql
git checkout -d v2.4.2
make ubuntu22
```
This will checkout the chosen version tag, pull the latest build image from DockerHub and build binaries and packages for the target distro.

The __executable__ file will be located in ./src, the __rpm__ or __deb__ installer file will be in ./binaries folder.

For valid target distros see above or inspect the Makefile.

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
- uuid-dev

Shortcut commands for installing pre-requisites:
```
# RHEL / CentOS < 7:
yum install -y automake bzip2 cmake make g++ gcc git openssl openssl-devel gnutls libtool patch libuuid-devel

# CentOS 7.4+ / Fedora 28+:
yum install -y automake bzip2 cmake make gcc-c++ gcc git openssl openssl-devel gnutls gnutls-devel libtool patch libuuid-devel

# Debian / Ubuntu Based:
apt-get install -y automake bzip2 cmake make g++ gcc git openssl libssl-dev libgnutls28-dev libtool patch uuid-dev
```

For more details, inspect the docker build images:
https://github.com/ProxySQL/docker-images/tree/main/build-images

For CLang builds, inspect the docker build-clang images
https://github.com/ProxySQL/docker-images/tree/main/build-clang-images

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
