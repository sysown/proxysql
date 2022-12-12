How to install ProxySQL
=======================

ProxySQL offers multiple ways of install:
- install deb or rpm packages - https://github.com/sysown/proxysql/releases
- install from the package repo - https://repo.proxysql.com/
- build from git repo any taged or dev version - https://github.com/sysown/proxysql.git
- build from source code archives - https://github.com/sysown/proxysql/releases


Instaling using native installer packages
----------------------------------------

The list of currently supported operating systems for native packaging is:
- AMD64
  - CentOS 6,7,8
  - Debian 8,9,0,11
  - Ubuntu 14,16,18,20,22
  - Fedora 27,28,33,34
  - OpenSUSE 15
  - AlmaLinux 8,9
- ARM64
  - CentOS 7,8
  - Debian 9,10,11
  - Ubuntu 16,18,20,22
  - Fedora 33,24
  - OpenSUSE 15
  - AlmaLinux 8,9
 
Download a __deb__ or __rpm__ installer file for your OS and architecture from:

https://github.com/sysown/proxysql/releases

There is also a choice of debug packages and CLang compiled packages.


Installing from package repository
----------------------------------
Please follow the intructions how to configure a repository:

https://repo.proxysql.com/


Building and installing from git repo using docker
--------------------------------------------------
This is the recommended way of building as it provides a reproducible environment.

Make sure you have docker installed, best from upstream docker.io

https://docs.docker.com/engine/install/

```
git clone https://github.com/sysown/proxysql.git
cd proxysql
git checkout -d v2.4.2
make ubuntu22
```
This will checkout the chosen version tag, pull the latest build image from DockerHub and build binaries and packages for the target distro.

The __executable__ file will be located in ./src, the __rpm__ or __deb__ installer file will be in ./binaries folder.

Install the package as usual on the target system.

For valid target distros see above or inspect the Makefile.


Building and installing from source
-----------------------------------
Download a release source code archive from:

https://github.com/sysown/proxysql/releases

or get the latest development sources from:

https://github.com/sysown/proxysql/archive/refs/heads/v2.x.zip

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

For CLang builds, inspect the docker build-clang images:

https://github.com/ProxySQL/docker-images/tree/main/build-clang-images

On modern Mac OSX, ProxySQL's dependencies are not fully satisfied by the tools included with the XCode/clang toolkit. Using the [Homebrew](https://brew.sh/) OSX package manager, dependencies can be installed and located on OSX like this:

```bash
brew install automake bzip2 cmake make git gpatch gnutls ossp-uuid
```

Go to the directory where you cloned the repo (or unpacked the tarball) and run:

```bash
make
sudo make install
```

Compilation time should be around a couple of minutes for the first time around. The configuration file will be found at `/etc/proxysql.cnf` afterwards.

Once you have installed it, please take a look at the document about [running and operating the proxy](https://github.com/sysown/proxysql/blob/master/RUNNING.md).
