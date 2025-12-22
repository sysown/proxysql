How to install ProxySQL
=======================

ProxySQL offers multiple ways of install:
- install deb or rpm packages - https://github.com/sysown/proxysql/releases
- install from the package repository - https://repo.proxysql.com/
- build from git repo using docker - https://github.com/sysown/proxysql.git
- build from source code archives - https://github.com/sysown/proxysql/releases


Installing using native installer packages
------------------------------------------

The list of currently supported operating systems for native packaging is:

- AMD64
  - AlmaLinux 8, 9, 10
  - Amazon Linux 2
  - CentOS Stream 9, 10
  - Debian 12 (bookworm), 13 (trixie)
  - Fedora 40, 41, 42
  - OpenSUSE Leap 15, 16
  - Ubuntu 22.04 (jammy), 24.04 (noble)
- ARM64
  - AlmaLinux 8, 9, 10
  - Amazon Linux 2
  - CentOS Stream 9, 10
  - Debian 12, 13
  - Fedora 40, 41, 42
  - OpenSUSE Leap 15, 16
  - Ubuntu 22.04, 24.04

Download a __deb__ or __rpm__ installer file for your OS and architecture from:

https://github.com/sysown/proxysql/releases

There is also a choice of debug packages and CLang compiled packages.


Installing from package repository
----------------------------------
Please follow the instructions how to configure a repository:

https://repo.proxysql.com/

For ProxySQL 3.0.x, the repository URLs are:

#### Ubuntu / Debian:
```bash
apt-get update && apt-get install -y --no-install-recommends lsb-release wget apt-transport-https ca-certificates
wget -nv -O /etc/apt/trusted.gpg.d/proxysql-3.0.x-keyring.gpg 'https://repo.proxysql.com/ProxySQL/proxysql-3.0.x/repo_pub_key.gpg'
echo "deb https://repo.proxysql.com/ProxySQL/proxysql-3.0.x/$(lsb_release -sc)/ ./" | tee /etc/apt/sources.list.d/proxysql.list
```

#### Red Hat / CentOS:
```bash
cat > /etc/yum.repos.d/proxysql.repo << EOF
[proxysql]
name=ProxySQL YUM repository
baseurl=https://repo.proxysql.com/ProxySQL/proxysql-3.0.x/centos/\$releasever
gpgcheck=1
gpgkey=https://repo.proxysql.com/ProxySQL/proxysql-3.0.x/repo_pub_key
EOF
```

#### Amazon Linux:
```bash
cat > /etc/yum.repos.d/proxysql.repo << EOF
[proxysql]
name=ProxySQL YUM repository
baseurl=https://repo.proxysql.com/ProxySQL/proxysql-3.0.x/centos/8
gpgcheck=1
gpgkey=https://repo.proxysql.com/ProxySQL/proxysql-3.0.x/repo_pub_key
EOF
```

#### AlmaLinux:
```bash
cat > /etc/yum.repos.d/proxysql.repo << EOF
[proxysql]
name=ProxySQL YUM repository
baseurl=https://repo.proxysql.com/ProxySQL/proxysql-3.0.x/almalinux/\$releasever
gpgcheck=1
gpgkey=https://repo.proxysql.com/ProxySQL/proxysql-3.0.x/repo_pub_key
EOF
```

#### OpenSUSE:
```bash
cat > /etc/zypp/repos.d/proxysql.repo << EOF
[proxysql]
name=ProxySQL Zypper repository
enabled=1
autorefresh=0
baseurl=https://repo.proxysql.com/ProxySQL/proxysql-3.0.x/opensuse/\$releasever_major
gpgcheck=1
EOF
```
or
```bash
zypper addrepo -g -n 'ProxySQL Zypper repository' 'https://repo.proxysql.com/ProxySQL/proxysql-3.0.x/opensuse/$releasever_major' proxysql
```

#### FreeBSD:
Installing (via pkg):
```bash
pkg install proxysql
```
Installing (via ports):
```bash
cd /usr/ports/databases/proxysql/ && make install clean
```

After configuring the repository, install ProxySQL with your package manager:

```bash
# Debian/Ubuntu
apt-get update
apt-get install proxysql

# RHEL/CentOS/AlmaLinux/Amazon Linux
yum install proxysql

# Fedora
dnf install proxysql

# OpenSUSE
zypper install proxysql
```


Building and installing from git repo using docker
--------------------------------------------------
This is the recommended way of building as it provides a reproducible environment.

Make sure you have docker installed, best from upstream docker.io

https://docs.docker.com/engine/install/

```bash
git clone https://github.com/sysown/proxysql.git
cd proxysql
git checkout v3.0.3
make ubuntu24   # or other target: ubuntu22, debian12, debian13, centos9, centos10, fedora40, fedora41, fedora42, opensuse15, opensuse16, almalinux8, almalinux9, almalinux10
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

https://github.com/sysown/proxysql/archive/refs/heads/v3.x.zip

Make sure you have installed the equivalent for each of these packages for your operating system:

### Debian / Ubuntu based:
```bash
apt-get install -y automake bzip2 cmake make g++ gcc git openssl libssl-dev libgnutls28-dev libmysqlclient-dev libunwind8 libunwind-dev uuid-dev libncurses-dev libicu-dev libevent-dev libtirpc-dev
```

### RHEL / CentOS / AlmaLinux based:
```bash
yum install -y epel-release
yum install -y automake bzip2 cmake make gcc-c++ gcc git openssl openssl-devel gnutls gnutls-devel libunwind libunwind-devel perl-IPC-Cmd perl-FindBin perl-Time-Piece libuuid-devel zlib-devel libicu-devel libevent-devel ncurses-devel
yum install -y --enablerepo=crb libtirpc-devel rpcgen
```

### Fedora based:
```bash
dnf install -y automake bzip2 cmake make gcc-c++ gcc git openssl openssl-devel gnutls gnutls-devel libunwind libunwind-devel perl-FindBin perl-IPC-Cmd perl-Time-Piece libuuid-devel libicu-devel libevent-devel ncurses-devel libtirpc-devel rpcgen
```

### OpenSUSE based:
```bash
zypper install -y automake bzip2 cmake make gcc-c++ gcc git openssl openssl-devel gnutls gnutls-devel libunwind libunwind-devel perl-IPC-Cmd perl-FindBin perl-Time-Piece libuuid-devel libicu-devel libevent-devel ncurses-devel libtirpc-devel rpcgen
```

### macOS (using Homebrew):
```bash
brew install automake bzip2 cmake make git gpatch gnutls ossp-uuid
```

For more details, inspect the docker build images:

https://github.com/ProxySQL/docker-images/tree/main/build-images

For CLang builds, inspect the docker build-clang images:

https://github.com/ProxySQL/docker-images/tree/main/build-clang-images

Go to the directory where you cloned the repo (or unpacked the tarball) and run:

```bash
make
sudo make install
```

Compilation time should be around a couple of minutes for the first time around. The configuration file will be found at `/etc/proxysql.cnf` afterwards.

Once you have installed it, please take a look at the document about [running and operating the proxy](https://github.com/sysown/proxysql/blob/master/RUNNING.md).
