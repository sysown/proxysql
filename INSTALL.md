How to install ProxySQL
=======================

ProxySQL offers 2 types of releases:
- pre-packaged versions of the __last stable version__ (periodically updated at `https://github.com/sysown/proxysql-binaries/blob/master/binaries/`).
The list of currently supported operating systems for binary packaging is:
 - [Ubuntu 14](https://github.com/sysown/proxysql-binaries/blob/master/binaries/Ubuntu14/proxysql_0.2.0902-ubuntu14_amd64.deb)
 - [Ubuntu 12](https://github.com/sysown/proxysql-binaries/blob/master/binaries/Ubuntu12/proxysql_0.2.0902-ubuntu12_amd64.deb)
 - [CentOS 7](https://github.com/sysown/proxysql-binaries/blob/master/binaries/Centos7/proxysql-0.2.0902-1.x86_64.rpm)

While the binaries or installing from source is enough to run ProxySQL, if you want to make use of ProxySQL's integration with external services, like Consul, you will need to install additional software. Check [Installing requirements for integrations](#installing-requirements-for-integrations) for what's needed for each integration.

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

Once you have installed it, please take a look at the document about [running and operating the proxy](RUNNING.md).

Installing requirements for integrations
----------------------------------------
#### Consul integration requirements
ProxySQL integrates with Consul to allow syncing of configuration in a cluster. Install requirements for this only if you plan to use the feature, ProxySQL will run fine without this if the feature is not used.

ProxySQL integrates with Consul through a python script. The requirements are documented in [Consul's integration requirements.txt](integrations/consul/requirements.txt).

To install, run:
```bash
pip install -r integrations/consul/requirements.txt
```
