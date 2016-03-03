ProxySQL cluster
=====================
A ProxySQL cluster is a way of setting up multiple ProxySQL instances that provides easier management over those instances. So far, a cluster setup offers this functionality:
* push configuration from a ProxySQL master to all other ProxySQL instances in that cluster.

# How the cluster works
ProxySQL uses [Consul](www.consul.io) to manage instances in a cluster. It makes use of Consul's key/value store and watch features to pass data between instances. Adding a ProxySQL instance to the cluster is a matter of running a Consul agent on the same machine that is configured to join the other Consul agents in the cluster.

Integration with Consul is done through a script named `proxysql-consul` that acts as a middleman between a ProxySQL instance and a Consul agent running on the same machine. Below is a description of the interaction between ProxySQL, proxysql-consul and Consul.

##### Copying configuration from a ProxySQL master instance to the other instances in the cluster 

When the ProxySQL master instance receives a command to save one of its runtime configurations to the cluster it calls proxysql-consul passing it the name of the configuration. proxysql-consul then connects to the ProxySQL instance through the admin interface and reads the content of the tables comprising the specified configuration. It puts that content into Consul's key/value store using keys prefixed wiht `proxysql/`.

Other Consul agents in the cluster are watching for changes to keys prefixed with `proxysql/`. When a watched key changes value Consul runs `proxyql-consul` as a handler which reads the data that has changed. `proxysql-consul` determines which tables need to be updated and then connects to the local ProxySQL instance through the admin interface and overwrites the tables in the memory database with the new content. It then loads the configuration to runtime.

`proxysql-consul` generates an unique identifier the first time it is run and stores it on disk to be read for subsequent runs. This id is used uniquely identify instances and to prevent applying configuration on the same machine that pushed it.

# How to configure it
#### Consul
To install Consul it's best to follow [Consul's own installation guide](https://www.consul.io/intro/getting-started/install.html). Read how to run the agent and how to configure agents for making a cluster.

For integration with ProxySQL a watch needs to be added to Consul's config file:
```json
{
  "watches": [
    {
      "type": "keyprefix",
      "prefix": "proxysql/",
      "handler": "proxysql-consul update"
    }
  ]
}
```
`proxysql-consul` is installed together with ProxySQL by default in `/usr/local/bin/` but any absolute path can be specified in the watch handler.

If you're running ProxySQL with `sudo` you'll also need to start the consul agent with `sudo`.

#### proxysql-consul
Running `sudo make install` to install ProxySQL also installs `proxysql-consul` in `/usr/local/bin` and puts a default `proxysql-consul.cnf` at `/etc/proxysql.cnf`.

`proxysql-consul` looks for its configuration file at `/etc/proxysql.cnf` which contains a JSON documnet. The default configuration looks like this:
```json
{
  "uuid_file": "/var/lib/proxysql/proxysql-consul.uuid",
  "consul_iface": "127.0.0.1",
  "consul_port": "8500",
  "proxysql_admin_iface": "127.0.0.1",
  "proxysql_admin_port": 6032,
  "proxysql_admin_username": "admin",
  "proxysql_admin_password": "admin"
}
```
Description of `proxysql-consul` configuration fields:
- `uuid_file` - path to file where to store unique id of instance "/var/lib/proxysql/proxysql-consul.uuid",
- `consul_iface` - address of local Consul HTTP interface
- `consul_port` - port of local Consul HTTP interface
- `proxysql_admin_iface` - address of local ProxySQL admin interface
- `proxysql_admin_port` - port of local ProxySQL admin interface
- `proxysql_admin_username` - username used to login to the ProxySQL admin interface
- `proxysql_admin_password` - password used to login to the ProxySQL admin interface

#Troubleshooting
`proxysql-consul` now writes log messages to its output. As it is being called by both ProxySQL and Consul its output goes to the caller's output.

If you get an error while running a `SAVE TO CLUSTER` command in the admin interface look for clues in ProxySQL's log at `/var/lib/proxysql/proxysql.log`.

You can check that configuration is properly stored in Consul by querying it's HTTP API:
```bash
curl http://127.0.0.1:8500/v1/kv/proxysql/?recurse
```
The data will be base64 encoded but you can decode it using the `base64` utilitary.

If all is fine on the master side but configs don't end up on the other ProxySQL servers have a look at Consul's output too.
