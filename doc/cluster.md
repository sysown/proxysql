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

# How to configure it
+ install Consul
+ configure Consul
+ running Consul
+ install proxysql-consul
+ configure proxysql-consul

#Troubleshooting
+ where to look for proxysql-consul output
