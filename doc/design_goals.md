Design Goals
============

ProxySQL has been built with a few key design choices in mind.

# Maximal uptime

Since ProxySQL is a proxy, it's expected to be up there as close to 100% of
the time as possible. This means that we should be handling differently the
usual suspects when it comes to downtime:
* __configuration changes__. This is usually done by changing the configuration
file and restarting the daemon. In ProxySQL, by design, the user is able to
modify most configuration variables through the admin interface, without
having to restart the server. Example things that can be modified at runtime:
  * interfaces on which ProxySQL is listening
  * backend servers to which ProxySQL is connecting
  * timeouts for the different operations performed by ProxySQL
* __crashes__. ProxySQL has an extensive suite of integration tests that are
ran using Docker, to ensure that it does not crash. Also, each major release
is performance-tested using sysbench, and memory-leak tested using valgrind.
In addition to this, an angel process has been implemented that monitors and
restarts ProxySQL when needed, in order to keep downtimes to a minimum, if they
end up occuring.

# Maximal scalability

There are several key scenarios that we wanted to run as fast as possible when
interacting with ProxySQL:
* time to complete a new MySQL connection to it: this is why ProxySQL has a
pool of threads all waiting via the system call `accept()` to receive a new
connection. Because of this, the probability of the new TCP connection of being
established faster is increased
* time to connect to a MySQL backend: this is why ProxySQL has a backend
connection pool in which it keeps some idle connections alive to the backend
servers, according to the configuration. When it needs to send a packet to
those servers, most of the time the connection is already open
* multi-core scalability: ProxySQL has a multi-threaded design where all threads
do the same thing (marshal messages back and forth between the backend servers
and the MySQL client connections), and our tests show that it scales very well
with the number of cores. 

# Cascade possibilities

ProxySQL can be cascaded to as many layers as required. For example, one common
scenario is to have a ProxySQL instance as close to the servers running the
application as possible, pointing to another middle layer cluster of ProxySQL
servers that routes all traffic to a farm of backend MySQL servers.

A -> P1 -----> {P2, P3, P4 ..} ------> {B1, B2, B3, ..}

The advantage in this case is that it is completely fault tolerant with respect
to the MySQL access, given that the app is not a single point of failure. There
is no modification needed at the application level for the application to
connect to a cluster of proxies instead of a single one. If any proxy from the
middle layer fails, the P1 proxy will detect that and will route traffic through
the other ones. If any of the backends B1, B2, B3, ... fails, then the middle
layer proxies will take care of the job in a way that is transparent to P1.