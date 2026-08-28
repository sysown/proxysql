

### Compiling

To run AWS Aurora automated testing, ProxySQL needs to be compiled with `make testaurora`.


### Prepare /etc/hosts

Add the following in `/etc/hosts` to simulate 30 IPs that proxysql will use to emulate 3 clusters:
```
127.0.1.11      host.1.11.aws-test.com
127.0.1.12      host.1.12.aws-test.com
127.0.1.13      host.1.13.aws-test.com
127.0.1.14      host.1.14.aws-test.com
127.0.1.15      host.1.15.aws-test.com
127.0.1.16      host.1.16.aws-test.com
127.0.1.17      host.1.17.aws-test.com
127.0.1.18      host.1.18.aws-test.com
127.0.1.19      host.1.19.aws-test.com
127.0.1.20      host.1.20.aws-test.com

127.0.2.11      host.2.11.cluster2.aws.test
127.0.2.12      host.2.12.cluster2.aws.test
127.0.2.13      host.2.13.cluster2.aws.test
127.0.2.14      host.2.14.cluster2.aws.test
127.0.2.15      host.2.15.cluster2.aws.test
127.0.2.16      host.2.16.cluster2.aws.test
127.0.2.17      host.2.17.cluster2.aws.test
127.0.2.18      host.2.18.cluster2.aws.test
127.0.2.19      host.2.19.cluster2.aws.test
127.0.2.20      host.2.20.cluster2.aws.test

127.0.3.11      host.3.11.aws.3.test.com
127.0.3.12      host.3.12.aws.3.test.com
127.0.3.13      host.3.13.aws.3.test.com
127.0.3.14      host.3.14.aws.3.test.com
127.0.3.15      host.3.15.aws.3.test.com
127.0.3.16      host.3.16.aws.3.test.com
127.0.3.17      host.3.17.aws.3.test.com
127.0.3.18      host.3.18.aws.3.test.com
127.0.3.19      host.3.19.aws.3.test.com
127.0.3.20      host.3.20.aws.3.test.com
```

### shutdown mysqld

When running automated testing, ProxySQL will listen on many IPs (30) an on port 3306.  
You need to make sure that MySQL server is not running, or not listening on port 3306.


### Running proxysql

`proxysql` needs to be executed with `--sqlite3-server` .  
For example, to run it under `gdb`: `run -f -D . --sqlite3-server`


