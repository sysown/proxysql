# SSL configuration for backends

ProxySQL supports SSL connections to the backends since version v1.2.0e . Attempts to configure an older
version will fail. **IMPORTANT NOTES:**

- **SSL is supported only for backends in v1.x. Clients cannot use SSL to connect to ProxySQL in versions
  prior to v2.x**
- **As of v1.4.5, because ProxySQL uses mariadb-connector-c-2.3.1 only SSL/TLSv1.0 is supported:
  [https://mariadb.com/kb/en/library/mariadb-connector-c-300-release-notes/](https://mariadb.com/kb/en/library/mariadb-connector-c-300-release-notes/).**
- **In ProxySQL v2.x the mariadb-connector-3.0.2 supports SSL/TLSv1.0,TLSv1.1, TLSv1.2 and TLSv1.3. This
  applies to frontend and backend connections**

<!-- -->

## Configuration:

This section uses the SSL
[global_variables](https://proxysql.com/global-variables/mysql-variables/) to exemplify how to
configure SSL connections for backends. Since ProxySQL `v2.6.0` there is also the possibility of configuring
this in a per MySQL backend basis, for more information about this please refer to [mysql_servers_ssl_params
doc](https://proxysql.com/main-runtime/#mysql_servers_ssl_params).

To enable SSL connections you need to:

- Update `mysql_servers`.`use_ssl` for the server you want to use SSL.
- Update associated global variables (only required in ProxySQL v1.x releases, not required for ProxySQL v2.x)

<!-- -->

If you want to connect to the same server with both SSL and non-SSL you need to configure the same server in
two different hostgroups, and define access rules. For example, to configure SSL on one server:

```sql
mysql> SELECT * FROM mysql_servers;
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
| hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
| 1            | 127.0.0.1 | 21891 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
| 2            | 127.0.0.1 | 21892 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
| 2            | 127.0.0.1 | 21893 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
3 rows in set (0.00 sec)

mysql> UPDATE mysql_servers SET use_ssl=1 WHERE port=21891;
Query OK, 1 row affected (0.00 sec)

mysql> SELECT * FROM mysql_servers;
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
| hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
| 1            | 127.0.0.1 | 21891 | ONLINE | 1      | 0           | 1000            | 0                   | 1       | 0              |
| 2            | 127.0.0.1 | 21892 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
| 2            | 127.0.0.1 | 21893 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
3 rows in set (0.00 sec)

mysql> LOAD MYSQL SERVERS TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)

mysql> SELECT * FROM runtime_mysql_servers;
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
| hostgroup_id | hostname  | port  | status | weight | compression | max_connections | max_replication_lag | use_ssl | max_latency_ms |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
| 1            | 127.0.0.1 | 21891 | ONLINE | 1      | 0           | 1000            | 0                   | 1       | 0              |
| 2            | 127.0.0.1 | 21892 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
| 2            | 127.0.0.1 | 21893 | ONLINE | 1      | 0           | 1000            | 0                   | 0       | 0              |
+--------------+-----------+-------+--------+--------+-------------+-----------------+---------------------+---------+----------------+
3 rows in set (0.00 sec)
```

At this stage:

- In ProxySQL v1.x, trying to connect to host 127.0.0.1 and port 21891 **will not** use SSL because no key and
  no certificate are configured. Instead, normal non-SSL connections will be established.
- In ProxySQL v2.x, if `use_ssl=1` then all new connections will use SSL (by means of MySQL's builtin
  key/certs).

<!-- -->

The next step to use SSL connections in ProxySQL 1.x is to configure key and certificate (this can also be
applied to ProxySQL v2.x in case you would like to use a specific key and certificate).

```sql
mysql> SELECT * FROM global_variables WHERE variable_name LIKE 'mysql-ssl%';
+-----------------------+----------------+
| variable_name         | variable_value |
+-----------------------+----------------+
| mysql-ssl_p2s_ca      |                |
| mysql-ssl_p2s_capath  |                |
| mysql-ssl_p2s_cert    |                |
| mysql-ssl_p2s_key     |                |
| mysql-ssl_p2s_cipher  |                |
| mysql-ssl_p2s_crl     |                |
| mysql-ssl_p2s_crlpath |                |
+-----------------------+----------------+
7 rows in set (0.00 sec)

mysql> SET mysql-ssl_p2s_cert="/home/vagrant/newcerts/client-cert.pem";
Query OK, 1 row affected (0.00 sec)

mysql> SET mysql-ssl_p2s_key="/home/vagrant/newcerts/client-key.pem";
Query OK, 1 row affected (0.00 sec)

mysql> SELECT * FROM global_variables WHERE variable_name LIKE 'mysql-ssl%';
+-----------------------+-----------------------------------------+
| variable_name         | variable_value                          |
+-----------------------+-----------------------------------------+
| mysql-ssl_p2s_ca      |                                         |
| mysql-ssl_p2s_capath  |                                         |
| mysql-ssl_p2s_cert    | /home/vagrant/newcerts/client-cert.pem  |
| mysql-ssl_p2s_key     | /home/vagrant/newcerts/client-key.pem   |
| mysql-ssl_p2s_cipher  |                                         |
| mysql-ssl_p2s_crl     |                                         |
| mysql-ssl_p2s_crlpath |                                         |
+-----------------------+-----------------------------------------+
7 rows in set (0.00 sec)

mysql> LOAD MYSQL VARIABLES TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

At this point, all **new connections** to host 127.0.0.1 and port 21891 will use SSL. If you are happy with
the new changes, you can make them persistent by saving the configuration on disk:

```sql
mysql> SAVE MYSQL SERVERS TO DISK;
Query OK, 0 rows affected (0.01 sec)

mysql> SAVE MYSQL VARIABLES TO DISK;
Query OK, 58 rows affected (0.00 sec)
```

To verify that SSL is working as expected between ProxySQL and MySQL, and to check the SSL CIPHER, connect to
ProxySQL and run `SHOW SESSION STATUS LIKE "Ssl_cipher"`, for example:

```sql
mysql -h127.0.0.1 -P6033 -uroot -psecret -e 'SHOW SESSION STATUS LIKE "Ssl_cipher"'
+---------------+----------------------+
| Variable_name | Value                |
+---------------+----------------------+
| Ssl_cipher    | ECDHE-RSA-AES256-SHA |
+---------------+----------------------+
```

## Extra configuration variables:

ProxySQL also offers the following extra SSL related global configuration variables for backend connections:

- `mysql-ssl_p2s_ca`
- `mysql-ssl_p2s_capath`
- `mysql-ssl_p2s_cipher`
- `mysql-ssl_p2s_crl`
- `mysql-ssl_p2s_crlpath`

<!-- -->

Which details can be check in
[mysql_variables](https://proxysql.com/global-variables/mysql-variables/) documentation section.

Since `v2.6.0` all the previously mentioned variables can be configured in a per MySQL backend server basis,
via the [mysql_servers_ssl_params](https://proxysql.com/main-runtime/#mysql_servers_ssl_params)
configuration table.

## Backend certificates renewal:

For renewing the certificates and keys used for backend connections, two approaches can be followed:

1\. Swapping the files pointed by the previously specified configuration variables with the new certificates.
**It's very important** that the swapping operation is performed in an atomic way, since ProxySQL will be
accessing this paths when creating new backend connections.

2\. Changing the previously specified variables to point to the new files locations and issuing a _'LOAD MYSQL
VARIABLES TO RUNTIME'_ command against the Admin interface. This operation is **guaranteed to be atomic**.

# SSL configuration for frontends

Available since `2.0`, SSL for frontend connections. It's **enabled** by default since version `v2.6.0`, it
was previously **disabled** by default.

Please take into account that having **SSL** enabled for frontend connections is not the same as **enforcing**
it. Enforcing SSL connections is supported in a per-user basis via `mysql_users.use_ssl` configuration option.
More information about `mysql_users` [here](https://proxysql.com/main-runtime/#mysql_users).

## Configuration:

To enable SSL for frontend connections, you need to enable `mysql-have_ssl=true`. Once this variable has been
enabled ProxySQL will generate the following files automatically in the datadir (`/var/lib/proxysql`):

```
proxysql-ca.pem
proxysql-cert.pem
proxysql-key.pem
```

NOTE: These files can be replaced with your own if you would like to use a predefined configuration. Also be
aware that only new connections will use SSL after the `mysql-have_ssl=true` variable is updated and
`LOAD MYSQL VARIABLES TO RUNTIME` is executed. To verify SSL is working and to check the SSL CIPHER between
your MySQL client and ProxySQL connect to ProxySQL and run `\s`, for example:

```
mysql -h127.0.0.1 -P6033 -uroot -psecret -e '\s' | grep -P 'SSL|Connection'
SSL: Cipher in use is DHE-RSA-AES256-SHA
Connection: 127.0.0.1 via TCP/IP
```

The supported protocols are:

```
TLSv1
TLSv1.1
TLSv1.2
TLSv1.3
```

`SSLv2` and `SSLv3` were removed in version `v2.0.6`. As for version `v2.6.2` support ciphers are:

```
+-------------------------------+---------------------------------------------------------------------------------------------------+
| cipher_name                   | cipher_description                                                                                |
+-------------------------------+---------------------------------------------------------------------------------------------------+
| TLS_AES_256_GCM_SHA384        | TLS_AES_256_GCM_SHA384         TLSv1.3 Kx=any      Au=any   Enc=AESGCM(256)            Mac=AEAD   |
| TLS_CHACHA20_POLY1305_SHA256  | TLS_CHACHA20_POLY1305_SHA256   TLSv1.3 Kx=any      Au=any   Enc=CHACHA20/POLY1305(256) Mac=AEAD   |
| TLS_AES_128_GCM_SHA256        | TLS_AES_128_GCM_SHA256         TLSv1.3 Kx=any      Au=any   Enc=AESGCM(128)            Mac=AEAD   |
| ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE-ECDSA-AES256-GCM-SHA384  TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(256)            Mac=AEAD   |
| ECDHE-RSA-AES256-GCM-SHA384   | ECDHE-RSA-AES256-GCM-SHA384    TLSv1.2 Kx=ECDH     Au=RSA   Enc=AESGCM(256)            Mac=AEAD   |
| DHE-RSA-AES256-GCM-SHA384     | DHE-RSA-AES256-GCM-SHA384      TLSv1.2 Kx=DH       Au=RSA   Enc=AESGCM(256)            Mac=AEAD   |
| ECDHE-ECDSA-CHACHA20-POLY1305 | ECDHE-ECDSA-CHACHA20-POLY1305  TLSv1.2 Kx=ECDH     Au=ECDSA Enc=CHACHA20/POLY1305(256) Mac=AEAD   |
| ECDHE-RSA-CHACHA20-POLY1305   | ECDHE-RSA-CHACHA20-POLY1305    TLSv1.2 Kx=ECDH     Au=RSA   Enc=CHACHA20/POLY1305(256) Mac=AEAD   |
| DHE-RSA-CHACHA20-POLY1305     | DHE-RSA-CHACHA20-POLY1305      TLSv1.2 Kx=DH       Au=RSA   Enc=CHACHA20/POLY1305(256) Mac=AEAD   |
| ECDHE-ECDSA-AES128-GCM-SHA256 | ECDHE-ECDSA-AES128-GCM-SHA256  TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(128)            Mac=AEAD   |
| ECDHE-RSA-AES128-GCM-SHA256   | ECDHE-RSA-AES128-GCM-SHA256    TLSv1.2 Kx=ECDH     Au=RSA   Enc=AESGCM(128)            Mac=AEAD   |
| DHE-RSA-AES128-GCM-SHA256     | DHE-RSA-AES128-GCM-SHA256      TLSv1.2 Kx=DH       Au=RSA   Enc=AESGCM(128)            Mac=AEAD   |
| ECDHE-ECDSA-AES256-SHA384     | ECDHE-ECDSA-AES256-SHA384      TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AES(256)               Mac=SHA384 |
| ECDHE-RSA-AES256-SHA384       | ECDHE-RSA-AES256-SHA384        TLSv1.2 Kx=ECDH     Au=RSA   Enc=AES(256)               Mac=SHA384 |
| DHE-RSA-AES256-SHA256         | DHE-RSA-AES256-SHA256          TLSv1.2 Kx=DH       Au=RSA   Enc=AES(256)               Mac=SHA256 |
| ECDHE-ECDSA-AES128-SHA256     | ECDHE-ECDSA-AES128-SHA256      TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AES(128)               Mac=SHA256 |
| ECDHE-RSA-AES128-SHA256       | ECDHE-RSA-AES128-SHA256        TLSv1.2 Kx=ECDH     Au=RSA   Enc=AES(128)               Mac=SHA256 |
| DHE-RSA-AES128-SHA256         | DHE-RSA-AES128-SHA256          TLSv1.2 Kx=DH       Au=RSA   Enc=AES(128)               Mac=SHA256 |
| ECDHE-ECDSA-AES256-SHA        | ECDHE-ECDSA-AES256-SHA         TLSv1   Kx=ECDH     Au=ECDSA Enc=AES(256)               Mac=SHA1   |
| ECDHE-RSA-AES256-SHA          | ECDHE-RSA-AES256-SHA           TLSv1   Kx=ECDH     Au=RSA   Enc=AES(256)               Mac=SHA1   |
| DHE-RSA-AES256-SHA            | DHE-RSA-AES256-SHA             SSLv3   Kx=DH       Au=RSA   Enc=AES(256)               Mac=SHA1   |
| ECDHE-ECDSA-AES128-SHA        | ECDHE-ECDSA-AES128-SHA         TLSv1   Kx=ECDH     Au=ECDSA Enc=AES(128)               Mac=SHA1   |
| ECDHE-RSA-AES128-SHA          | ECDHE-RSA-AES128-SHA           TLSv1   Kx=ECDH     Au=RSA   Enc=AES(128)               Mac=SHA1   |
| DHE-RSA-AES128-SHA            | DHE-RSA-AES128-SHA             SSLv3   Kx=DH       Au=RSA   Enc=AES(128)               Mac=SHA1   |
| RSA-PSK-AES256-GCM-SHA384     | RSA-PSK-AES256-GCM-SHA384      TLSv1.2 Kx=RSAPSK   Au=RSA   Enc=AESGCM(256)            Mac=AEAD   |
| DHE-PSK-AES256-GCM-SHA384     | DHE-PSK-AES256-GCM-SHA384      TLSv1.2 Kx=DHEPSK   Au=PSK   Enc=AESGCM(256)            Mac=AEAD   |
| RSA-PSK-CHACHA20-POLY1305     | RSA-PSK-CHACHA20-POLY1305      TLSv1.2 Kx=RSAPSK   Au=RSA   Enc=CHACHA20/POLY1305(256) Mac=AEAD   |
| DHE-PSK-CHACHA20-POLY1305     | DHE-PSK-CHACHA20-POLY1305      TLSv1.2 Kx=DHEPSK   Au=PSK   Enc=CHACHA20/POLY1305(256) Mac=AEAD   |
| ECDHE-PSK-CHACHA20-POLY1305   | ECDHE-PSK-CHACHA20-POLY1305    TLSv1.2 Kx=ECDHEPSK Au=PSK   Enc=CHACHA20/POLY1305(256) Mac=AEAD   |
| AES256-GCM-SHA384             | AES256-GCM-SHA384              TLSv1.2 Kx=RSA      Au=RSA   Enc=AESGCM(256)            Mac=AEAD   |
| PSK-AES256-GCM-SHA384         | PSK-AES256-GCM-SHA384          TLSv1.2 Kx=PSK      Au=PSK   Enc=AESGCM(256)            Mac=AEAD   |
| PSK-CHACHA20-POLY1305         | PSK-CHACHA20-POLY1305          TLSv1.2 Kx=PSK      Au=PSK   Enc=CHACHA20/POLY1305(256) Mac=AEAD   |
| RSA-PSK-AES128-GCM-SHA256     | RSA-PSK-AES128-GCM-SHA256      TLSv1.2 Kx=RSAPSK   Au=RSA   Enc=AESGCM(128)            Mac=AEAD   |
| DHE-PSK-AES128-GCM-SHA256     | DHE-PSK-AES128-GCM-SHA256      TLSv1.2 Kx=DHEPSK   Au=PSK   Enc=AESGCM(128)            Mac=AEAD   |
| AES128-GCM-SHA256             | AES128-GCM-SHA256              TLSv1.2 Kx=RSA      Au=RSA   Enc=AESGCM(128)            Mac=AEAD   |
| PSK-AES128-GCM-SHA256         | PSK-AES128-GCM-SHA256          TLSv1.2 Kx=PSK      Au=PSK   Enc=AESGCM(128)            Mac=AEAD   |
| AES256-SHA256                 | AES256-SHA256                  TLSv1.2 Kx=RSA      Au=RSA   Enc=AES(256)               Mac=SHA256 |
| AES128-SHA256                 | AES128-SHA256                  TLSv1.2 Kx=RSA      Au=RSA   Enc=AES(128)               Mac=SHA256 |
| ECDHE-PSK-AES256-CBC-SHA384   | ECDHE-PSK-AES256-CBC-SHA384    TLSv1   Kx=ECDHEPSK Au=PSK   Enc=AES(256)               Mac=SHA384 |
| ECDHE-PSK-AES256-CBC-SHA      | ECDHE-PSK-AES256-CBC-SHA       TLSv1   Kx=ECDHEPSK Au=PSK   Enc=AES(256)               Mac=SHA1   |
| SRP-RSA-AES-256-CBC-SHA       | SRP-RSA-AES-256-CBC-SHA        SSLv3   Kx=SRP      Au=RSA   Enc=AES(256)               Mac=SHA1   |
| SRP-AES-256-CBC-SHA           | SRP-AES-256-CBC-SHA            SSLv3   Kx=SRP      Au=SRP   Enc=AES(256)               Mac=SHA1   |
| RSA-PSK-AES256-CBC-SHA384     | RSA-PSK-AES256-CBC-SHA384      TLSv1   Kx=RSAPSK   Au=RSA   Enc=AES(256)               Mac=SHA384 |
| DHE-PSK-AES256-CBC-SHA384     | DHE-PSK-AES256-CBC-SHA384      TLSv1   Kx=DHEPSK   Au=PSK   Enc=AES(256)               Mac=SHA384 |
| RSA-PSK-AES256-CBC-SHA        | RSA-PSK-AES256-CBC-SHA         SSLv3   Kx=RSAPSK   Au=RSA   Enc=AES(256)               Mac=SHA1   |
| DHE-PSK-AES256-CBC-SHA        | DHE-PSK-AES256-CBC-SHA         SSLv3   Kx=DHEPSK   Au=PSK   Enc=AES(256)               Mac=SHA1   |
| AES256-SHA                    | AES256-SHA                     SSLv3   Kx=RSA      Au=RSA   Enc=AES(256)               Mac=SHA1   |
| PSK-AES256-CBC-SHA384         | PSK-AES256-CBC-SHA384          TLSv1   Kx=PSK      Au=PSK   Enc=AES(256)               Mac=SHA384 |
| PSK-AES256-CBC-SHA            | PSK-AES256-CBC-SHA             SSLv3   Kx=PSK      Au=PSK   Enc=AES(256)               Mac=SHA1   |
| ECDHE-PSK-AES128-CBC-SHA256   | ECDHE-PSK-AES128-CBC-SHA256    TLSv1   Kx=ECDHEPSK Au=PSK   Enc=AES(128)               Mac=SHA256 |
| ECDHE-PSK-AES128-CBC-SHA      | ECDHE-PSK-AES128-CBC-SHA       TLSv1   Kx=ECDHEPSK Au=PSK   Enc=AES(128)               Mac=SHA1   |
| SRP-RSA-AES-128-CBC-SHA       | SRP-RSA-AES-128-CBC-SHA        SSLv3   Kx=SRP      Au=RSA   Enc=AES(128)               Mac=SHA1   |
| SRP-AES-128-CBC-SHA           | SRP-AES-128-CBC-SHA            SSLv3   Kx=SRP      Au=SRP   Enc=AES(128)               Mac=SHA1   |
| RSA-PSK-AES128-CBC-SHA256     | RSA-PSK-AES128-CBC-SHA256      TLSv1   Kx=RSAPSK   Au=RSA   Enc=AES(128)               Mac=SHA256 |
| DHE-PSK-AES128-CBC-SHA256     | DHE-PSK-AES128-CBC-SHA256      TLSv1   Kx=DHEPSK   Au=PSK   Enc=AES(128)               Mac=SHA256 |
| RSA-PSK-AES128-CBC-SHA        | RSA-PSK-AES128-CBC-SHA         SSLv3   Kx=RSAPSK   Au=RSA   Enc=AES(128)               Mac=SHA1   |
| DHE-PSK-AES128-CBC-SHA        | DHE-PSK-AES128-CBC-SHA         SSLv3   Kx=DHEPSK   Au=PSK   Enc=AES(128)               Mac=SHA1   |
| AES128-SHA                    | AES128-SHA                     SSLv3   Kx=RSA      Au=RSA   Enc=AES(128)               Mac=SHA1   |
| PSK-AES128-CBC-SHA256         | PSK-AES128-CBC-SHA256          TLSv1   Kx=PSK      Au=PSK   Enc=AES(128)               Mac=SHA256 |
| PSK-AES128-CBC-SHA            | PSK-AES128-CBC-SHA             SSLv3   Kx=PSK      Au=PSK   Enc=AES(128)               Mac=SHA1   |
+-------------------------------+---------------------------------------------------------------------------------------------------+
60 rows in set (0.00 sec)
```

## Frontend certificates renewal:

Since `v2.3.0` frontend certificates can be renewed dynamically through the Admin variable command: '_PROXYSQL
RELOAD TLS_'.

The correct way of making use of this command for replacing current certificates being used for **client**
connections is:

1. Make sure SSL is enabled for client connections, if not, set _mysql-have_ssl=true_ and then issue command:
   _LOAD MYSQL VARIABLES TO RUNTIME_.
2. Replace the previously mentioned certificates files, with the new certificates files:

   - `${DATADIR_PATH}/proxysql-ca.pem`
   - `${DATADIR_PATH}/proxysql-cert.pem`
   - `${DATADIR_PATH}/proxysql-key.pem`

   <!-- -->

3. Issue the new command: _PROXYSQL RELOAD TLS_.

<!-- -->

If all the operations were successful, to verify this, it's important to remember to check **_ProxySQL error
log_** for errors, the new certificates would be loaded, and will be used for all the **_new incoming
connections_**.
