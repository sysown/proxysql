# MySQL Passwords in ProxySQL

ProxySQL is a protocol aware proxy.

Because ProxySQL performs routing based on traffic, when a client connects it cannot yet identify a
destination HG, therefore ProxySQL needs to authenticate the client.

For this reason, it needs to have some information related to the password of the user: enough information to
allow the authentication.

ProxySQL also needs these information to later establish connections to backends, or issue `CHANGE_USER`
within already established connections.

The 3 layers configuration architecture applies also for users information.

ProxySQL stores users information in table `mysql_users`:

- An object `MySQL_Authentication()` is responsible to store these information at runtime.
- `main`.`mysql_users` is the in-memory database.
- `disk`.`mysql_users` is the on-disk database.

<!-- -->

In `mysql_users` tables, both in-memory and on-disk, the credentials are stored in columns `username` and
`password`. Since [dual-passwords][5] support was introduced in ProxySQL `3.0`, an additional password can be
stored for the user in the `attributes` field. See [dual-passwords][5].

## Password formats

Password can be stored in 2 formats in `mysql_users`.`password` , no matter if in-memory or on-disk:

- Plain text
- Hashed password

<!-- -->

Passwords in plain text are simple as that, very easy to read. If database and config file are kept in a safe
location the security concern is limited, yet present.

Hashed passwords have the same format of the passwords in MySQL server, as stored into column
`authentication_string` from [mysql.user][3].

ProxySQL considers a password starting with `*` has a hashed `mysql_native_password` password. Detection based
only on this hash characteristic is a current limitation that will be improved.

## Dual-Passwords

Since ProxySQL `3.0` dual-password support was introduced. Additional user passwords are stored in the
`attributes` column in the `mysql_users` table, using the field `additional_password` inside the JSON. The
password value, **hashed or not**, should **always** be in `HEX` format. For an example go to
[How-to-input-passwords][6].

This feature is analogous to MySQL [dual-passwords][7]. It simplifies credentials management, allowing for
easier migrations during password rotations scenarios. Thanks to it, password migrations can be done in
stages, waiting for the password change to propage to all services before performing an invalidation of the
current password.

Thanks to ProxySQL stats, it's also possible to ensure that no users are using one or other passwords prior to
invalidation. As most metrics, these are also available through the [Prometheus exporter][8]:

```
admin> SELECT * FROM stats.stats_mysql_global WHERE variable_name LIKE 'Client%Connected%';
+----------------------------------------+----------------+
| Variable_Name                          | Variable_Value |
+----------------------------------------+----------------+
| Client_Connections_connected           | 0              |
| Client_Connections_connected_prim_pass | 0              |
| Client_Connections_connected_addl_pass | 0              |
+----------------------------------------+----------------+
3 rows in set (0.00 sec)
```

## Hashed passwords and Authentication

### mysql_native_password

In MySQL and in ProxySQL, a hashed password is `SHA1(SHA1('clear_password'))`:

- From a hashed password is not possible to derive a plain text password.
- When a client connects to ProxySQL, is able to authenticate it using the hashed password.

During the first client authentication, ProxySQL can derive a partially hashed password:
`SHA1('clear_password')`. This information is internally stored at runtime and allows ProxySQL to connect to
backends.

### caching_sha2_password

Supported since version `2.6.0`, as with `mysql_native_password`, passwords can be stored either hashed or
clear text. When dealing with hashed passwords, the only configuration requirement is allowing an SSL
connection to be created between ProxySQL and the client. This is achieved either by:

- Setting variable [mysql-have_ssl][1] to `true` (default value since `2.6.0`).
- Setting variable [mysql-default_authentication_plugin][2] to `caching_sha2_password`. This will override
  `mysql-have_ssl`, enabling SSL in frontend connections.

This ensures that ProxySQL is providing the required environment for creating the secure channel required by
`caching_sha2_password`, the reason for this requirement is explained in
[mysql-default_authentication_plugin][2] documentation.

For logging using command line `MySQL` clients, no extra flags should be required when working with clients
newer than `8.0`. But for previous versions, and other clients, some extra options may be required. This is
covered in the [following documentation section][4] for `MySQL` and `MariaDB` clients. For more details please
refer to you client official documentation.

## How to input passwords

When adding user passwords to the `mysql.users` table, no transformation is performed on the passwords being
provided. This means that they are stored in the format they are inserted, either in plain text or hashed.

### Insert hashed passwords (post v2.6.2)

Prior to version `v2.6.2` passwords were required to be imported using the methods described below.

In `v2.6.2` two new `SQLite3` functions were introduced for simplifying password management,
`MYSQL_NATIVE_PASSWORD()` and `CACHING_SHA2_PASSWORD()`. These functions are accessible from the `Admin`
interface; both receive the clear text password, and return a `MySQL` compatible hash of the supplied
password. Both can be used to directly insert **hashed passwords** into `ProxySQL` without any dependency:

```
admin> INSERT INTO mysql_users (username, password) VALUES ('example_user', CACHING_SHA2_PASSWORD('example_pass'));
Query OK, 1 row affected (0.00 sec)

admin> SELECT username,password FROM mysql_users WHERE username='example_user';
+--------------+------------------------------------------------------------------------+
| username     | password                                                               |
+--------------+------------------------------------------------------------------------+
| example_user | $A$005$!w3,h?`Cs*5"3pOAVM8mqFGjk2MY1d/PMZavYyOEL6YIpZLjYictnuXMTc/ |
+--------------+------------------------------------------------------------------------+
1 row in set (0.00 sec)

admin> SELECT username,HEX(password) FROM mysql_users WHERE username='example_user';
+--------------+----------------------------------------------------------------------------------------------------------------------------------------------+
| username     | HEX(password)                                                                                                                                |
+--------------+----------------------------------------------------------------------------------------------------------------------------------------------+
| example_user | 244124303035242177332C683F6043732A5F0F0835220E33704F41564D386D7146476A6B324D5931642F504D5A617659794F454C365949705A4C6A596963746E75584D54632F |
+--------------+----------------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.00 sec)
```

Check the next sections for more details.

#### `MYSQL_NATIVE_PASSWORD()` function

Expects one argument, the desired user password and returns it's hashed version, using the `SHA1` of the
`SHA1` as MySQL:

```
admin> SELECT MYSQL_NATIVE_PASSWORD('example_pass');
+-------------------------------------------+
| MYSQL_NATIVE_PASSWORD('example_pass')     |
+-------------------------------------------+
| *520BA5BE3924F1A0DB9941C4EA0911B19CBDE1A3 |
+-------------------------------------------+
1 row in set (0.00 sec)
```

#### `CACHING_SHA2_PASSWORD()` function

Expects either one, or two arguments. The first argument is the password to hash nd the second, and _optional
one_, is the salt use for the hash generation. If no second argument is rovided, the password will be
generated using a randomly generated salt. Use with one argument:

```
admin> SELECT CACHING_SHA2_PASSWORD('example_pass');
+------------------------------------------------------------------------+
| CACHING_SHA2_PASSWORD('example_pass')                                  |
+------------------------------------------------------------------------+
| $A$005$Lpnj_Ps)C4q2hg;%       EISfOW43XEg7z7e3VScxZg6Qn1/WGKo8sT.k4Tb9mB1 |
+------------------------------------------------------------------------+
1 row in set (0.02 sec)

admin> SELECT HEX(CACHING_SHA2_PASSWORD('example_pass'));
+----------------------------------------------------------------------------------------------------------------------------------------------+
| HEX(CACHING_SHA2_PASSWORD('example_pass'))                                                                                                   |
+----------------------------------------------------------------------------------------------------------------------------------------------+
| 244124303035244B337D2B184A464C50195B2377463F790A193B4D4B307566385637646A5457692E646B6C765768734A5145765863555939684732566A624E6D464E4C317838 |
+----------------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.02 sec)
```

The resulting hash should always be copied using the `HEX` format, otherwise characters could be escaped,
because it could contain characters that are not representable, see [Import caching_sha2_passwords][5]. Using
the second parameter, a salt can be provided, this can be used to replicate `MySQL` generated hash, without
having the complete password hash, only the used salt. In `MySQL`:

```
mysql> CREATE USER 'example_user'@'%' IDENTIFIED WITH 'caching_sha2_password' BY 'example_pass';
Query OK, 0 rows affected (0.00 sec)

mysql> SELECT user, HEX(authentication_string), HEX(SUBSTR(authentication_string, 8, 20)) AS salt FROM mysql.user WHERE user='example_user';
+--------------+----------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------+
| user         | HEX(authentication_string)                                                                                                                   | salt                                     |
+--------------+----------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------+
| example_user | 24412430303524156B250133593C08146133655714470A700D203D7A646833593169655241513430396C3833464B7764377661755138586563446F4A63466454676367747737 | 156B250133593C08146133655714470A700D203D |
+--------------+----------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------+
1 row in set (0.00 sec)
```

Now on `ProxySQL Admin`:

```
admin> SELECT HEX(CACHING_SHA2_PASSWORD('example_pass', UNHEX('156B250133593C08146133655714470A700D203D')));
+----------------------------------------------------------------------------------------------------------------------------------------------+
| HEX(CACHING_SHA2_PASSWORD('example_pass', UNHEX('156B250133593C08146133655714470A700D203D')))                                                |
+----------------------------------------------------------------------------------------------------------------------------------------------+
| 24412430303524156B250133593C08146133655714470A700D203D7A646833593169655241513430396C3833464B7764377661755138586563446F4A63466454676367747737 |
+----------------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.02 sec)
```

### Import mysql_native_passwords

When dealing with older MySQL versions (`< 8.0`) and `mysql_native_password`, we need to take into account
that the Admin interface doesn't have any `PASSWORD()` function (deprecated in MySQL after `8.0`). So, while
inputting a password in the Admin interface, it is not possible to derive a hashed password from a plain text
password, yet, you can run `SELECT PASSWORD('password')` in MySQL server and copy paste the result.

After MySQL `5.7` the `PASSWORD` function is now deprecated. So, when importing MySQL users to ProxySQL, it's
best to refer to `authentication_string` column from [mysql.user][3] table for fetching the hashed passwords.

### Import caching_sha2_passwords

The password for a user can be stored as 'clear-text' or hashed, when storing the password in 'clear-text',
updating the value in `mysql_users.password` for the target user should be enough. When dealing with hashed
passwords, it's possible that the hash contains characters which are not representable, this could lead to
inserting an incomplete password hash while copying it. Because of this, the following procedure is
recommended for importing these passwords hashes from MySQL to ProxySQL:

1. Extract the desired user password from MySQL using the following query:
   ```
   SELECT HEX(authentication_string) FROM mysql.user WHERE user='$USERNAME';
   ```
2. Update the `mysql_user` with the retrieved password:
   ```
   UPDATE mysql_users SET password=UNHEX('$HEX_PASSWORD') WHERE username='$USERNAME';
   ```

Using the `HEX` representation ensures that no invalid characters are being escaped. ProxySQL detection of a
`caching_sha2_password` is based on the hash start (`$A$0`) and it's length (`70`), using this determines
whether the stored password is a 'clear-text' or a hashed `caching_sha2_password`. A user can double-check
this information using the `Admin` interface:

```
SELECT SUBSTR(password,0,5) AS pass_start, LENGTH(password) AS pass_length FROM mysql_users WHERE username='$USERNAME';
```

The following is the expected output for the previous query for a correctly imported password from MySQL:

```
+------------+-------------+
| pass_start | pass_length |
+------------+-------------+
| $A$0       | 70          |
+------------+-------------+
1 row in set (0.00 sec)
```

### Insert/Import dual-passwords

When dealing with additional passwords, we require to input it as a field in the `JSON` field `attributes`
from `mysql_users`. We also have the requisite that the password should always be in `HEX` format, no matter
if the original password was hashed or not. Gladly, the `Admin` interface and the underlying `SQLite3`
interface packs the utilities to perform this operation in a simple way.

Let's first create a user with `dual-passwords` using the previously described utilities:

```
admin> INSERT INTO mysql_users (username, password, attributes) VALUES ('example_user', CACHING_SHA2_PASSWORD('example_pass2'), json_object('additional_password', HEX(CACHING_SHA2_PASSWORD('example_pass'))));
Query OK, 1 row affected (0.02 sec)

admin> LOAD MYSQL USERS TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

With only the two previous commands we already have a working dual-password setup with hashed passwords:

```
$ mysqladmin ping -uexample_user -pexample_pass -P6033 --protocol=TCP
mysqladmin: [Warning] Using a password on the command line interface can be insecure.
mysqld is alive
$ mysqladmin ping -uexample_user -pexample_pass2 -P6033 --protocol=TCP
mysqladmin: [Warning] Using a password on the command line interface can be insecure.
mysqld is alive
```

As a final example, let's simulate a password rotation for a `MySQL` user and import the resulting
dual-password setup. First, let's create the user and import it to ProxySQL:

`MySQL`:

```
mysql> CREATE USER 'example_user'@'%' IDENTIFIED WITH 'caching_sha2_password' BY 'example_pass';
Query OK, 0 rows affected (0.01 sec)

mysql> SELECT user, HEX(authentication_string), HEX(SUBSTR(authentication_string, 8, 20)) AS salt FROM mysql.user WHERE user='example_user';
+--------------+----------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------+
| user         | HEX(authentication_string)                                                                                                                   | salt                                     |
+--------------+----------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------+
| example_user | 2441243030352454426A295F353E1C77212A372F5A02271612163E31485031626F447A625350627A6658776F714550393078434F555143546F377457426F3131333648747143 | 0E1A500B67372316664E65310D697225604C0F17 |
+--------------+----------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------+
1 row in set (0.00 sec)

```

`ProxySQL`:

```
admin> INSERT INTO mysql_users (username, password) VALUES ('example_user', UNHEX('2441243030352454426A295F353E1C77212A372F5A02271612163E31485031626F447A625350627A6658776F714550393078434F555143546F377457426F3131333648747143'));
Query OK, 1 row affected (0.00 sec)

admin> LOAD MYSQL USERS TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

After this, we can already log into ProxySQL with our primary password:

```
$ mysqladmin ping -uexample_user -pexample_pass -P6033 --protocol=TCP
mysqladmin: [Warning] Using a password on the command line interface can be insecure.
mysqld is alive
```

When we are required to perform the password rotation, first we are going to perform the changes in MySQL, and
later we are going to import the updated dual-password setup into ProxySQL:

`MySQL`:

```
mysql> ALTER USER 'example_user'@'%' IDENTIFIED BY 'example_pass2' RETAIN CURRENT PASSWORD;
Query OK, 0 rows affected (0.02 sec)

mysql> SELECT user, HEX(authentication_string), HEX(SUBSTR(authentication_string, 8, 20)) AS salt, HEX(json_unquote(json_extract(user_attributes,'$.additional_password'))) AS additional_password FROM mysql.user WHERE user='example_user';
+--------------+----------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------+
| user         | HEX(authentication_string)                                                                                                                   | salt                                     | additional_password                                                                                                                          |
+--------------+----------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------+
| example_user | 244124303035240E1A500B67372316664E65310D697225604C0F176941684C646853342E5369502F34466F5049675A42734D6874553266566173726736677442446869675A31 | 0E1A500B67372316664E65310D697225604C0F17 | 2441243030352454426A295F353E1C77212A372F5A02271612163E31485031626F447A625350627A6658776F714550393078434F555143546F377457426F3131333648747143 |
+--------------+----------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.00 sec)
```

`ProxySQL`:

```
admin> INSERT INTO mysql_users (username, password, attributes) VALUES ('example_user', UNHEX('244124303035240E1A500B67372316664E65310D697225604C0F176941684C646853342E5369502F34466F5049675A42734D6874553266566173726736677442446869675A31'), json_object('additional_password', '2441243030352454426A295F353E1C77212A372F5A02271612163E31485031626F447A625350627A6658776F714550393078434F555143546F377457426F3131333648747143'));
Query OK, 1 row affected (0.00 sec)

admin> LOAD MYSQL USERS TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)
```

We have successfully imported our dual-password setup, and we can access to ProxySQL using both passwords:

```
$ mysqladmin ping -uexample_user -pexample_pass2 -P6033 --protocol=TCP
mysqladmin: [Warning] Using a password on the command line interface can be insecure.
mysqld is alive
$ mysqladmin ping -uexample_user -pexample_pass -P6033 --protocol=TCP
mysqladmin: [Warning] Using a password on the command line interface can be insecure.
mysqld is alive
```

<!-- -->

## Variable `admin-hash_passwords` (deprecated)

**UPDATE-DEPRECATED**: Since version `2.6.0` this variable has been deprecated, a user is now expected to
provide the password in it's final form (either clear-text or hashed) directly into `mysql_users.password`.
This simplifies password handling when dealing with different users, whose passwords are stored hashed for
different authentication methods.

To facilitate the support of hashed passwords, ProxySQL v1.2.3 introduced a new global boolean variable,
`admin-hash_passwords`, enabled by default.

When `admin-hash_passwords=true`, password are automatically hashed _at RUNTIME only_ when running
`LOAD MYSQL USERS TO RUNTIME`.

Passwords in `mysql_users` tables are yet _not_ automatically hashed.

Nonetheless, it is easily possible to hash the passwords in `mysql_users` table, both in-memory and on-disk.
It is enough to copy users _from RUNTIME_, for example running `SAVE MYSQL USERS FROM RUNTIME` after
`LOAD MYSQL USERS TO RUNTIME`, and then `SAVE MYSQL USERS TO DISK` (recommended).

Here an example:

```sql
Admin> SELECT * FROM mysql_users;
Empty set (0.00 sec)

Admin> INSERT INTO mysql_users(username,password) VALUES ('user1','password1'), ('user2','password2');
Query OK, 2 rows affected (0.00 sec)

Admin> SELECT username,password FROM mysql_users;
+----------+-----------+
| username | password  |
+----------+-----------+
| user1    | password1 |
| user2    | password2 |
+----------+-----------+
2 rows in set (0.00 sec)

Admin> LOAD MYSQL USERS TO RUNTIME;
Query OK, 0 rows affected (0.00 sec)

Admin> SELECT username,password FROM mysql_users;
+----------+-----------+
| username | password  |
+----------+-----------+
| user1    | password1 |
| user2    | password2 |
+----------+-----------+
2 rows in set (0.00 sec)
```

At this stage, passwords are hashed at runtime, but still not hashed on `mysql_users`. To hash them also on
`mysql_users` :

```sql
Admin> SAVE MYSQL USERS FROM RUNTIME;
Query OK, 0 rows affected (0.00 sec)

Admin> SELECT username,password FROM mysql_users;
+----------+-------------------------------------------+
| username | password                                  |
+----------+-------------------------------------------+
| user1    | *668425423DB5193AF921380129F465A6425216D0 |
| user2    | *DC52755F3C09F5923046BD42AFA76BD1D80DF2E9 |
+----------+-------------------------------------------+
2 rows in set (0.00 sec)
```

The hashed password can now be saved to disk running `SAVE MYSQL USERS TO DISK` .

**Note**: `admin-hash_passwords` is an `admin-` variable, not a `mysql-` variable. This because it affects the
behaviour of Admin.

These details are important because to apply changes in `admin-hash_passwords` you need to run
`LOAD ADMIN VARIABLES TO RUNTIME` and **not** `LOAD MYSQL VARIABLES TO RUNTIME`

[1]: /documentation/global-variables/mysql-variables/#mysql-have_ssl
[2]: /documentation/global-variables/mysql-variables/#mysql-default_authentication_plugin
[3]: https://dev.mysql.com/doc/refman/8.0/en/grant-tables.html
[4]: https://proxysql.com/documentation/authentication-methods/#login-with-different-mysql-clients
[5]: #import-caching_sha2_passwords
[5]: #dual-passwords
[6]: #how-to-input-passwords
[7]: https://dev.mysql.com/doc/refman/8.4/en/password-management.html#dual-passwords
[8]: https://proxysql.com/documentation/prometheus-exporter/
