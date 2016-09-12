# MySQL Passwords in ProxySQL

ProxySQL is a protocol aware proxy.  
Because ProxySQL performs routing based on traffic, when a client connects it cannot yet identify a destination HG, therefore ProxySQL needs to authenticate the client.  
For this reason, ProxySQL needs to have some information related to the password of the user: enough information to allow the authentication.

ProxySQL also needs these information to later establish connections to backends, or issue `CHANGE_USER` within already established connections.

The 3 layers configuration architecture applies also for users information.  
ProxySQL stores users information in table `mysql_users`:
* an object `MySQL_Authentication()` is responsible to store these information at runtime;
* `main`.`mysql_users` is the in-memory database;
* `runtime`.`mysql_users` is the on-disk database.

In `mysql_users` tables, both in-memory and on-disk, the credentials are stored in columns `username` and `password`.

## Password formats

Password can be stored in 2 formats in `mysql_users`.`password` , no matter if in-memory or on-disk:
* plain text
* hashed password

Passwords in plain text are simple as that, very easy to read. If database and config file are kept in a safe location the security concern is limited, yet present.
Hashed passwords have the same format of the passwords in MySQL server, as stored into column `mysql`.`user`.`password`.

ProxySQL considers a password starting with `*` has a hashed password.

### Hashed passwords and authentication

In MySQL and in ProxySQL, a hashed password is `SHA1(SHA1('clear_password'))` .  
From a hashed password is not possible to derive a plain text password.  
When a client connects to ProxySQL, this is able to authenticate it using the hashed password.  
During the first client authentication, ProxySQL can derive a partially hashed password: `SHA1('clear_password')` . This information is internally stored at runtime and allows ProxySQL to connect to backends.


### How to input new passwords

The Admin interface of ProxySQL does not have any  `PASSWORD()` function. That means that:
* passwords are stored in the format they are inserted, either in plain text or hashed
* while inputting password in the Admin interface, it is not possible to derive an hashed password from a plain text password (yet you can run `SELECT PASSWORD('password')` in MySQL server and copy paste the result)


### Variable `admin-hash_passwords`

To facilitate the support of hashed passwords, ProxySQL v1.2.3 introduced a new global boolean variable, `admin-hash_password`, enabled by default.  
When `admin-hash_password=true` , password are automatically _at_RUNTIME_only_ hashed when running `LOAD MYSQL USERS TO RUNTIME` .
Passwords in `mysql_users` are yet *not* automatically hashed.  
Nonetheless, it is easily possible to hash the password in `mysql_users` table, both in-memory and on-disk. It is enough to copy users from RUNTIME, for example running `SAVE MYSQL USERS FROM RUNTIME` after `LOAD MYSQL USERS TO RUNTIME`, and then `SAVE MYSQL USERS TO DISK` (recommended).

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

At this stage, passwords are hashed at runtime, but still not hashed on `mysql_users`. To hash them also on `mysql_users` :

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


**Note**: `admin-hash_passwords` is an `admin-` variable, not a `mysql-` variable. This because it affects the behaviour of Admin.  
This details is important because to apply changes in `admin-hash_passwords` you need to run `LOAD ADMIN VARIABLES TO RUNTIME` and **not** `LOAD MYSQL VARIABLES TO RUNTIME`
