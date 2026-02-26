# Global Variables

- [Admin Variable Reference][1]
- [General MySQL Variable Reference][2]
- [MySQL Monitor Variable Reference][3]
- [PgSQL Monitor Variable Reference][4]

<!-- -->

The behaviour of ProxySQL can be tweaked using global variables. These can be configured in 2 ways:

- at runtime, using the admin interface (preferred)
- at startup, using the dedicated section in the configuration file

<!-- -->

ProxySQL supports maximal uptime by allowing most variables to change at runtime and take effect immediately,
without having to restart the daemon. There are only 3x variables that cannot be changed at runtime -
`mysql-interfaces`, `mysql-threads` and `mysql-stacksize`. Also, there are 2 types of global variables,
depending on which part of ProxySQL they control:

- admin variables, which control the behaviour of the admin interface. Their names begin with the token
  "admin-"
- mysql variables, which control the MySQL functionality of the proxy. Their names begin with the token
  "mysql-"

<!-- -->

These global variables are stored in a per-thread fashion inside of the proxy in order to speed up access to
them, as they are used extremely frequently. They control the behaviour of the proxy in terms of memory
footprint or the number of connections accepted, and other essential aspects. Whenever a
`LOAD MYSQL VARIABLES TO RUNTIME` or `LOAD ADMIN VARIABLES TO RUNTIME` command is issued, all the threads
using the mysql or admin variables are notified that they have to update their values. To change the value of
a global variable either use an `UPDATE` statement:

```
UPDATE global_variables SET variable_value=1900 WHERE variable_name='admin-refresh_interval';
```

or the shorter `SET` statement, similar to MySQL's:

```
SET admin-refresh_interval = 1700;
SET admin-version = '1.1.1beta8';
```

## `A note about the 'mysql-default_xxx' variables`

ProxySQL is able to track several session variables required by the client connection, and it sets those
variables on every backend connection used by that client connection. Because ProxySQL is not aware of the
default value of those variables when creating a new connection, several `mysql-default_` variables define the
default value for such variables. Up to version 2.0.10 ProxySQL assumed that `mysql-default_variable` is the
default in MySQL server as well: given that is important to have these variables correctly configured. Because
configuring correctly these variables was a source of problem for many users, from ProxySQL version 2.0.11
many of these variables are now deprecated (and removed in 2.0.13) because a new algorithm was introduced:

- If the client explicitly sets a supported variable, ProxySQL will ensure that said variable is configured on
  the backend connection as well.
- If the client does not explicitly set a supported variable, ProxySQL won't configure the variable on the
  backend connection. That is: if the client doesn't set a value for a variable, it will use whatever value is
  configured on the backend connection

<!-- -->

[1]: /Documentation/global-variables/admin-variables
[2]: /Documentation/global-variables/mysql-variables
[3]: /Documentation/global-variables/mysql-monitor-variables
[4]: /Documentation/global-variables/pgsql-monitor-variables
