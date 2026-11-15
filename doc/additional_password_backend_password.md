# Backend password independent of the frontend passwords (`use_backend_password`)

## Summary

A `mysql_users` entry can hold a second frontend password in
`attributes.additional_password` ("Dual Passwords", see
https://proxysql.com/documentation/password-management). Clients can then
authenticate with either the primary password or the additional one, which is
what a password rotation needs: clients move from the old password to the new
one at their own pace.

By default a session uses **the password it authenticated with** also towards
the backends. This works when the backend accepts both passwords, for example
MySQL 8.0.14+ with dual passwords (`ALTER USER ... RETAIN CURRENT PASSWORD`),
or MariaDB 10.4 with two authentication methods joined by `OR`
(`IDENTIFIED VIA mysql_native_password USING PASSWORD('old_pw') OR
mysql_native_password USING PASSWORD('new_pw')`). These backends don't need
the attribute described here.

Backends that keep a single password per account (for example MySQL 5.7) reject
whichever of the two passwords they don't currently hold. For them, set the
user attribute `use_backend_password` to `true`: every session of the user,
whether it authenticated with the primary or with the additional password,
then connects to the backends with the password of the user's **backend
entry** (`backend=1`, same `username`). The frontend passwords and the backend
password become independent, and each can change on its own schedule.

## Configuration

| Attribute | Type | Default | Meaning |
|---|---|---|---|
| `additional_password` | string (hex-encoded) | absent | Second frontend password; see the `mysql_users` documentation. |
| `use_backend_password` | JSON boolean | absent (`false`) | When `true`, all sessions of the user use the backend entry password towards the backends. |

Rules:

- Only the JSON boolean `true` enables it. `"true"`, `1`, or any other value
  keeps the default behaviour.
- The attribute is read from the frontend entry (the one clients authenticate
  against).
- The backend entry is the `backend=1` entry with the same `username`. It can be
  the same row (`frontend=1, backend=1`) or a separate one
  (`frontend=0, backend=1`).
- The backend entry password must be stored **in clear text**. ProxySQL
  cannot authenticate against a backend with a stored hash (`*...`,
  `$A$0...`, `$ED$...`) unless a client has authenticated with that same
  password first, and that knowledge is not persisted.
- If the attribute is enabled and no usable backend password exists, the
  session is **rejected** at authentication, and an error is logged:

  ```
  User 'app' has 'use_backend_password' enabled but no backend entry with a clear-text password. Rejecting connection
  ```

- It applies to the initial handshake and to `COM_CHANGE_USER`, through Auth
  Switch or with inline authentication data.
- Users without the attribute behave exactly as before.
- Only MySQL sessions are affected (not Admin, Stats, SQLite3 server or
  ClickHouse sessions). LDAP-authenticated sessions are not affected: they
  already map to a backend user. This includes a session that authenticated
  through LDAP and later switches user with `COM_CHANGE_USER`; combining LDAP
  authentication with this attribute is not supported.
- Not meant to be combined with pass-through authentication
  (`mysql-passthrough_auth_enabled` with an empty-password row): there the
  backend verifies the client password itself. The combination is not tested.

## Example: rotating a password on MySQL 5.7

The backend account `app` currently has the password `old_pw`, and the
clients use it. The new password is `new_pw`.

1. Configure ProxySQL: `new_pw` as the primary password, `old_pw` as the
   additional one, and a backend entry that holds the password the backend
   has **now** (`old_pw`):

   ```sql
   DELETE FROM mysql_users WHERE username='app';
   INSERT INTO mysql_users (username, password, frontend, backend, default_hostgroup, attributes)
   VALUES ('app', MYSQL_NATIVE_PASSWORD('new_pw'), 1, 0, 0,
           json_object('additional_password', HEX(MYSQL_NATIVE_PASSWORD('old_pw')),
                       'use_backend_password', json('true')));
   INSERT INTO mysql_users (username, password, frontend, backend, default_hostgroup)
   VALUES ('app', 'old_pw', 0, 1, 0);
   LOAD MYSQL USERS TO RUNTIME;
   SAVE MYSQL USERS TO DISK;
   ```

   From now on, clients can use either `old_pw` or `new_pw`, and ProxySQL uses
   `old_pw` towards the backend.

2. Change the backend password, and right after it the backend entry:

   ```sql
   -- on the backend
   ALTER USER 'app'@'%' IDENTIFIED BY 'new_pw';

   -- on the ProxySQL Admin interface
   UPDATE mysql_users SET password='new_pw' WHERE username='app' AND frontend=0 AND backend=1;
   LOAD MYSQL USERS TO RUNTIME;
   SAVE MYSQL USERS TO DISK;
   ```

   Run the two back to back: in between, new backend connections fail, because
   ProxySQL still holds the old backend password.

   Then reconnect the client connections of `app` that were open before this
   step. A session resolves the backend password when it authenticates and
   keeps it, so these sessions still hold `old_pw`: they keep working on
   backend connections that are already open, but every new backend
   connection they need fails with error 1045. List them and kill them on the
   ProxySQL MySQL interface; the clients reconnect with either password:

   ```sql
   -- on the ProxySQL Admin interface
   SELECT SessionID FROM stats_mysql_processlist WHERE user='app';

   -- on the ProxySQL MySQL interface, for each SessionID
   KILL CONNECTION <SessionID>;
   ```

   Sessions opened after this step use `new_pw` towards the backend, whichever
   password they authenticated with.

3. Move the clients to `new_pw`. `stats_mysql_global` reports how many client
   connections authenticated with each password:
   `Client_Connections_connected_prim_pass` and
   `Client_Connections_connected_addl_pass`.

4. Remove the old frontend password:

   ```sql
   UPDATE mysql_users SET attributes=json_remove(attributes, '$.additional_password')
   WHERE username='app' AND frontend=1;
   LOAD MYSQL USERS TO RUNTIME;
   SAVE MYSQL USERS TO DISK;
   ```

   New logins with `old_pw` are rejected. Client connections that are already
   open keep working until they disconnect or are killed
   (`KILL CONNECTION <SessionID>`).

## Limitations

- Without the attribute, on a single-password backend, a session that
  authenticated with a password the backend doesn't hold can still appear to
  work when it reuses an idle backend connection that another session of the
  same user opened: pooled connections of the same username are reused
  without re-authentication. This depends on the pool contents, and stops
  after a restart or once those connections are gone, so it must not be relied
  on.
- A session keeps the backend password it resolved at authentication. After
  the backend entry password changes, sessions opened before the change open
  new backend connections with the old password, and the backend rejects them,
  until they reconnect (step 2 above). This is the same as for users without
  the attribute.
- The backend password is stored in clear text in `mysql_users`, like any
  `frontend=0, backend=1` entry.
