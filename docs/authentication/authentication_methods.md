# Frontend vs Backend Authentication

When talking about authentication for ProxySQL we should distinguish between:

- _Frontend authentication_: This is performed for clients connecting to ProxySQL. Here, ProxySQL acts as the
  server.
- _Backend authentication_: This occurs when ProxySQL connects to the database instances. In this scenario,
  ProxySQL acts as the client.

Depending on the authentication we are referring to, different authentication methods are supported.

# Authentication Methods

For both frontend and backends connections, ProxySQL supports:

- [mysql_clear_password][6]
- [mysql_native_password][7]
- [caching_sha2_password][8]

For these authentications methods, dual-passwords are supported since version `3.0`. For more information see

And other extra frontend authentication methods:

- [SPIFFE][9]: Password-less authentication
- [LDAP][10]: With special consideration for both OpenLDAP and ActiveDirectory

For checking support across different ProxySQL versions check [the following section][11].

## Configuration

Essential configuration for the [non-extra authentication methods][17] is performed via:

- [mysql-default_authentication_plugin][1] global variable.
- [mysql_users][16] configuration table.

## MySQL Authentication Methods - Version Differences

For the authentication methods prior to `MySQL 8`, i.e. for `mysql_clear_password` and
`mysql_native_password`, there is **no need** to perform any special configuration in ProxySQL, no matter the
version. This means that no matter how the password is stored in `mysql_users` table, and the value of
`admin-hash_passwords` authentication should work. When talking about `caching_sha2_password` we need to take
into account ProxySQL version:

- `Pre-2.0.2`: ProxySQL lacked support for `caching_sha2_password`, for both backend and frontend, client
  should be configured using `mysql_native_password`.
- `Pre-2.6.0`: ProxySQL lacked support for **frontend** `caching_sha2_password`, because of this, the only
  downside is that passwords are required to be stored in `clear text` (not hashed) and the admin variable
  [admin-hash_passwords][2] should be set to `false`. To further clarify, in this case frontend authentication
  is constraint to either `mysql_clear_password` or `mysql_native_password`, while backend authentication can
  be performed in both `mysql_native_password` and `caching_sha2_password`.
- `Post-2.6.0`: ProxySQL has support for `caching_sha2_password` for **both** frontend and backend
  connections, the admin variable [admin-hash_passwords][2] is now **deprecated** and the passwords can be
  stored both in `clear text` or `hashed` at users preference.

After version `2.6.0` ProxySQL also introduced the variable [mysql-default_authentication_plugin][1]. This
variable allows to control which authentication method is sent to the client in the
`Initial Handshake Packet`. This setting will relate to the potential `Auth Switches` asked to a client,
please refer to [variable documentation][1] and to the [limitations section][12] for extra details.

### Supported scenarios

Aside the limitations covered in [limitations section][12], ProxySQL is well tested against the possible
combinations that arise from the use of the different configuration flags, together with client connection
options that can affect the authentication process, these combinations include:

- Default authentication plugin announced by ProxySQL, [mysql-default_authentication_plugin][1].
- The type of password stored in `mysql_users.password`, either hashed, with `mysql_native_password` or
  `caching_sha2_password`, or in clear text.
- Wether client connection supports `SSL` or not, ProxySQL will automatically enable `SSL` for frontend
  connections when [mysql-default_authentication_plugin][1] is set to `caching_sha2_password`.
- Requested authentication method: A client connection can initially request any of the supported
  authentication methods.

All the previous scenarios are covered by automated testing, and they are expected to work.

### Login with different MySQL clients

When trying to use `caching_sha2_password`, it's important to verify first that the client we are using has
support for it. And if they have support, it may be required to supply some extra flags depending on the
client default behavior. For each client, this process might be slightly different, here we are going to
elaborate on `MySQL` and `MariaDB` clients. For more details please refer to you client official
documentation.

#### MySQL Client - caching_sha256_password

`MySQL` client switched to `caching_sha256_password` as default authentication method in `8.0`. Said this,
when using `MySQL` client, to check if the client has support for `caching_sha256_password`, it's best just
trying to select it as the default authentication method:

```
mysql -h$HOST --default-auth='caching_sha256_password' -u$USERNAME -p$PASSWORD -P6033
```

If the authentication method isn't supported, the client is explicit about it:

```
ERROR 2059 (HY000): Authentication plugin 'caching_sha256_password' cannot be loaded: /usr/lib/mysql/plugin/caching_sha256_password.so: cannot open shared object file: No such file or directory
```

NOTE: Being explicit about the default authentication (`--default-auth`) also avoid extra `auth-switchs`
during the connection phase, this mitigates one current limitation [described here][12].

#### MariaDB Client - caching_sha2_password

The compatible plugin for `caching_sha256_password` password for `MariaDB` (`caching_sha2_password`) has been
present for `MariaDB Connector/C` since versions `3.0.8`/`3.1.0`, see [CONC-312][13] for more information. But
it's important to notice that the plugin will only be available if the package installed was bundled with the
`caching_sha2_password.so` plugin binary.

`MariaDB` client isn't as explicit as `MySQL` client when the plugin can't be loaded. Instead of reporting an
explicit error, it issues generic fallback authentication attempt. This obscures the underlying error that
caused the failure. For this reason, it's best to check if the required plugin binary is present in the
system:

```
[root@system /]# find /usr -name "caching*"
/usr/lib64/mariadb/plugin/caching_sha2_password.so
```

If the plugin is found in the system, the client should support the authentication method, the following
command should allow for authentication in older and newer systems:

```
mysql -h$HOST --ssl --default-auth='caching_sha2_password' -u$USERNAME -p$PASSWORD -P6033'
```

Breaking down the previous command:

- Default authentication a `caching_sha2_password`, same motivation as for the `MySQL` client.
- The `--ssl` flag is mandatory for versions prior to `10.10`. This is because `caching_sha2_password`
  requires a secure channel, but `MariaDB` client doesn't tries to enable it when detects that
  `caching_sha2_password` is required. This leads to a failed authentication.

### Limitations

In order to simplify password management, ProxySQL tries to detect the type of stored passwords, and acts
differently depending on this detection, currently this detection fails for passwords starting with `*`,
assuming these are hashed `mysql_native_password`, see [issue #1762][5]. Because of this, passwords starting
with `*` are currently not supported, and should be avoided. This detection is expected to be improved in the
future.

Since version `2.6.0`, `caching_sha2_password` support was introduced, this version presents some limitations
regarding `Auth Switches`, this means, when the user specified `mysql-default_authentication_plugin` doesn't
match the authentication method later requested by the client during the handshake process. While not common
practice between clients, it's considered [sensible behavior][4] for a client trying to infer the required
authentication method from the initial `Handshake Packet`, instead of sending the default authentication
method, thus avoiding unnecessary `Auth Switches`. If the client doesn't exhibit this behavior, the following
scenarios, for now, are expected to fail:

_Scenario 1_:

- `mysql-default_authentication_plugin` **is** `caching_sha2_password`.
- Password stored for user in `mysql_users` table is a hashed `caching_sha2_password`.
- Client requested authentication **isn't** `caching_sha2_password`.

In this scenario, ProxySQL will be required to perform an `Auth Switch`, and later follow with regular
`caching_sha2_password` full authentication; this is currently unsupported.

_Scenario 2_:

- `mysql-default_authentication_plugin` is **not** `caching_sha2_password`.
- Password stored for user in `mysql_users` table is a hashed `caching_sha2_password`.
- Client requested authentication **is** `caching_sha2_password`.

In this scenario, ProxySQL fails to correctly infer the authentication that should be requested to the client,
instead an `Auth Switch` is performed from which the authentication info can't be verified since ProxySQL
doesn't have the `cleartext` password for the user stored.

_Scenario 3_:

`mysql_change_user` (`COM_CHANGE_USER`) is currently not supported in combination with
`caching_sha2_password`. This limitation can be considered an extension of `Scenario 1`, since
`COM_CHANGE_USER` requires `Auth Switch` support.

## Extra Authentication Methods

- `SPIFFE`: Supported since `2.3.0`.
- `LDAP`: Supported since since `2.0.1`.

For more information, please refer to the specific documentation for each of these authentication methods:

- [SPIFFE][14]
- [LDAP][15]

[1]: /documentation/global-variables/mysql-variables/#mysql-default_authentication_plugin
[2]: /documentation/global-variables/admin-variables/#admin-hash_passwords-deprecated
[3]: /documentation/global-variables/mysql-variables/#mysql-have_ssl
[4]: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html/#sect_protocol_connection_phase_auth_method_mismatch
[5]: https://github.com/sysown/proxysql/issues/1762
[6]: https://dev.mysql.com/doc/refman/8.0/en/cleartext-pluggable-authentication.html
[7]: https://dev.mysql.com/doc/refman/8.0/en/native-pluggable-authentication.html
[8]: https://dev.mysql.com/doc/refman/8.0/en/caching-sha2-pluggable-authentication.html
[9]: https://spiffe.io/
[10]: https://www.openldap.org/
[11]: #mysql-authentication-methods-version---differences
[12]: #limitations
[13]: https://jira.mariadb.org/browse/CONC-312
[14]: /documentation/spiffe-support
[15]: documentation/ldap-support
[16]: /documentation/main-runtime/#mysql_users
[17]: #extra-authentication-methods
