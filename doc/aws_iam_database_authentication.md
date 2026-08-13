# AWS IAM database authentication for MySQL backends

ProxySQL can use its AWS workload identity instead of a stored database
password when it opens selected MySQL-protocol backend connections to Amazon
RDS for MySQL or Aurora MySQL. Applications still authenticate to the ProxySQL
frontend in the usual way. This feature does not add IAM authentication to the
frontend.

## Build and package the feature

AWS IAM support is a ProxySQL 4.0 plugin.  The pinned AWS SDK for C++ 1.11.869
source archive, including its required CRT sources, is stored through Git LFS
at `deps/aws-sdk-cpp/aws-sdk-cpp-1.11.869-with-crt.tar.xz`.  Fetch LFS objects
before building; the dependency target unpacks this archive under `deps/` and
builds only the static SDK libraries required by the plugin.

```console
git lfs pull
PROXYSQL40=1 PROXYSQLAWSIAM=1 make -j
```

The normal 4.0 build remains SDK-free:

```console
PROXYSQL40=1 make -j
```

The AWS SDK is linked statically into
`ProxySQL_AwsIam_Plugin.so`, not into `src/proxysql`.  The main daemon contains
no AWS C++ SDK symbols or shared-library dependency.  Do not remove or rewrite
the pinned LFS archive: `deps/Makefile` verifies and unpacks it as a normal
native dependency.  `PROXYSQL40=1 PROXYSQLAWSIAM=1 make -j -C deps
aws_sdk_cpp_clean` removes only the unpacked AWS SDK build tree when that is
genuinely necessary.

Enable the provider by loading the installed plugin from the `plugins` list in
the ProxySQL configuration.  The path must match the package installation
location:

```ini
plugins = (
  "/usr/lib/proxysql/ProxySQL_AwsIam_Plugin.so"
)
```

The plugin is optional even in a feature-enabled build.  If it is not built or
not configured, attempted IAM backend authentication fails closed.  AWS SDK
for C++ is Apache-2.0; the exact upstream license and notice are retained in
the pinned archive and its manifest.  An AWS IAM-enabled DEB/RPM/tarball also
installs `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md` under
`/usr/share/doc/proxysql/aws-sdk-cpp/` (under `share/doc/...` in the tarball).

## Give the ProxySQL workload permission

AWS SDK for C++ uses its standard credential-provider chain. Depending on the
deployment, credentials can come from environment variables, shared
configuration/profile files, web identity (including EKS), an ECS task role,
or an EC2 instance profile. Prefer a temporary workload role. Do not put AWS
credentials or an RDS authentication token in ProxySQL configuration.

One provider chain and therefore one AWS identity belongs to the ProxySQL
process. Every IAM database user served by that process uses the same workload
identity; per-database-user role assumption is not supported.

Grant only `rds-db:connect` for the intended database-user resource ARN. The
resource uses the RDS resource ID, not the endpoint hostname:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:us-east-1:123456789012:dbuser:db-ABCDEFGHIJKLMNOP/app_iam"
    }
  ]
}
```

An explicit deny or absence of that permission is never followed by password
fallback.

## Prepare the database and trust store

Enable IAM database authentication on the RDS/Aurora database. On that
database, create the backend user with the AWS authentication plugin and
require TLS:

```sql
CREATE USER 'app_iam'@'%'
  IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS';
ALTER USER 'app_iam'@'%' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO 'app_iam'@'%';
```

Download the current Amazon RDS CA bundle through the operating system or your
configuration-management process. Store it at a stable, readable path such as
`/etc/proxysql/rds-ca-bundle.pem`. Follow the Amazon RDS CA rotation schedule:
install the new bundle, update ProxySQL's SSL row if the path changes, load
servers to runtime, canary the connection, and only then remove the old trust
material. ProxySQL does not install or rotate the bundle itself.

## Configure ProxySQL

The server hostname must be the real RDS/Aurora endpoint. Do not use an IP
address, Unix socket, custom CNAME, or alternate DNS alias: the configured
hostname is used for both token signing and TLS certificate identity.

The following complete Admin-interface example uses hostgroup `10`. Replace
the endpoint, port, region, CA path, usernames, and frontend password for the
deployment:

```sql
INSERT INTO mysql_servers
  (hostgroup_id, hostname, port, use_ssl, max_connections, comment)
VALUES
  (10, 'db.cluster-example.us-east-1.rds.amazonaws.com', 3306, 1, 200,
   'AWS IAM canary');

INSERT INTO mysql_servers_ssl_params
  (hostname, port, username, ssl_ca, comment)
VALUES
  ('db.cluster-example.us-east-1.rds.amazonaws.com', 3306, 'app_iam',
   '/etc/proxysql/rds-ca-bundle.pem',
   'Amazon RDS CA; IAM mode enforces certificate and hostname verification');

INSERT INTO mysql_hostgroup_attributes(hostgroup_id, hostgroup_settings)
VALUES (10, '{"aws_iam_region":"us-east-1"}');

INSERT INTO mysql_users
  (username, password, active, default_hostgroup, backend, frontend, attributes)
VALUES
  ('app_iam', 'replace-with-frontend-secret', 1, 10, 0, 1, '');

INSERT INTO mysql_users
  (username, password, active, default_hostgroup, backend, frontend, attributes)
VALUES
  ('app_iam', '', 1, 10, 1, 0,
   '{"backend_auth":{"type":"aws_iam"}}');

LOAD MYSQL USERS TO RUNTIME;
LOAD MYSQL SERVERS TO RUNTIME;

SAVE MYSQL USERS TO DISK;
SAVE MYSQL SERVERS TO DISK;
```

`LOAD MYSQL SERVERS TO RUNTIME` publishes `mysql_servers`,
`mysql_servers_ssl_params`, and `mysql_hostgroup_attributes` together. The
backend row's password should be empty. If it is nonempty, it is ignored for
IAM authentication and produces an operator warning; it is never a fallback.
Frontend and backend rows are deliberately separate even when their usernames
match.

IAM mode requires all of these values at selection time: `use_ssl=1`, a CA
file or CA path, certificate-chain and hostname verification, a supported real
RDS/Aurora endpoint, and `aws_iam_region` on the selected hostgroup. A malformed
or unknown `backend_auth` object is invalid policy, not password mode.

## Verify and roll out

Begin with a dedicated canary user and hostgroup. Connect through ProxySQL and
check both monitoring surfaces. `stats_mysql_global` always exports these
fixed rows, including zero-valued rows on SDK-free builds:

```text
AwsIam_Token_requests
AwsIam_Token_cache_hits
AwsIam_Token_refresh_successes
AwsIam_Token_refresh_failures
AwsIam_Credential_provider_failures
AwsIam_Queue_rejections
AwsIam_Backend_connection_successes
AwsIam_Backend_connection_failures
AwsIam_Token_cache_entries
AwsIam_In_flight_generations
AwsIam_Queued_generations
AwsIam_Waiting_sessions
```

The exact label-free Prometheus samples are:

```text
proxysql_mysql_aws_iam_token_requests_total
proxysql_mysql_aws_iam_token_cache_hits_total
proxysql_mysql_aws_iam_token_refresh_successes_total
proxysql_mysql_aws_iam_token_refresh_failures_total
proxysql_mysql_aws_iam_credential_provider_failures_total
proxysql_mysql_aws_iam_queue_rejections_total
proxysql_mysql_aws_iam_backend_connection_successes_total
proxysql_mysql_aws_iam_backend_connection_failures_total
proxysql_mysql_aws_iam_token_cache_entries
proxysql_mysql_aws_iam_in_flight_generations
proxysql_mysql_aws_iam_queued_generations
proxysql_mysql_aws_iam_waiting_sessions
```

For the canary, verify that token requests and backend successes rise, refresh
successes appear before token expiry, waiting/in-flight gauges return to zero,
and failures, provider failures, and queue rejections remain stable. Review
ProxySQL logs for redacted AWS IAM categories. Logs may include the backend
username, hostgroup, endpoint, region, AWS error code, or request ID; they must
not include a token, access key, secret, session token, profile contents, or
web-identity token.

Clients receive the generic ProxySQL backend error `9002/HY000`, not AWS
provider messages or the RDS authentication response. A second `1045` after
the one permitted fresh-token retry logs the operator hint
`verify_system_clock_for_sigv4_clock_skew`; verify NTP/chrony and the system
clock before investigating policy further. ProxySQL never adjusts the clock.

Move traffic beyond the canary only after CA validation, expected cache/refresh
behavior, redacted logging, and workload-role policy have been observed. Keep
any migration password account as a distinct password-mode backend row/user;
never put a fallback password on the IAM row.

## Roll back

To disable the IAM backend, stop or reroute canary traffic, remove its backend
row, and publish the new user policy. The frontend row can remain if it routes
somewhere valid:

```sql
DELETE FROM mysql_users
WHERE username='app_iam' AND backend=1 AND frontend=0;
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;
```

If continued backend service requires a database password, create a separate
password-mode database identity and corresponding backend row. Do not convert
the IAM row in place while it carries traffic:

```sql
INSERT INTO mysql_users
  (username, password, active, default_hostgroup, backend, frontend, attributes)
VALUES
  ('app_password_backend', 'replace-with-backend-password', 1, 20, 1, 0, '');
DELETE FROM mysql_users
WHERE username='app_iam' AND backend=1 AND frontend=0;
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;
```

Update the frontend row or routing rules to the replacement backend identity
using the deployment's existing backend-username mapping procedure. Runtime
policy reload drains connections whose recorded authentication mode no longer
matches.

## Scope and non-goals

This first version intentionally does not provide:

- IAM authentication into the ProxySQL frontend;
- PostgreSQL backend IAM authentication;
- per-user `AssumeRole`, role ARNs, external IDs, or session tags;
- AWS Secrets Manager password retrieval;
- IAM authentication for ProxySQL monitor accounts;
- custom DNS aliases in place of a real RDS/Aurora endpoint;
- token persistence, token display, or ProxySQL Cluster token synchronization;
- automatic AWS SDK or Amazon RDS CA installation; or
- any password fallback after IAM policy, credential, token, TLS, transport, or
  backend authentication failure.

Ordinary backend rows without `backend_auth` continue to use the existing
password behavior and do not invoke the AWS provider.

## Optional real-AWS CI contract

Ordinary CI uses a fake signer and a controlled local TLS/MySQL server. It does
not access AWS. The optional real-AWS job is an externally provisioned,
self-hosted-runner contract. The runner must carry the `self-hosted`, `linux`,
`x64`, and `aws-iam-integration` labels. Its protected environment supplies the OIDC role,
`AWS_REGION`, `RDS_ENDPOINT`, `RDS_PORT`, `RDS_DB_USER`, `RDS_CA_FILE`, and an
executable absolute path in `AWS_IAM_INTEGRATION_RUNNER`; GitHub OIDC supplies
temporary credentials. That runner must verify successful IAM login, denied
`rds-db:connect`, a nonexistent database user, wrong region, credential
rotation, token refresh, and validation with the real Amazon RDS CA. It must
not print tokens, credential values, or the contents of the OIDC response.

A GitHub-hosted preflight skips cleanly when the entire protected contract is
absent and fails explicitly when it is partial. A complete contract schedules
the labeled self-hosted job. Once scheduled, that job fails clearly if the
external suite path is not absolute and executable or the CA path is not an
absolute, readable file. If no online self-hosted runner has all four labels,
GitHub keeps the configured job queued before any repository step can run; the
queued job is the visible infrastructure-unavailable signal, and no pre-step
diagnostic can run. This repository does not provision the runner, RDS
resources, or AWS policy in ordinary CI and never reports controlled fake
coverage as real-RDS verification.
