# AWS IAM Database Authentication for MySQL Backends — Design Spec

**Status:** Draft, pending specification review
**Date:** 2026-08-12
**Target:** ProxySQL `v3.0`
**Scope:** ProxySQL-to-RDS/Aurora MySQL backend authentication using AWS IAM database authentication. Frontend authentication remains unchanged.

## Problem

ProxySQL currently authenticates new MySQL backend connections with password material held in `MySQL_Connection_userinfo`. An application can use AWS IAM database authentication when it connects directly to Amazon RDS or Aurora, but ProxySQL cannot generate and present an IAM authentication token when it opens the backend connection. Operators therefore have to keep a database password in ProxySQL even when their AWS security model is based on workload roles and short-lived credentials.

This feature lets selected backend users authenticate from ProxySQL to RDS/Aurora MySQL with an AWS IAM token. Applications continue to authenticate to ProxySQL normally. The first version supports MySQL/MariaDB protocol backends only.

## Goals

- Allow per-backend-user opt-in to AWS IAM database authentication.
- Use the AWS SDK for C++ standard credential provider chain, including environment, profile, web-identity/EKS, ECS task-role, and EC2 instance-profile credentials.
- Use one AWS identity for the ProxySQL process. Different database users do not assume different IAM roles.
- Keep MySQL worker event loops free from AWS credential-provider and token-generation blocking.
- Cache and coalesce token generation safely while respecting the 15-minute authentication-token lifetime.
- Require encrypted, certificate-verified connections for every IAM-authenticated backend connection.
- Preserve normal password authentication and normal builds when the optional feature is disabled.
- Never persist, cluster-sync, log, or expose generated tokens or AWS credentials.

## Non-goals

- IAM authentication from applications into the ProxySQL frontend.
- PostgreSQL backend support. It is a later phase and will need a separate protocol integration.
- Per-user `AssumeRole`, role ARN, external ID, or session-tag configuration.
- AWS Secrets Manager password retrieval.
- IAM authentication for ProxySQL monitor accounts in the first version.
- Custom DNS aliases or Route 53 CNAMEs in place of the real RDS/Aurora endpoint.
- Token persistence across restart or token synchronization through ProxySQL Cluster.
- Automatic installation, download, or vendoring of the AWS SDK or Amazon RDS CA bundle.
- Password fallback when an IAM policy, credential provider, token, TLS configuration, or backend authentication fails.

## Chosen dependency approach

The optional build uses the official AWS SDK for C++, supplied by the operating system or build environment. ProxySQL does not vendor it. Only the SDK components needed for `Aws::RDS::RDSClient::GenerateConnectAuthToken` are linked: `core` and `rds`.

The proposed build gate is:

```text
PROXYSQLAWSIAM=1
```

With the gate unset, no AWS headers are included, no AWS libraries are linked, no token-provider threads are created, and the existing build remains unchanged. With the gate set, configuration fails early unless compatible system AWS SDK headers and libraries are found. Discovery should use the installed AWS SDK CMake package metadata so transitive link requirements are handled correctly; a dynamic system SDK is preferred for release packages.

The AWS SDK for C++ is Apache-2.0 licensed. ProxySQL is GPL-3.0-or-later, and Apache-2.0 is compatible with GPLv3. Release packaging must nevertheless inventory the exact SDK version and its transitive dependencies, retain the applicable license and notice material, and run the normal dependency-license scan for each shipped binary. Relevant upstream material:

- <https://github.com/aws/aws-sdk-cpp/blob/main/LICENSE.txt>
- <https://github.com/aws/aws-sdk-cpp/blob/main/NOTICE.txt>
- <https://www.gnu.org/licenses/license-list.html#apache2>

## User-facing configuration

### Backend-user opt-in

The IAM mode is declared in the existing `mysql_users.attributes` JSON on a backend row:

```json
{
  "backend_auth": {
    "type": "aws_iam"
  }
}
```

`backend_auth.type` is read only from the runtime backend-account lookup (`USERNAME_BACKEND`). Its supported initial values are absent, meaning the existing password behavior, and `aws_iam`. If `backend_auth` exists but is malformed or has an unknown type, the backend account is invalid and fails closed rather than silently reverting to password authentication.

A non-empty password on an `aws_iam` backend row is ignored for backend authentication and produces an admin warning. Operators should leave it empty to avoid retaining an unnecessary secret.

Frontend and backend policy are deliberately separate. A recommended split-row configuration for the same database username is:

```sql
INSERT INTO mysql_users
  (username, password, active, default_hostgroup, backend, frontend, attributes)
VALUES
  ('app_iam', 'frontend-secret', 1, 10, 0, 1, '');

INSERT INTO mysql_users
  (username, password, active, default_hostgroup, backend, frontend, attributes)
VALUES
  ('app_iam', '', 1, 10, 1, 0,
   '{"backend_auth":{"type":"aws_iam"}}');
```

The application uses `frontend-secret` to enter ProxySQL. ProxySQL resolves the second row before opening a backend connection and uses an IAM token as `app_iam` on RDS. Existing LDAP backend-username mapping remains authoritative: the backend lookup is performed after mapping, using the username that will be sent to MySQL.

Ordinary users with no `backend_auth` object continue through the current password path without an AWS lookup.

### Region

The AWS region belongs to the destination hostgroup and is stored in the existing `mysql_hostgroup_attributes.hostgroup_settings` JSON:

```sql
INSERT INTO mysql_hostgroup_attributes(hostgroup_id, hostgroup_settings)
VALUES (10, '{"aws_iam_region":"us-east-1"}');
```

The value is normalized into the hostgroup's runtime attributes on `LOAD MYSQL SERVERS TO RUNTIME`, is persisted by existing save/config-file paths, and is synchronized by ProxySQL Cluster because `hostgroup_settings` already participates in those paths. It is required only when an IAM backend account is routed to that hostgroup.

Region is intentionally not inferred from the hostname. Explicit configuration avoids ambiguous endpoints and keeps signing behavior deterministic.

### Server and TLS requirements

For an IAM backend connection, all of the following are mandatory:

- `mysql_servers.use_ssl=1` for the selected server;
- a non-empty CA file or CA path, selected through the existing per-server/user `mysql_servers_ssl_params` rules or the global proxy-to-server CA settings;
- certificate-chain and hostname verification enabled;
- a TCP server using the real RDS/Aurora DNS endpoint, not an IP address, Unix socket, or custom CNAME;
- a non-empty `aws_iam_region` on the selected hostgroup.

Validation happens both when runtime configuration is loaded, where combinations that can be checked statically produce an operator-visible error, and immediately after the concrete backend user/server/hostgroup tuple is selected. Dynamic validation is necessary because routing rules decide the hostgroup at query time. An invalid tuple is never connected with a password.

The endpoint used in the token signature and certificate verification is the original configured RDS hostname. ProxySQL may still connect the socket to an address from its DNS cache. The bundled MariaDB Connector/C therefore needs a small internal option/patch that separates the TLS verification name from the network address; IAM connections set the former to the configured endpoint and the latter to the resolved address. The option falls back to current connector behavior when unset.

IAM connections explicitly enable the bundled static `mysql_clear_password` client plugin and require both `MYSQL_OPT_SSL_ENFORCE` and `MYSQL_OPT_SSL_VERIFY_SERVER_CERT`. Cleartext authentication is enabled only on IAM-mode connections.

## Backend identity resolution

The frontend session's password cannot be reused as the source of backend policy. Before a backend connection is acquired from or returned by the pool, a centralized resolver:

1. takes the mapped backend username from the connection request;
2. looks it up in `GloMyAuth` with `USERNAME_BACKEND`;
3. parses or reads the normalized `backend_auth` policy;
4. returns either the existing password mode, AWS IAM mode, or an invalid-policy result.

The resolved authentication mode is part of the requested pool identity and is copied onto `MySQL_Connection` as connection identity metadata. Pool matching must compare the mode as well as the username and session options. This prevents a password-authenticated pooled connection from being reused after the account is changed to IAM mode, and vice versa. A runtime user-policy reload invalidates or drains pooled connections whose recorded mode no longer matches.

The implementation must not place an IAM token into the frontend `userinfo`, the backend account row, or the long-lived `userinfo->password` field.

## Token-provider architecture

### Process lifetime

When compiled in, `Aws::InitAPI` runs once in the final daemon process after daemonization/forking and before MySQL workers start. `Aws::ShutdownAPI` runs after token-provider threads have joined and before dependent global facilities are destroyed.

One process-wide `AwsIamTokenProvider` owns:

- the AWS default credential provider chain;
- lazily created RDS clients/signers for configured regions;
- a bounded request queue and a small background worker pool;
- the token cache and in-flight request map;
- counters and redacted failure state.

ProxySQL supplies no explicit credentials. Credential discovery and refresh stay under the SDK's standard provider chain. No provider object or derived credential is assigned to a database user.

### Interface and test seam

Backend connection code depends on a narrow interface rather than directly on AWS SDK types:

```cpp
struct AwsIamTokenKey {
    std::string endpoint;
    uint16_t port;
    std::string region;
    std::string database_user;
};

struct AwsIamTokenResult {
    Status status;
    SecureString token;
    std::chrono::steady_clock::time_point expires_at;
    uint64_t generation;
    RedactedFailure failure;
};

class AwsIamTokenSource {
public:
    virtual RequestHandle request(const AwsIamTokenKey&, CompletionTarget) = 0;
    virtual void invalidate(const AwsIamTokenKey&, uint64_t generation) = 0;
    virtual ~AwsIamTokenSource() = default;
};
```

The production implementation wraps the AWS SDK; tests inject a fake provider and controllable clock. `SecureString` is a move-only buffer whose destructor cleanses its allocation.

### Cache semantics

Tokens are keyed by the exact tuple:

```text
(configured RDS endpoint, port, region, database user)
```

The endpoint is not the resolved IP and the hostgroup ID is not a substitute for it. Tokens are generated with a 15-minute lifetime. A cached token is returned only while at least two minutes remain; otherwise it is treated as expired for connection purposes and refreshed. Cache timing uses a monotonic clock derived from the generation point so wall-clock adjustments cannot accidentally extend local reuse.

Concurrent misses for the same key coalesce into one in-flight generation. All waiters receive separate move-controlled result buffers. Entries are cleansed when replaced, invalidated, evicted, or destroyed at shutdown. The cache is memory-only and has a bounded number of entries; least-recently-used entries without in-flight waiters are evicted first.

Token generation itself is local SigV4 signing after credentials are available, but obtaining or refreshing standard-chain credentials can contact profile processes, web-identity/STS, ECS, or EC2 metadata services. All of that work occurs on token-provider threads, never on MySQL workers.

The initial operational bounds are implementation constants with conservative defaults and can become runtime variables if production evidence requires tuning:

- 2 token-provider threads;
- 1,024 queued distinct keys;
- 5-second per-session wait deadline;
- 2-minute minimum remaining token lifetime;
- bounded exponential backoff with jitter after provider failures.

Queue capacity applies after coalescing. Total waiters and waiters per key are bounded separately from the distinct-key queue; their ceilings are no greater than the corresponding session/backend connection limits. A saturated distinct-key queue or waiter set fails new requests immediately and cannot grow an unbounded completion list.

## Connection lifecycle and state machine

### New connection

The normal pool path first attempts to reuse a compatible established connection. When it selects a fresh connection whose resolved mode is `aws_iam`, the lifecycle is:

```text
fresh backend selected
        |
        v
validate IAM user + hostgroup + server + TLS tuple
        |
        v
request token from AwsIamTokenProvider
        |
  cache hit --------------------------+
        |                             |
  cache miss                          |
        |                             |
        v                             |
WAITING_AWS_IAM_TOKEN                 |
        | completion / failure        |
        +-----------------------------+
        |
        v
attach ephemeral token to MySQL_Connection
        |
        v
existing nonblocking CONNECTING_SERVER path
        |
    success or failure
        |
        v
cleanse all handshake token copies
```

`WAITING_AWS_IAM_TOKEN` is a two-phase session state similar in shape to the existing pass-through authentication wrapper around `CONNECTING_SERVER`. The session retains the selected fresh connection so the token key cannot drift to a different endpoint between request and connect.

Provider threads never dereference a session or connection. They place completions into an owner-worker queue and signal that worker through an eventfd/pipe already integrated with its poll loop. Each request carries a cancelable generation handle. Session teardown cancels its waiter; a late completion is cleansed and dropped. The owner worker alone resumes or destroys session state.

Once a token result is available, `MySQL_Connection::connect_start()` uses it as `auth_password` without copying it into `userinfo->password`. MariaDB Connector/C necessarily duplicates the password into `MYSQL::passwd` during its handshake, so success, failure, timeout, cancellation, and destruction paths must cleanse both ProxySQL's ephemeral buffer and the connector-owned duplicate. The connector password is cleared after authentication; IAM connections never use connector reconnect or `mysql_change_user` with that cleared value.

Token wait time is part of the existing backend acquisition deadline. If the session deadline or 5-second IAM wait deadline expires first, its waiter is canceled, the selected fresh connection is destroyed, and the client receives the normal generic backend connection failure.

### Established and pooled connections

An IAM token is an initial authentication credential. Expiration does not terminate an already authenticated MySQL session. Healthy IAM connections therefore remain reusable and multiplexable in the existing pool after the token's 15-minute lifetime.

The pool records that the connection was established in IAM mode. It may be returned only for requests whose resolved backend username and authentication mode match. Token value and token generation are not part of the pool key.

### Reset, change-user, and auxiliary connections

The first version never runs `mysql_change_user` or a change-user-based reset on an IAM connection. If an IAM pooled connection would enter `CHANGING_USER_SERVER` or `RESETTING_CONNECTION`, ProxySQL destroys it and creates a new connection through the token-provider path. This applies even when the target username is unchanged.

Auxiliary connections that authenticate as the application user, including asynchronous query/connection kill helpers, resolve the same backend policy. They may synchronously wait on a token only in their already detached/background helper thread; they cannot use a saved password or stale token. Monitor connections remain on their existing separately configured monitor credentials in this phase.

## Failure behavior

IAM mode always fails closed. The following classes never trigger password fallback:

| Failure | Behavior |
|---|---|
| Feature not compiled | Runtime configuration warning; attempted IAM connection fails with an internal `support_not_compiled` reason. |
| Malformed/unknown backend policy | Account is marked invalid for backend use until configuration is corrected and reloaded. |
| Missing/invalid region or unsupported endpoint | Selected connection is rejected before token generation. |
| `use_ssl=0`, missing CA trust, or verification unavailable | Selected connection is rejected before sending a token. |
| Credential provider unavailable/expired | Bounded provider retry/backoff; session fails at its deadline. |
| Token queue saturated | Request fails immediately with a queue-rejected reason. |
| Token generation failure | No connection is attempted; cache retains no failed token. |
| Transport/TLS failure | Connection follows normal backend transport failure handling; cached token is not invalidated. |
| MySQL `1045` during initial IAM auth | Conditionally invalidate the exact token generation and allow one fresh-token connection attempt. Continued failure enters backoff. |
| Shutdown/cancellation | Waiter is canceled and all returned token material is cleansed. |

Invalidation after `1045` includes the token generation number. A delayed failure from an older connection cannot evict a newer token already installed in the cache. The one fresh-token retry is an IAM-specific ceiling for the backend acquisition; it must not combine with the normal connect retry loop into attempts across many servers. Selecting a different endpoint requires a token for that endpoint's own key.

Clients receive the existing generic backend authentication/connection error. They do not receive AWS provider messages, endpoint internals, IAM policy details, or the backend's raw authentication text. Operator logs may contain the backend username, hostgroup, endpoint, region, redacted failure category, AWS error code, and request ID where available, but never a token, access key, secret key, session token, profile contents, or web-identity token.

Repeated `1045` failures for a newly generated token should include a diagnostic suggesting system-clock verification because SigV4 is time-sensitive. ProxySQL does not attempt to adjust the system clock.

## Observability

Counters are exported through both `stats_mysql_global` and the existing Prometheus registry. They have no username or token-key labels, avoiding secret exposure and unbounded cardinality.

Required counters:

- token requests;
- cache hits;
- token refresh successes;
- token refresh failures;
- credential-provider failures;
- queue rejections;
- IAM backend connection successes;
- IAM backend connection failures.

Required gauges:

- cached token entries;
- in-flight distinct token generations;
- queued distinct token generations;
- sessions waiting for IAM tokens.

Prometheus names use the `proxysql_mysql_aws_iam_...` prefix. `stats_mysql_global` names use the `AwsIam_...` prefix. Exact spellings will be fixed in the implementation plan and treated as public monitoring API thereafter.

No table or metric exposes token text, token expiry timestamps per user, access-key IDs, profile names, role ARNs, or credential-provider payloads.

## Testing strategy

### Build matrix

- Default build with `PROXYSQLAWSIAM` unset and no AWS SDK installed.
- IAM build against the minimum supported system AWS SDK.
- IAM build against a current system AWS SDK.
- Deliberate missing/incompatible SDK configuration failure.
- Dynamic-link inspection confirming only intended SDK components and their system dependencies are present.

### Unit tests

Tests use a fake `AwsIamTokenSource` and controllable clock to cover:

- exact cache-key separation by endpoint, port, region, and user;
- hit, two-minute refresh boundary, expiration, replacement, eviction, and shutdown;
- coalescing many waiters onto one generation;
- cancellation and late completion after session destruction;
- bounded queue behavior and retry backoff;
- provider failure and recovery;
- generation-conditional invalidation after `1045`;
- one-fresh-token retry ceiling;
- move-only secure-buffer cleanup on every result path;
- parsing valid, absent, malformed, and unknown `backend_auth` objects;
- password/IAM pool-mode matching and mode changes after runtime reload;
- redaction tests that feed recognizable fake secrets through every failure path and assert they never reach logs, errors, stats, or metrics.

### Connector and protocol tests

A controlled MySQL protocol test server requests `mysql_clear_password` and validates:

- the token is sent only after TLS is established and verified;
- cleartext authentication is disabled on ordinary password connections;
- tokens larger than 1 KiB are not truncated;
- the configured endpoint, not resolved IP, is used for certificate hostname verification;
- an untrusted certificate, wrong hostname, absent CA, and `use_ssl=0` all fail before token transmission;
- `MYSQL::passwd` and the ProxySQL ephemeral buffer are cleansed after success, failure, timeout, and cancellation.

### Pool and session tests

- Establish an IAM connection, advance the fake clock beyond 15 minutes, and prove the established pooled connection remains reusable.
- Require a fresh connection after expiry and prove it obtains a new token.
- Prove reset and `CHANGE USER` paths destroy and reconnect rather than calling `mysql_change_user`.
- Prove a password-mode pooled connection is not reused after the backend account switches to IAM, and vice versa.
- Exercise query-kill and connection-kill helpers for an IAM user.
- Disconnect a frontend while waiting and verify no session use-after-free or leaked waiter.
- Shut down while provider requests and backend handshakes are active.

### Regression tests

- Existing password users with no `backend_auth` attribute do not invoke the token provider.
- Password and IAM users coexist in the same deployment and may route through overlapping hostgroups when TLS requirements are satisfied.
- Existing frontend authentication methods, LDAP mapping, routing, multiplexing, connection throttling, and max-connections enforcement retain their current behavior.
- Cluster sync and save/load round-trip both the backend-user attributes and `aws_iam_region` hostgroup setting.
- A build without AWS support accepts ordinary configuration and fails only attempted IAM backend use, with a clear operator diagnostic.

### Optional AWS integration tests

An opt-in suite provisions or targets an IAM-enabled RDS MySQL/Aurora instance and tests the standard credential chain with temporary CI credentials. It verifies successful connection, insufficient `rds-db:connect` policy, nonexistent database user, wrong region, credential rotation, token refresh, and real Amazon RDS CA validation. These tests remain outside ordinary CI because they require AWS infrastructure, permissions, and cost.

ASan and TSan runs cover the fake-provider suites, cancellation, completion queues, cache replacement, and shutdown races.

## Documentation and rollout

Operator documentation must include:

1. installing the supported system AWS SDK for C++ packages;
2. building with `PROXYSQLAWSIAM=1`;
3. assigning the ProxySQL workload an IAM policy permitting `rds-db:connect` for the intended database-user resource ARNs;
4. creating the RDS/Aurora MySQL database user with `AWSAuthenticationPlugin` and requiring SSL;
5. installing and rotating the Amazon RDS CA trust bundle;
6. configuring the real RDS endpoint with `use_ssl=1`, CA parameters, hostgroup region, and split frontend/backend user rows;
7. loading users, servers, SSL parameters, and hostgroup attributes to runtime;
8. checking the IAM counters and redacted logs before moving production traffic.

Rollout should begin with a dedicated canary user and hostgroup. Password users remain available as separate backend rows during migration, but a row marked `aws_iam` never uses its password as a fallback.

## Risks and mitigations

- **Credential-provider stalls:** standard providers may make network calls. A bounded background pool, per-session deadline, coalescing, and queue cap isolate MySQL workers and bound memory.
- **Connection burst near expiry:** the two-minute refresh boundary and per-key coalescing create one refresh, not one SDK operation per connection.
- **DNS/TLS identity mismatch:** resolved IPs cannot be used for certificate hostname checks. A connector verification-name option preserves the configured endpoint while retaining ProxySQL DNS resolution.
- **Pool reuse across policy changes:** the authentication mode becomes part of pool compatibility and mismatched connections drain.
- **Lingering connector password copy:** IAM cleanup explicitly includes `MYSQL::passwd`, not only ProxySQL's source buffer.
- **Configuration typo causing password fallback:** any present-but-invalid `backend_auth` object is an invalid policy, never equivalent to absence.
- **AWS SDK packaging complexity:** the feature is optional, uses system packages, links only `core` and `rds`, and has an explicit release license/dependency check.
- **Future AWS endpoint formats:** endpoint validation must be partition-aware and covered by tests. Documentation still requires the actual RDS endpoint; unsupported formats fail closed until recognized.

## Acceptance criteria

The feature is complete when an IAM-enabled ProxySQL build can use its process AWS identity to open a certificate-verified RDS/Aurora MySQL connection for an opted-in backend user, without storing a database password; ordinary password users and SDK-free builds remain unchanged; MySQL workers do not block on AWS credential work; token material is bounded, ephemeral, redacted, and cleansed; pool/reset/error behavior matches this specification; and the build, unit, protocol, regression, sanitizer, and opt-in AWS integration coverage described above is present.
