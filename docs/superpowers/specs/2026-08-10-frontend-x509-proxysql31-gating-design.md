# Frontend X.509 Authentication: PROXYSQL31 Gating Design

**Status:** Approved design addendum

**Applies to:** `mysql_users.attributes.require_x509`, its certificate evidence, and the related initial-login, `COM_CHANGE_USER`, and pass-through authentication policy

## Goal

Treat per-user frontend X.509 authentication as a new Innovative-tier feature. It is available only in builds that define `PROXYSQL31`; `PROXYSQL40` inherits it because the build hierarchy already makes `PROXYSQL40=1` imply `PROXYSQL31=1`.

A stable v3.0.x build has no knowledge of `require_x509`. It does not look up, parse, validate, log, or enforce that key. If the key is present in the attributes JSON, v3.0.x continues applying only the attributes it already recognizes.

## Tier Contract

### Stable tier: v3.0.x

- Do not define or populate the new generic client-certificate evidence fields.
- Do not compile or call the `require_x509` policy evaluator.
- Do not inspect the `require_x509` key.
- Preserve the existing SPIFFE initial-authentication and `COM_CHANGE_USER` behavior.
- Preserve the existing stable-tier pass-through gate.
- A frontend user carrying `{"require_x509":true}` still follows ordinary v3.0.x authentication because the key is unknown to that tier.

### Innovative and later tiers: v3.1.x and v4.x

- Capture certificate presence and `SSL_get_verify_result()` once when the physical frontend TLS handshake completes.
- Enforce `require_x509` during initial login, `COM_CHANGE_USER`, and row-backed pass-through authentication.
- Require the existing password or authentication-plugin check in addition to a trusted client certificate.
- Apply the agreed SPIFFE session-origin restrictions to `COM_CHANGE_USER` without TLS renegotiation.
- Reject pass-through targets during `COM_CHANGE_USER`, preserving the existing Phase 1 contract.
- Never forward the frontend client certificate to a backend.

## Compile-Time Boundaries

Use fine-grained `#ifdef PROXYSQL31` boundaries around all new feature state and behavior:

- `MySQL_Data_Stream` certificate-presence and verification fields;
- the flag recording that the frontend session authenticated via SPIFFE;
- initialization and TLS-handshake population of those fields;
- the shared frontend certificate-policy types and evaluator;
- `require_x509` handling in initial authentication;
- new X.509/SPIFFE restrictions in `COM_CHANGE_USER`; and
- row-backed pass-through integration.

The stable `#else` path retains the pre-feature SPIFFE code. The gate must prevent a stable build from merely compiling the evaluator and short-circuiting it at runtime; the key is not a recognized feature in that tier.

## Cross-Tier Hardening

Two corrections apply unconditionally because they harden existing SPIFFE handling rather than expose `require_x509`:

- Null-check the `GENERAL_NAMES*` returned by `X509_get_ext_d2i()` before iterating it. A certificate without a SAN must not crash any tier.
- Make existing `spiffe_id` parsing, including the DEBUG helper, type-safe and exception-safe. Malformed values must not terminate the process.

Existing SPIFFE identity matching and the earlier TLS-handshake failure for an invalid certificate carrying a SPIFFE URI SAN remain unchanged.

## v3.1+ Policy and Errors

In a `PROXYSQL31` build:

- `require_x509` must be a JSON boolean.
- `true` requires TLS, a presented peer certificate, and `X509_V_OK` on the current physical connection.
- `false` adds no certificate requirement.
- Password or authentication-plugin verification remains mandatory.
- Invalid JSON, a non-boolean `require_x509`, or malformed `spiffe_id` fails closed.
- Authentication policy denials use generic MySQL error 1045; detailed configuration or certificate information is logged internally only.

The stored TLS evidence is connection-scoped and survives `COM_RESET_CONNECTION` and `COM_CHANGE_USER`. No code attempts TLS renegotiation.

## Tests and Verification

- Register the feature TAP test with `@proxysql_min_version:3.1` in addition to its server groups.
- Use a clean `PROXYSQL31=1` DEBUG build to run the complete initial-login, `COM_CHANGE_USER`, SPIFFE, malformed-attribute, and pass-through matrix.
- Use a clean default v3.0 DEBUG build to run existing authentication and TLS regressions.
- Add a focused v3.0 compatibility probe showing that a user row containing `{"require_x509":true}` still authenticates normally without a client certificate because the key is not recognized.
- Clean before changing build tiers or DEBUG/release flags; the Makefiles do not reliably invalidate objects when these flags change.
- Verify `PROXYSQL40=1` through the existing implication to `PROXYSQL31`; do not add a separate X.509 gate for v4.x.

## Non-Goals

- No new `mysql_users` column or schema change.
- No global client-certificate requirement for unknown-user pass-through.
- No PostgreSQL frontend authentication change.
- No TLS renegotiation or backend certificate forwarding.
- No change to the per-user behavior of a stable v3.0.x build beyond the unconditional crash hardening described above.
