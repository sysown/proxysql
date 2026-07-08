#!/usr/bin/env node
/**
 * behaviors-prisma: Prisma ORM behavior CLI (SP3-Task 5, the ORM tier).
 *
 * CLI contract (see docs/superpowers/plans/2026-07-08-pgsql-sp3-driver-matrix.md,
 * Global Constraints): `behaviors-prisma <behavior>` where <behavior> is one
 * of connect, transactions, prepared, session_isolation.
 *   exit 0 -> behavior passed
 *   exit 1 -> behavior assertion failed (reason on stderr)
 *   exit 2 -> usage error only (unknown behavior name / wrong arg count).
 * All four behaviors are implemented, so there is no NotImplementedError /
 * "not yet wired" exit-2 path -- exit 2 is reserved for CLI misuse.
 * No stdout output is required on pass.
 *
 * Why Prisma is in scope (and why failures here are FINDINGS, not blockers):
 * Prisma is the notorious connection-pooler breaker. Its query engine (a
 * Rust binary) ALWAYS speaks the extended protocol with server-side prepared
 * statements and makes its own connection-pooling assumptions, which is
 * exactly the combination that trips proxies that multiplex client sessions
 * across a smaller set of backend connections. A behavior that works direct
 * but fails through ProxySQL is a catalogued [[xfail]], not a bug to hide.
 *
 * ---- Env / URL contract (deliberately unchanged from the other drivers) ----
 * The harness only ever sets PGCOMPAT_PROXY_HOST (default "proxysql") and
 * PGCOMPAT_PROXY_PORT (default "6133"); user/pass/db is
 * "testuser"/"testuser"/"testuser", ssl disabled. Prisma's datasource in
 * schema.prisma reads url = env("PGCOMPAT_PRISMA_URL"), so this program
 * CONSTRUCTS that URL from the two proxy vars and injects it into
 * process.env BEFORE instantiating any PrismaClient. That keeps the env
 * contract identical to the other language programs (no new required vars):
 * the schema's env() simply reads what this program planted.
 *
 * connection_limit=1 is pinned in the URL on purpose (see session_isolation
 * below): Prisma maintains an INTERNAL connection pool per PrismaClient, so
 * without this pin a SET on one query and a SHOW on the next could land on
 * two different pooled backend connections WITHIN THE SAME CLIENT -- a false
 * "leak" that has nothing to do with ProxySQL. Pinning the client to exactly
 * one connection makes every statement issued through a given PrismaClient
 * hit the same connection, so the isolation probe measures cross-CLIENT
 * (i.e. cross backend-connection) state, which is the contract under test.
 */
'use strict';

// Build PGCOMPAT_PRISMA_URL from the proxy env vars and plant it BEFORE the
// PrismaClient import is instantiated. (ESM import bindings are resolved
// first, but PrismaClient reads the datasource env only when a client is
// constructed, so setting it here -- top of the module body -- is in time.)
const HOST = process.env.PGCOMPAT_PROXY_HOST || 'proxysql';
const PORT = process.env.PGCOMPAT_PROXY_PORT || '6133';
process.env.PGCOMPAT_PRISMA_URL =
  `postgresql://testuser:testuser@${HOST}:${PORT}/testuser` +
  `?sslmode=disable&connection_limit=1`;

import { PrismaClient } from '@prisma/client';

// TX_TABLE is per-language (parallel-safe with the other drivers' behavior
// programs, which each use their own behavior_tx_t_<lang> table -- see the
// plan's Global Constraints).
const TX_TABLE = 'behavior_tx_t_prisma';

// DISTINCTIVE_TZ is the session-isolation probe value. NEVER
// application_name -- ProxySQL lists it in ignore_vars, so it can never
// reflect a client SET through the proxy (see session_isolation.py's
// docstring). TimeZone is a tracked/forwarded/reset variable, a valid probe.
const DISTINCTIVE_TZ = 'Antarctica/Troll';

// newClient: the shared client-factory every behavior uses. Besides
// constructing the PrismaClient it applies the client_encoding=UTF8 pin the
// Global Constraints mark MUST-reproduce for every port.
//
// Encoding-pin mechanism (empirical answer, Task 5 review; evidence in the
// SP3-Task 5 report): Prisma's PostgreSQL connector does NOT propagate a
// `client_encoding` URL param -- it is accepted but IGNORED. Probed direct
// against the SQL_ASCII primary (so ProxySQL's own UTF8-forcing could not
// confound the answer): with NO param `SHOW client_encoding` already
// returns UTF8 (the Rust query engine unconditionally sets UTF8 on its
// connections), and even `client_encoding=LATIN1` in the URL still yields
// UTF8 -- proof the param is discarded, while psycopg direct with no pin
// sees the true backend default SQL_ASCII. So the engine structurally
// guarantees UTF8 today; the explicit SET below is the pgjdbc-precedent
// fallback (URL param doesn't propagate -> SET right after construction),
// keeping this port's pin EXPLICIT like the other four instead of relying
// on an undocumented engine default. connection_limit=1 (module header)
// guarantees the SET lands on the same single connection every subsequent
// statement of this client uses.
async function newClient() {
  const prisma = new PrismaClient();
  await prisma.$executeRawUnsafe("SET client_encoding TO 'UTF8'");
  return prisma;
}

// firstVal: pull the single scalar out of a one-row/one-column raw result,
// independent of what Prisma named the column (SHOW returns "TimeZone",
// "client_encoding", etc.). Mirrors the other drivers' Object.values() dance.
function firstVal(rows) {
  return Object.values(rows[0])[0];
}

// connect: a fresh client can run a trivial query, and the client_encoding
// pin ProxySQL imposes is visible. Mirrors behaviors/connect.py plus the
// UTF8 assertion the node port also carries (recorded SP-2 finding: the
// SQL_ASCII backend reports UTF8 through ProxySQL).
async function connect() {
  const prisma = await newClient();
  try {
    // int4 literal -> Prisma returns a JS number for `one`; coerce with
    // Number() defensively and compare to 1.
    const rows = await prisma.$queryRaw`SELECT 1 AS one`;
    const one = Number(firstVal(rows));
    if (one !== 1) {
      throw new Error(`SELECT 1 returned ${one}, want 1`);
    }
    const enc = firstVal(await prisma.$queryRawUnsafe('SHOW client_encoding'));
    if (enc !== 'UTF8') {
      throw new Error(`client_encoding is ${JSON.stringify(enc)}, want "UTF8" (ProxySQL pin did not take effect)`);
    }
  } finally {
    await prisma.$disconnect();
  }
}

// verifyCount runs the RW-split-safe verification read INSIDE its own
// $transaction (Prisma interactive transaction). Mirrors the other ports'
// "verify read inside its own BEGIN/COMMIT": BEGIN does not match ^SELECT so
// it takes the writer hostgroup, and ProxySQL pins the whole interactive
// transaction to that one backend connection -- so the count is read from
// the same node the INSERT/COMMIT hit, never a lagging replica. The
// count(*)::int cast is deliberate: count(*) is int8, which Prisma would
// return as a JS BigInt; casting to int4 makes Prisma hand back a plain JS
// number so the `=== 0` / `=== 1` comparisons below are apples-to-apples.
// The cast also preserves the distinctive `AS verify_read` alias used for
// pg_stat_statements traceability across all the language ports.
async function verifyCount(prisma) {
  const rows = await prisma.$transaction(async (tx) => {
    return tx.$queryRawUnsafe(`SELECT count(*)::int AS verify_read FROM ${TX_TABLE}`);
  });
  return Number(rows[0].verify_read);
}

// transactions: $transaction rollback/commit semantics honored end-to-end.
// Mirrors behaviors/transactions.py; the ORM adaptation of "rollback" is the
// documented one: in a Prisma INTERACTIVE transaction there is no explicit
// rollback() call -- THROWING out of the callback makes Prisma roll the
// transaction back. So the rollback leg wraps the INSERT in $transaction and
// deliberately throws "force-rollback", which we catch; the committing leg
// simply returns normally from the callback, so Prisma COMMITs.
async function transactions() {
  const prisma = await newClient();
  try {
    await prisma.$executeRawUnsafe(`DROP TABLE IF EXISTS ${TX_TABLE}`);
    await prisma.$executeRawUnsafe(`CREATE TABLE ${TX_TABLE} (id int)`);

    // Rollback leg: throw inside the interactive txn -> Prisma rolls back.
    let rolledBack = false;
    try {
      await prisma.$transaction(async (tx) => {
        await tx.$executeRawUnsafe(`INSERT INTO ${TX_TABLE} VALUES (1)`);
        throw new Error('force-rollback');
      });
    } catch (e) {
      if (e && e.message === 'force-rollback') {
        rolledBack = true;
      } else {
        throw e; // an UNEXPECTED error (e.g. proxy rejected the statement)
      }
    }
    if (!rolledBack) {
      throw new Error('interactive transaction did not throw as expected for the rollback leg');
    }

    let count = await verifyCount(prisma);
    if (count !== 0) {
      throw new Error(`rollback did not discard the insert: count=${count}, want 0`);
    }

    // Commit leg: return normally -> Prisma commits.
    await prisma.$transaction(async (tx) => {
      await tx.$executeRawUnsafe(`INSERT INTO ${TX_TABLE} VALUES (2)`);
    });

    count = await verifyCount(prisma);
    if (count !== 1) {
      throw new Error(`commit did not persist the insert: count=${count}, want 1`);
    }
  } finally {
    // Leave no state behind whether or not the assertions above passed
    // (mirrors the other ports' finally-equivalent cleanup). A cleanup
    // failure is caught and only printed -- it must never mask the original
    // error propagating out of this try block.
    try {
      await prisma.$executeRawUnsafe(`DROP TABLE IF EXISTS ${TX_TABLE}`);
    } catch (e) {
      process.stderr.write(`cleanup failed (suppressed, not the real error): ${e}\n`);
    }
    await prisma.$disconnect();
  }
}

// prepared: a parameterized statement, reused many times, keeps working
// across ProxySQL's connection multiplexing. Mirrors behaviors/prepared.py.
//
// Prisma's distinct (and most-hostile-to-poolers) mechanism: its Rust query
// engine ALWAYS uses the extended protocol with server-side prepared
// statements -- there is no "simple text substitution" mode and no
// threshold to cross (unlike psycopg3's auto-prepare@5 or pgjdbc's
// prepareThreshold). Every one of the 50 $queryRaw calls below therefore
// issues a real Parse/Bind/Execute the engine multiplexes over its single
// (connection_limit is 1 here) backend connection. The tagged-template
// interpolation ${i}/${1} becomes bound parameters $1/$2 -- NOT text
// splicing -- which is exactly the prepared-statement path this port exists
// to probe through the proxy.
async function prepared() {
  const prisma = await newClient();
  try {
    for (let i = 0; i < 50; i++) {
      // ::int (int4) result -> Prisma returns a JS number for `sum`
      // (int8/BigInt would only appear for an uncast count()/bigint column;
      // verified empirically that int4 comes back as number). Number() makes
      // the coercion explicit and tolerant if a build ever returns BigInt.
      const rows = await prisma.$queryRaw`SELECT ${i}::int + ${1}::int AS sum`;
      const sum = Number(rows[0].sum);
      if (sum !== i + 1) {
        throw new Error(`iteration ${i}: got ${sum}, want ${i + 1}`);
      }
    }
  } finally {
    await prisma.$disconnect();
  }
}

// sessionIsolation: session state set on one CLIENT must not leak to a
// different CLIENT. Mirrors behaviors/session_isolation.py, including
// closing A before opening B (so B *can* reuse A's just-freed backend
// connection -- the reuse case ProxySQL must reset). Two PrismaClient
// instances, each pinned to connection_limit=1 (see the module header) so
// the SET and the SHOW on A are guaranteed to run on the SAME backend
// connection within A -- otherwise Prisma's internal pool could scatter them
// and produce a false negative unrelated to ProxySQL.
async function sessionIsolation() {
  const a = await newClient();
  let b = null;
  let aClosed = false;
  try {
    await a.$executeRawUnsafe(`SET TimeZone = '${DISTINCTIVE_TZ}'`);
    const tzA = firstVal(await a.$queryRawUnsafe('SHOW TimeZone'));
    if (tzA !== DISTINCTIVE_TZ) {
      throw new Error(`SHOW TimeZone (A) = ${JSON.stringify(tzA)}, want ${JSON.stringify(DISTINCTIVE_TZ)}`);
    }
    // Disconnect A before B connects (deliberate -- see the doc comment).
    await a.$disconnect();
    aClosed = true;

    b = await newClient();
    const tzB = firstVal(await b.$queryRawUnsafe('SHOW TimeZone'));
    if (tzB === DISTINCTIVE_TZ) {
      throw new Error(`session state leaked across connections: B's TimeZone is ${JSON.stringify(tzB)}`);
    }
    await b.$disconnect();
    b = null;
  } finally {
    if (!aClosed) {
      try { await a.$disconnect(); } catch (e) { /* best-effort cleanup */ }
    }
    if (b !== null) {
      try { await b.$disconnect(); } catch (e) { /* best-effort cleanup */ }
    }
  }
}

const BEHAVIOR_FNS = {
  connect,
  transactions,
  prepared,
  session_isolation: sessionIsolation,
};

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 1) {
    process.stderr.write('usage: behaviors-prisma <behavior>\n');
    process.exit(2);
  }
  const behavior = args[0];
  const fn = Object.prototype.hasOwnProperty.call(BEHAVIOR_FNS, behavior)
    ? BEHAVIOR_FNS[behavior] : undefined;
  if (!fn) {
    process.stderr.write(`unknown behavior: ${behavior}\n`);
    process.exit(2);
  }
  try {
    await fn();
  } catch (err) {
    // Any error out of a behavior body is a behavior assertion failure
    // (exit 1) -- including a proxy rejecting a Prisma prepared statement,
    // which is precisely the finding this program exists to surface.
    process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
    process.exit(1);
  }
  process.exit(0);
}

main();
