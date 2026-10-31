#!/usr/bin/env node
/**
 * behaviors-node: node-postgres (pg) behavior CLI stub.
 *
 * CLI contract (see docs/superpowers/plans/2026-07-08-pgsql-sp3-driver-matrix.md,
 * Global Constraints): `behaviors-node <behavior>` where <behavior> is one
 * of connect, transactions, prepared, session_isolation.
 *   exit 0 -> behavior passed
 *   exit 1 -> behavior assertion failed (reason on stderr)
 *   exit 2 -> usage/infra error (unknown behavior name, not-yet-implemented
 *             behavior, missing/invalid env, etc.)
 * No stdout output is required on pass.
 *
 * All four behaviors (connect, transactions, prepared, session_isolation)
 * are implemented end to end; an unknown behavior name is the only exit-2
 * case dispatch() produces.
 *
 * Env contract (read, never invent): PGCOMPAT_PROXY_HOST (default
 * "proxysql"), PGCOMPAT_PROXY_PORT (default "6133"); user/pass/db is
 * "testuser"/"testuser"/"testuser"; ssl disabled; client_encoding pinned
 * to UTF8.
 *
 * Encoding-pin finding (verified empirically for SP3-Task-1, see report):
 * node-postgres's ConnectionParameters reads a `client_encoding` key
 * straight off the config object (lib/connection-parameters.js) and, if
 * set, sends it as a startup-packet parameter -- confirmed by inspecting
 * pg@8.13.1's source AND by `SHOW client_encoding` returning `UTF8`
 * through this exact stub against the ProxySQL PG frontend (the connect
 * behavior below asserts this on every run). No post-connect
 * `SET client_encoding` is needed for this driver.
 */
'use strict';

const { Client } = require('pg');

function clientConfig() {
  return {
    host: process.env.PGCOMPAT_PROXY_HOST || 'proxysql',
    port: parseInt(process.env.PGCOMPAT_PROXY_PORT || '6133', 10),
    user: 'testuser',
    password: 'testuser',
    database: 'testuser',
    ssl: false,
    client_encoding: 'UTF8',
  };
}

// connect: a fresh connection can run a trivial query. The simplest
// possible contract -- if this fails, nothing else is meaningful for this
// driver/target. Mirrors behaviors/connect.py, plus an explicit assertion
// that the client_encoding=UTF8 pin actually took effect (recorded SP-2
// finding; asserting it here keeps any encoding-pin regression visible in
// every run).
async function connect() {
  const client = new Client(clientConfig());
  await client.connect();
  try {
    const res = await client.query('SELECT 1');
    const one = res.rows[0]['?column?'] !== undefined ? res.rows[0]['?column?'] : Object.values(res.rows[0])[0];
    if (one !== 1) {
      throw new Error(`SELECT 1 returned ${one}, want 1`);
    }
    const encRes = await client.query('SHOW client_encoding');
    const enc = encRes.rows[0].client_encoding;
    if (enc !== 'UTF8') {
      throw new Error(`client_encoding is ${JSON.stringify(enc)}, want "UTF8" (config pin did not take effect)`);
    }
  } finally {
    await client.end();
  }
}

// txTable is per-language (parallel-safe with the other drivers' behavior
// programs, which each use their own behavior_tx_t_<lang> table -- see the
// plan's Global Constraints).
const TX_TABLE = 'behavior_tx_t_node';

// transactions: BEGIN/COMMIT/ROLLBACK are honored end-to-end through
// ProxySQL. Mirrors behaviors/transactions.py exactly, including its
// RW-split trap fix: every verification read runs inside its own explicit
// BEGIN/COMMIT so it is pinned to the same (writer) backend connection as
// the preceding INSERT/COMMIT, instead of racing replication lag on a bare
// SELECT routed to a reader hostgroup. The verify-read carries the same
// "AS verify_read" alias as the other language ports for pg_stat_statements
// traceability.
//
// node-pg trap note: `count(*)` returns PostgreSQL's int8/bigint type, which
// node-pg deliberately returns as a STRING (not a JS number) by default --
// JS numbers cannot losslessly represent the full int8 range, so pg's
// built-in type parser leaves int8 as text unless the app opts into a
// custom parser (pg-types). Comparing count to a number with `===` would
// therefore always be false even when the value is correct. This behavior
// compares against the string "0"/"1" deliberately, to reflect exactly what
// the driver hands back rather than silently coercing it away.
async function transactions() {
  const client = new Client(clientConfig());
  await client.connect();
  try {
    await client.query(`DROP TABLE IF EXISTS ${TX_TABLE}`);
    await client.query(`CREATE TABLE ${TX_TABLE} (id int)`);

    await client.query('BEGIN');
    await client.query(`INSERT INTO ${TX_TABLE} VALUES (1)`);
    await client.query('ROLLBACK');

    let count = await verifyCount(client);
    if (count !== '0') {
      throw new Error(`rollback did not discard the insert: count=${count}, want "0"`);
    }

    await client.query('BEGIN');
    await client.query(`INSERT INTO ${TX_TABLE} VALUES (2)`);
    await client.query('COMMIT');

    count = await verifyCount(client);
    if (count !== '1') {
      throw new Error(`commit did not persist the insert: count=${count}, want "1"`);
    }
  } finally {
    // Leave no state behind whether or not the assertions above passed
    // (mirrors the Python/Go/Java finally-equivalent cleanup), using a
    // table name distinct from other languages/behaviors so runs never
    // collide. If an exception above left the connection mid-transaction,
    // best-effort ROLLBACK first (catching/ignoring its own error) so the
    // DROP below is not itself rejected by an aborted transaction; a
    // cleanup failure is caught and only printed -- it must never mask the
    // original error propagating out of this try block.
    try {
      await client.query('ROLLBACK');
    } catch (e) {
      // no open/aborted transaction to roll back -- expected on the happy
      // path, ignored.
    }
    try {
      await client.query(`DROP TABLE IF EXISTS ${TX_TABLE}`);
    } catch (e) {
      process.stderr.write(`cleanup failed (suppressed, not the real error): ${e}\n`);
    }
    await client.end();
  }
}

// verifyCount runs the RW-split-safe verification read described in the
// transactions() comment above: its own explicit BEGIN/COMMIT wrapping a
// single "SELECT count(*) AS verify_read" against TX_TABLE. Returns the raw
// string node-pg hands back for int8 (see transactions()'s docstring).
async function verifyCount(client) {
  await client.query('BEGIN');
  const res = await client.query(`SELECT count(*) AS verify_read FROM ${TX_TABLE}`);
  await client.query('COMMIT');
  return res.rows[0].verify_read;
}

// prepared: a parameterized statement, reused many times, keeps working
// across ProxySQL's connection multiplexing. Mirrors behaviors/prepared.py.
//
// node-pg-specific mechanism (the value of this port): node-pg's distinct
// strategy is explicit NAMED prepared statements -- passing a `name` on the
// query config object makes node-pg send an extended-protocol Parse message
// with that statement name ONLY the first time that name is used on this
// connection; every subsequent query() call with the same `name` skips
// Parse and sends Bind+Execute only, reusing the already-parsed statement
// server-side (see pg/lib/client.js's query() -- it tracks previously
// parsed statement names per connection). Unlike psycopg3 (prepared.py,
// auto-prepares after a threshold) or pgjdbc (Behaviors.java, promotes
// after prepareThreshold executions), node-pg's named-statement reuse is
// unconditional and explicit from the very first call: every one of the 50
// iterations below -- not just a "back half" past some warm-up count --
// exercises a real extended-protocol Parse-once/Bind+Execute-many sequence
// multiplexed by ProxySQL, which is exactly the connection-pooler trap
// ("prepared statement ... does not exist") this port exists to probe.
// Placeholders are node-pg-native ($1, $2), same wire syntax as pgx --
// unlike Python's psycopg %s (see prepared.py's docstring).
async function prepared() {
  const client = new Client(clientConfig());
  await client.connect();
  try {
    for (let i = 0; i < 50; i++) {
      const res = await client.query({
        name: 'pgcompat_add',
        text: 'SELECT $1::int + $2::int AS sum',
        values: [i, 1],
      });
      // node-pg parses int4 (the ::int cast's result type) as a JS number
      // already -- unlike int8/count(*) above, no manual coercion is
      // needed here. Verified: typeof res.rows[0].sum === 'number'.
      const sum = res.rows[0].sum;
      if (typeof sum !== 'number') {
        throw new Error(`iteration ${i}: sum came back as ${typeof sum} (${JSON.stringify(sum)}), want a JS number`);
      }
      if (sum !== i + 1) {
        throw new Error(`iteration ${i}: got ${sum}, want ${i + 1}`);
      }
    }
  } finally {
    await client.end();
  }
}

// DISTINCTIVE_TZ is the session-isolation probe value. NEVER
// application_name -- ProxySQL lists it in ignore_vars, so it can never
// reflect a client SET through the proxy (see session_isolation.py's
// docstring). TimeZone is a tracked/forwarded/reset variable, so it is a
// valid probe.
const DISTINCTIVE_TZ = 'Antarctica/Troll';

// sessionIsolation: session state set on one connection must not leak to a
// different connection. Mirrors behaviors/session_isolation.py exactly,
// including closing connection A before opening B (see the Python module's
// docstring for why: it makes it possible, not guaranteed, for B to reuse
// A's just-freed backend connection, which is what makes this a real test
// of ProxySQL resetting/not-inheriting session state on reuse). Never
// application_name -- see DISTINCTIVE_TZ's comment above.
async function sessionIsolation() {
  const a = new Client(clientConfig());
  let b = null;
  let aEnded = false;
  let bEnded = false;
  await a.connect();
  try {
    await a.query(`SET TimeZone = '${DISTINCTIVE_TZ}'`);
    const tzARes = await a.query('SHOW TimeZone');
    const tzA = tzARes.rows[0].TimeZone;
    if (tzA !== DISTINCTIVE_TZ) {
      throw new Error(`SHOW TimeZone (A) = ${JSON.stringify(tzA)}, want ${JSON.stringify(DISTINCTIVE_TZ)}`);
    }
    // Close A before B opens (deliberate -- see the doc comment above).
    // The finally below ends A again as a resource-hygiene backstop on an
    // assert failure above. end() is defensive, not strictly required --
    // it is a no-op on an already-ended client in pg@8.13.1 (verified via a
    // mock server during Task 4 review); the aEnded flag is kept anyway so
    // this does not depend on that no-op behavior continuing to hold across
    // driver upgrades.
    await a.end();
    aEnded = true;

    b = new Client(clientConfig());
    await b.connect();
    const tzBRes = await b.query('SHOW TimeZone');
    const tzB = tzBRes.rows[0].TimeZone;
    if (tzB === DISTINCTIVE_TZ) {
      throw new Error(`session state leaked across connections: B's TimeZone is ${JSON.stringify(tzB)}`);
    }
    await b.end();
    bEnded = true;
  } finally {
    if (!aEnded) {
      try {
        await a.end();
      } catch (e) {
        // best-effort cleanup only
      }
    }
    if (b !== null && !bEnded) {
      try {
        await b.end();
      } catch (e) {
        // best-effort cleanup only
      }
    }
  }
}

const BEHAVIOR_FNS = {
  connect,
  transactions,
  prepared,
  session_isolation: sessionIsolation,
};

async function dispatch(behavior) {
  // hasOwnProperty guard: a prototype-chain key ("constructor", "toString")
  // must be an unknown behavior, not a callable.
  const fn = Object.prototype.hasOwnProperty.call(BEHAVIOR_FNS, behavior)
    ? BEHAVIOR_FNS[behavior] : undefined;
  if (!fn) {
    process.stderr.write(`unknown behavior: ${behavior}\n`);
    return 2;
  }
  try {
    await fn();
  } catch (err) {
    process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
    return 1;
  }
  return 0;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 1) {
    process.stderr.write('usage: behaviors-node <behavior>\n');
    process.exit(2);
  }
  process.exit(await dispatch(args[0]));
}

main();
