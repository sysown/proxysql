#!/usr/bin/env node
/**
 * behaviors-node: node-postgres (pg) behavior CLI stub.
 *
 * CLI contract (see docs/superpowers/plans/2026-07-08-pgsql-driver-matrix.md,
 * Global Constraints): `behaviors-node <behavior>` where <behavior> is one
 * of connect, transactions, prepared, session_isolation.
 *   exit 0 -> behavior passed
 *   exit 1 -> behavior assertion failed (reason on stderr)
 *   exit 2 -> usage/infra error (unknown behavior name, not-yet-implemented
 *             behavior, missing/invalid env, etc.)
 * No stdout output is required on pass.
 *
 * This is the SP3-Task-1 scaffold: only `connect` is implemented end to
 * end (open -> SELECT 1 -> assert first col == 1 -> assert client_encoding
 * is UTF8 -> close). The other three behaviors throw NotImplementedError
 * (exit 2) so Task 4 can fill in the function bodies below without
 * restructuring dispatch().
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

// Sentinel distinguishing "behavior not yet wired up" (exit 2, infra/usage
// error) from a genuine assertion failure (exit 1). Stub bodies throw it;
// dispatch()'s catch checks `instanceof`, so Task 4 replaces a stub body
// with a real implementation throwing ordinary Errors and gets exit-1
// semantics automatically -- a pure body-fill, no dispatch changes.
class NotImplementedError extends Error {}

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

// transactions: filled in by Task 4. Mirrors behaviors/transactions.py.
async function transactions() {
  throw new NotImplementedError('not implemented: transactions');
}

// prepared: filled in by Task 4. Mirrors behaviors/prepared.py.
async function prepared() {
  throw new NotImplementedError('not implemented: prepared');
}

// sessionIsolation: filled in by Task 4. Mirrors behaviors/session_isolation.py.
async function sessionIsolation() {
  throw new NotImplementedError('not implemented: session_isolation');
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
    if (err instanceof NotImplementedError) {
      process.stderr.write(`${err.message}\n`);
      return 2;
    }
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
