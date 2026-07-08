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
 * end (open -> SELECT 1 -> assert first col == 1 -> close). The other
 * three behaviors are stubbed to reject with "not implemented: <name>" so
 * Task 4 can fill in the function bodies below without restructuring
 * dispatch().
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
 * pg@8.13.1's source AND by running `SHOW client_encoding` through this
 * exact stub against the ProxySQL PG frontend, which returned `UTF8`.
 * No post-connect `SET client_encoding` is needed for this driver.
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
// driver/target. Mirrors behaviors/connect.py exactly.
async function connect() {
  const client = new Client(clientConfig());
  await client.connect();
  try {
    const res = await client.query('SELECT 1');
    const one = res.rows[0]['?column?'] !== undefined ? res.rows[0]['?column?'] : Object.values(res.rows[0])[0];
    if (one !== 1) {
      throw new Error(`SELECT 1 returned ${one}, want 1`);
    }
  } finally {
    await client.end();
  }
}

// transactions: filled in by Task 4. Mirrors behaviors/transactions.py.
async function transactions() {
  throw new Error('not implemented: transactions');
}

// prepared: filled in by Task 4. Mirrors behaviors/prepared.py.
async function prepared() {
  throw new Error('not implemented: prepared');
}

// sessionIsolation: filled in by Task 4. Mirrors behaviors/session_isolation.py.
async function sessionIsolation() {
  throw new Error('not implemented: session_isolation');
}

const NOT_IMPLEMENTED = new Set(['transactions', 'prepared', 'session_isolation']);

async function dispatch(behavior) {
  switch (behavior) {
    case 'connect':
      await connect();
      return 0;
    case 'transactions':
    case 'prepared':
    case 'session_isolation': {
      const fn = { transactions, prepared, session_isolation: sessionIsolation }[behavior];
      try {
        await fn();
      } catch (err) {
        if (NOT_IMPLEMENTED.has(behavior)) {
          process.stderr.write(`not implemented: ${behavior}\n`);
          return 2;
        }
        throw err;
      }
      // Once Task 4 lands, resolving without throwing means pass.
      return 0;
    }
    default:
      process.stderr.write(`unknown behavior: ${behavior}\n`);
      return 2;
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 1) {
    process.stderr.write('usage: behaviors-node <behavior>\n');
    process.exit(2);
  }
  let code;
  try {
    code = await dispatch(args[0]);
  } catch (err) {
    process.stderr.write(`${err && err.stack ? err.stack : err}\n`);
    code = 1;
  }
  process.exit(code);
}

main();
