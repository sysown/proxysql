// behaviors-go: Go/pgx behavior CLI stub.
//
// CLI contract (see docs/superpowers/plans/2026-07-08-pgsql-sp3-driver-matrix.md,
// Global Constraints): `behaviors-go <behavior>` where <behavior> is one of
// connect, transactions, prepared, session_isolation.
//
//	exit 0 -> behavior passed
//	exit 1 -> behavior assertion failed (reason on stderr)
//	exit 2 -> usage/infra error (unknown behavior name, not-yet-implemented
//	          behavior, missing/invalid env, etc.)
//
// No stdout output is required on pass.
//
// All four behaviors (connect, transactions, prepared, session_isolation)
// are implemented end to end; an unknown behavior name is the only exit-2
// case dispatch() produces.
//
// Env contract (read, never invent): PGCOMPAT_PROXY_HOST (default
// "proxysql"), PGCOMPAT_PROXY_PORT (default "6133"); user/pass/db is
// "testuser"/"testuser"/"testuser"; sslmode disabled; client_encoding
// pinned to UTF8 (backend DBs default to SQL_ASCII; ProxySQL imposes
// UTF8 -- see xfail.toml finding referenced in the plan).
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
)

func dsn() string {
	host := os.Getenv("PGCOMPAT_PROXY_HOST")
	if host == "" {
		host = "proxysql"
	}
	port := os.Getenv("PGCOMPAT_PROXY_PORT")
	if port == "" {
		port = "6133"
	}
	return fmt.Sprintf(
		"postgres://testuser:testuser@%s:%s/testuser?sslmode=disable&client_encoding=UTF8",
		host, port,
	)
}

// connect: a fresh connection can run a trivial query. The simplest
// possible contract -- if this fails, nothing else is meaningful for this
// driver/target. Mirrors behaviors/connect.py, plus an explicit assertion
// that the DSN's client_encoding=UTF8 pin actually took effect (the pin is
// a recorded SP-2 finding; asserting it here keeps any encoding-pin
// regression visible in every run).
func connect() error {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn())
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)

	var one int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("SELECT 1: %w", err)
	}
	if one != 1 {
		return fmt.Errorf("SELECT 1 returned %d, want 1", one)
	}

	var enc string
	if err := conn.QueryRow(ctx, "SHOW client_encoding").Scan(&enc); err != nil {
		return fmt.Errorf("SHOW client_encoding: %w", err)
	}
	if enc != "UTF8" {
		return fmt.Errorf("client_encoding is %q, want \"UTF8\" (DSN pin did not take effect)", enc)
	}
	return nil
}

// txTable is per-language (parallel-safe with the other drivers' behavior
// programs, which each use their own behavior_tx_t_<lang> table; see the
// plan's Global Constraints).
const txTable = "behavior_tx_t_go"

// transactions: BEGIN/COMMIT/ROLLBACK are honored end-to-end through
// ProxySQL. Mirrors behaviors/transactions.py exactly, including its
// RW-split trap fix: every verification read runs inside its own explicit
// BEGIN/COMMIT (via conn.Begin(ctx)/tx.Commit(ctx)) so it is pinned to the
// same (writer) backend connection as the preceding INSERT/COMMIT, instead
// of racing replication lag on a bare SELECT routed to a reader hostgroup.
// The verify-read carries the same "AS verify_read" alias as the Python
// behavior for pg_stat_statements traceability.
func transactions() error {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn())
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)

	// Cleanup runs on success AND on failure (defer), leaving no state
	// behind, same as the Python behavior's try/finally. Parity with
	// Java/Node/Prisma: best-effort ROLLBACK first (error ignored) restores
	// a usable session state before the DROP -- if a non-assertion error
	// above left the connection mid-transaction, an aborted implicit
	// transaction would otherwise reject the DROP.
	defer func() {
		conn.Exec(ctx, "ROLLBACK")
		conn.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", txTable))
	}()

	if _, err := conn.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", txTable)); err != nil {
		return fmt.Errorf("DROP TABLE IF EXISTS: %w", err)
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (id int)", txTable)); err != nil {
		return fmt.Errorf("CREATE TABLE: %w", err)
	}

	tx1, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("BEGIN (insert 1): %w", err)
	}
	if _, err := tx1.Exec(ctx, fmt.Sprintf("INSERT INTO %s VALUES (1)", txTable)); err != nil {
		return fmt.Errorf("INSERT (1): %w", err)
	}
	if err := tx1.Rollback(ctx); err != nil {
		return fmt.Errorf("ROLLBACK: %w", err)
	}

	count, err := verifyCount(ctx, conn)
	if err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("rollback did not discard the insert: count=%d, want 0", count)
	}

	tx2, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("BEGIN (insert 2): %w", err)
	}
	if _, err := tx2.Exec(ctx, fmt.Sprintf("INSERT INTO %s VALUES (2)", txTable)); err != nil {
		return fmt.Errorf("INSERT (2): %w", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		return fmt.Errorf("COMMIT (insert 2): %w", err)
	}

	count, err = verifyCount(ctx, conn)
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("commit did not persist the insert: count=%d, want 1", count)
	}

	return nil
}

// verifyCount runs the RW-split-safe verification read described in the
// transactions() comment above: its own explicit BEGIN...COMMIT wrapping a
// single "SELECT count(*) AS verify_read" against txTable.
func verifyCount(ctx context.Context, conn *pgx.Conn) (int, error) {
	vtx, err := conn.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("BEGIN (verify): %w", err)
	}
	var count int
	if err := vtx.QueryRow(ctx, fmt.Sprintf("SELECT count(*) AS verify_read FROM %s", txTable)).Scan(&count); err != nil {
		return 0, fmt.Errorf("verify SELECT: %w", err)
	}
	if err := vtx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("COMMIT (verify): %w", err)
	}
	return count, nil
}

// prepared: a parameterized statement, reused many times, keeps working
// across ProxySQL's connection multiplexing. Mirrors behaviors/prepared.py.
//
// Exec mode in play: pgx v5's default QueryExecMode is
// QueryExecModeCacheStatement ("cache_statement") -- pgx.Connect does not
// override it here, so this is the mode used. Under cache_statement, pgx
// consults its per-connection statement cache (keyed by SQL text) FIRST:
// only a cache miss -- the first occurrence of a given SQL text -- sends an
// extended-protocol Parse (via Prepare); every subsequent call with the
// same SQL text goes through execPrepared, i.e. Bind/Execute only against
// the already-parsed server-side statement (pgx v5.7.5 conn.go, the
// QueryExecModeCacheStatement branches; also its QueryExecMode doc comment:
// "Queries are executed in a single round trip after the statement is
// cached"). In the 50x loop below that means iteration 0 Parses once and
// iterations 1-49 are Bind/Execute-only reuse of one server-side prepared
// statement -- so every iteration exercises real extended-protocol prepared
// statements multiplexed by ProxySQL, with no warm-up threshold to cross
// (unlike psycopg3's prepare_threshold -- see prepared.py's docstring);
// the loop's job is to prove that cached server-side statement keeps
// resolving correctly across many round trips through the proxy.
// Placeholders are pgx-native ($1, $2), unlike Python's psycopg %s -- see
// the plan's Global Constraints on driver-native placeholder syntax.
func prepared() error {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn())
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)

	for i := 0; i < 50; i++ {
		var sum int
		if err := conn.QueryRow(ctx, "SELECT $1::int + $2::int", i, 1).Scan(&sum); err != nil {
			return fmt.Errorf("iteration %d: %w", i, err)
		}
		if sum != i+1 {
			return fmt.Errorf("iteration %d: got %d, want %d", i, sum, i+1)
		}
	}
	return nil
}

// distinctiveTZ is the session-isolation probe value. NEVER application_name
// -- ProxySQL lists it in ignore_vars, so it can never reflect a client SET
// through the proxy (see session_isolation.py's docstring). TimeZone is a
// tracked/forwarded/reset variable, so it is a valid probe.
const distinctiveTZ = "Antarctica/Troll"

// sessionIsolation: session state set on one connection must not leak to a
// different connection. Mirrors behaviors/session_isolation.py exactly,
// including closing connection A before opening B (see the module's
// docstring for why: it makes it possible, not guaranteed, for B to reuse
// A's just-freed backend connection, which is what makes this a real test
// of ProxySQL resetting/not-inheriting session state on reuse).
func sessionIsolation() error {
	ctx := context.Background()
	a, err := pgx.Connect(ctx, dsn())
	if err != nil {
		return fmt.Errorf("connect A: %w", err)
	}
	var b *pgx.Conn
	defer func() {
		// Idempotent-safe backstop, matching the Python finally: closing A
		// again after the deliberate early close below is a safe no-op.
		if a != nil {
			a.Close(ctx)
		}
		if b != nil {
			b.Close(ctx)
		}
	}()

	if _, err := a.Exec(ctx, fmt.Sprintf("SET TimeZone = '%s'", distinctiveTZ)); err != nil {
		return fmt.Errorf("SET TimeZone (A): %w", err)
	}
	var tzA string
	if err := a.QueryRow(ctx, "SHOW TimeZone").Scan(&tzA); err != nil {
		return fmt.Errorf("SHOW TimeZone (A): %w", err)
	}
	if tzA != distinctiveTZ {
		return fmt.Errorf("SHOW TimeZone (A) = %q, want %q", tzA, distinctiveTZ)
	}
	// Close A before B opens (deliberate -- see the doc comment above).
	if err := a.Close(ctx); err != nil {
		return fmt.Errorf("close A: %w", err)
	}

	b, err = pgx.Connect(ctx, dsn())
	if err != nil {
		return fmt.Errorf("connect B: %w", err)
	}
	var tzB string
	if err := b.QueryRow(ctx, "SHOW TimeZone").Scan(&tzB); err != nil {
		return fmt.Errorf("SHOW TimeZone (B): %w", err)
	}
	if tzB == distinctiveTZ {
		return fmt.Errorf("session state leaked across connections: B's TimeZone is %q", tzB)
	}
	return nil
}

func dispatch(behavior string) int {
	var fn func() error
	switch behavior {
	case "connect":
		fn = connect
	case "transactions":
		fn = transactions
	case "prepared":
		fn = prepared
	case "session_isolation":
		fn = sessionIsolation
	default:
		fmt.Fprintf(os.Stderr, "unknown behavior: %q\n", behavior)
		return 2
	}
	if err := fn(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: behaviors-go <behavior>")
		os.Exit(2)
	}
	os.Exit(dispatch(os.Args[1]))
}
