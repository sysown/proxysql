// behaviors-go: Go/pgx behavior CLI stub.
//
// CLI contract (see docs/superpowers/plans/2026-07-08-pgsql-driver-matrix.md,
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
// This is the SP3-Task-1 scaffold: only `connect` is implemented end to end
// (open -> SELECT 1 -> assert first col == 1 -> assert client_encoding is
// UTF8 -> close). The other three behaviors are stubbed to exit 2 with
// "not implemented: <name>" on stderr so Tasks 2-4 can fill in the function
// bodies below without restructuring dispatch().
//
// Env contract (read, never invent): PGCOMPAT_PROXY_HOST (default
// "proxysql"), PGCOMPAT_PROXY_PORT (default "6133"); user/pass/db is
// "testuser"/"testuser"/"testuser"; sslmode disabled; client_encoding
// pinned to UTF8 (backend DBs default to SQL_ASCII; ProxySQL imposes
// UTF8 -- see xfail.toml finding referenced in the plan).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
)

// errNotImplemented is the sentinel distinguishing "behavior not yet wired
// up" (exit 2, infra/usage error) from a genuine assertion failure
// (exit 1). Stub bodies wrap it with %w; dispatch() checks errors.Is, so
// Task 2 replaces a stub body with a real implementation returning
// ordinary errors and gets exit-1 semantics automatically -- a pure
// body-fill, no dispatch changes.
var errNotImplemented = errors.New("not implemented")

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

// transactions: filled in by Task 2. Mirrors behaviors/transactions.py.
func transactions() error {
	return fmt.Errorf("%w: transactions", errNotImplemented)
}

// prepared: filled in by Task 2. Mirrors behaviors/prepared.py.
func prepared() error {
	return fmt.Errorf("%w: prepared", errNotImplemented)
}

// sessionIsolation: filled in by Task 2. Mirrors behaviors/session_isolation.py.
func sessionIsolation() error {
	return fmt.Errorf("%w: session_isolation", errNotImplemented)
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
		if errors.Is(err, errNotImplemented) {
			return 2
		}
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
