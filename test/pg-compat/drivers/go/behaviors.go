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
// (open -> SELECT 1 -> assert first col == 1 -> close). The other three
// behaviors are stubbed to exit 2 with "not implemented: <name>" on stderr
// so Tasks 2-4 can fill in the function bodies below without restructuring
// dispatch().
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
// driver/target. Mirrors behaviors/connect.py exactly.
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
	return nil
}

// transactions: filled in by Task 2. Mirrors behaviors/transactions.py.
func transactions() error {
	return fmt.Errorf("not implemented: transactions")
}

// prepared: filled in by Task 2. Mirrors behaviors/prepared.py.
func prepared() error {
	return fmt.Errorf("not implemented: prepared")
}

// sessionIsolation: filled in by Task 2. Mirrors behaviors/session_isolation.py.
func sessionIsolation() error {
	return fmt.Errorf("not implemented: session_isolation")
}

// notImplemented is a sentinel used to distinguish "behavior not yet wired
// up" (exit 2, infra/usage error) from a genuine assertion failure
// (exit 1). Since Tasks 2-4 replace the stub bodies above with real
// implementations that return ordinary errors, dispatch() special-cases
// the not-implemented functions by name rather than by error type.
var notImplementedBehaviors = map[string]func() error{
	"transactions":      transactions,
	"prepared":          prepared,
	"session_isolation": sessionIsolation,
}

func dispatch(behavior string) int {
	switch behavior {
	case "connect":
		if err := connect(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "transactions", "prepared", "session_isolation":
		fn := notImplementedBehaviors[behavior]
		if err := fn(); err != nil {
			fmt.Fprintf(os.Stderr, "not implemented: %s\n", behavior)
			return 2
		}
		// Once Tasks 2-4 land, a nil error here means pass.
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown behavior: %q\n", behavior)
		return 2
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: behaviors-go <behavior>")
		os.Exit(2)
	}
	os.Exit(dispatch(os.Args[1]))
}
