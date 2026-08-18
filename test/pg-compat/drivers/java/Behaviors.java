import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Properties;

/**
 * behaviors-java: Java/pgjdbc behavior CLI stub.
 *
 * CLI contract (see docs/superpowers/plans/2026-07-08-pgsql-sp3-driver-matrix.md,
 * Global Constraints): {@code behaviors-java <behavior>} where
 * {@code <behavior>} is one of connect, transactions, prepared,
 * session_isolation.
 * <ul>
 *   <li>exit 0 -&gt; behavior passed</li>
 *   <li>exit 1 -&gt; behavior assertion failed (reason on stderr)</li>
 *   <li>exit 2 -&gt; usage/infra error (unknown behavior name,
 *       not-yet-implemented behavior, missing/invalid env, etc.)</li>
 * </ul>
 * No stdout output is required on pass.
 *
 * All four behaviors (connect, transactions, prepared, session_isolation)
 * are implemented end to end; an unknown behavior name is the only exit-2
 * case {@code dispatch()} produces.
 *
 * Env contract (read, never invent): PGCOMPAT_PROXY_HOST (default
 * "proxysql"), PGCOMPAT_PROXY_PORT (default "6133"); user/pass/db is
 * "testuser"/"testuser"/"testuser"; sslmode disabled; client_encoding
 * pinned to UTF8.
 *
 * Encoding-pin finding (verified empirically for SP3-Task-1, see report):
 * pgjdbc 42.7.4 accepts the {@code options} connection property set to
 * {@code -c client_encoding=UTF8} and forwards it as a libpq-style startup
 * option -- confirmed by running {@code SHOW client_encoding} through this
 * exact stub against the ProxySQL PG frontend, which returned {@code UTF8}.
 * No post-connect {@code SET client_encoding} statement is needed.
 */
public class Behaviors {

    private static String proxyHost() {
        String h = System.getenv("PGCOMPAT_PROXY_HOST");
        return (h == null || h.isEmpty()) ? "proxysql" : h;
    }

    private static String proxyPort() {
        String p = System.getenv("PGCOMPAT_PROXY_PORT");
        return (p == null || p.isEmpty()) ? "6133" : p;
    }

    private static Connection openConnection() throws Exception {
        String url = "jdbc:postgresql://" + proxyHost() + ":" + proxyPort() + "/testuser";
        Properties props = new Properties();
        props.setProperty("user", "testuser");
        props.setProperty("password", "testuser");
        props.setProperty("sslmode", "disable");
        // Encoding pin: pgjdbc does not accept client_encoding as a direct
        // connection property, but does forward `options` as libpq-style
        // startup options -- this is the form ProxySQL/postgres accepts.
        props.setProperty("options", "-c client_encoding=UTF8");
        return DriverManager.getConnection(url, props);
    }

    // connect: a fresh connection can run a trivial query. The simplest
    // possible contract -- if this fails, nothing else is meaningful for
    // this driver/target. Mirrors behaviors/connect.py, plus an explicit
    // assertion that the options=-c client_encoding=UTF8 pin actually took
    // effect (recorded SP-2 finding; asserting it here keeps any
    // encoding-pin regression visible in every run).
    private static void connect() throws Exception {
        try (Connection conn = openConnection();
             Statement st = conn.createStatement()) {
            try (ResultSet rs = st.executeQuery("SELECT 1")) {
                if (!rs.next()) {
                    throw new AssertionError("SELECT 1 returned no rows");
                }
                int one = rs.getInt(1);
                if (one != 1) {
                    throw new AssertionError("SELECT 1 returned " + one + ", want 1");
                }
            }
            try (ResultSet rs = st.executeQuery("SHOW client_encoding")) {
                if (!rs.next()) {
                    throw new AssertionError("SHOW client_encoding returned no rows");
                }
                String enc = rs.getString(1);
                if (!"UTF8".equals(enc)) {
                    throw new AssertionError("client_encoding is \"" + enc
                            + "\", want \"UTF8\" (options pin did not take effect)");
                }
            }
        }
    }

    // txTable is per-language (parallel-safe with the other drivers' behavior
    // programs, which each use their own behavior_tx_t_<lang> table -- see
    // the plan's Global Constraints).
    private static final String TX_TABLE = "behavior_tx_t_java";

    // transactions: BEGIN/COMMIT/ROLLBACK are honored end-to-end through
    // ProxySQL. Mirrors behaviors/transactions.py exactly, including its
    // RW-split trap fix: every verification read runs inside its own
    // explicit setAutoCommit(false).../commit() pair (see verifyCount())
    // so it is pinned to the same (writer) backend connection as the
    // preceding INSERT/COMMIT, instead of racing replication lag on a bare
    // SELECT routed to a reader hostgroup. The verify-read carries the same
    // "AS verify_read" alias as the Python/Go behaviors for
    // pg_stat_statements traceability.
    private static void transactions() throws Exception {
        try (Connection conn = openConnection()) {
            try {
                try (Statement st = conn.createStatement()) {
                    st.execute("DROP TABLE IF EXISTS " + TX_TABLE);
                    st.execute("CREATE TABLE " + TX_TABLE + " (id int)");
                }

                conn.setAutoCommit(false);
                try (Statement st = conn.createStatement()) {
                    st.execute("INSERT INTO " + TX_TABLE + " VALUES (1)");
                }
                conn.rollback();
                conn.setAutoCommit(true);

                int count0 = verifyCount(conn);
                if (count0 != 0) {
                    throw new AssertionError("rollback did not discard the insert");
                }

                conn.setAutoCommit(false);
                try (Statement st = conn.createStatement()) {
                    st.execute("INSERT INTO " + TX_TABLE + " VALUES (2)");
                }
                conn.commit();
                conn.setAutoCommit(true);

                int count1 = verifyCount(conn);
                if (count1 != 1) {
                    throw new AssertionError("commit did not persist the insert");
                }
            } finally {
                // Leave no state behind whether or not the assertions above
                // passed (mirrors the Python/Go finally-equivalent cleanup),
                // using a table name distinct from other languages/behaviors
                // so runs never collide. If an exception above left
                // autocommit off mid-transaction, restore it (rollback +
                // setAutoCommit(true)) before the DROP so the connection is
                // usable; a cleanup failure here is caught and only printed
                // -- it must never mask the real error propagating out of
                // this try block.
                cleanupTable(conn, TX_TABLE);
            }
        }
    }

    // verifyCount runs the RW-split-safe verification read described in the
    // transactions() comment above: its own explicit
    // setAutoCommit(false)/commit() pair wrapping a single
    // "SELECT count(*) AS verify_read" against TX_TABLE.
    private static int verifyCount(Connection conn) throws Exception {
        conn.setAutoCommit(false);
        int count;
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT count(*) AS verify_read FROM " + TX_TABLE)) {
            if (!rs.next()) {
                throw new AssertionError("verify_read returned no rows");
            }
            count = rs.getInt(1);
        }
        conn.commit();
        conn.setAutoCommit(true);
        return count;
    }

    // cleanupTable restores the connection to a usable autocommit state (in
    // case an exception left a transaction open) and drops the table. It
    // never throws -- any failure here is printed to stderr and swallowed
    // so it cannot mask a real assertion/exception already propagating out
    // of the caller's try block.
    private static void cleanupTable(Connection conn, String table) {
        try {
            if (!conn.getAutoCommit()) {
                try {
                    conn.rollback();
                } catch (Exception ignore) {
                    // best effort; setAutoCommit below still runs
                }
                conn.setAutoCommit(true);
            }
            try (Statement st = conn.createStatement()) {
                st.execute("DROP TABLE IF EXISTS " + table);
            }
        } catch (Exception e) {
            System.err.println("cleanup failed (suppressed, not the real error): " + e);
        }
    }

    // prepared: a parameterized statement, reused many times, keeps working
    // across ProxySQL's connection multiplexing. Mirrors behaviors/prepared.py.
    //
    // pgjdbc-specific mechanism (the value of this port): pgjdbc starts every
    // PreparedStatement as a client-side-substituted "simple" query and only
    // promotes it to a real server-side NAMED statement (extended-protocol
    // Parse-once/Bind+Execute-many) once the SAME PreparedStatement object has
    // been executed more than `prepareThreshold` times (default 5; see
    // org.postgresql.jdbc.PgConnection / PGProperty.PREPARE_THRESHOLD). We
    // therefore prepare ONCE outside the loop and reuse that single
    // PreparedStatement object for all 50 executions -- re-preparing per
    // iteration would reset the threshold counter and the back half of the
    // loop would never leave simple-query mode. Past iteration 5, this test
    // is genuinely exercising a real named prepared statement multiplexed by
    // ProxySQL across its backend connection pool -- the classic
    // connection-pooler trap ("prepared statement \"S_1\" does not exist")
    // that this port exists to probe.
    private static void prepared() throws Exception {
        try (Connection conn = openConnection();
             PreparedStatement ps = conn.prepareStatement("SELECT ?::int + ?::int AS sum")) {
            for (int i = 0; i < 50; i++) {
                ps.setInt(1, i);
                ps.setInt(2, 1);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        throw new AssertionError("iteration " + i + ": no rows returned");
                    }
                    int sum = rs.getInt(1);
                    if (sum != i + 1) {
                        throw new AssertionError(
                                "iteration " + i + ": got " + sum + ", want " + (i + 1));
                    }
                }
            }
        }
    }

    // distinctiveTz is the session-isolation probe value. NEVER
    // application_name -- ProxySQL lists it in ignore_vars, so it can never
    // reflect a client SET through the proxy (see session_isolation.py's
    // docstring). TimeZone is a tracked/forwarded/reset variable, so it is a
    // valid probe.
    private static final String DISTINCTIVE_TZ = "Antarctica/Troll";

    // sessionIsolation: session state set on one connection must not leak to
    // a different connection. Mirrors behaviors/session_isolation.py
    // exactly, including closing connection A before opening B (see the
    // Python module's docstring for why: it makes it possible, not
    // guaranteed, for B to reuse A's just-freed backend connection, which is
    // what makes this a real test of ProxySQL resetting/not-inheriting
    // session state on reuse).
    private static void sessionIsolation() throws Exception {
        Connection a = null;
        Connection b = null;
        try {
            a = openConnection();
            try (Statement st = a.createStatement()) {
                st.execute("SET TimeZone = '" + DISTINCTIVE_TZ + "'");
            }
            try (Statement st = a.createStatement();
                 ResultSet rs = st.executeQuery("SHOW TimeZone")) {
                if (!rs.next()) {
                    throw new AssertionError("SHOW TimeZone (A) returned no rows");
                }
                String tzA = rs.getString(1);
                if (!DISTINCTIVE_TZ.equals(tzA)) {
                    throw new AssertionError(
                            "SHOW TimeZone (A) = \"" + tzA + "\", want \"" + DISTINCTIVE_TZ + "\"");
                }
            }
            // Close A before B opens (deliberate -- see the doc comment
            // above). The finally below closes A again as a
            // resource-hygiene backstop on an assert failure above;
            // closeQuietly() is idempotent-safe so that repeat call is a
            // safe no-op.
            a.close();

            b = openConnection();
            try (Statement st = b.createStatement();
                 ResultSet rs = st.executeQuery("SHOW TimeZone")) {
                if (!rs.next()) {
                    throw new AssertionError("SHOW TimeZone (B) returned no rows");
                }
                String tzB = rs.getString(1);
                if (DISTINCTIVE_TZ.equals(tzB)) {
                    throw new AssertionError(
                            "session state leaked across connections: B's TimeZone is \"" + tzB + "\"");
                }
            }
        } finally {
            closeQuietly(a);
            closeQuietly(b);
        }
    }

    // closeQuietly is the idempotent-safe backstop referenced above: closing
    // an already-closed (or never-opened) connection is a safe no-op, same
    // as the Python adapter's close().
    private static void closeQuietly(Connection c) {
        if (c == null) {
            return;
        }
        try {
            if (!c.isClosed()) {
                c.close();
            }
        } catch (Exception ignore) {
            // best-effort cleanup only
        }
    }

    private static int dispatch(String behavior) {
        try {
            switch (behavior) {
                case "connect":
                    connect();
                    return 0;
                case "transactions":
                    transactions();
                    return 0;
                case "prepared":
                    prepared();
                    return 0;
                case "session_isolation":
                    sessionIsolation();
                    return 0;
                default:
                    System.err.println("unknown behavior: " + behavior);
                    return 2;
            }
        } catch (UnsupportedOperationException e) {
            System.err.println(e.getMessage());
            return 2;
        } catch (AssertionError e) {
            System.err.println(e.getMessage());
            return 1;
        } catch (Exception e) {
            System.err.println(e.toString());
            return 1;
        }
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("usage: behaviors-java <behavior>");
            System.exit(2);
        }
        System.exit(dispatch(args[0]));
    }
}
