import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Properties;

/**
 * behaviors-java: Java/pgjdbc behavior CLI stub.
 *
 * CLI contract (see docs/superpowers/plans/2026-07-08-pgsql-driver-matrix.md,
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
 * This is the SP3-Task-1 scaffold: only {@code connect} is implemented end
 * to end (open -&gt; SELECT 1 -&gt; assert first col == 1 -&gt; assert
 * client_encoding is UTF8 -&gt; close). The
 * other three behaviors are stubbed to exit 2 with "not implemented:
 * &lt;name&gt;" on stderr so Task 3 can fill in the method bodies below
 * without restructuring {@code dispatch()}.
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

    // transactions: filled in by Task 3. Mirrors behaviors/transactions.py.
    private static void transactions() throws Exception {
        throw new UnsupportedOperationException("not implemented: transactions");
    }

    // prepared: filled in by Task 3. Mirrors behaviors/prepared.py.
    private static void prepared() throws Exception {
        throw new UnsupportedOperationException("not implemented: prepared");
    }

    // sessionIsolation: filled in by Task 3. Mirrors behaviors/session_isolation.py.
    private static void sessionIsolation() throws Exception {
        throw new UnsupportedOperationException("not implemented: session_isolation");
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
