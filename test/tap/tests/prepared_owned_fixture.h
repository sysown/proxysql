#ifndef PREPARED_OWNED_FIXTURE_H
#define PREPARED_OWNED_FIXTURE_H
// Each acceptance client owns its ProxySQL process, listeners and private data.
#include "duckdb_replica_test_utils.h"
#undef PROTOCOL_VERSION
#include <algorithm>
#include <filesystem>
#include <map>
namespace prepared_owned_fixture {
using namespace duckdb_replica_test;
struct Fixture {
    inline static std::vector<Fixture *> active;
    static void exit_cleanup() {
        while (!active.empty()) {
            Fixture *fixture = active.back();
            active.pop_back();
            fixture->cleanup();
        }
    }
    std::string dir, binary, plugin;
    pid_t pid = -1;
    MYSQL *admin = nullptr;
    std::vector<int> leases;
    std::map<std::string, std::pair<bool, std::string>> saved;
    int a, ap, m, p, d, dp;
    int port() {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t len = sizeof(addr);
        if (fd < 0 || bind(fd, (sockaddr *)&addr, len) || getsockname(fd, (sockaddr *)&addr, &len))
            BAIL_OUT("cannot reserve fixture port");
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        leases.push_back(fd);
        return ntohs(addr.sin_port);
    }
    void set(const char *key, const std::string &value) {
        const char *old = getenv(key);
        saved[key] = {old != nullptr, old ? old : ""};
        setenv(key, value.c_str(), 1);
    }
    bool config(bool load) {
        std::ofstream f(dir + "/proxysql.cnf");
        f << "admin_variables={admin_credentials=\"fixture_admin:fixture_admin\";stats_credentials="
             "\"fixture_stats:fixture_stats\";mysql_ifaces=\"127.0.0.1:"
          << a << "\";pgsql_ifaces=\"127.0.0.1:" << ap << "\";}\n"
          << "mysql_variables={threads=2;interfaces=\"127.0.0.1:" << m << "\";}\n"
          << "pgsql_variables={threads=2;interfaces=\"127.0.0.1:" << p << "\";}\n"
          << "mysql_users=({username=\"fixture_client\";password=\"fixture_client\";active=1;"
             "default_hostgroup=0;})\n"
          << "pgsql_users=({username=\"fixture_client\";password=\"fixture_client\";active=1;"
             "default_hostgroup=0;})\n";
        if (load)
            f << "plugins=(" << config_string(plugin) << ")\n";
        return bool(f);
    }
    bool start(bool load) {
        if (!config(load))
            return false;
        for (size_t i = 0; i < leases.size(); ++i) {
            if (load || i < 4) {
                close(leases[i]);
                leases[i] = -1;
            }
        }
        fflush(nullptr);
#ifdef __linux__
        pid_t parent = getpid();
#endif
        pid = fork();
        if (pid == 0) {
#ifdef __linux__
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent)
                _exit(125);
#endif
            rlimit limit{0, 0};
            setrlimit(RLIMIT_CORE, &limit);
            int log = open((dir + "/proxysql.log").c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (log < 0)
                _exit(126);
            dup2(log, 1);
            dup2(log, 2);
            close(log);
            execl(binary.c_str(), binary.c_str(), "-f", "-M", "-c",
                  (dir + "/proxysql.cnf").c_str(), "-D", dir.c_str(), (char *)nullptr);
            _exit(127);
        }
        if (pid < 0)
            return false;
        bool ready = wait_for(
            [&] {
                if (!admin)
                    admin = connect("127.0.0.1", a, "fixture_admin", "fixture_admin");
                if (!admin)
                    return false;
                if (!load)
                    return true;
                MYSQL *c = connect("127.0.0.1", d, "fixture_client", "fixture_client");
                if (c)
                    mysql_close(c);
                return c != nullptr;
            },
            10);
        if (!ready)
            diag("owned fixture failed to start; log: %s/proxysql.log", dir.c_str());
        return ready;
    }
    bool stop() {
        if (admin) {
            mysql_close(admin);
            admin = nullptr;
        }
        if (pid > 0) {
            kill(pid, SIGTERM);
            int status = 0;
            bool clean = false;
            bool reaped = wait_for(
                [&] {
                    pid_t r = waitpid(pid, &status, WNOHANG);
                    clean = r == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
                    return r == pid || (r < 0 && errno == ECHILD);
                },
                5);
            if (!reaped) {
                kill(pid, SIGKILL);
                while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
                }
            }
            pid = -1;
            return reaped && clean;
        }
        return true;
    }
    Fixture(const char *mysql_dialect = "native", bool with_duckdb = true) {
        const char *external = getenv("TAP_EMBEDDED_PREPARED_EXTERNAL");
        if (external && std::string(external) == "1") {
            if (std::string(mysql_dialect) != "native")
                BAIL_OUT("analytical tests require an owned fixture");
            return;
        }
        static const int cleanup_registered = std::atexit(exit_cleanup);
        if (cleanup_registered)
            BAIL_OUT("cannot register fixture cleanup");
        active.push_back(this);
        // mkdtemp creates the directory with mode 0700 inside the platform temporary directory
        // (TMPDIR when set), so other users cannot read or replace the fixture's files.
        std::string pattern =
            (std::filesystem::temp_directory_path() / "proxysql-prepared-XXXXXX").string();
        char *made = mkdtemp(pattern.data());
        if (!made)
            BAIL_OUT("cannot create fixture directory");
        dir = made;
        binary =
            std::filesystem::absolute(getenv("TAP_PROXYSQL_BINARY") ? getenv("TAP_PROXYSQL_BINARY")
                                                                    : PROXYSQL_TEST_BINARY)
                .string();
        plugin = std::filesystem::absolute(getenv("TAP_DUCKDB_PLUGIN") ? getenv("TAP_DUCKDB_PLUGIN")
                                                                       : DUCKDB_TEST_PLUGIN)
                     .string();
        a = port();
        ap = port();
        m = port();
        p = port();
        d = port();
        dp = port();
        if (access(binary.c_str(), X_OK) || (with_duckdb && access(plugin.c_str(), R_OK)) || !start(false)) {
            cleanup();
            BAIL_OUT("cannot start owned prepared fixture");
        }
        if (with_duckdb) {
            bool configured = query(
                admin, "INSERT OR REPLACE INTO disk.global_variables VALUES('duckdb-database_path'," +
                           quote(dir + "/prepared.duckdb") + "),('duckdb-mysql_ifaces'," +
                           quote("127.0.0.1:" + std::to_string(d)) + "),('duckdb-pgsql_ifaces'," +
                           quote("127.0.0.1:" + std::to_string(dp)) + "),('duckdb-threads','2')," +
                           "('duckdb-mysql_dialect'," + quote(mysql_dialect) + ")");
            stop();
            if (!configured || !start(true)) {
                cleanup();
                BAIL_OUT("cannot initialize owned prepared fixture");
            }
        }
        set("TAP_HOST", "127.0.0.1");
        set("TAP_USERNAME", "fixture_client");
        set("TAP_PASSWORD", "fixture_client");
        set("TAP_DUCKDB_MYSQL_PORT", std::to_string(d));
        set("TAP_DUCKDB_PGSQL_PORT", std::to_string(dp));
        set("TAP_ADMINPORT", std::to_string(a));
        set("TAP_ADMINUSERNAME", "fixture_admin");
        set("TAP_ADMINPASSWORD", "fixture_admin");
        set("TAP_STATSUSERNAME", "fixture_stats");
        set("TAP_STATSPASSWORD", "fixture_stats");
        set("TAP_PGSQL_ADMINHOST", "127.0.0.1");
        set("TAP_PGSQL_ADMINPORT", std::to_string(ap));
        set("TAP_PGSQL_ADMINUSERNAME", "fixture_admin");
        set("TAP_PGSQL_ADMINPASSWORD", "fixture_admin");
        set("TAP_PGSQL_STATSUSERNAME", "fixture_stats");
        set("TAP_PGSQL_STATSPASSWORD", "fixture_stats");
    }
    void cleanup() {
        stop();
        for (int fd : leases)
            if (fd >= 0)
                close(fd);
        leases.clear();
        for (const auto &e : saved) {
            if (e.second.first)
                setenv(e.first.c_str(), e.second.second.c_str(), 1);
            else
                unsetenv(e.first.c_str());
        }
        if (!dir.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
            if (ec)
                diag("fixture cleanup failed: %s", ec.message().c_str());
            dir.clear();
        }
    }
    Fixture(const Fixture &) = delete;
    Fixture &operator=(const Fixture &) = delete;
    ~Fixture() {
        // Destructors must not throw; a failed cleanup here is reported by cleanup() itself.
        try {
            cleanup();
        } catch (...) {
        }
        active.erase(std::remove(active.begin(), active.end(), this), active.end());
    }
};
} // namespace prepared_owned_fixture
#endif
