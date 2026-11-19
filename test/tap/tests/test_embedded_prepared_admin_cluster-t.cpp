#include "prepared_owned_fixture.h"
#include "tap.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <libpq-fe.h>
#include <memory>
#include <string>
#include <thread>

namespace {
using prepared_owned_fixture::Fixture;
using duckdb_replica_test::cell;
using duckdb_replica_test::query;
using duckdb_replica_test::wait_for;

struct Traffic {
    std::atomic<bool> pause{false};
    std::atomic<bool> release{false};
    std::atomic<unsigned> parked{0};

    void park() {
        ++parked;
        while (!release)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
};

struct Client {
    std::atomic<unsigned> completed{0};
    std::atomic<bool> failed{false};
};

void mysql_traffic(int port, bool stats, Traffic &traffic, Client &client) {
    mysql_thread_init();
    const char *user = stats ? "fixture_stats" : "fixture_admin";
    std::unique_ptr<MYSQL, decltype(&mysql_close)> connection(
        duckdb_replica_test::connect("127.0.0.1", port, user, user), mysql_close);
    std::unique_ptr<MYSQL_STMT, decltype(&mysql_stmt_close)> statement(
        connection ? mysql_stmt_init(connection.get()) : nullptr, mysql_stmt_close);
    if (!statement || mysql_stmt_prepare(statement.get(), "SELECT ?", 8)) {
        client.failed = true;
        statement.reset();
        connection.reset();
        mysql_thread_end();
        return;
    }
    int input = 7;
    char result[16]{};
    unsigned long result_size = 0;
    MYSQL_BIND in{}, out{};
    in.buffer_type = MYSQL_TYPE_LONG;
    in.buffer = &input;
    out.buffer_type = MYSQL_TYPE_STRING;
    out.buffer = result;
    out.buffer_length = sizeof(result);
    out.length = &result_size;
    if (mysql_stmt_bind_param(statement.get(), &in) ||
        mysql_stmt_bind_result(statement.get(), &out)) {
        client.failed = true;
    }
    while (!client.failed && !traffic.pause) {
        bool good = !mysql_stmt_execute(statement.get()) &&
                    !mysql_stmt_fetch(statement.get()) &&
                    result_size == 1 && result[0] == '7' &&
                    mysql_stmt_fetch(statement.get()) == MYSQL_NO_DATA;
        if (!good || mysql_stmt_free_result(statement.get())) {
            client.failed = true;
            break;
        }
        ++client.completed;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    if (!client.failed)
        traffic.park();
    statement.reset();
    connection.reset();
    mysql_thread_end();
}

void pgsql_traffic(int port, bool stats, Traffic &traffic, Client &client) {
    const std::string port_text = std::to_string(port);
    const char *user = stats ? "fixture_stats" : "fixture_admin";
    const char *keys[] = {"host", "port", "user", "password", "dbname", "sslmode",
                          "connect_timeout", nullptr};
    const char *values[] = {"127.0.0.1", port_text.c_str(), user, user, "main", "disable",
                            "3", nullptr};
    std::unique_ptr<PGconn, decltype(&PQfinish)> connection(
        PQconnectdbParams(keys, values, 0), PQfinish);
    if (!connection || PQstatus(connection.get()) != CONNECTION_OK) {
        client.failed = true;
        return;
    }
    const Oid text = 25;
    std::unique_ptr<PGresult, decltype(&PQclear)> result(
        PQprepare(connection.get(), "work", "SELECT $1", 1, &text), PQclear);
    if (PQresultStatus(result.get()) != PGRES_COMMAND_OK) {
        client.failed = true;
        return;
    }
    const char *bound[] = {"prepared"};
    while (!traffic.pause) {
        result.reset(PQexecPrepared(connection.get(), "work", 1, bound, nullptr, nullptr, 0));
        if (PQresultStatus(result.get()) != PGRES_TUPLES_OK || PQntuples(result.get()) != 1 ||
            PQnfields(result.get()) != 1 || PQgetisnull(result.get(), 0, 0) ||
            strcmp(PQgetvalue(result.get(), 0, 0), bound[0])) {
            client.failed = true;
            return;
        }
        ++client.completed;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    traffic.park();
}

bool cluster_credentials(MYSQL *admin) {
    return query(admin, "SET admin-admin_credentials='fixture_admin:fixture_admin;"
                        "fixture_cluster:fixture_cluster'") &&
           query(admin, "SET admin-cluster_username='fixture_cluster'") &&
           query(admin, "SET admin-cluster_password='fixture_cluster'") &&
           query(admin, "SET admin-cluster_check_interval_ms=100") &&
           query(admin, "SET admin-cluster_mysql_query_rules_diffs_before_sync=2") &&
           query(admin, "SET admin-cluster_admin_variables_diffs_before_sync=0") &&
           query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
}

bool cluster_peers(Fixture &node, const std::string &members) {
    return query(node.admin, "INSERT INTO proxysql_servers(hostname,port,weight) VALUES " + members) &&
           query(node.admin, "LOAD PROXYSQL SERVERS TO RUNTIME");
}

std::string rule_comment(MYSQL *admin) {
    return cell(admin, "SELECT coalesce(max(comment),'') FROM runtime_mysql_query_rules "
                       "WHERE rule_id=6648");
}

bool progress_after(Client (&clients)[4], const unsigned (&before)[4]) {
    for (unsigned i=0; i<4; ++i) {
        if (clients[i].failed || clients[i].completed <= before[i])
            return false;
    }
    return true;
}
} // namespace

int main() {
    plan(NO_PLAN);
    if (getenv("TAP_EMBEDDED_PREPARED_EXTERNAL"))
        BAIL_OUT("Cluster test requires two owned ProxySQL processes");
    alarm(80);
    Fixture a("native", false);
    Fixture b("native", false);

    if (!cluster_credentials(a.admin) || !cluster_credentials(b.admin))
        BAIL_OUT("cannot configure private Cluster credentials");
    const std::string members = "('127.0.0.1'," + std::to_string(a.a) + ",0),"
                                "('127.0.0.1'," + std::to_string(b.a) + ",0)";
    if (!cluster_peers(a, members) || !cluster_peers(b, members))
        BAIL_OUT("cannot register private Cluster peers");

    ok(rule_comment(a.admin).empty() && rule_comment(b.admin).empty(),
       "test rule is absent from both peers before the write");

    Traffic traffic;
    Client clients[4];
    std::thread workers[] = {
        std::thread(mysql_traffic, a.a, false, std::ref(traffic), std::ref(clients[0])),
        std::thread(pgsql_traffic, a.ap, true, std::ref(traffic), std::ref(clients[1])),
        std::thread(mysql_traffic, b.a, true, std::ref(traffic), std::ref(clients[2])),
        std::thread(pgsql_traffic, b.ap, false, std::ref(traffic), std::ref(clients[3])),
    };
    const unsigned zero[4]{};
    bool started = wait_for([&] { return progress_after(clients, zero); }, 5);
    ok(started, "all four prepared clients execute on both Admin and STATS roles");
    unsigned before[4]{};
    for (unsigned i=0; i<4; ++i)
        before[i] = clients[i].completed;

    const bool loaded = started &&
        query(a.admin, "INSERT INTO mysql_query_rules(rule_id,active,match_digest,apply,comment) "
                       "VALUES (6648,1,'^SELECT 6648$',1,'from_a')") &&
        query(a.admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
    ok(loaded && rule_comment(a.admin) == "from_a",
       "legacy Admin load updates the source rule during prepared traffic");
    const bool synchronized = loaded && wait_for([&] { return rule_comment(b.admin) == "from_a"; }, 8);
    ok(synchronized, "Cluster copies the exact source rule to the second node");
    ok(synchronized && progress_after(clients, before),
       "all prepared clients make progress during the first Cluster sync");

    // Cluster checksums use seconds for epochs. Allow the next load its own epoch.
    if (synchronized)
        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    for (unsigned i=0; i<4; ++i)
        before[i] = clients[i].completed;
    const bool reverse = synchronized &&
        query(b.admin, "UPDATE mysql_query_rules SET comment='from_b' WHERE rule_id=6648") &&
        query(b.admin, "LOAD MYSQL QUERY RULES TO RUNTIME") &&
        wait_for([&] { return rule_comment(a.admin) == "from_b"; }, 8);
    ok(reverse && rule_comment(b.admin) == "from_b", "Cluster synchronizes a peer update back");
    ok(reverse && progress_after(clients, before),
       "all prepared clients make progress during the reverse Cluster sync");

    traffic.pause = true;
    const bool parked = wait_for([&] { return traffic.parked == 4; }, 4);
    ok(parked, "all four clients still own prepared statements before shutdown");
    ok(b.stop(), "second Cluster node shuts down cleanly with live prepared statements");
    ok(a.stop(), "first Cluster node shuts down cleanly with live prepared statements");
    traffic.release = true;
    for (auto &worker : workers)
        worker.join();
    alarm(0);
    return exit_status();
}
