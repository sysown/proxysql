#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#ifdef PROXYSQL31
#include "proxysql.h"
#include <any>
#include <sstream>
#include <type_traits>
#define private public
#include "cpp.h"
#undef private
#include "MySQL_Data_Stream.h"
#include "MySQL_Logger.hpp"
#include "MySQL_Query_Processor.h"
#include "PgSQL_Logger.hpp"
#include "Worker_Scheduler.h"
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

extern MySQL_Logger *GloMyLogger;
extern PgSQL_Logger *GloPgSQL_Logger;

// Count visits around the real scheduling template, without reproducing its
// traversal or supplying a second implementation of the scheduling policy.
struct CountedSession;
struct CountedStream {
    void *myconn = nullptr;
    unsigned long long max_connect_time = 0;
    int fd = -1, poll_fds_idx = -1;
};
struct CountedBackend { CountedStream *server_myds = nullptr; };
struct CountedSession {
    bool healthy = true, killed = false, mirror = false, continuation_queued = false;
    int to_process = 0;
    unsigned long long pause_until = 0;
    session_status status = WAITING_CLIENT_DATA;
    PgSQL_Waiter_Node waiter_node;
    CountedBackend *mybe = nullptr;
    bool last_pool_ff = false, last_pool_gtid = false;
    int last_pool_max_lag_ms = -1;
    Session_Run_Result result = Session_Run_Result::WaitIO;
    Session_Run_Result run_step(Pool_Acquire_Mode, bool) { return result; }
};
struct CountedArray {
    std::vector<CountedSession*> entries;
    unsigned len = 0;
    size_t visits = 0;
    CountedSession *index(unsigned i) { ++visits; return entries[i]; }
    void add(CountedSession *s) { entries.push_back(s); len = entries.size(); }
};
struct CountedWorker {
    CountedArray sessions;
    CountedArray *mysql_sessions = &sessions;
    PgSQL_Waiter_Lists waiter_lists;
    std::deque<CountedSession*> session_continuations;
    std::vector<unsigned> released_hostgroups;
    bool collecting_releases = false;
    unsigned long long curtime = 1000000;
    size_t closed = 0;
    CountedSession *unpause_on_close = nullptr;
    struct { void add(int, int, CountedStream*, unsigned long long) {} } mypolls;
    void queue_session_continuation(CountedSession *s) {
        queue_session_work(session_continuations, s);
    }
    void leave_waiter(CountedSession *s, bool = true) {
        waiter_lists.unlink(s->waiter_node);
        s->waiter_node = {};
    }
    void close_scheduled_session(unsigned i) {
        auto *s = sessions.entries[i];
        leave_waiter(s, false);
        cancel_session_work(session_continuations, s);
        sessions.entries[i] = sessions.entries.back();
        sessions.entries.pop_back();
        sessions.len = sessions.entries.size();
        ++closed;
        if (unpause_on_close) {
            // Model a destructor publishing capacity for a previously paused
            // waiter, including an error when that waiter next runs.
            unpause_on_close->pause_until = 0;
            unpause_on_close->result = Session_Run_Result::Close;
            unpause_on_close = nullptr;
            released_hostgroups.push_back(1);
        }
    }
};
struct CountedPool {};

static void test_idle_late_phase() {
    CountedWorker worker;
    CountedPool pool;
    std::vector<CountedSession> idle(4096);
    for (auto &s : idle) worker.sessions.add(&s);
    Worker_Scheduler<CountedWorker, CountedSession, void, CountedPool> scheduler(worker, pool);
    scheduler.run_late();
    ok(worker.sessions.visits == 0,
       "a late phase without deferred backendless work does not revisit 4096 idle sessions (visits=%zu)",
       worker.sessions.visits);
}

static void test_closing_continuations() {
    CountedWorker worker;
    CountedPool pool;
    std::vector<CountedSession> idle(4096), closing(128);
    for (auto &s : idle) worker.sessions.add(&s);
    CountedSession paused;
    paused.pause_until = worker.curtime + 1000000;
    worker.sessions.add(&paused);
    worker.queue_session_continuation(&paused);
    for (auto &s : closing) {
        s.result = Session_Run_Result::Close;
        worker.sessions.add(&s);
        worker.queue_session_continuation(&s);
    }
    Worker_Scheduler<CountedWorker, CountedSession, void, CountedPool> scheduler(worker, pool);
    scheduler.run_late();
    ok(worker.closed == closing.size() && worker.sessions.len == idle.size() + 1 &&
       worker.session_continuations.size() == 1 && worker.session_continuations.front() == &paused &&
       paused.continuation_queued,
       "closing queued sessions are removed while idle sessions and a paused continuation remain intact");
    ok(worker.sessions.visits <= 2 * (idle.size() + closing.size() + 1),
       "closing 128 continuations uses bounded whole-array work (visits=%zu)", worker.sessions.visits);
}

static void test_close_release_cleanup() {
    CountedWorker worker;
    CountedPool pool;
    CountedSession waiting, closing;
    waiting.status = CONNECTING_SERVER;
    waiting.pause_until = worker.curtime + 1000000;
    waiting.waiter_node.session = &waiting;
    waiting.waiter_node.hid = 1;
    worker.waiter_lists.push_back(waiting.waiter_node);
    worker.sessions.add(&waiting);
    worker.sessions.add(&closing);
    closing.result = Session_Run_Result::Close;
    worker.queue_session_continuation(&closing);
    worker.unpause_on_close = &waiting;
    Worker_Scheduler<CountedWorker, CountedSession, void, CountedPool> scheduler(worker, pool);
    scheduler.run_late();
    ok(worker.closed == 2 && worker.sessions.len == 0 && worker.waiter_lists.empty() &&
       worker.released_hostgroups.empty(),
       "cleanup hands released capacity to waiters and reaps a waiter that then closes in the same pass");
}

static void test_waiter_close_release_cleanup() {
    CountedWorker worker;
    CountedPool pool;
    CountedSession waiting, closing;
    waiting.status = closing.status = CONNECTING_SERVER;
    waiting.pause_until = worker.curtime + 1000000;
    closing.result = Session_Run_Result::Close;
    for (auto *s : {&closing, &waiting}) {
        s->waiter_node.session = s;
        s->waiter_node.hid = 1;
        worker.waiter_lists.push_back(s->waiter_node);
    }
    // Visit the paused waiter before deleting the terminal waiter, so simply
    // continuing the same array scan cannot reap its eventual terminal result.
    worker.sessions.add(&waiting);
    worker.sessions.add(&closing);
    worker.unpause_on_close = &waiting;
    Worker_Scheduler<CountedWorker, CountedSession, void, CountedPool> scheduler(worker, pool);
    scheduler.run_late();
    ok(worker.closed == 2 && worker.sessions.len == 0 && worker.waiter_lists.empty() &&
       worker.released_hostgroups.empty(),
       "late waiter cleanup dispatches its released capacity before the scheduler returns");
}

#ifdef __linux__
struct DispatchEvent { MySQL_Session *session; Pool_Acquire_Mode mode; };
static std::vector<DispatchEvent> events;
extern "C" Session_Run_Result __wrap__ZN13MySQL_Session8run_stepE23PgSQL_Pool_Acquire_Modeb(
    MySQL_Session *s, Pool_Acquire_Mode mode, bool io_only) {
    if (io_only) return Session_Run_Result::WaitIO;
    events.push_back({s, mode});
    if (mode == Pool_Acquire_Mode::EstablishedOnly)
        return Session_Run_Result::EstablishedUnavailable;
    s->to_process = 0;
    return Session_Run_Result::WaitIO;
}

static void test_response_first() {
    MySQL_Thread worker;
    if (!worker.init()) BAIL_OUT("worker init failed");
    worker.maintenance_loop = false;
    worker.curtime = 1000000;
    auto *frontend = new MySQL_Session();
    auto *backend = new MySQL_Session();
    for (auto *s : {frontend, backend}) {
        s->connections_handler = true;
        s->thread = &worker;
        s->status = WAITING_CLIENT_DATA;
        s->to_process = 1;
        worker.mysql_sessions->add(s);
    }
    backend->mybe = backend->find_or_create_backend(991);
    auto *connection = new MySQL_Connection();
    backend->mybe->server_myds->myconn = connection;
    events.clear();
    worker.process_all_sessions();
    ok(!events.empty() && events.front().session == backend,
       "a ready backend response runs before a new frontend request");
    ok(events.size() == 2 && events[0].mode == Pool_Acquire_Mode::Normal &&
       events[1].mode == Pool_Acquire_Mode::Normal,
       "a frontend request needs one normal handler visit rather than speculative and normal visits");
    backend->mybe->server_myds->myconn = nullptr;
    delete connection;
    while (worker.mysql_sessions->len) {
        auto *s = static_cast<MySQL_Session*>(worker.mysql_sessions->index(0));
        worker.unregister_session(0);
        delete s;
    }
}

template<class Worker, class Session>
static void test_paused_kill(const char *protocol) {
    Worker worker;
    if (!worker.init()) BAIL_OUT("worker init failed");
    worker.maintenance_loop = false;
    worker.curtime = 1000000;
    auto *s = new Session();
    s->connections_handler = true;
    s->thread = &worker;
    s->status = WAITING_CLIENT_DATA;
    s->to_process = 1;
    s->killed = true;
    s->pause_until = worker.curtime + 1000000;
    worker.mysql_sessions->add(s);
    worker.process_all_sessions();
    ok(worker.mysql_sessions->len == 0,
       "%s: a killed ordinary session is removed even while its query is paused", protocol);
}

static void test_cache_publication_scope() {
    MySQL_Thread worker;
    if (!worker.init()) BAIL_OUT("worker init failed");
    const auto saved_threads = GloMTH->num_threads;
    GloMTH->num_threads = 1;
    worker.curtime = 1000000;
    srv_info_t info {"127.0.0.1", 2, "cache publication unit"};
    srv_info_t other_info {"127.0.0.1", 3, "unrelated cache publication unit"};
    srv_opts_t opts {1, 1, 0};
    MyHGM->wrlock();
    int rc = MyHGM->create_new_server_in_hg(992, info, opts);
    rc |= MyHGM->create_new_server_in_hg(993, other_info, opts);
    auto *target_hg = MyHGM->MyHGC_find(992);
    auto *unrelated_hg = MyHGM->MyHGC_find(993);
    MyHGM->wrunlock();
    if (rc || !target_hg || !unrelated_hg) BAIL_OUT("cache hostgroup initialization failed");
    auto *target = target_hg->mysrvs->idx(0);
    auto *unrelated = unrelated_hg->mysrvs->idx(0);
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) BAIL_OUT("socketpair failed");
    auto *session = new MySQL_Session();
    session->thread = &worker;
    session->connections_handler = true;
    session->status = CONNECTING_SERVER;
    session->current_hostgroup = session->default_hostgroup = 992;
    session->client_myds = new MySQL_Data_Stream();
    session->client_myds->init(MYDS_FRONTEND, session, fds[0]);
    session->client_myds->myconn = new MySQL_Connection();
    char user[] = "scheduler", password[] = "", database[] = "unit";
    session->client_myds->myconn->userinfo->set(user, password, database, nullptr);
    session->mybe = session->find_or_create_backend(992);
    session->qpo->create_new_conn = true;
    MySQL_Connection *retained = nullptr;
    for (auto *server : {target, unrelated}) {
        auto *c = new MySQL_Connection();
        c->parent = server;
        c->mysql = mysql_init(nullptr);
        c->ret_mysql = c->mysql;
        c->mysql->charset = mariadb_get_charset_by_name("utf8mb4");
        c->userinfo->set(user, password, database, nullptr);
        c->async_state_machine = ASYNC_IDLE;
        c->healthy = c->reusable = true;
        server->ConnectionsUsed->add(c);
        worker.push_MyConn_local(c);
        if (server == unrelated) retained = c;
    }
    worker.mysql_sessions->add(session);
    const auto acquired = MyHGM->status.myconnpoll_get_ok;
    session->handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection();
    ok(MyHGM->status.myconnpoll_get_ok > acquired,
       "a fresh normal checkout still recovers capacity cached for its hostgroup");
    ok(worker.cached_connections->len == 1 && worker.cached_connections->index(0) == retained &&
       unrelated->ConnectionsUsed->conns_length() == 1 && unrelated->ConnectionsFree->conns_length() == 0,
       "a normal miss preserves the local cache for unrelated hostgroups");
    worker.unregister_session(0);
    delete session;
    close(fds[1]);
    worker.return_local_connections();
    GloMTH->num_threads = saved_threads;
}
#endif // __linux__
#endif // PROXYSQL31

int main() {
#ifdef PROXYSQL31
#ifdef __linux__
    plan(11);
#else
    plan(5);
#endif
    if (test_init_minimal() || test_init_auth() || test_init_query_processor() || test_init_hostgroups())
        BAIL_OUT("scheduler cost initialization failed");
    GloMyLogger = new MySQL_Logger();
    GloPgSQL_Logger = new PgSQL_Logger();
    test_idle_late_phase();
    test_closing_continuations();
    test_close_release_cleanup();
    test_waiter_close_release_cleanup();
#ifdef __linux__
    test_response_first();
    test_paused_kill<MySQL_Thread, MySQL_Session>("MySQL");
    test_paused_kill<PgSQL_Thread, PgSQL_Session>("PgSQL");
    test_cache_publication_scope();
#endif
    delete GloMyLogger;
    GloMyLogger = nullptr;
    delete GloPgSQL_Logger;
    GloPgSQL_Logger = nullptr;
    test_cleanup_hostgroups();
    test_cleanup_query_processor();
    test_cleanup_auth();
    test_cleanup_minimal();
#else
    plan(1);
    skip(1, "shared phased scheduling requires PROXYSQL31");
#endif
    return exit_status();
}
