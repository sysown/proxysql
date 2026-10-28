#ifndef PROXYSQL_WORKER_SCHEDULER_H
#define PROXYSQL_WORKER_SCHEDULER_H

#ifdef PROXYSQL31

#include <algorithm>
#include <deque>
#include <type_traits>
#include "Session_Scheduler.h"

// Definitions stay visible to the worker translation units. Each protocol
// instantiates concrete types; there is no runtime protocol or callback dispatch.
template<class Worker, class Session, class Connection, class Pool>
class Worker_Scheduler {
    Worker &worker;
    Pool &pool;

    template<class Server>
    static bool server_online(const Server *server) {
        if constexpr (std::is_same_v<Session, PgSQL_Session>)
            return server->status == MYSQL_SERVER_STATUS_ONLINE;
        else
            return server->get_status() == MYSQL_SERVER_STATUS_ONLINE;
    }

public:
    Worker_Scheduler(Worker &w, Pool &p) : worker(w), pool(p) {
        worker.released_hostgroups.clear();
        worker.collecting_releases = std::is_same_v<Session, PgSQL_Session>;
    }
    ~Worker_Scheduler() {
        worker.collecting_releases = false;
        worker.released_hostgroups.clear();
    }
    Worker_Scheduler(const Worker_Scheduler&) = delete;
    Worker_Scheduler& operator=(const Worker_Scheduler&) = delete;

    Session_Run_Result run_session(Session *sess, Pool_Acquire_Mode mode = Pool_Acquire_Mode::Normal,
                                   bool io_only = false) {
        // MySQL still consumes readiness in its poll scan. PostgreSQL's
        // deferred-I/O handler must also run while query execution is paused.
        if constexpr (std::is_same_v<Session, MySQL_Session>) {
            if (io_only) return Session_Run_Result::WaitIO;
        }
        const auto result = sess->run_step(mode, io_only);
        if (result == Session_Run_Result::Runnable) worker.queue_session_continuation(sess);
        return result;
    }

    size_t serve_waiters(unsigned hid, size_t budget, bool retry_unavailable = false) {
        size_t served = 0;
        bool checkout_blocked = false;
        for (auto *node = worker.waiter_lists.head(hid); node && (retry_unavailable || served < budget);) {
            auto *next = node->next;
            auto *waiting = static_cast<Session*>(node->session);
            if (waiting->killed || waiting->healthy == 0) {
                // Defer deletion to the main scan, whose array indices must
                // remain stable while it is interleaving a different session.
                waiting->healthy = 0;
                worker.leave_waiter(waiting, false);
                node = next;
                continue;
            }
            auto *bds = waiting->mybe ? waiting->mybe->server_myds : nullptr;
            if constexpr (std::is_same_v<Session, MySQL_Session>) {
                if (retry_unavailable && worker.refreshing_waiter_deadlines) {
                    if (!bds) worker.waiter_deadline_hint = 0;
                    else if (bds->max_connect_time && worker.waiter_deadline_hint)
                        worker.waiter_deadline_hint = std::min(worker.waiter_deadline_hint, bds->max_connect_time);
                }
            }
            const bool deadline_due = bds && bds->max_connect_time && worker.curtime >= bds->max_connect_time;
            // A failed ordinary checkout can stop further speculative retries,
            // but every expired waiter still needs its timeout state machine.
            if (retry_unavailable && !deadline_due && checkout_blocked) {
                if constexpr (std::is_same_v<Session, MySQL_Session>) {
                    // Admission only lowers this bound. Removed waiters leave
                    // it conservatively early; unknown/expired bounds force
                    // a complete traversal, including every expired tail.
                    if (!worker.refreshing_waiter_deadlines && worker.waiter_deadline_hint &&
                        worker.curtime < worker.waiter_deadline_hint) break;
                }
                node = next;
                continue;
            }
            if (waiting->pause_until > worker.curtime && !deadline_due) { node = next; continue; }
            if (deadline_due) waiting->pause_until = 0;
            waiting->to_process = 1;
            const auto waiting_result = run_session(waiting, retry_unavailable
                ? Pool_Acquire_Mode::Normal : Pool_Acquire_Mode::EstablishedOnly);
            if (waiting_result == Session_Run_Result::Close) {
                waiting->healthy = 0;
                worker.leave_waiter(waiting, false);
                node = next;
                continue;
            }
            if (waiting_result == Session_Run_Result::EstablishedUnavailable) break;
            const bool got = waiting->mybe && waiting->mybe->server_myds && waiting->mybe->server_myds->myconn;
            if (got) {
                worker.leave_waiter(waiting);
                auto *bds = waiting->mybe->server_myds;
                if (bds->fd >= 0 && bds->poll_fds_idx < 0)
                    worker.mypolls.add(POLLIN | POLLOUT, bds->fd, bds, worker.curtime);
                ++served;
            } else if (waiting->status != CONNECTING_SERVER) {
                worker.leave_waiter(waiting);
            } else if (vanilla_pool_checkout(waiting->last_pool_ff,
                       waiting->last_pool_gtid ? "" : nullptr, waiting->last_pool_max_lag_ms)) {
                if (!retry_unavailable) break;
                checkout_blocked = true;
            }
            node = next;
        }
        return served;
    }

    void dispatch_released() {
        // Immediate local reacquisition can strand another MySQL worker with
        // no backend I/O to wake it. Preserve MySQL's batched waiter phase.
        if constexpr (std::is_same_v<Session, MySQL_Session>) return;
        // A synchronous completion may release again. Bound the chain rather
        // than recurse; remaining availability is retried at the next pass.
        size_t i = 0;
        while (i < worker.released_hostgroups.size() && i < 64) {
            const unsigned hid = worker.released_hostgroups[i++];
            serve_waiters(hid, 1);
        }
        worker.released_hostgroups.clear();
    }

    // These phases were part of process_all_sessions() before extraction.
    // Keep that call boundary unchanged in release builds: inline alone is
    // only a hint and -O2 otherwise outlines these larger template methods.
    __attribute__((always_inline)) inline void run_early() {
    // Reuse connections already available before doing more response work,
    // including connections published by another worker.
    // If waiters consume all known capacity, avoid another frontend scan.
    // This is deliberately a global gate; hostgroup scheduling comes later.
    bool early_capacity_available = worker.waiter_lists.empty();
    worker.waiter_lists.for_each_hid([&](unsigned hid, PgSQL_Waiter_Node*, size_t count) {
        size_t available = 0;
        for (unsigned i = 0; i < worker.cached_connections->len; ++i) {
            auto *conn = static_cast<Connection*>(worker.cached_connections->index(i));
            if (conn->parent->myhgc->hid == hid) ++available;
        }
        pool.wrlock();
        auto *hg = pool.MyHGC_find(hid);
        if (hg) for (unsigned i = 0; i < hg->mysrvs->cnt(); ++i) {
            auto *server = hg->mysrvs->idx(i);
            if (server_online(server))
                available += server->ConnectionsFree->conns_length();
        }
        pool.wrunlock();
        // An empty-pool retry would pause the oldest waiter just before the
        // response scan releases a connection. Only attempt real availability.
        if (available) {
            const size_t served = serve_waiters(hid, std::min(count, available));
            if (available > served) early_capacity_available = true;
        }
    });
    dispatch_released();
    // Try new frontend work before response processing, stopping globally on
    // the first established-connection miss. Hostgroup scheduling is deferred.
    for (unsigned i = 0; early_capacity_available && i < worker.mysql_sessions->len; ++i) {
        auto *sess = static_cast<Session*>(worker.mysql_sessions->index(i));
        if (sess->healthy == 0 || sess->killed || sess->mirror || sess->waiter_node.session || sess->continuation_queued)
            continue;
        if (sess->to_process != 1 || sess->pause_until > worker.curtime) continue;
        if (sess->mybe && sess->mybe->server_myds && sess->mybe->server_myds->myconn) continue;
        // Authentication and connection maintenance retain their normal order.
        if (sess->status != WAITING_CLIENT_DATA && sess->status != CONNECTING_SERVER) continue;
        const auto early_result = run_session(sess, Pool_Acquire_Mode::EstablishedOnly);
        if (early_result == Session_Run_Result::Close)
            worker.leave_waiter(sess, false);
        dispatch_released();
        if (early_result == Session_Run_Result::EstablishedUnavailable) break;
    }
    }

    __attribute__((always_inline)) inline void run_late() {
        dispatch_released();
        // Recovery and expired deadlines still use ordinary pool acquisition.
        if constexpr (std::is_same_v<Session, MySQL_Session>) {
            worker.refreshing_waiter_deadlines = !worker.waiter_lists.empty() &&
                (!worker.waiter_deadline_hint || worker.curtime >= worker.waiter_deadline_hint);
            if (worker.refreshing_waiter_deadlines) worker.waiter_deadline_hint = ~0ULL;
        }
        worker.waiter_lists.for_each_hid([&](unsigned hid, PgSQL_Waiter_Node*, size_t count) {
            serve_waiters(hid, count, true);
        });
        if constexpr (std::is_same_v<Session, MySQL_Session>) worker.refreshing_waiter_deadlines = false;
        dispatch_released();
        for (unsigned n = 0; n < worker.mysql_sessions->len; ++n) {
            auto *sess = static_cast<Session*>(worker.mysql_sessions->index(n));
            if (!sess->healthy || sess->killed) {
                worker.close_scheduled_session(n--);
                continue;
            }
            if (sess->waiter_node.session || sess->continuation_queued) continue;
            if (sess->mybe && sess->mybe->server_myds && sess->mybe->server_myds->myconn) continue;
            if (sess->to_process == 1 && sess->pause_until <= worker.curtime) {
                const auto result = run_session(sess);
                if (result == Session_Run_Result::Close) worker.close_scheduled_session(n--);
                dispatch_released();
            }
        }
        // Only the starting snapshot is drained. Paused or newly queued work
        // remains durable, without extending this worker pass indefinitely.
        size_t remaining = worker.session_continuations.size();
        while (remaining-- && !worker.session_continuations.empty()) {
            auto *sess = worker.session_continuations.front();
            worker.session_continuations.pop_front();
            sess->continuation_queued = false;
            if (sess->healthy && !sess->killed && sess->pause_until > worker.curtime) {
                worker.queue_session_continuation(sess);
                continue;
            }
            const auto result = (!sess->healthy || sess->killed) ? Session_Run_Result::Close : run_session(sess);
            if (result == Session_Run_Result::Close) {
                for (unsigned i = 0; i < worker.mysql_sessions->len; ++i) {
                    if (worker.mysql_sessions->index(i) == sess) {
                        worker.close_scheduled_session(i);
                        break;
                    }
                }
            }
            dispatch_released();
        }
    }
};

template<class Session>
void queue_session_work(std::deque<Session*> &queue, Session *sess) {
    if (sess->continuation_queued) return;
    sess->continuation_queued = true;
    queue.push_back(sess);
}

template<class Session>
void cancel_session_work(std::deque<Session*> &queue, Session *sess) {
    if (!sess->continuation_queued) return;
    queue.erase(std::remove(queue.begin(), queue.end(), sess), queue.end());
    sess->continuation_queued = false;
}

template<class Session>
bool tune_queued_work_poll_timeout(const std::deque<Session*> &queue, unsigned long long now, int &timeout) {
    for (const auto *sess : queue) {
        if (!sess->healthy || sess->killed || sess->pause_until <= now) return true;
        const auto remaining = sess->pause_until - now;
        const auto delay_ms = remaining / 1000 + (remaining % 1000 != 0);
        if (delay_ms < static_cast<unsigned long long>(timeout)) timeout = static_cast<int>(delay_ms);
    }
    return false;
}

#endif // PROXYSQL31
#endif // PROXYSQL_WORKER_SCHEDULER_H
