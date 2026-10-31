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
    bool cleanup_needed = false;

public:
    Worker_Scheduler(Worker &w, Pool &) : worker(w) {
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
                cleanup_needed = true;
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
                cleanup_needed = true;
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

    // Backend responses run first. Released capacity goes to existing waiters;
    // new frontend work needs only an ordinary checkout in this late phase.
    // Keep the phase inline in release builds, as it was before extraction.
    __attribute__((always_inline)) inline void run_late(bool no_backend_loop_needed = false) {
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
        if (no_backend_loop_needed || cleanup_needed) {
            cleanup_needed = false;
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
            dispatch_released();
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
                sess->healthy = 0;
                cleanup_needed = true;
            }
            dispatch_released();
        }
        // A disconnect burst needs one cleanup traversal, rather than one
        // index search per closing continuation. Deletion may release capacity;
        // drain it and reap any waiters that terminate during that handoff too.
        while (cleanup_needed) {
            cleanup_needed = false;
            for (unsigned n = 0; n < worker.mysql_sessions->len; ++n) {
                auto *sess = static_cast<Session*>(worker.mysql_sessions->index(n));
                if (!sess->healthy || sess->killed)
                    worker.close_scheduled_session(n--);
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
