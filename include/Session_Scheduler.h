#ifndef PROXYSQL_SESSION_SCHEDULER_H
#define PROXYSQL_SESSION_SCHEDULER_H
#include "PgSQL_Scheduler.h"
// Preserve the PR's enum ABI while giving shared code protocol-neutral names.
using Pool_Acquire_Mode = PgSQL_Pool_Acquire_Mode;
using Session_Run_Result = PgSQL_Session_Run_Result;

#ifdef PROXYSQL31
#include <poll.h>

// Waiters apply input backpressure between their periodic read rearms, but
// disconnects must still wake the owning worker, including behind unread data.
constexpr short waiter_client_poll_events() {
#ifdef POLLRDHUP
    return POLLRDHUP;
#else
    return 0; // poll still reports POLLHUP/POLLERR without requesting them.
#endif
}

inline bool waiter_client_terminal(short revents) {
    return revents & (POLLHUP | POLLERR | waiter_client_poll_events());
}
#endif
#endif
