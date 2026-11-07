#ifndef PROXYSQL_SESSION_SCHEDULER_H
#define PROXYSQL_SESSION_SCHEDULER_H
#include "PgSQL_Scheduler.h"
// Preserve the PR's enum ABI while giving shared code protocol-neutral names.
using Pool_Acquire_Mode = PgSQL_Pool_Acquire_Mode;
using Session_Run_Result = PgSQL_Session_Run_Result;
#endif
