#ifndef PROXYSQL_PGSQL_SCHEDULER_H
#define PROXYSQL_PGSQL_SCHEDULER_H

// Speculation must not run connection creation or normal failed-checkout policy.
enum class PgSQL_Pool_Acquire_Mode { Normal, EstablishedOnly };

// A completed scheduling step says what can make progress next. Runnable is
// an explicit continuation, independent of a subsequent socket notification.
enum class PgSQL_Session_Run_Result {
	WaitIO,
	WaitBackend,
	EstablishedUnavailable,
	Runnable,
	Close
};

#endif
