# mysqlx-tsan-g1 group environment.
#
# Scope: mysqlx_*-t and plugin_*-t unit-test binaries built with
#        WITHTSAN=1. ThreadSanitizer's instrumentation is most
#        valuable on the concurrency-heavy code paths the mysqlx
#        feature stack added (worker pool, shared_mutex on
#        MysqlxConfigStore, plugin manager active-mutex on the
#        dispatch hot path). Running TSAN against every unit test
#        in the broader unit-tests-g1 group would balloon
#        wall-clock with low marginal value.
#
# No backend / no proxysql daemon needed: each *-t binary links
# libproxysql.a via the test stub globals (test_globals.o) and runs
# standalone. SKIP_PROXYSQL=1 makes ensure-infras.bash short-circuit
# before the docker-compose loop.
#
# TSAN_OPTIONS:
#   halt_on_error=0 + abort_on_error=0  collect every race in one run
#                                        rather than bailing on the first
#   second_deadlock_stack=1              second stack for deadlock reports
#   history_size=7                       deeper trace history per access
#
# IMPORTANT: TSAN cannot reserve its shadow region on Linux 5.18+
# kernels with the default vm.mmap_rnd_bits=32. Caller (CI workflow
# or local dev) must `sudo sysctl -w vm.mmap_rnd_bits=28` BEFORE
# any TSAN-instrumented binary loads.

export SKIP_PROXYSQL=1
export TSAN_OPTIONS="halt_on_error=0:abort_on_error=0:second_deadlock_stack=1:history_size=7"
