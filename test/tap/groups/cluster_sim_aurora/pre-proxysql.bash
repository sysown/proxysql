#!/usr/bin/env bash
set -e
# ProxySQL's admin port goes live before its startup is done. Wait for all
# init_<module>_variables() to complete before running pre-proxysql.sql;
# concurrent writes return SQLITE_LOCKED, which flush-variables functions
# treat as fatal (assert on rc != 0).
sleep 5
