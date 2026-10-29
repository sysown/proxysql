#!/bin/bash
set -u

if [ -n "${MYSQL_DELAY_SECONDS:-}" ]; then
    sleep "${MYSQL_DELAY_SECONDS}"
fi
printf '%s\n' "$@" > "${MYSQL_RECORD_FILE:?MYSQL_RECORD_FILE is required}"
exit "${MYSQL_EXIT_CODE:-0}"
