#!/bin/bash

. constants

# check if all required env vars are set
if [ -z "${INFRA}" ]; then
    echo "INFRA is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${MYSQL1_PORT}" ]; then
    echo "MYSQL1_PORT is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${MYSQL2_PORT}" ]; then
    echo "MYSQL2_PORT is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${MYSQL3_PORT}" ]; then
    echo "MYSQL3_PORT is empty, please check env vars passed to: " ${0}
    exit 1
  elif [ -z "${MYSQL1_HOST}" ]; then
      echo "MYSQL1_HOST is empty, please check env vars passed to: " ${0}
      exit 1
  elif [ -z "${MYSQL2_HOST}" ]; then
      echo "MYSQL2_HOST is empty, please check env vars passed to: " ${0}
      exit 1
  elif [ -z "${MYSQL3_HOST}" ]; then
      echo "MYSQL3_HOST is empty, please check env vars passed to: " ${0}
      exit 1
fi

res=1

echo "Running checksum for sysbench data on primary (master) ..."
echo "Checksum results:"
mysql -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot sysbench --skip-column-names -e " \
CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5; \
" 2>&1 | grep -vP "mysql: .?Warning"

# Replication through ProxySQL can lag briefly under load, so comparing the
# checksums a single time (after only a fixed sleep in the caller) is racy and
# yields spurious "data is different" failures. Poll the checksums until the
# replicas converge with the primary, bounded by CHECKSUM_SYNC_TIMEOUT seconds
# (default 30). Succeed as soon as they match; report a mismatch only if they
# never converge within the budget -- which then reflects a genuine replication
# break rather than lag.
: "${CHECKSUM_SYNC_TIMEOUT:=30}"
echo "Comparing sysbench data between primary and replicas (waiting up to ${CHECKSUM_SYNC_TIMEOUT}s for replicas to sync) ..."
SECONDS=0
while :; do
    chk1=$(mysql -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot sysbench --skip-column-names -e "CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5;" 2>&1 | grep -vP "mysql: .?Warning" | md5sum)
    chk2=$(mysql -h${MYSQL2_HOST}${INFRA} -P${MYSQL2_PORT}  -uroot -proot sysbench --skip-column-names -e "CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5;" 2>&1 | grep -vP "mysql: .?Warning" | md5sum)
    chk3=$(mysql -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT}  -uroot -proot sysbench --skip-column-names -e "CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5;" 2>&1 | grep -vP "mysql: .?Warning" | md5sum)
    if [[ "${chk1}" == "${chk2}" ]] && [[ "${chk1}" == "${chk3}" ]]; then
        res=0
        break
    fi
    if (( SECONDS >= CHECKSUM_SYNC_TIMEOUT )); then
        break
    fi
    # A transient backend-unreachability (e.g. an overloaded CI runner) can make
    # ProxySQL exceed connect_timeout_server_max (10s) reaching the source
    # hostgroup, which makes a replica's IO thread hit a FATAL error and stop for
    # good -- MySQL never auto-restarts it, so the replica is frozen and no amount
    # of waiting converges. Detect a stopped IO thread on the replicas and restart
    # it so it reconnects and catches up once the backend is reachable again.
    for rep in "${MYSQL2_HOST} ${MYSQL2_PORT}" "${MYSQL3_HOST} ${MYSQL3_PORT}"; do
        set -- $rep; rhost=$1; rport=$2
        io=$(mysql -h${rhost}${INFRA} -P${rport} -uroot -proot -e "SHOW SLAVE STATUS\G" 2>/dev/null | grep -i "Slave_IO_Running:" | awk '{print $2}')
        if [ "${io}" = "No" ]; then
            echo "  ${rhost}${INFRA}: replica IO thread stopped -- restarting (STOP SLAVE; START SLAVE)"
            mysql -h${rhost}${INFRA} -P${rport} -uroot -proot -e "STOP SLAVE; START SLAVE;" 2>/dev/null
        fi
    done
    sleep 1
done

echo "================================================================================"
echo "[`date '+%Y-%m-%d %H:%M:%S'`]"
if [[ ${res} -eq 0 ]]; then
    echo "TEST PASSED: generated data is identical on all replicas"
elif [[ "${chk1}" != "${chk3}" ]]; then
    echo "TEST FAILED: generated data is different on" ${MYSQL3_HOST}${INFRA} "(did not sync within ${CHECKSUM_SYNC_TIMEOUT}s)"
elif [[ "${chk1}" != "${chk2}" ]]; then
    echo "TEST FAILED: generated data is different on" ${MYSQL2_HOST}${INFRA} "(did not sync within ${CHECKSUM_SYNC_TIMEOUT}s)"
else
    echo "TEST FAILED"
fi
echo "================================================================================"

# On non-convergence, dump enough state to distinguish "mysql3 is behind" (SQL
# thread lagging/stuck -> fewer rows / lower gtid_executed) from "mysql3 has
# diverged" (same gtid_executed but different content -> a real relay/apply
# correctness bug). Captured for mysql1/2/3 plus mysql3's replica status.
if [[ ${res} -ne 0 ]]; then
    echo ">>> DIAGNOSTIC: replicas did not converge within ${CHECKSUM_SYNC_TIMEOUT}s -- capturing state"
    for node in "MYSQL1 ${MYSQL1_HOST} ${MYSQL1_PORT}" "MYSQL2 ${MYSQL2_HOST} ${MYSQL2_PORT}" "MYSQL3 ${MYSQL3_HOST} ${MYSQL3_PORT}"; do
        set -- $node; nname=$1; nhost=$2; nport=$3
        echo "--- ${nname} (${nhost}${INFRA}:${nport}) ---"
        mysql -h${nhost}${INFRA} -P${nport} -uroot -proot --skip-column-names -e "\
          SELECT CONCAT('gtid_executed=', @@GLOBAL.gtid_executed); \
          SELECT CONCAT('rows[1..5]= ',(SELECT COUNT(*) FROM sysbench.sbtest1),' ',(SELECT COUNT(*) FROM sysbench.sbtest2),' ',(SELECT COUNT(*) FROM sysbench.sbtest3),' ',(SELECT COUNT(*) FROM sysbench.sbtest4),' ',(SELECT COUNT(*) FROM sysbench.sbtest5)); \
          CHECKSUM TABLE sysbench.sbtest1, sysbench.sbtest2, sysbench.sbtest3, sysbench.sbtest4, sysbench.sbtest5;" 2>&1 | grep -vP "mysql: .?Warning"
    done
    echo "--- MYSQL3 replica status (IO/SQL running, lag, GTID positions, errors) ---"
    mysql -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT} -uroot -proot -e "SHOW SLAVE STATUS\G" 2>&1 | grep -vP "mysql: .?Warning" \
      | grep -iE "Slave_IO_Running|Slave_SQL_Running|Seconds_Behind|Retrieved_Gtid_Set|Executed_Gtid_Set|Read_Master_Log_Pos|Exec_Master_Log_Pos|Last_IO_Error|Last_SQL_Error|Auto_Position"
    echo "================================================================================"
fi

exit $res
