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

exit $res
