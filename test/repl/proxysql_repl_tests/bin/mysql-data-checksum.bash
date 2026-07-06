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
mysql ${SSLOPT} -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot sysbench --skip-column-names -e " \
CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5; \
" 2>&1 | grep -v "Using a password"

echo "Comparing sysbench data between primary and replicas ..."
chk1=$(mysql ${SSLOPT} -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot sysbench --skip-column-names -e "CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5;" 2>&1 | grep -v "Using a password" | md5sum)
chk2=$(mysql ${SSLOPT} -h${MYSQL2_HOST}${INFRA} -P${MYSQL2_PORT}  -uroot -proot sysbench --skip-column-names -e "CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5;" 2>&1 | grep -v "Using a password" | md5sum)
chk3=$(mysql ${SSLOPT} -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT}  -uroot -proot sysbench --skip-column-names -e "CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5;" 2>&1 | grep -v "Using a password" | md5sum)


echo "================================================================================"
echo "[`date '+%Y-%m-%d %H:%M:%S'`]"
if [[ "${chk1}" == "${chk2}" ]] && [[ "${chk1}" == "${chk3}" ]]; then
    echo "TEST PASSED: generated data is identical on all replicas"
    res=0
elif [[ "${chk1}" != "${chk3}" ]]; then
    echo "TEST FAILED: generated data is different on" ${MYSQL3_HOST}${INFRA}
elif [[ "${chk1}" != "${chk2}" ]]; then
    echo "TEST FAILED: generated data is different on" ${MYSQL2_HOST}${INFRA}
else
    echo "TEST FAILED"
fi
echo "================================================================================"

exit $res
