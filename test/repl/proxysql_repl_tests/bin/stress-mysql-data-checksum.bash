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
elif [ -z "${MYSQL4_PORT}" ]; then
    echo "MYSQL4_PORT is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${MYSQL5_PORT}" ]; then
    echo "MYSQL5_PORT is empty, please check env vars passed to: " ${0}
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
elif [ -z "${MYSQL4_HOST}" ]; then
    echo "MYSQL4_HOST is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${MYSQL5_HOST}" ]; then
    echo "MYSQL5_HOST is empty, please check env vars passed to: " ${0}
    exit 1
fi

res=1

echo "Running checksum for sysbench data on primary (master) ..."
echo "Checksum results:"
mysql -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot sysbench --skip-column-names -e " \
CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5; \
" 2>&1 | grep -vP "mysql: .?Warning"

echo "Comparing sysbench data between primary and replicas ..."
chk1=$(mysql -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot sysbench --skip-column-names -e "CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5;" 2>&1 | grep -vP "mysql: .?Warning" | md5sum)
chk2=$(mysql -h${MYSQL2_HOST}${INFRA} -P${MYSQL2_PORT} -uroot -proot sysbench --skip-column-names -e "CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5;" 2>&1 | grep -vP "mysql: .?Warning" | md5sum)
chk3=$(mysql -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT} -uroot -proot sysbench --skip-column-names -e "CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5;" 2>&1 | grep -vP "mysql: .?Warning" | md5sum)
chk4=$(mysql -h${MYSQL4_HOST}${INFRA} -P${MYSQL4_PORT} -uroot -proot sysbench --skip-column-names -e "CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5;" 2>&1 | grep -vP "mysql: .?Warning" | md5sum)
chk5=$(mysql -h${MYSQL5_HOST}${INFRA} -P${MYSQL5_PORT} -uroot -proot sysbench --skip-column-names -e "CHECKSUM TABLE sbtest1, sbtest2, sbtest3, sbtest4, sbtest5;" 2>&1 | grep -vP "mysql: .?Warning" | md5sum)

echo "================================================================================"
echo "[`date '+%Y-%m-%d %H:%M:%S'`]"
if [[ "${chk1}" == "${chk2}" ]] && [[ "${chk1}" == "${chk3}" ]] && [[ "${chk1}" == "${chk4}" ]] && [[ "${chk1}" == "${chk5}" ]]; then
    echo "TEST PASSED: generated data is identical on all 4 replicas"
    res=0
elif [[ "${chk1}" != "${chk3}" ]] || [[ "${chk1}" != "${chk4}" ]] || [[ "${chk1}" != "${chk5}" ]]; then
    echo "TEST FAILED: generated data is different on: "
    if [[ "${chk1}" != "${chk3}" ]]; then
      echo "                                             "${MYSQL3_HOST}${INFRA}
    fi
    if [[ "${chk1}" != "${chk4}" ]]; then
      echo "                                             "${MYSQL4_HOST}${INFRA}
    fi
    if [[ "${chk1}" != "${chk5}" ]]; then
      echo "                                             "${MYSQL5_HOST}${INFRA}
    fi
elif [[ "${chk1}" != "${chk2}" ]]; then
    echo "TEST FAILED: generated data is different on" ${MYSQL2_HOST}${INFRA}
else
    echo "TEST FAILED"
fi
echo "================================================================================"

exit $res
