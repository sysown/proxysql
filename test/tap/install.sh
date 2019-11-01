#!/bin/bash

# Installation script for MyTAP

SQLHOST='localhost';
SQLPORT=3306;
SQLSOCK=''
NOTESTS=0
NOINSTALL=0
FILTER=0

while [[ "${#}" > 0 ]]; do
    case ${1} in
        -u|--user)
            SQLUSER="${2}";
            shift
            ;;
        -p|--password)
            SQLPASS="${2}"
            shift
            ;;
        -h|--host)
            SQLHOST="${2}"
            shift
            ;;
        -P|--port)
            SQLPORT="${2}"
            shift
            ;;
        -S|--socket)
            SQLSOCK="${2}"
            shift
            ;;
        -f|--filter)
            NOFILTER=0
            FILTER="${2}"
            shift
            ;;
        -t|--no-tests)
            NOTESTS=1
            ;;
        -i|--no-install)
            NOINSTALL=1
            ;;
        -?|--help)
            cat << EOF
Usage:
 install.sh [options]

Options:
 -u, --user string      MySQL username
 -p, --password string  MySQL password
 -h, --host name or IP  MySQL host
 -P, --port name        MySQL port
 -S, --socket filename  MySQL host
 -t, --no-tests         Don't run the test suite when the install is completed
 -i, --no-install       Don't perform the installation, i.e. just run the test suite
 -f, --filter string    Perform the action on one class of objects <matching|eq|moretap|todo|utils|charset|collation|column|constraint|engine|event|index|partition|privilege|role|routines|table|trigger|schemata|user|view>
EOF
            exit 1
            ;;
        *)
            exit 1
            ;;
    esac;
    shift;
done


MYSQLOPTS="--disable-pager --batch --raw --skip-column-names --unbuffered"

if [[ ${SQLUSER} != '' ]] && [[ ${SQLPASS} != '' ]]; then
    MYSQLOPTS="${MYSQLOPTS} -u${SQLUSER} -p${SQLPASS}";
fi

if [[ ${SQLSOCK} != '' ]]; then
   MYSQLOPTS="${MYSQLOPTS} --socket=${SQLSOCK}";
fi

if [[ ${SQLHOST} != 'localhost' ]]; then
   MYSQLOPTS="${MYSQLOPTS} --host=${SQLHOST}";
fi

if [[ ${SQLPORT} != '3306' ]]; then
  MYSQLOPTS="${MYSQLOPTS} --port=${SQLPORT}"
fi

MYVER=$(mysql ${MYSQLOPTS} --execute "
    SELECT (SUBSTRING_INDEX(VERSION(), '.', 1) * 100000)
        + (SUBSTRING_INDEX(SUBSTRING_INDEX(VERSION(), '.', 2), '.', -1) * 1000)
        + CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(SUBSTRING_INDEX(VERSION(), '-', 1),'.', 3), '.', -1) AS UNSIGNED);
    ")

# checking thread_stack settings. See #44 for reference.

thread_stack=$(mysql ${MYSQLOPTS} --execute "SELECT @@thread_stack" --skip_column_names)
if [[ ${thread_stack} -lt 262144 ]]; then
  echo "Your thread_stack variable is set to ${thread_stack} bytes and will"
  echo "be too low to use myTAP. You should change the thread_stack variable to"
  echo "at least 262144 bytes (add thread_stack=256k to your mysql conf file)."
  exit 1
fi


# import the full package before running the tests
# you can't use a wildcard with the source command so all version specific files need
# to be separately listed


if [[ ${NOINSTALL} -eq 0 ]]; then
    echo "============= installing myTAP ============="
    echo "Importing myTAP base"
    mysql ${MYSQLOPTS} --execute 'source ./mytap.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-schemata.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-engine.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-collation.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-charset.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-timezone.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-user.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-event.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-table.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-view.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-column.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-trigger.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-role.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-routines.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-constraint.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-index.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-partition.sql';
    mysql ${MYSQLOPTS} --execute 'source ./mytap-privilege.sql';

    if [[ ${MYVER} -ge 506004 ]]; then
       echo "Importing Version 5.6.4 patches";
       mysql ${MYSQLOPTS} --execute 'source ./mytap-table-564.sql';
    fi

    if [[ ${MYVER} -ge 507006 ]]; then
       echo "Importing Version 5.7.6 patches";
       mysql ${MYSQLOPTS} --execute 'source ./mytap-table-576.sql';
       mysql ${MYSQLOPTS} --execute 'source ./mytap-global-576.sql';
       mysql ${MYSQLOPTS} --execute 'source ./mytap-user-576.sql';
    fi

    if [[ ${MYVER} -ge 800011 ]]; then
       echo "Importing Version 8.0.11 patches";
       mysql ${MYSQLOPTS} --execute 'source ./mytap-role-8011.sql';
       mysql ${MYSQLOPTS} --execute 'source ./mytap-table-8011.sql';
    fi
fi

if [[ ${NOTESTS} -eq 0 ]]; then
   if [[ ${FILTER} != 0 ]]; then
      echo "Running test suite with filter: ${FILTER}";
   else
      echo "Running Full test suite, this will take a couple of minutes to complete."
   fi

   sleep 2;

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "matching" ]]; then
      echo "============= matching ============="
      mysql ${MYSQLOPTS} --database tap --execute 'source t/matching.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "eq" ]]; then
      echo "============= eq ============="
      mysql ${MYSQLOPTS} --database tap --execute 'source t/eq.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "moretap" ]]; then
      echo "============= moretap ============="
      mysql ${MYSQLOPTS} --database tap --execute 'source t/moretap.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "todotap" ]]; then
      echo "============= todotap ============="
      mysql ${MYSQLOPTS} --database tap --execute 'source t/todotap.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "utils" ]]; then
      echo "============= utils ============="
      mysql ${MYSQLOPTS} --database tap --execute 'source t/utils.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "charset" ]]; then
      echo "============= character sets ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-charset.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "collation" ]]; then
      echo "============= collations ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-collation.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "column" ]]; then
      echo "============= columns ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-column.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "constraint" ]]; then
      echo "============= constraints ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-constraint.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "engine" ]]; then
      echo "============= engines ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-engine.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "event" ]]; then
      echo "============= events ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-event.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "index" ]]; then
      echo "============= indexes ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-index.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "partition" ]]; then
      echo "============= partitions ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-partition.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "privilege" ]]; then
      echo "============= privileges ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-privilege.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "role" ]]; then
      echo "============= role ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-role.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "routines" ]]; then
      echo "============= routines ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-routines.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "schemata" ]]; then
      echo "============= schemas ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-schemata.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "table" ]]; then
      echo "============= tables ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-table.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "trigger" ]]; then
      echo "============= triggers ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-trigger.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "user" ]]; then
      echo "============= users ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-user.my'
   fi

   if [[ ${FILTER} == 0 ]] || [[ ${FILTER} =~ "view" ]]; then
      echo "============= views ============"
      mysql ${MYSQLOPTS} --database tap --execute 'source t/test-mytap-view.my'
   fi

fi

echo "Finished"
