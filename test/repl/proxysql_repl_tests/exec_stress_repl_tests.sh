#!/usr/bin/bash

res=0

source ../env.sh

. constants

# export env vars from .env to the environment of subsequent commands
set -a
. .env

if [ -z "${1}" ]; then
    iterations=1
else
    iterations=${1}
fi

export SCRIPTPATH=${PWD}

for i in $(seq 1 ${iterations})
do
   echo "Stress test run $i"
   ./stress_all_repl_tests.sh
   if [ $? -ne 0 ]; then
     echo "Stress test run $i FAILED"
     res=1
     exit $res
   else
     echo "Stress test run $i PASSED"
   fi
done

exit $res
