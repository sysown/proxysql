#!/bin/bash

HOST=$1
PORT=$2
USER=$3
PASS=$4
INTERVAL=${5:-1.0}

while true; do
    mysql -h $HOST -P $PORT -u $USER -p$PASS -e "SELECT 1;" > /dev/null 2>&1
    sleep $INTERVAL
done
