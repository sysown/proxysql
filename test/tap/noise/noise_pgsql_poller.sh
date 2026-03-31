#!/bin/bash

HOST=$1
PORT=$2
USER=$3
PASS=$4
INTERVAL=${5:-0.5}

export PGPASSWORD=$PASS

while true; do
    psql -h $HOST -p $PORT -U $USER -c "SELECT 1;" > /dev/null 2>&1
    sleep $INTERVAL
done
