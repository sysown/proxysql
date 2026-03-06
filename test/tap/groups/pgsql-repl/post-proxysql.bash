#!/bin/bash

set -e

. constants

echo "[$(date)] Shutting down PGSQL_REPL testing infra ..."
./docker-compose-destroy.bash
