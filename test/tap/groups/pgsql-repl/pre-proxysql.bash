#!/bin/bash
set -o pipefail

set -e

. constants

echo "[$(date)] Cleaning infra prior to PGSQL_REPL group testing"
./docker-compose-destroy.bash

echo "[$(date)] Starting infra required for PGSQL_REPL group testing"
./docker-compose-init.bash
