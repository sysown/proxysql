#!/bin/bash

set -e

rsubnet=$(docker exec --user root pgsql-repl-pg_replica-1 sh -c \
	'getent hosts pg_primary_int | cut -d" " -f1')
vintf=$(docker exec --user root pgsql-repl-pg_primary-1 sh -c \
	"ip route show to match \"$rsubnet\" | grep -E \"$rsubnet\" | cut -d' ' -f3")

tbf_count=$(docker exec --user root pgsql-repl-pg_primary-1 sh -c \
	"tc qdisc list dev $vintf | grep 'qdisc tbf' | wc -l")

if [[ $tbf_count -ne 0 ]]; then
	echo "[$(date)] Deleting found TBF rule to interface...   vintf=$vintf count=$tbf_count"
	docker exec --user root pgsql-repl-pg_primary-1 sh -c \
		"tc qdisc del dev $vintf root"
fi
