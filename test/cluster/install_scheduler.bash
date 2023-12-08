#!/usr/bin/env bash

cp -f check_all_nodes.bash /tmp/check_all_nodes.bash
chmod +x /tmp/check_all_nodes.bash

mysql -u admin -padmin -h 127.0.0.1 -P6032 -e "\
INSERT INTO scheduler (interval_ms, filename) VALUES (12000, '/tmp/check_all_nodes.bash'); \
LOAD SCHEDULER TO RUNTIME; \
SAVE SCHEDULER TO DISK; \
" 2>&1 | grep -v "Using a password"

for i in 1 2 3; do
	sleep 3
	mysql -u admin -padmin -h 127.0.0.1 -P2600$i -e "\
INSERT INTO scheduler (interval_ms, filename) VALUES (12000, '/tmp/check_all_nodes.bash'); \
LOAD SCHEDULER TO RUNTIME; \
SAVE SCHEDULER TO DISK; \
" 2>&1 | grep -v "Using a password"
done
