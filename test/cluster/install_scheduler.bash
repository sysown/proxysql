#/bin/bash
cp -f check_all_nodes.bash /tmp/check_all_nodes.bash
chmod +x /tmp/check_all_nodes.bash
mysql -u admin -padmin -h 127.0.0.1 -P6032 -e "INSERT INTO scheduler (interval_ms, filename) VALUES (7000, '/tmp/check_all_nodes.bash'); LOAD SCHEDULER TO RUNTIME; SAVE SCHEDULER TO DISK;"
