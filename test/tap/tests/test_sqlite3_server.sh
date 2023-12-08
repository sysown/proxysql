#!/usr/bin/env bash

# This script allows to manually check that 'test_sqlite3_server-t' is resillient to port change collisions
# for 'SQLite3' interface. It assumes that the port being used is the default '6030'. The script should be
# executed prior to the test. It should keep failing to bind the port with output:
#
# ```
# exit_code: 1, stderr: `Error: Couldn't setup listening socket (err=-3)`
# ```
#
# During the testing when ProxySQL changes the port, the script takes ownwership for 5 seconds. Triggering
# the section of the test of instructing to ProxySQL to reload SQLite3 interface due to the EADDRINUSE.

while true; do
    stderr=$(netcat -l -p 6030 -w 5 2>&1);

    if [[ $? == 1 ]] && [[ ${#stderr} == 0 ]]; then
         break;
    else
         echo "exit_code: $?, stderr: \`$stderr\`";
    fi;

    sleep 0.1;
done
