#!/bin/bash


#export ORCHESTRATOR_API="http://localhost:${ORC1_PORT}/api http://localhost:${ORC2_PORT}/api http://localhost:${ORC3_PORT}/api"
export ORCHESTRATOR_API="http://orc1.${INFRA}:3000/api http://orc2.${INFRA}:3000/api http://orc3.${INFRA}:3000/api"

echo -n "Configuring 'orchestrator' ..."
sleep 5
orchestrator-client -c discover -i mysql1 >/dev/null
orchestrator-client -c discover -i mysql2 >/dev/null
orchestrator-client -c discover -i mysql3 >/dev/null
echo " done."

#echo -n "Orchestrator discovering mysql1 ... got "
#orchestrator-client -c discover -i mysql1
#echo -n "Orchestrator discovering mysql2 ... got "
#orchestrator-client -c discover -i mysql2
#echo -n "Orchestrator discovering mysql3 ... got "
#orchestrator-client -c discover -i mysql3

echo "Cluster topology:"
orchestrator-client -c topology -a $(orchestrator-client -c clusters)

#echo -n "Cluster name: $(orchestrator-client -c clusters)"
#echo " done."
