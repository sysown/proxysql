.[0]
    | {repl_hgs: .mysql_replication_hostgroups, proxysql_state: .[$state]}
    | [.repl_hgs[] as $repl_hg | (.proxysql_state[] | select($repl_hg[$type] == .hostgroup_id and .hostname == $hostname))]
    | .[]
