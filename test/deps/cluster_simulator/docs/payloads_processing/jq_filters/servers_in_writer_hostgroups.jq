.[0]
    | [.mysql_servers[] as $server
        | (.mysql_replication_hostgroups[] | if $server.hostgroup_id == .writer_hostgroup then $server else empty end)]
    | unique_by([.hostgroup_id, .hostname])
    | .[]
