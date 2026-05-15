.[0]
    | {
          init_state: .proxysql_init_state,
          replication_hostgroups: .mysql_replication_hostgroups,
          writers_only:
             [
                 [.mysql_servers[] as $server
                         | .proxysql_init_state[] as $init_server
                         | .mysql_replication_hostgroups[]
                         | if $server.hostgroup_id == .writer_hostgroup and
                              $init_server.hostgroup_id == .writer_hostgroup
                           then $server
                           else empty end
                 ][] as $writer
                 | .mysql_servers[] as $server
                     | .mysql_replication_hostgroups[]
                     | if $server.hostname == $writer.hostname and
                          $server.hostgroup_id == .reader_hostgroup
                       then empty
                       else $writer end
             ]
      }
    | .writers_only
    | unique_by([.hostname, .hostgroup_id]) | .[]
