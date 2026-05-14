.[0]
    | {
          init_state: .proxysql_init_state,
          replication_hostgroups: .mysql_replication_hostgroups,
          readers: [
              .mysql_replication_hostgroups[] as $hg
              | .mysql_servers[]
              | select(.hostgroup_id == $hg.reader_hostgroup)
          ] | map({hostgroup_id, hostname, port, status: "ONLINE", comment}),
          exp_writers: [
              .mysql_servers[] as $server
                  | .proxysql_init_state[] as $init_server
                  | .mysql_replication_hostgroups[]
                  | if $server.hostgroup_id == .writer_hostgroup and
                       $init_server.hostgroup_id == .writer_hostgroup
                    then $server
                    else empty end
          ]
      }
    | {
          init_state: .init_state,
          replication_hostgroups: .mysql_replication_hostgroups,
          readers: .readers,
          exp_writers: .exp_writers,
          matching_writers_readers: [
              .exp_writers[] as $writer | .replication_hostgroups[] as $hg
              | if $writer.hostgroup_id == $hg.writer_hostgroup
                then $writer else empty end
              | $writer.hostgroup_id = $hg.reader_hostgroup
          ] | map({hostgroup_id, hostname, port, status: "ONLINE", comment})
      }
    | [
        .init_state[] as $init | [.matching_writers_readers[]
            | select($init.hostgroup_id == .hostgroup_id and $init.hostname ==.hostname)]
                | if length != 0 then empty else $init end
      ] + .readers
    | unique_by([.hostname, .hostgroup_id]) | .[]
