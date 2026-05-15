.[1] | .mysql_servers |
    map(
        if .hostname == "127.1.1.11" then
            . + {comment: "mysql01"}
        elif .hostname == "127.1.1.12" then
            . + {comment: "mysql02"}
        elif .hostname == "127.1.1.13" then
            . + {comment: "mysql03"} else . end
    ) | .[]
