//
//  test_keep_multiplexing.cpp
//  debug
//
//  Created by zhangyanjun on 2019/3/5.
//

#include <iostream>
#include "proxysql.h"
#include "mysql_connection.h"
#include "cpp.h"

int main(int argc, const char * argv[]) {
    char* query_digest_text = "select @@session.tx_isolation as a,@@tx_isolation,@@tx_isolation as a,@@version";
    MySQL_Connection *conn = NULL;
    
    if(conn->IsKeepMultiplexEnabledVariables(query_digest_text)){
        std::cout<< "true";
    }else{
        std::cout<< "false";
    }
    return 0;
}
