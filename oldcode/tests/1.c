#include <mysql/mysql.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>



int main() {
    int i;
    char query[24];
    MYSQL *mysql=mysql_init(NULL);
    //if (!mysql_real_connect(mysql,"127.0.0.1","root","","test",3306,NULL,0))
    if (!mysql_real_connect(mysql,"127.0.0.1","root","","test",3306,NULL,0))
    {
        fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
        return 0;
    }
     mysql_query(mysql,"SELECT id FROM INFORMATION_SCHEMA.PROCESSLIST WHERE COMMAND='Sleep' AND USER='vegaicm'");
//            fprintf(stderr,"%s\n", mysql_error(mysql));
     mysql_close(mysql);
	 sleep(100);
     return 0;
}
