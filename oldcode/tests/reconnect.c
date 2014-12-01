#include <mysql/mysql.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

pthread_attr_t attr;

int qnum=0;

typedef struct _setting_reconnect_t {
	int enabled;
	int threads;
	int queries;
	int slave_pct;
	int min_sleep;
	int max_sleep;
	int kill_interval;
	int select_OK;
	int select_ERR;
	int kills;
} setting_reconnect_t;


setting_reconnect_t reconnect;



void * mysql_client_reconnect_kill() {
	int i;
	char query[24];
	MYSQL *mysql=mysql_init(NULL);
	//if (!mysql_real_connect(mysql,"127.0.0.1","root","","test",3306,NULL,0))
	if (!mysql_real_connect(mysql,"127.0.0.1","root","","test",3306,NULL,0))
	{
    	fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		return NULL;
	}
	while (reconnect.enabled==1) {
		usleep(reconnect.kill_interval*1000);
		if (mysql_query(mysql,"SELECT id FROM INFORMATION_SCHEMA.PROCESSLIST WHERE COMMAND='Sleep' AND USER='vegaicm'")) {
			fprintf(stderr,"%s\n", mysql_error(mysql));
			mysql_close(mysql);
			return NULL;
    	}
		MYSQL_RES *result = mysql_store_result(mysql);
		MYSQL_ROW row;
//		for (i=0; i<mysql_num_rows(result); i++) {
		while ((row = mysql_fetch_row(result))) {
			memset(query,0,24);
			sprintf(query,"KILL %s", row[0]);
			printf("%s\n", query);
			if (mysql_query(mysql,query)) {
				fprintf(stderr,"%s\n", mysql_error(mysql));
//				mysql_close(mysql);
//				return NULL;
    		} else {
				__sync_fetch_and_add(&reconnect.kills,1);
			}
		}
		mysql_free_result(result);
	}
}

void * mysql_client_reconnect_thread() {
	int i;
	char query[128];
	MYSQL *mysql=mysql_init(NULL);
//	if (!mysql_real_connect(mysql,"localhost","root","","test",0,"/tmp/proxysql.sock",0))
	//if (!mysql_real_connect(mysql,"127.0.0.1","root","","test",3306,NULL,0))
	if (!mysql_real_connect(mysql,"127.0.0.1","vegaicm","password","test",6033,NULL,0))
	{
    	fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		return NULL;
	}
	for (i=0; i<reconnect.queries; i++) {
		int r1=rand();
		memset(query,0,128);
		usleep(r1%(reconnect.max_sleep*1000-reconnect.min_sleep*1000)+reconnect.min_sleep);
		sprintf(query,"SELECT %d%s", r1, ( r1%100>reconnect.slave_pct ? " FOR UPDATE" : ""));
//		printf("%s\n", query);
		if (mysql_query(mysql,query)) {
			fprintf(stderr,"%s %s\n", mysql_error(mysql), query);
			__sync_fetch_and_add(&reconnect.select_ERR,1);
			mysql_close(mysql);
			return NULL;
    	}
		MYSQL_RES *result = mysql_store_result(mysql);
		mysql_free_result(result);
		__sync_fetch_and_add(&reconnect.select_OK,1);
	}
	return NULL;
}
int main(int argc, char **argv) {
	int i;
/*	int thrnum;
	if (argc < 3) exit(EXIT_FAILURE);
	thrnum=atoi(argv[1]);
	if (thrnum==0) exit(EXIT_FAILURE);
	qnum=atoi(argv[2]);
	if (qnum==0) exit(EXIT_FAILURE);*/
	mysql_library_init(0,NULL,NULL);
	pthread_attr_init(&attr);
	//pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize (&attr, 64*1024);
	reconnect.enabled=1;
	reconnect.threads=64;
	reconnect.queries=1000;
	reconnect.slave_pct=70;
	reconnect.min_sleep=1000;
	reconnect.max_sleep=3000;
	reconnect.kill_interval=10000;
	reconnect.kills=0;
	reconnect.select_OK=0;
	reconnect.select_ERR=0;
	pthread_t *thi=malloc(sizeof(pthread_t)*reconnect.threads);
	if (thi==NULL) exit(EXIT_FAILURE);
	pthread_t kill;
	if ( pthread_create(&kill, &attr, mysql_client_reconnect_kill, NULL ) != 0 )
    		perror("Thread creation");
	for (i=0; i<reconnect.threads; i++) {
		if ( pthread_create(&thi[i], &attr, mysql_client_reconnect_thread , NULL) != 0 )
    		perror("Thread creation");
	}
	for (i=0; i<reconnect.threads; i++) {
		pthread_join(thi[i], NULL);
	}
	free(thi);
	reconnect.enabled=0;
	pthread_join(kill, NULL);
	printf("Select OK: %d\n", reconnect.select_OK);
	printf("Select ERR: %d\n", reconnect.select_ERR);
	printf("Kills: %d\n", reconnect.kills);
	return 0;
}
