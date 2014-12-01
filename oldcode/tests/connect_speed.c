#include <mysql/mysql.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

pthread_attr_t attr;

static volatile int load_;

int qnum=0;

typedef struct _setting_reconnect_t {
	int enabled;
	int threads;
	int queries;
	int iterations;
	int slave_pct;
	int min_sleep;
	int max_sleep;
	int kill_interval;
	int select_OK;
	int select_ERR;
	int connect_OK;
	int kills;
	int ssl;
} setting_reconnect_t;


setting_reconnect_t reconnect;


/*
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
*/


static __thread unsigned int g_seed;


inline void fast_srand( int seed ) {
g_seed = seed;
}
inline int fastrand() {
    g_seed = (214013*g_seed+2531011);
    return (g_seed>>16)&0x7FFF;
}


void * mysql_client_reconnect_thread() {
	int select_OK=0;
	int select_ERR=0;
	int connect_OK=0;
	int i, j, k;
	//char *query="SELECT 1";
	char query[100];
	MYSQL *mysql=NULL;
//	if (!mysql_real_connect(mysql,"localhost","root","","test",0,"/tmp/proxysql.sock",0))
	//if (!mysql_real_connect(mysql,"127.0.0.1","root","","test",3306,NULL,0))
	//for (i=0; i<2000; i++) {
	__sync_fetch_and_sub(&load_,1);
	fast_srand((int)&g_seed);
	do { usleep(20000); } while (load_);
	for (i=0; i<reconnect.iterations; i++) {
//		mysql=mysql_init(NULL);
		//if (!mysql_real_connect(mysql,"127.0.0.1","root","","test",3306,NULL,0)) {
		mysql=mysql_init(NULL);
		if (reconnect.ssl) mysql_ssl_set(mysql,NULL,NULL,NULL,NULL,"AES128-SHA");
		if (!mysql_real_connect(mysql,"localhost","root","","test",0,"/tmp/proxysql.sock",0)) {
		//if (!mysql_real_connect(mysql,"127.0.0.1","root","","test",6033,NULL,0)) {
		//if (!mysql_real_connect(mysql,"localhost","root","","test",0,"/var/run/mysqld/mysqld.sock",0)) {
 	   	fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
			goto exit_thread;
		}
			memset(query,0,30);
			sprintf(query,"SELECT 1");
		connect_OK++;
		for (j=0; j<reconnect.queries; j++) {
			int r1=fastrand();
			memset(query,0,30);
			//usleep(r1%(reconnect.max_sleep*1000-reconnect.min_sleep*1000)+reconnect.min_sleep*1000);
//			sprintf(query,"SELECT %d%s", r1, ( r1%100>reconnect.slave_pct ? " FOR UPDATE" : ""));
			sprintf(query,"SELECT %d", r1%100);
			//fprintf(stderr,"%s\n", query);


			if (mysql_query(mysql,query)) {
				fprintf(stderr,"%s %s\n", mysql_error(mysql), query);
				//__sync_fetch_and_add(&reconnect.select_ERR,1);
				select_ERR++;
				goto exit_thread;
			} else {
				MYSQL_RES *result = mysql_store_result(mysql);
				mysql_free_result(result);
				//__sync_fetch_and_add(&reconnect.select_OK,1);
				select_OK++;
			}
/*
		int s, j;
		for (j=0; j<10000; j++) {
			//s=(fastrand()%50+10)*1000;
			//usleep(s);
			mysql_ping(mysql);
		}
*/
/**/
		}
		mysql_close(mysql);
	}
	exit_thread:
	__sync_fetch_and_add(&reconnect.select_OK,select_OK);
	__sync_fetch_and_add(&reconnect.select_ERR,select_ERR);
	__sync_fetch_and_add(&reconnect.connect_OK,connect_OK);
	return NULL;
}
int main(int argc, char **argv) {
	int i;
	if (argc<3) {
		fprintf(stderr,"Usage: ./connect_speed <threads> <queries> <iterations> [-ssl]\n");
		exit(EXIT_FAILURE);
	}
	mysql_library_init(0,NULL,NULL);
	pthread_attr_init(&attr);
	pthread_attr_setstacksize (&attr, 64*1024);
//	reconnect.enabled=1;
	//reconnect.threads=8000;
	reconnect.threads=atoi(argv[1]);
	if (reconnect.threads==0) reconnect.threads=4;
	reconnect.queries=atoi(argv[2]);
	//if (reconnect.queries==0) reconnect.queries=1000;
	reconnect.iterations=atoi(argv[3]);
	if (reconnect.iterations==0) reconnect.iterations=10;
	if (argc==5 && strcmp(argv[3],"-ssl")==0)
		reconnect.ssl=1;
	else
		reconnect.ssl=0;
	reconnect.slave_pct=80;
	reconnect.min_sleep=1;
	reconnect.max_sleep=10;
	reconnect.kill_interval=10000;
	reconnect.kills=0;
	reconnect.connect_OK=0;
	reconnect.select_OK=0;
	reconnect.select_ERR=0;

	load_ = reconnect.threads + 1;

	pthread_t *thi=malloc(sizeof(pthread_t)*reconnect.threads);
	if (thi==NULL) exit(EXIT_FAILURE);
//	pthread_t kill;
//	if ( pthread_create(&kill, &attr, mysql_client_reconnect_kill, NULL ) != 0 )
//    		perror("Thread creation");
	for (i=0; i<reconnect.threads; i++) {
		if ( pthread_create(&thi[i], &attr, mysql_client_reconnect_thread , NULL) != 0 )
    		perror("Thread creation");
	}
	do { /* nothing */ } while (load_ != 1);
	load_ = 0;
	for (i=0; i<reconnect.threads; i++) {
		pthread_join(thi[i], NULL);
	}
	free(thi);
//	reconnect.enabled=0;
//	pthread_join(kill, NULL);
	printf("Connect OK: %d\n", reconnect.connect_OK);
	printf("Select OK: %d\n", reconnect.select_OK);
	printf("Select ERR: %d\n", reconnect.select_ERR);
//	printf("Kills: %d\n", reconnect.kills);
	return 0;
}
