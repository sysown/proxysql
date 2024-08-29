#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <fstream>
#include <algorithm>    // std::sort
#include <memory>
#include <vector>       // std::vector
#include <unordered_set>

#include "MySQL_Data_Stream.h"

#include "query_processor.h"

extern Query_Processor *GloQPro;

int ProxySQL_Test___GetDigestTable(bool reset, bool use_swap) {
	int r = 0;
	if (!GloQPro) return 0;
	if (use_swap == false) {
		SQLite3_result * resultset=NULL;
		if (reset==true) {
			resultset=GloQPro->get_query_digests_reset();
		} else {
			resultset=GloQPro->get_query_digests();
		}
		if (resultset==NULL) return 0;
		r = resultset->rows_count;
		delete resultset;
	} else {
		umap_query_digest uqd;
		umap_query_digest_text uqdt;
		GloQPro->get_query_digests_reset(&uqd, &uqdt);
		r = uqd.size();
		for (std::unordered_map<uint64_t, void *>::iterator it=uqd.begin(); it!=uqd.end(); ++it) {
			QP_query_digest_stats * qds = (QP_query_digest_stats *)it->second;
			delete qds;
		}
		uqd.erase(uqd.begin(),uqd.end());
		for (std::unordered_map<uint64_t, char *>::iterator it=uqdt.begin(); it!=uqdt.end(); ++it) {
			free(it->second);
		}
		uqdt.erase(uqdt.begin(),uqdt.end());
	}
	return r;
}

bool ProxySQL_Test___Refresh_MySQL_Variables(unsigned int cnt) {
	MySQL_Thread *mysql_thr=new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	for (unsigned int i = 0; i < cnt ; i++) {
		mysql_thr->refresh_variables();
	}
	delete mysql_thr;
	return true;
}

int ProxySQL_Test___PurgeDigestTable(bool async_purge, bool parallel, char **msg) {
	int r = 0;
	r = GloQPro->purge_query_digests(async_purge, parallel, msg);
	return r;
}

int ProxySQL_Test___GenerateRandomQueryInDigestTable(int n) {
	//unsigned long long queries=n;
	//queries *= 1000;
	MySQL_Session *sess = new MySQL_Session();
	// When the session is destroyed, client_connections is automatically decreased.
	// Because this is not a real connection, we artificially increase
	// client_connections
	__sync_fetch_and_add(&MyHGM->status.client_connections,1);
	sess->client_myds = new MySQL_Data_Stream();
	sess->client_myds->fd=0;
	sess->client_myds->init(MYDS_FRONTEND, sess, sess->client_myds->fd);
	MySQL_Connection *myconn=new MySQL_Connection();
	sess->client_myds->attach_connection(myconn);
	myconn->set_is_client(); // this is used for prepared statements
	//unsigned long long cur = monotonic_time();
	SQP_par_t qp;
	qp.first_comment=NULL;
	qp.query_prefix=NULL;
	qp.digest_text = (char *)malloc(1024);
	MySQL_Connection_userinfo ui;
	char * username_buf = (char *)malloc(32);
	char * schemaname_buf = (char *)malloc(64);
	//ui.username = username_buf;
	//ui.schemaname = schemaname_buf;
	strcpy(username_buf,"user_name_");
	strcpy(schemaname_buf,"shard_name_");
	bool orig_norm = mysql_thread___query_digests_normalize_digest_text;
	for (int i=0; i<n; i++) {
		if (i%10 == 0) {
			mysql_thread___query_digests_normalize_digest_text = true;
		} else {
			mysql_thread___query_digests_normalize_digest_text = orig_norm;
		}
		for (int j=0; j<10; j++) {
			sprintf(qp.digest_text,"SELECT ? FROM table%d a JOIN table%d b WHERE a.id > ? AND a.c IN (?,?,?) ORDER BY k,l DESC LIMIT ?",i, j);
			int digest_text_length = strlen(qp.digest_text);
			qp.digest=SpookyHash::Hash64(qp.digest_text, digest_text_length, 0);
			for (int k=0; k<10; k++) {
				//sprintf(username_buf,"user_%d",k%10);
				int _a = fastrand();
				int _k = _a%20;
				int _j = _a%7;
				for (int _i=0 ; _i<_k ; _i++) {
					username_buf[10+_i]='0' + (_j+_i)%10;
				}
				username_buf[10+_k]='\0';
				for (int l=0; l<10; l++) {
					//if (fastrand()%100==0) {
					//	sprintf(schemaname_buf,"long_shard_name_shard_whatever_%d",l%10);
					//} else {
					//	sprintf(schemaname_buf,"shard_%d",l%10);
					//}
					int _a = fastrand();
					int _k = _a%30;
					int _j = _a%11;
					for (int _i=0 ; _i<_k ; _i++) {
						schemaname_buf[11+_i]='0' + (_j+_i)%10;
					}
					schemaname_buf[11+_k]='\0';
					ui.set(username_buf, NULL, schemaname_buf, NULL);
					int hg = 0;
					uint64_t hash2;
					SpookyHash myhash;
					myhash.Init(19,3);
					myhash.Update(ui.username,strlen(ui.username));
					myhash.Update(&qp.digest,sizeof(qp.digest));
					myhash.Update(ui.schemaname,strlen(ui.schemaname));
					myhash.Update(&hg,sizeof(hg));
					myhash.Final(&qp.digest_total,&hash2);
					//update_query_digest(qp, sess->current_hostgroup, ui, t, sess->thread->curtime, NULL, sess);
					GloQPro->update_query_digest(&qp,hg, &ui,fastrand(),0,NULL,sess);
				}
			}
		}
	}
	delete sess;
	mysql_thread___query_digests_normalize_digest_text = orig_norm;
	return n*1000;
}
