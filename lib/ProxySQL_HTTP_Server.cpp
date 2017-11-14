#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "cpp.h"

#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "SpookyV2.h"

#include <fcntl.h>
#include <sys/utsname.h>

#include "platform.h"
#include "microhttpd.h"


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_HTTP_SERVER_VERSION "1.4.1031" DEB


//extern struct MHD_Daemon *Admin_HTTP_Server;

extern ProxySQL_Statistics *GloProxyStats;

extern char * Chart_bundle_js_c;
#define RATE_LIMIT_PAGE "<html><head><title>Rate Limit Page</title></head><body>Rate Limit Reached</body></html>"



char * ProxySQL_HTTP_Server::extract_values(SQLite3_result *result, int idx, bool relative, double mult) {
	string s = "[";
	int i;
	for ( i= (relative ? 1 : 0) ; i < result->rows_count ; i++) {
		SQLite3_row *r1 = ( relative ? result->rows[i-1] : NULL );
		SQLite3_row *r2 = result->rows[i];
		double v;
		if (relative) {
			double d2 = atol(r2->fields[idx]);
			double d1 = atol(r1->fields[idx]);
			double diff = (atol(r2->fields[1])-atol(r1->fields[1]));
			v = (d2-d1)/diff;
		} else {
			v = atol(r2->fields[idx]);
		}
		v *= mult;
		if (v<0) v=0;
		s.append(std::to_string(v));
		if (i != result->rows_count-1) {
			s.append(", ");
		}
	}
	s.append("];");
	char *ret=strdup(s.c_str());
	return ret;
}

char * ProxySQL_HTTP_Server::extract_ts(SQLite3_result *result, bool relative) {
	string s = "[";
	int i;
	for ( i= (relative ? 1 : 0) ; i < result->rows_count ; i++) {
		SQLite3_row *r2 = result->rows[i];
		s.append("\"");
		s.append(r2->fields[0]);
		s.append("\"");
		if (i != result->rows_count-1) {
			s.append(", ");
		}
	}
	s.append("];");
	char *ret=strdup(s.c_str());
	return ret;
}


void ProxySQL_HTTP_Server::init() {
}

void ProxySQL_HTTP_Server::print_version() {
	fprintf(stderr,"Standard ProxySQL HTTP Server Handler rev. %s -- %s -- %s\n", PROXYSQL_HTTP_SERVER_VERSION, __FILE__, __TIMESTAMP__);
}

#define EMPTY_PAGE "<html><head><title>File not found</title></head><body>File not found<br/><a href=\"/\">Go back home</a></body></html>"

int ProxySQL_HTTP_Server::handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr) {

	struct MHD_Response *response;
	int ret;
	char *valmetric = NULL;
	char *valinterval = NULL;
	char *valunit = NULL;

	time_t now = time(NULL);
	if (now != cur_time) {
		page_sec = 0;
		cur_time = now;
	}
	page_sec++;
	if (page_sec > ProxySQL_HTTP_Server_Rate_Limit) {
		response = MHD_create_response_from_buffer(strlen(RATE_LIMIT_PAGE), (void *) RATE_LIMIT_PAGE, MHD_RESPMEM_PERSISTENT); 
  		ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  		MHD_destroy_response (response);
		return ret;
	}

	if (0 != strcmp (method, "GET"))
		return MHD_NO;              /* unexpected method */
//	if (&aptr != *ptr) { 
//		/* do never respond on first call */
//		*ptr = &aptr;
//		return MHD_YES;
//	}
//	*ptr = NULL;                  /* reset when done */

	if (strcmp(url,"/stats")==0) {
		valmetric = (char *)MHD_lookup_connection_value (connection, MHD_GET_ARGUMENT_KIND, (char *)"metric");
		valinterval = (char *)MHD_lookup_connection_value (connection, MHD_GET_ARGUMENT_KIND, (char *)"points");
		valunit = (char *)MHD_lookup_connection_value (connection, MHD_GET_ARGUMENT_KIND, (char *)"unit");
		if (valmetric == NULL) {
			response = MHD_create_response_from_buffer (strlen (EMPTY_PAGE), (void *) EMPTY_PAGE, MHD_RESPMEM_PERSISTENT);
			ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response (response);
			return ret;
		}
		if (valunit == NULL) {
			valunit = (char *)"second";
		}
		if ( (strcmp(valunit,"second")) && (strcmp(valunit,"hour")) && (strcmp(valunit,"day")) ) {
			response = MHD_create_response_from_buffer (strlen (EMPTY_PAGE), (void *) EMPTY_PAGE, MHD_RESPMEM_PERSISTENT);
			ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
			MHD_destroy_response (response);
			return ret;
		}
		if (valinterval == NULL) {
			if ((strcmp(valunit,(char *)"second") == 0)) {
				valinterval = (char *)"14400";
			}
			if ((strcmp(valunit,(char *)"hour") == 0)) {
				valinterval = (char *)"720";
			}
			if ((strcmp(valunit,"day") == 0)) {
				valinterval = (char *)"365";
			}
		}

		if (strcmp(valmetric,"system")==0) {
			string *s = generate_header((char *)"ProxySQL Graphs");
			string *s1 = generate_canvas((char *)"myChart1");
			s->append(s1->c_str());
			s1 = generate_canvas((char *)"myChart2");
			s->append(s1->c_str());
			s1 = generate_canvas((char *)"myChart3");
			s->append(s1->c_str());
			s1 = generate_canvas((char *)"myChart4");
			s->append(s1->c_str());
			SQLite3_result *cpu_sqlite = GloProxyStats->get_system_cpu_metrics();
			SQLite3_result *memory_sqlite = GloProxyStats->get_system_memory_metrics();
			//SQLite3_result *mysql_metrics_sqlite = GloProxyStats->get_mysql_metrics();
			char **nm = NULL;
			char **nl = NULL;
			char **nv = NULL;
			char *ts = NULL;

			nm = (char **)malloc(sizeof(char *)*2);
			nm[0] = (char *)"utime";
			nm[1] = (char *)"stime";
			nl = (char **)malloc(sizeof(char *)*2);
			nl[0] = (char *)"User Time";
			nl[1] = (char *)"System Time";
			nv = (char **)malloc(sizeof(char *)*2);
			nv[0] = extract_values(cpu_sqlite,2,true,(double)1/sysconf(_SC_CLK_TCK));
			nv[1] = extract_values(cpu_sqlite,3,true,(double)1/sysconf(_SC_CLK_TCK));
			ts = extract_ts(cpu_sqlite,true);
			s1 = generate_chart((char *)"myChart1",ts,2,nm,nl,nv);
			s->append(s1->c_str());
			free(nm);
			free(nl);
			free(nv[0]);
			free(nv[1]);
			free(nv);
			free(ts);
			

			nm = (char **)malloc(sizeof(char *)*5);
			nm[0] = (char *)"allocated";
			nm[1] = (char *)"resident";
			nm[2] = (char *)"active";
			nm[3] = (char *)"mapped";
			nm[4] = (char *)"metadata";
			nl = (char **)malloc(sizeof(char *)*5);
			nl[0] = (char *)"Allocated";
			nl[1] = (char *)"Resident";
			nl[2] = (char *)"Active";
			nl[3] = (char *)"Mapped";
			nl[4] = (char *)"Metadata";
			nv = (char **)malloc(sizeof(char *)*5);
			nv[0] = extract_values(memory_sqlite,2,false);
			nv[1] = extract_values(memory_sqlite,3,false);
			nv[2] = extract_values(memory_sqlite,4,false);
			nv[3] = extract_values(memory_sqlite,5,false);
			nv[4] = extract_values(memory_sqlite,6,false);
			ts = extract_ts(cpu_sqlite,true);
			s1 = generate_chart((char *)"myChart2",ts,5,nm,nl,nv);
			s->append(s1->c_str());
			free(nm);
			free(nl);
			free(nv[0]);
			free(nv[1]);
			free(nv[2]);
			free(nv[3]);
			free(nv[4]);
			free(nv);
			free(ts);
			
			s->append("</body></html>");
	 		response = MHD_create_response_from_buffer(s->length(), (void *) s->c_str(), MHD_RESPMEM_PERSISTENT); 
  			ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  			MHD_destroy_response (response);
			return ret;
		}

		if (strcmp(valmetric,"mysql")==0) {
			string *s = generate_header((char *)"ProxySQL Graphs");
			string *s1 = generate_canvas((char *)"myChart1");
			s->append(s1->c_str());
			s1 = generate_canvas((char *)"myChart2");
			s->append(s1->c_str());
			s1 = generate_canvas((char *)"myChart3");
			s->append(s1->c_str());
			s1 = generate_canvas((char *)"myChart4");
			s->append(s1->c_str());
			//SQLite3_result *cpu_sqlite = GloProxyStats->get_system_cpu_metrics();
			//SQLite3_result *memory_sqlite = GloProxyStats->get_system_memory_metrics();
			SQLite3_result *mysql_metrics_sqlite = GloProxyStats->get_mysql_metrics();
			char **nm = NULL;
			char **nl = NULL;
			char **nv = NULL;
			char *ts = NULL;

//Client_Connections_aborted, Client_Connections_connected, Client_Connections_created, Server_Connections_aborted, Server_Connections_connected, Server_Connections_created, ConnPool_get_conn_immediate, ConnPool_get_conn_success, Questions

			nm = (char **)malloc(sizeof(char *)*6);
			nm[0] = (char *)"Client_Connections_aborted";
			nm[1] = (char *)"Client_Connections_connected";
			nm[2] = (char *)"Client_Connections_created";
			nm[3] = (char *)"Server_Connections_aborted";
			nm[4] = (char *)"Server_Connections_connected";
			nm[5] = (char *)"Server_Connections_created";
			nl = (char **)malloc(sizeof(char *)*6);
			nl[0] = (char *)"Client Connections aborted";
			nl[1] = (char *)"Client Connections connected";
			nl[2] = (char *)"Client Connections created";
			nl[3] = (char *)"Server Connections aborted";
			nl[4] = (char *)"Server Connections connected";
			nl[5] = (char *)"Server Connections created";
			nv = (char **)malloc(sizeof(char *)*6);
			nv[0] = extract_values(mysql_metrics_sqlite,2,true,(double)1);
			nv[1] = extract_values(mysql_metrics_sqlite,3,false,(double)1);
			nv[2] = extract_values(mysql_metrics_sqlite,4,true,(double)1);
			nv[3] = extract_values(mysql_metrics_sqlite,5,true,(double)1);
			nv[4] = extract_values(mysql_metrics_sqlite,6,false,(double)1);
			nv[5] = extract_values(mysql_metrics_sqlite,7,true,(double)1);
			ts = extract_ts(mysql_metrics_sqlite,true);
			s1 = generate_chart((char *)"myChart1",ts,6,nm,nl,nv);
			s->append(s1->c_str());
			free(nm);
			free(nl);
			for (int aa=0 ; aa<6 ; aa++) {
				free(nv[aa]);
			}
			free(nv);
			free(ts);
			

			nm = (char **)malloc(sizeof(char *)*4);
			nm[0] = (char *)"ConnPool_get_conn_failure";
			nm[1] = (char *)"ConnPool_get_conn_immediate";
			nm[2] = (char *)"ConnPool_get_conn_success";
			nm[3] = (char *)"Questions";
			nl = (char **)malloc(sizeof(char *)*4);
			nl[0] = (char *)"ConnPool failure";
			nl[1] = (char *)"ConnPool immediate";
			nl[2] = (char *)"ConnPool success";
			nl[3] = (char *)"Questions";
			nv = (char **)malloc(sizeof(char *)*4);
			nv[0] = extract_values(mysql_metrics_sqlite,8,true);
			nv[1] = extract_values(mysql_metrics_sqlite,9,true);
			nv[2] = extract_values(mysql_metrics_sqlite,10,true);
			nv[3] = extract_values(mysql_metrics_sqlite,11,true);
			ts = extract_ts(mysql_metrics_sqlite,true);
			s1 = generate_chart((char *)"myChart2",ts,4,nm,nl,nv);
			s->append(s1->c_str());
			free(nm);
			free(nl);
			for (int aa=0 ; aa<4 ; aa++) {
				free(nv[aa]);
			}
			free(nv);
			free(ts);

			s->append("</body></html>");
	 		response = MHD_create_response_from_buffer(s->length(), (void *) s->c_str(), MHD_RESPMEM_MUST_COPY); 
  			ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  			MHD_destroy_response (response);
			delete s;
			return ret;
		}
	}

	if (strcmp(url,"/Chart.bundle.js")==0) {
		response = MHD_create_response_from_buffer(strlen(Chart_bundle_js_c), Chart_bundle_js_c, MHD_RESPMEM_PERSISTENT); 
  		ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  		MHD_destroy_response (response);
		return ret;
	}
	response = MHD_create_response_from_buffer (strlen (EMPTY_PAGE), (void *) EMPTY_PAGE, MHD_RESPMEM_PERSISTENT);
	ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
	MHD_destroy_response (response);

	return ret;
}

string * ProxySQL_HTTP_Server::generate_header(char *s) {
	string *a = new string();
	a->append("<head>\n<title>");
	a->append(s);
	a->append("</title>\n<script src=\"/Chart.bundle.js\"></script>\n</head>\n<body>\n");
	return a;
}

string * ProxySQL_HTTP_Server::generate_canvas(char *s) {
	string *a = new string();
	a->append("<div class=\"wrapper\" style=\"width: 700px; height: 300px\"><canvas id=\"");
	a->append(s);
	a->append("\" width=\"650\" height=\"280\"></canvas></div>\n");
	return a;
}
ProxySQL_HTTP_Server::ProxySQL_HTTP_Server() {
	page_sec = 0;
	cur_time = time(NULL);
}

ProxySQL_HTTP_Server::~ProxySQL_HTTP_Server() {
}

string * ProxySQL_HTTP_Server::generate_chart(char *chart_name, char *ts, int nsets, char **dname, char **llabel, char **values) {
	char *h=(char *)"0123456789abcdef";
	string *ret= new string();
	int i;
	ret->append("<script>\n");
	ret->append("var ts = ");
	ret->append(ts);
	ret->append("\n");
	for (i=0;i<nsets;i++) {
		ret->append("var ");
		ret->append(dname[i]);
		ret->append(" = ");
		ret->append(values[i]);
		ret->append("\n");
	}
	ret->append("var ctx = document.getElementById(\"");
	ret->append(chart_name);
	ret->append("\");\nvar ");
	ret->append(chart_name);
	ret->append(" = new Chart(ctx, { \n");
	ret->append("type: 'line', \n");
	ret->append("  data: { \n");
	ret->append("    labels: ts,\n");
	ret->append("    datasets: [ \n");
	for (i=0;i<nsets;i++) {
		ret->append("      {\n");
		ret->append("        data: "); ret->append(dname[i]); ret->append(",\n");
		ret->append("        label: \""); ret->append(llabel[i]); ret->append("\",\n");
		int j;
		char pal[7];
		for (j=0; j<6; j++) { pal[j]=h[rand()%16]; }
		pal[6]='\0';
		ret->append("        borderColor: \"#"); ret->append(pal); ret->append("\",\n");
		ret->append("        fill: false\n");
		ret->append("      }");
		if (i<nsets-1) {
			ret->append(",");
		}
		ret->append("\n");
	}
	ret->append("    ]\n");
	ret->append("  }\n");
	ret->append("});\n");
	ret->append("</script>\n");
	return ret;
	
}
/*
    <script>\n";
	

	char *script5 = "\
var ctx = document.getElementById(\"myChart1\"); var myChart1 = new Chart(ctx, { \n\
type: 'line', \n\
  data: { \n\
    labels: ts, \n\
    datasets: [ \n\
      { \n\
        data: utime, \n\
        label: \"User Time\", \n\
        borderColor: \"#3e95cd\", \n\
        fill: false \n\
      }, \n\
      { \n\
        data: stime, \n\
        label: \"System Time\", \n\
        borderColor: \"#8e5ea2\", \n\
        fill: false \n\
      } \n\
    ] \n\
  } \n\
});\n";

*/
