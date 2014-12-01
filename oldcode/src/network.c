#include "proxysql.h"

int listen_on_port(char *ip, uint16_t port) {
    int rc, arg_on=1;
	struct sockaddr_in addr;
	int sd;
	if ( (sd = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
		PANIC("Socket - TCP");
	rc = setsockopt(sd, SOL_SOCKET,  SO_REUSEADDR, (char *)&arg_on, sizeof(arg_on));
	if (rc < 0) {
		PANIC("setsockopt() failed");
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
		proxy_error("Error on Bind , address %s:%d\n", ip, port);
		exit(EXIT_FAILURE);
	}
	if ( listen(sd, glovars.backlog) != 0 ) {
		proxy_error("Error on Listen , address %s:%d\n", ip, port);
		exit(EXIT_FAILURE);
	}
	return sd;
}

int listen_on_unix(char *path) {
	struct sockaddr_un serveraddr;
	int sd;
	int r;
	r=unlink(path);
	if ( (r==-1) && (errno!=ENOENT) ) {
		PANIC("Error unlink Unix Socket");
	}
	if ( ( sd = socket(AF_UNIX, SOCK_STREAM, 0)) <0 )
		PANIC("Socket - Unix");
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strncpy(serveraddr.sun_path, path, sizeof(serveraddr.sun_path) - 1);
    if ( bind(sd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_un)) != 0 )
		PANIC("Bind - Unix");
	if ( listen(sd, glovars.backlog) != 0 )
		PANIC("Listen - Unix");
	r=chmod(path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH);
	return sd;
}


int connect_socket(char *address, int connect_port)
{
	struct sockaddr_in a;
	int s;

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		close(s);
		return -1;
	}

	memset(&a, 0, sizeof(a));
	a.sin_port = htons(connect_port);
	a.sin_family = AF_INET;

	if (!inet_aton(address, (struct in_addr *) &a.sin_addr.s_addr)) {
		perror("bad IP address format");
		close(s);
		return -1;
	}

	if (connect(s, (struct sockaddr *) &a, sizeof(a)) == -1) {
		perror("connect()");
		shutdown(s, SHUT_RDWR);
		close(s);
		return -1;
	}
	return s;
}

gboolean write_one_pkt_to_net(mysql_data_stream_t *myds, pkt *p) {// this should be used ONLY when sure that only 1 packet is expected, for example during authentication
	l_ptr_array_add(myds->output.pkts, p);
	myds->array2buffer(myds);
	queue_t *q=&myds->output.queue;
	while (queue_data(q) && (myds->active==TRUE)) {
		myds->write_to_net(myds);
	}
	if (myds->active==FALSE) {
		return FALSE;
	}
	return TRUE;
}
