#include "proxysql.h"

/*
 * create a socket and listen on a specified IP and port
 * returns the socket
 */
int listen_on_port(char *ip, uint16_t port, int backlog) {
	int rc, arg_on=1;
	struct sockaddr_in addr;
	int sd;

	// create a socket
	if ( (sd = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
		proxy_error("Error on creating socket\n");
		close(sd);
		return -1;
	}

#ifdef SO_REUSEPORT
	// set SO_REUSEADDR and SO_REUSEPORT
	rc = setsockopt(sd, SOL_SOCKET,  SO_REUSEADDR | SO_REUSEPORT, (char *)&arg_on, sizeof(arg_on));
#else
	// set SO_REUSEADDR
	rc = setsockopt(sd, SOL_SOCKET,  SO_REUSEADDR, (char *)&arg_on, sizeof(arg_on));
#endif /* SO_REUSEPORT */

	if (rc < 0) {
		proxy_error("setsockopt() failed\n");
	}

	// define addr with the specified IP and port	
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	// call bind() to bind the socket on the specified address
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
		proxy_error("Error on Bind , address %s:%d\n", ip, port);
		close(sd);
		return -1;
	}

	// define the backlog
	if ( listen(sd, backlog) != 0 ) {
		proxy_error("Error on Listen , address %s:%d\n", ip, port);
		close(sd);
		return -1;
	}

	// return the socket
	return sd;
}

/*
 * create a socket and listen on the specified path
 * returns the socket
 */
int listen_on_unix(char *path, int backlog) {
	struct sockaddr_un serveraddr;
	int sd;
	int r;

	// remove the socket
	r=unlink(path);
	if ( (r==-1) && (errno!=ENOENT) ) {
		proxy_error("Error unlink Unix Socket %s\n", path);
		return -1;
	}

	// create a socket
	if ( ( sd = socket(AF_UNIX, SOCK_STREAM, 0)) <0 ) {
		proxy_error("Error on creating socket\n");
		close(sd);
		return -1;
	}

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sun_family = AF_UNIX;
	strncpy(serveraddr.sun_path, path, sizeof(serveraddr.sun_path) - 1);

	// call bind() to bind the socket on the specified file
	if ( bind(sd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_un)) != 0 ) {
		proxy_error("Error on Bind , Unix Socket %s\n", path);
		close(sd);
		return -1;
	}

	// define the backlog
	if ( listen(sd, backlog) != 0 ) {
		proxy_error("Error on Listen , Unix Socket %s\n", path);
		close(sd);
		return -1;
	}

	// change the permission on socket
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
