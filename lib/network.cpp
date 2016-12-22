#include "network.h"

#include <cerrno>
#include <cstdio>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "proxysql_debug.h"

/*
 * create a socket and listen on a specified IP and port
 * returns the socket
 */
int listen_on_port(char *ip, uint16_t port, int backlog, bool reuseport) {
	int rc, arg_on = 1;
	struct addrinfo hints;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
        struct addrinfo *next, *ai;
        char port_string[NI_MAXSERV];
        int sd = -1;

        snprintf(port_string, sizeof(port_string), "%d", port);
	rc = getaddrinfo(ip, port_string, &hints, &ai);
	if (rc) {
		proxy_error("getaddrinfo(): %s\n", gai_strerror(rc));
		return -1;
	}

        for (next = ai; next != NULL; next = next->ai_next) {
	        if ((sd = socket(next->ai_family, next->ai_socktype, next->ai_protocol)) == -1) 
                        continue;
#ifdef IPV6_V6ONLY
                if (next->ai_family == AF_INET6) {
                        if(setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&arg_on, sizeof(arg_on)) == -1) 
				proxy_error("setsockopt() IPV6_V6ONLY: %d\n", gai_strerror(errno));
                }
#endif

                if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&arg_on, sizeof(arg_on)) == -1) {
                        proxy_error("setsockopt() SO_REUSEADDR: %s\n", gai_strerror(errno));
                        close(sd);
                        freeaddrinfo(ai);
                        return -1;
                }

#ifdef SO_REUSEPORT
  		if (reuseport) {
			if (setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, (char *)&arg_on, sizeof(arg_on)) == -1) {
				proxy_error("setsockopt() SO_REUSEPORT: %d\n", gai_strerror(errno));
			}
		}
#endif /* SO_REUSEPORT */

                if (bind(sd, next->ai_addr, next->ai_addrlen) == -1) {
                        if (errno != EADDRINUSE) {
                                proxy_error("bind(): %s\n", gai_strerror(errno));
                                close(sd);
                                freeaddrinfo(ai);
                                return -1;
                        }
                } else {
                        if (listen(sd, backlog) == -1) {
                                proxy_error("listen(): %s\n", gai_strerror(errno));
                                close(sd);
                                freeaddrinfo(ai);
                                return -1;
                        }
                }
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
