#include "proxysql.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "Proxy_Protocol.h"


bool Proxy_Protocol::parse_subnets(const char *list, std::vector<proxy_protocol_subnet_t> &subnets) {
    char *input = strdup(list), *cidr, *saveptr = NULL;
    const char *delim = ",; ";

    subnets.clear();
    for(cidr = strtok_r(input, delim, &saveptr); cidr != NULL; cidr = strtok_r(NULL, delim, &saveptr)) {
        if(!Proxy_Protocol::add_subnet(cidr, subnets)) {
            proxy_warning("PROXY protocol subnet parsing failed, invalid CIDR: %s\n", cidr);
            free(input);
            return false;
        };
    }

    free(input);
    return true;
}

bool Proxy_Protocol::add_subnet(const char *cidr, std::vector<proxy_protocol_subnet_t> &subnets) {
    char *addr = strdup(cidr), *mask;
    proxy_protocol_subnet_t subnet = {
        .family = AF_INET
    };

    if (strchr(addr, ':')) {
        subnet.family = AF_INET6;
    }

    subnet.bits = (unsigned short)(subnet.family == AF_INET? 32: 128);
    mask = strchr(addr, '/');
    if (mask) {
        *mask++ = '\0';
        subnet.bits = (unsigned short)atoi(mask);
        if (subnet.bits > (subnet.family == AF_INET? 32: 128)) {
            free(addr);
            return false;
        }
    }

    if (inet_pton(subnet.family, addr, subnet.addr) == 1) {
        subnets.push_back(subnet);
        free(addr);
        return true;
    }

    free(addr);
    return false;
}

bool Proxy_Protocol::match_subnet(struct sockaddr *addr, socklen_t addrlen, std::vector<proxy_protocol_subnet_t> &subnets) {
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    unsigned char *a1, *a2;

    for (size_t i = 0; i < subnets.size(); i++) {
        if (addr->sa_family != subnets[i].family) {
            continue;
        }

        switch (addr->sa_family) {
            case AF_INET:
                sin = (struct sockaddr_in *)addr;
                a1 = (unsigned char *)&(sin->sin_addr);
                break;
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *)addr;
                a1 = (unsigned char *)&(sin6->sin6_addr);
                break;
            default:
                return false;
                break;
        }
        a2 = subnets[i].addr;

        int n_bytes = subnets[i].bits / 8;
        if (n_bytes && memcmp(a1, a2, n_bytes)) {
            continue;
        }

        int n_bits = subnets[i].bits % 8;
        if (n_bits) {
            int mask = (1<<n_bits)-1;
            if ((a1[n_bytes] & mask) != (a2[n_bytes] & mask)) {
                continue;
            }
        }

        return true;
	}

	return false;
}

// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
// TODO: parse TCP6, parse V2 headers
bool Proxy_Protocol::parse_header(unsigned char *header, size_t n, struct sockaddr_storage *out) {
    char src_ip[64], dst_ip[64];
    int src_port, dst_port;

    // skip parsing if there's less data than the minimum V1 header
    if (n < 15) return false;
    if (memcmp(header, "PROXY ", 6)) return false;

    header[n - 2] = '\0'; // Zap CRLF
    header[n - 1] = '\0';
    header += 6;
    if (!memcmp(header, "TCP4 ", 5)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;

        header += 5;
        if (sscanf((char *)header, "%15s %15s %d %d", src_ip, dst_ip, &src_port, &dst_port) != 4)
            return false;
        src_ip[15] = '\0';
        dst_ip[15] = '\0';
        sin->sin_family = AF_INET;
        sin->sin_port = htons(src_port);
        if (inet_pton(sin->sin_family, src_ip, (void *)&sin->sin_addr) != 1)
            return false;
    }
    else if(!memcmp(header, "TCP6 ", 5)) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;

        header += 5;
        if (sscanf((char *)header, "%63s %63s %d %d", src_ip, dst_ip, &src_port, &dst_port) != 4)
            return false;
        src_ip[sizeof(dst_ip)-1] = '\0';
        dst_ip[sizeof(dst_ip)-1] = '\0';
        sin6->sin6_family = AF_INET;
        sin6->sin6_port = htons(src_port);
        if (inet_pton(sin6->sin6_family, src_ip, (void *)&sin6->sin6_addr) != 1)
            return false;
    }
    else if(!memcmp(header, "UNKNOWN", 7)) {
        // not sure how to deal with this
        out->ss_family = AF_UNIX;
        return true;
    }
    else {
        return false;
    }

    return true;
}
