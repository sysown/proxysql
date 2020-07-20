#ifndef __CLASS_PROXY_PROTOCOL_H
#define __CLASS_PROXY_PROTOCOL_H

#include <vector>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>


class Proxy_Protocol {
    private:
    Proxy_Protocol() {}
    ~Proxy_Protocol() {}
    static bool add_subnet(const char *cidr, std::vector<proxy_protocol_subnet_t> &subnets);

    public:
    static bool parse_subnets(const char *list, std::vector<proxy_protocol_subnet_t> &subnets);
    static bool match_subnet(struct sockaddr *addr, socklen_t addrlen, std::vector<proxy_protocol_subnet_t> &subnets);
    static bool parse_header(unsigned char *, size_t n, struct sockaddr_storage *out);
};

#endif /* __CLASS_PROXY_PROTOCOL_H */
