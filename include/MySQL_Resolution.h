#ifndef MYSQL_RESOLUTION_H
#define MYSQL_RESOLUTION_H

#include <strings.h>
#include <sys/socket.h>

inline bool mysql_resolution_family_is_valid(const char* value) {
	return value &&
		(strcasecmp(value, "system") == 0 ||
		 strcasecmp(value, "ipv4") == 0 ||
		 strcasecmp(value, "ipv6") == 0);
}

inline const char* mysql_resolution_family_normalize(const char* value) {
	if (value && strcasecmp(value, "ipv4") == 0) {
		return "ipv4";
	}
	if (value && strcasecmp(value, "ipv6") == 0) {
		return "ipv6";
	}
	return "system";
}

inline int mysql_resolution_family_to_ai_family(const char* value) {
	if (value && strcasecmp(value, "ipv4") == 0) {
		return AF_INET;
	}
	if (value && strcasecmp(value, "ipv6") == 0) {
		return AF_INET6;
	}
	return AF_UNSPEC;
}

#endif // MYSQL_RESOLUTION_H
