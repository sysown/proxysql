#ifndef MYSQL_RESOLUTION_H
#define MYSQL_RESOLUTION_H

#include <strings.h>
#include <sys/socket.h>

/**
 * Validation, normalization, and conversion helpers for mysql-resolution_family.
 *
 * Supported values: "system" (AF_UNSPEC), "ipv4" (AF_INET), "ipv6" (AF_INET6).
 * NULL or invalid values fall back to "system" / AF_UNSPEC to preserve default
 * OS resolver behavior and avoid breaking changes.
 */

inline bool mysql_resolution_family_is_valid(const char* value) {
	return value &&
		(strcasecmp(value, "system") == 0 ||
		 strcasecmp(value, "ipv4") == 0 ||
		 strcasecmp(value, "ipv6") == 0);
}

inline const char* mysql_resolution_family_normalize(const char* value) {
	// NULL or invalid values fall back to "system"
	if (value && strcasecmp(value, "ipv4") == 0) {
		return "ipv4";
	}
	if (value && strcasecmp(value, "ipv6") == 0) {
		return "ipv6";
	}
	return "system";
}

inline int mysql_resolution_family_to_ai_family(const char* value) {
	// NULL or invalid values fall back to AF_UNSPEC (system default)
	if (value && strcasecmp(value, "ipv4") == 0) {
		return AF_INET;
	}
	if (value && strcasecmp(value, "ipv6") == 0) {
		return AF_INET6;
	}
	return AF_UNSPEC;
}

#endif // MYSQL_RESOLUTION_H
