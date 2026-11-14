#ifndef __CLASS_HOSTGROUP_STRINGS_H
#define __CLASS_HOSTGROUP_STRINGS_H

#include <string>
#include <unordered_map>

/**
 * @brief Per-hostgroup attribute strings that worker threads read when they
 *   open backend connections.
 * @details LOAD ... SERVERS TO RUNTIME frees and replaces these strings in the
 *   hostgroup (under the Hostgroup Manager lock). Worker threads never read
 *   them there: each worker keeps its own copy, refreshed when the servers
 *   table version changes (see Base_Thread::refresh_hostgroup_strings()), so
 *   reading them costs neither a lock nor a shared cache line.
 */
struct HostgroupStrings {
	std::string init_connect;
#ifdef PROXYSQL40
	std::string aws_iam_region;
#endif // PROXYSQL40
};

/** @brief Hostgroup id -> its attribute strings; hostgroups without any are absent. */
using HostgroupStringsMap = std::unordered_map<unsigned int, HostgroupStrings>;

#endif // __CLASS_HOSTGROUP_STRINGS_H
