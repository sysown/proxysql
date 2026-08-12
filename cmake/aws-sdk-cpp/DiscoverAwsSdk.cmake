cmake_minimum_required(VERSION 3.13)

if(NOT DEFINED PROXYSQL_SOURCE_DIR OR NOT DEFINED PROXYSQL_REQUEST_ID)
	message(FATAL_ERROR "ProxySQL AWS SDK discovery arguments are required")
endif()

set(discovery_root "${PROXYSQL_SOURCE_DIR}/build/aws-sdk-cpp")
set(configure_dir "${discovery_root}/configure-${PROXYSQL_REQUEST_ID}")
set(discovered_fragment "${configure_dir}/aws-sdk-cpp.mk")
set(canonical_fragment "${discovery_root}/aws-sdk-cpp.mk")
set(identity_fragment_dir "${discovery_root}/fragments")

file(MAKE_DIRECTORY "${discovery_root}")
file(LOCK "${discovery_root}/discovery.lock" GUARD PROCESS TIMEOUT 300
	RESULT_VARIABLE lock_result)
if(NOT lock_result STREQUAL "0")
	message(FATAL_ERROR "Unable to lock AWS SDK discovery: ${lock_result}")
endif()

# A configure directory is private to the requested-prefix identity. The
# process-wide lock prevents same-identity cache cleanup and canonical
# publication from racing with another Make process.
file(MAKE_DIRECTORY "${configure_dir}")
file(REMOVE "${configure_dir}/CMakeCache.txt")
file(REMOVE_RECURSE "${configure_dir}/CMakeFiles")

set(configure_command
	"${CMAKE_COMMAND}"
	-S "${PROXYSQL_SOURCE_DIR}/cmake/aws-sdk-cpp"
	-B "${configure_dir}")
set(requested_root "$ENV{AWS_SDK_CPP_ROOT}")
if(requested_root)
	# AWSSDK's config performs nested find_package calls for core, rds, and
	# CRT dependencies. Keep the explicit prefix authoritative in the project
	# while also making it available to those nested lookups.
	list(APPEND configure_command "-DCMAKE_PREFIX_PATH=${requested_root}")
endif()

execute_process(
	COMMAND ${configure_command}
	RESULT_VARIABLE configure_result
	OUTPUT_QUIET)
if(NOT configure_result EQUAL 0 OR NOT EXISTS "${discovered_fragment}")
	message(FATAL_ERROR "AWS SDK discovery configure failed")
endif()

# The per-identity fragment is what this Make process consumes. Publish the
# same content at the canonical path for diagnostics and packaging checks,
# preserving its mtime when its effective metadata is unchanged.
file(READ "${discovered_fragment}" discovered_content)
string(REGEX MATCH "AWS_IAM_DISCOVERY_ID := ([0-9a-f]+)" identity_match
	"${discovered_content}")
set(discovery_id "${CMAKE_MATCH_1}")
if(NOT discovery_id MATCHES "^[0-9a-f]+$")
	message(FATAL_ERROR "AWS SDK discovery fragment has no identity")
endif()

# Publish an immutable full-identity fragment for the calling Make process.
# A later in-place SDK upgrade can replace the requested-root configure output
# without changing the metadata this already-running process will include.
file(MAKE_DIRECTORY "${identity_fragment_dir}")
set(identity_fragment "${identity_fragment_dir}/${discovery_id}.mk")
if(EXISTS "${identity_fragment}")
	file(READ "${identity_fragment}" identity_content)
	if(NOT identity_content STREQUAL discovered_content)
		message(FATAL_ERROR "AWS SDK discovery identity collision")
	endif()
else()
	string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef identity_suffix)
	set(identity_tmp "${identity_fragment}.tmp.${identity_suffix}")
	file(WRITE "${identity_tmp}" "${discovered_content}")
	file(RENAME "${identity_tmp}" "${identity_fragment}")
endif()

set(publish_fragment TRUE)
if(EXISTS "${canonical_fragment}")
	file(READ "${canonical_fragment}" canonical_content)
	if(canonical_content STREQUAL discovered_content)
		set(publish_fragment FALSE)
	endif()
endif()
if(publish_fragment)
	string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef publish_suffix)
	set(publish_tmp "${canonical_fragment}.tmp.${publish_suffix}")
	file(WRITE "${publish_tmp}" "${discovered_content}")
	file(RENAME "${publish_tmp}" "${canonical_fragment}")
endif()

execute_process(COMMAND "${CMAKE_COMMAND}" -E echo "${discovery_id}")
