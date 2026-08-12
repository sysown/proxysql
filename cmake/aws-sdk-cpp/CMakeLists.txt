cmake_minimum_required(VERSION 3.13)
project(proxysql_aws_sdk_discovery LANGUAGES NONE)

set(PROXYSQL_AWS_REQUESTED_ROOT "$ENV{AWS_SDK_CPP_ROOT}")
if(PROXYSQL_AWS_REQUESTED_ROOT)
	# An explicit prefix is authoritative. Do not silently fall back to an
	# unrelated system installation when validating AWS_SDK_CPP_ROOT.
	find_package(AWSSDK 1.9 REQUIRED COMPONENTS core rds
		PATHS "${PROXYSQL_AWS_REQUESTED_ROOT}" NO_DEFAULT_PATH)
else()
	find_package(AWSSDK 1.9 REQUIRED COMPONENTS core rds)
endif()

function(proxysql_make_shell_quote output value)
	# The generated value is parsed once by Make and then once by the shell.
	# Protect Make's expansion/comment characters before single-quoting the
	# complete shell word. The quote replacement emits the shell sequence '\''.
	string(REPLACE "$" "$$" escaped "${value}")
	string(REPLACE "#" "\\#" escaped "${escaped}")
	string(REPLACE "'" "'\\''" escaped "${escaped}")
	set(${output} "'${escaped}'" PARENT_SCOPE)
endfunction()

function(proxysql_quote_flag_list output prefix)
	set(result "")
	foreach(value IN LISTS ARGN)
		proxysql_make_shell_quote(quoted "${prefix}${value}")
		string(APPEND result " ${quoted}")
	endforeach()
	string(STRIP "${result}" result)
	set(${output} "${result}" PARENT_SCOPE)
endfunction()

function(proxysql_quote_link_list output)
	set(result "")
	foreach(value IN LISTS ARGN)
		if(value MATCHES "^-" OR IS_ABSOLUTE "${value}")
			set(link_word "${value}")
		else()
			set(link_word "-l${value}")
		endif()
		proxysql_make_shell_quote(quoted "${link_word}")
		string(APPEND result " ${quoted}")
	endforeach()
	string(STRIP "${result}" result)
	set(${output} "${result}" PARENT_SCOPE)
endfunction()

set(AWS_IAM_COMPONENTS core rds)
if(AWSSDK_INSTALL_AS_SHARED_LIBS)
	set(AWS_IAM_LINK_LIBRARIES ${AWSSDK_LINK_LIBRARIES})
	set(AWS_IAM_SDK_SHARED 1)
else()
	# AWSSDK_DETERMINE_LIBS_TO_LINK uses ALL_SERVICES as macro scratch state.
	# Clearing it is necessary when AWSSDKConfig already called the macro once.
	set(ALL_SERVICES "")
	AWSSDK_DETERMINE_LIBS_TO_LINK(AWS_IAM_COMPONENTS AWS_IAM_LINK_LIBRARIES)
	set(AWS_IAM_SDK_SHARED 0)
endif()

proxysql_quote_flag_list(AWS_IAM_CPPFLAGS "-I" ${AWSSDK_INCLUDE_DIRS})
proxysql_quote_flag_list(AWS_IAM_LDFLAGS "-L" ${AWSSDK_LIB_DIR})
proxysql_quote_link_list(AWS_IAM_LIBS ${AWS_IAM_LINK_LIBRARIES})

if(DEFINED AWSSDK_VERSION)
	set(AWS_IAM_SDK_VERSION "${AWSSDK_VERSION}")
else()
	set(AWS_IAM_SDK_VERSION "${PACKAGE_VERSION}")
endif()

string(SHA256 AWS_IAM_DISCOVERY_ID
	"${PROXYSQL_AWS_REQUESTED_ROOT}\n${AWS_IAM_SDK_VERSION}\n${AWS_IAM_SDK_SHARED}\n${AWSSDK_INCLUDE_DIRS}\n${AWSSDK_LIB_DIR}\n${AWS_IAM_LINK_LIBRARIES}")

set(output_file "${CMAKE_BINARY_DIR}/aws-sdk-cpp.mk")
string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef output_suffix)
set(output_tmp "${output_file}.tmp.${output_suffix}")
file(WRITE "${output_tmp}" "AWS_IAM_CPPFLAGS := ${AWS_IAM_CPPFLAGS}\n")
file(APPEND "${output_tmp}" "AWS_IAM_LDFLAGS := ${AWS_IAM_LDFLAGS}\n")
file(APPEND "${output_tmp}" "AWS_IAM_LIBS := ${AWS_IAM_LIBS}\n")
file(APPEND "${output_tmp}" "AWS_IAM_SDK_VERSION := \"${AWS_IAM_SDK_VERSION}\"\n")
file(APPEND "${output_tmp}" "AWS_IAM_SDK_SHARED := \"${AWS_IAM_SDK_SHARED}\"\n")
file(APPEND "${output_tmp}" "AWS_IAM_DISCOVERY_ID := ${AWS_IAM_DISCOVERY_ID}\n")

# Discovery runs for each feature-on Make invocation so an SDK package that is
# upgraded in place is noticed. Avoid changing the fragment timestamp unless
# its effective compile/link identity actually changed.
set(replace_output TRUE)
if(EXISTS "${output_file}")
	file(READ "${output_file}" existing_output)
	file(READ "${output_tmp}" new_output)
	if(existing_output STREQUAL new_output)
		set(replace_output FALSE)
	endif()
endif()
if(replace_output)
	file(RENAME "${output_tmp}" "${output_file}")
else()
	file(REMOVE "${output_tmp}")
endif()
