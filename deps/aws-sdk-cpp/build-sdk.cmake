cmake_minimum_required(VERSION 3.16)

foreach(required_var IN ITEMS
    AWS_BUNDLE_DIR AWS_ARCHIVE AWS_SOURCE_DIR AWS_BUILD_DIR AWS_INSTALL_DIR
    AWS_RDS_LIB AWS_CORE_LIB AWS_CURL_INCLUDE_DIR AWS_CURL_LIBRARY
    AWS_IDENTITY AWS_LOCK_FILE
    AWS_CC AWS_CXX AWS_MAKE_COMMAND)
  if(NOT DEFINED ${required_var} OR "${${required_var}}" STREQUAL "")
    message(FATAL_ERROR "AWS SDK build helper is missing ${required_var}")
  endif()
endforeach()

# GNU make executes recursive-make recipe lines even under `make -n`. The
# parent passes that state explicitly so this helper remains read-only during
# a dry run while still using the real recursive make/jobserver when building.
if(DEFINED AWS_DRY_RUN AND AWS_DRY_RUN)
  message(STATUS "AWS SDK dry run: ${AWS_IDENTITY}")
  return()
endif()

# Different top-level make processes may discover the missing concrete archive
# at the same time. CMake's process-scoped lock is portable across the Unix
# platforms supported by this build and is released automatically on failure.
file(LOCK "${AWS_LOCK_FILE}" GUARD PROCESS TIMEOUT 1800 RESULT_VARIABLE lock_result)
if(NOT "${lock_result}" STREQUAL "0")
  message(FATAL_ERROR "Could not acquire AWS SDK build lock: ${lock_result}")
endif()

set(expected_archive_sha256
  "5737158953b0a46f4c9ad68254cc9abdeecc16853dbdec04ba7c74aa885dc573")
file(SHA256 "${AWS_ARCHIVE}" actual_archive_sha256)
if(NOT "${actual_archive_sha256}" STREQUAL "${expected_archive_sha256}")
  message(FATAL_ERROR "Vendored AWS SDK checksum mismatch")
endif()
file(SHA256 "${AWS_CURL_LIBRARY}" curl_archive_sha256)
set(effective_identity "${AWS_IDENTITY};curl=${curl_archive_sha256}")

set(installed_identity "${AWS_INSTALL_DIR}/.proxysql-build-identity")
if(EXISTS "${AWS_RDS_LIB}" AND EXISTS "${AWS_CORE_LIB}" AND
   EXISTS "${installed_identity}")
  file(READ "${installed_identity}" current_identity)
  string(STRIP "${current_identity}" current_identity)
  if("${current_identity}" STREQUAL "${effective_identity}")
    message(STATUS "AWS SDK ${effective_identity} is already built")
    return()
  endif()
endif()

file(REMOVE_RECURSE "${AWS_SOURCE_DIR}")
execute_process(
  COMMAND tar -C "${AWS_BUNDLE_DIR}" -Jxf "${AWS_ARCHIVE}"
  RESULT_VARIABLE extract_status)
if(NOT extract_status EQUAL 0)
  message(FATAL_ERROR "Vendored AWS SDK extraction failed")
endif()
if(NOT EXISTS "${AWS_SOURCE_DIR}/CMakeLists.txt" OR
   NOT EXISTS "${AWS_SOURCE_DIR}/crt/aws-crt-cpp/CMakeLists.txt")
  message(FATAL_ERROR "Vendored AWS SDK archive has an unexpected layout")
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "CC=${AWS_CC}" "CXX=${AWS_CXX}"
    "${CMAKE_COMMAND}"
    -S "${AWS_SOURCE_DIR}"
    -B "${AWS_BUILD_DIR}"
    -DCMAKE_BUILD_TYPE=RelWithDebInfo
    -DCMAKE_INSTALL_PREFIX=${AWS_INSTALL_DIR}
    -DCMAKE_INSTALL_LIBDIR=lib
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    -DCURL_INCLUDE_DIR=${AWS_CURL_INCLUDE_DIR}
    -DCURL_LIBRARY=${AWS_CURL_LIBRARY}
    -DBUILD_ONLY=core\;rds
    -DBUILD_SHARED_LIBS=OFF
    -DBUILD_DEPS=ON
    # The source archive deliberately contains no nested Git metadata.
    -DENFORCE_SUBMODULE_VERSIONS=OFF
    -DENABLE_TESTING=OFF
    -DAUTORUN_UNIT_TESTS=OFF
    -DENABLE_UNITY_BUILD=ON
  RESULT_VARIABLE configure_status)
if(NOT configure_status EQUAL 0)
  message(FATAL_ERROR "Vendored AWS SDK configuration failed")
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "CC=${AWS_CC}" "CXX=${AWS_CXX}"
    "${AWS_MAKE_COMMAND}" -C "${AWS_BUILD_DIR}" install
  RESULT_VARIABLE build_status)
if(NOT build_status EQUAL 0)
  message(FATAL_ERROR "Vendored AWS SDK build failed")
endif()
if(NOT EXISTS "${AWS_RDS_LIB}" OR NOT EXISTS "${AWS_CORE_LIB}")
  message(FATAL_ERROR "Vendored AWS SDK build did not produce core and rds archives")
endif()

file(WRITE "${installed_identity}.tmp" "${effective_identity}\n")
file(RENAME "${installed_identity}.tmp" "${installed_identity}")
