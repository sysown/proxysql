cmake_minimum_required(VERSION 3.10)
project(ProxySQL_OTel_Tests)

# Find required packages
find_package(GTest REQUIRED)
find_package(GMock REQUIRED)

# Include parent directory
include_directories(..)
include_directories(../include)
include_directories(../lib)

# Define test sources
set(TEST_SOURCES
    test_otel_span.cpp
    test_otel_span_stack.cpp
    test_otel_tracer.cpp
    test_unsafe_shared_ptr.cpp
)

# Create executable
add_executable(otel_tests ${TEST_SOURCES})

# Link with GTest and GMock
target_link_libraries(otel_tests
    GTest::gtest
    GTest::gtest_main
    GTest::gmock
    GTest::gmock_main
)

# Add OpenTelemetry libraries
# Note: This assumes OpenTelemetry is properly installed and available
# You may need to adjust these paths based on your installation
find_package(OpenTelemetryCpp REQUIRED)
target_link_libraries(otel_tests
    OpenTelemetryCpp::TraceAPI
    OpenTelemetryCpp::TraceContext
    OpenTelemetryCpp::Sdk
    OpenTelemetryCpp::ExporterOtlp
)

# Enable testing
include(GoogleTest)
gtest_discover_tests(otel_tests)

# Add post-build steps if needed
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(otel_tests PRIVATE -Wall -Wextra -Werror)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(otel_tests PRIVATE -Wall -Wextra -Werror)
endif()