cmake_minimum_required(VERSION 3.0.0)
project(OpenSSL_C++ VERSION 0.1.0)

include(CTest)
enable_testing()

set(CMAKE_CXX_STANDARD 11)
add_definitions(-DSOURCE_DIR="${PROJECT_SOURCE_DIR}/")
# configure_file(include/openssl_test.h include/openssl_test.hpp)
add_subdirectory(src)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
