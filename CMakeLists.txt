cmake_minimum_required(VERSION 3.0.0)
project(OpenSSL_C++ VERSION 0.1.0)

include(CTest)
enable_testing()

include_directories(
	${PROJECT_SOURCE_DIR}/include
)

add_executable(Test openssl_test.cpp)
target_link_libraries(Test
	${LINK_LIBRARIES}
	ssl
	crypto
)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
