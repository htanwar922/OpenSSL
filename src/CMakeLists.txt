include_directories(
	${PROJECT_SOURCE_DIR}/include
)

add_executable(Test openssl_test.cpp)
target_link_libraries(Test
	${LINK_LIBRARIES}
	ssl
	crypto
)