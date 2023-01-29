include_directories(
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_SOURCE_DIR}/ipc/include
)

add_executable(Test openssl_test.cpp)
target_link_libraries(Test
	${LINK_LIBRARIES}
	ssl
	crypto
)

add_executable(writer_openssl openssl_writer.cpp)
target_link_libraries(writer_openssl
	${LINK_LIBRARIES}
	ssl
	crypto
)

add_executable(reader_openssl openssl_reader.cpp)
target_link_libraries(reader_openssl
	${LINK_LIBRARIES}
	ssl
	crypto
)