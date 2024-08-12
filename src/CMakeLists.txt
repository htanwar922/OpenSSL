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

add_executable(Test_AES test_aes.cpp)
target_link_libraries(Test_AES
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

add_executable(Test_AES1 test_aes1.cpp)
target_link_libraries(Test_AES1
	${LINK_LIBRARIES}
	ssl
	crypto
)
