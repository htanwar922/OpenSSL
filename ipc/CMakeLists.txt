include_directories(
	${PROJECT_SOURCE_DIR}/include
)

add_executable(writer writer.cpp)
target_link_libraries(writer
	${LINK_LIBRARIES}
	# boost_system
	# rt
	# pthread
)

add_executable(reader reader.cpp)
target_link_libraries(reader
	${LINK_LIBRARIES}
	# boost_system
	# rt
	# pthread
)