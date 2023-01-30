#pragma once

#include "iostream"
#include "iomanip"
#include "cstring"
#include "cerrno"

#include "openssl/rsa.h"
#include "openssl/err.h"

namespace LibOpenSSL {

#ifndef SOURCE_DIR
#define SOURCE_DIR __FILE__"/../../" // "@PROJECT_SOURCE_DIR@" // use with configure_file in CMakeLists.txt
#endif

#define ERROR(str) {\
	fprintf(stderr, "__ERROR__: %s:%d : %s\n__ERROR__: %s : %s\n__ERROR__: ", \
		__FILE__, __LINE__, __PRETTY_FUNCTION__, str, std::strerror(errno));	\
	ERR_print_errors_fp(stderr);	\
}

#define MAX_BUFFER_SIZE 1024

struct Message
{
	size_t Len = 0;
	uint8_t * Body = NULL;
	Message(bool empty = false)
	{
		if(not empty)
			Body = new uint8_t[MAX_BUFFER_SIZE];
	}
	void Clear()
	{
		if(Body)
			delete[] Body;
	}
	~Message()
	{
		Clear();
	}
};

} // namespace LibOpenSSL