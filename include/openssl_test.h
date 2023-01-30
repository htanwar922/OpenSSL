#pragma once

#ifndef SOURCE_DIR
#define SOURCE_DIR "../" // "@PROJECT_SOURCE_DIR@" // use with configure_file in CMakeLists.txt
#endif

#include "openssl/err.h"

#include "utils.h"
#include "digest.h"
#include "encode.h"
#include "key.h"
#include "encrypt.h"

#define MAX_BUFFER_SIZE 1024

namespace LibOpenSSL {

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