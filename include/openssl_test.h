#pragma once

#include "openssl/err.h"

#include "encode.h"
#include "key.h"
#include "encrypt.h"
#include "digest.h"

#ifndef SOURCE_DIR
#define SOURCE_DIR "../" // "@PROJECT_SOURCE_DIR@" // use with configure_file in CMakeLists.txt
#endif

#define MAX_BUFFER_SIZE 1024

namespace LibOpenSSL {

struct Message
{
	size_t Len = 0;
	uint8_t Body[MAX_BUFFER_SIZE] {0};
};



} // namespace LibOpenSSL