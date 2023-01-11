#pragma once

#include "stdio.h"
#include "string"
#include "string.h"
#include "stdint.h"

#include "openssl/md5.h"
#include "openssl/sha.h"

namespace LibOpenSSL {

std::string GenerateMD5(const uint8_t data[])
{
	uint8_t digest[MD5_DIGEST_LENGTH];
	MD5(data, strlen((char *)data), digest);		// use strlen, not sizeof. (sizeof = strlen + 1)

	char messageDigestString[MD5_DIGEST_LENGTH << 1 + 1];
	for(int i=0; i<MD5_DIGEST_LENGTH; i++)
		sprintf(messageDigestString + i*2, "%02x", digest[i]);
	
	printf("Message Digest:\n%s\n", messageDigestString);
	return messageDigestString;
}

std::string GenerateSHA1(const uint8_t data[])
{
	uint8_t hash[SHA_DIGEST_LENGTH];
	SHA1(data, strlen((char *)data), hash);		// use strlen, not sizeof. (sizeof = strlen + 1)

	char messageDigestString[SHA_DIGEST_LENGTH << 1 + 1];
	for(int i=0; i<SHA_DIGEST_LENGTH; i++)
		sprintf(messageDigestString + i*2, "%02x", hash[i]);
	
	printf("Message Digest:\n%s\n", messageDigestString);
	return messageDigestString;
}

}