#pragma once

#include "string"
#include "cstdio"
#include "cstring"
#include "stdint.h"

#include "openssl/md5.h"
#include "openssl/sha.h"
#include "openssl/evp.h"

#include "utils.h"

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

// openssl dgst -sha256
// openssl sha256
uint8_t * MessageDigest(const uint8_t data[], uint32_t len, uint32_t * md_len, const char * algorithm)
{
	// OpenSSL_add_all_digests();
	const EVP_MD * md = EVP_get_digestbyname(algorithm);	// EVP_sha256();
	uint8_t * digest = new uint8_t[EVP_MAX_MD_SIZE];
	
	EVP_MD_CTX * ctx = EVP_MD_CTX_create();
	EVP_MD_CTX_init(ctx);					// EVP_MD_CTX_new in OpenSSL 1.1.0+
	
	if(ERR_LIB_NONE != EVP_DigestInit(ctx, md)) {
		ERROR("EVP_DigestInit error\n");
		return NULL;
	}
	if(ERR_LIB_NONE != EVP_DigestUpdate(ctx, data, len)) {	// Repeat for more data blocks before finishing.
		ERROR("EVP_DigestUpdate error\n");
		return NULL;
	}	// EVP_DigestUpdate(ctx, data2, len);
	if(ERR_LIB_NONE != EVP_DigestFinal(ctx, digest, md_len)) {
		ERROR("EVP_DigestFinal error\n");
		return NULL;
	}
	
	EVP_MD_CTX_cleanup(ctx);				// EVP_MD_CTX_free in OpenSSL 1.1.0+
	return digest;
}

void PrintDigest(const uint8_t * digest, int len)
{
	BIO * bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	BIO_printf(bio_out, "Digest is:\n");
	BIO_dump(bio_out, (const char *)digest, len);
	BIO_free(bio_out);
}

} // namespace LibOpenSSL
