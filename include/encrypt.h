#pragma once

#include "stdint.h"

#include "openssl/evp.h"
#include "openssl/err.h"

#include "utils.h"

// For encryption/decryption, we need four components:
// - algorithm	: Ciphers - AES, DES, 3DES, RC2, RC4, RC5, etc.
// - mode		: CBC, GCM, GCM, CCM, CFB, ECB, etc.
// - key		: the key to be used by the cipher.
// - iv			: the initialization vector - a hex number.

namespace LibOpenSSL {

// AES CBC 256-bit encryption class
// AES - Advanced Encryption Standard
// CBC - Cipher Block Chain mode
//
class AES_CBC_256
{
private:
	uint8_t * key = NULL, * iv = NULL;
public:
	AES_CBC_256()
	{
		// BIGNUM k;
		// BN_bn2hex(&k);
		ERROR("CHECK");
	}

	int Encrypt(const uint8_t * plaintext, int len, uint8_t * ciphertext)
	{
		EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
		if(ERR_LIB_NONE != EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, (const uint8_t *)iv)) {
			ERROR("EVP_EncryptInit error\n");
			return -1;
		}
		int retLength1 = 0;
		if(ERR_LIB_NONE != EVP_EncryptUpdate(ctx, ciphertext, &retLength1, plaintext, len)) {
			ERROR("EVP_EncryptUpdate error\n");
			return -1;
		}
		int retLength2 = 0;
		if(ERR_LIB_NONE != EVP_EncryptFinal(ctx, ciphertext + retLength1, &retLength2)) {
			ERROR("EVP_EncryptFinal error\n");
			return -1;
		}
		EVP_CIPHER_CTX_free(ctx);
		return retLength1 + retLength2;
	}

	int Decrypt(const uint8_t * ciphertext, int len, uint8_t * plaintext)
	{
		EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
		if(ERR_LIB_NONE != EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, (const uint8_t *)iv)) {
			ERROR("EVP_EncryptInit error\n");
			return -1;
		}
		int retLength1 = 0;
		if(ERR_LIB_NONE != EVP_DecryptUpdate(ctx, plaintext, &retLength1, ciphertext, len)) {
			ERROR("EVP_EncryptUpdate error\n");
			return -1;
		}
		int retLength2 = 0;
		if(ERR_LIB_NONE != EVP_DecryptFinal(ctx, plaintext + retLength1, &retLength2)) {
			ERROR("EVP_EncryptFinal error\n");
			return -1;
		}
		EVP_CIPHER_CTX_free(ctx);
		return retLength1 + retLength2;
	}

	~AES_CBC_256()
	{
		if(key)	delete[] key;
		if(iv) delete[] iv;
	}
};

}