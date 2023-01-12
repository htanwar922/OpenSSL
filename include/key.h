#pragma once

#include "string.h"
#include "stdint.h"

#include "openssl/rsa.h"
#include "openssl/pem.h"

namespace LibOpenSSL {

void GenRSAPrivateKey(const char * filename = "../private.pem", const char * passphrase = "Himanshu")
{
	FILE * file = fopen(filename, "wb");

	// An exponent for the key.
	BIGNUM * bn = BN_new();
	BN_set_word(bn, RSA_F4);	// (1<<16 | 1)

	// To generate the key:
	RSA * rsa = RSA_new();
	RSA_generate_key_ex(
		rsa,		// pointer to the RSA structure
		2048,		// number of key bits
		bn,			// pointer to key exponent
		NULL		// BigNum generator callback - BN_GENCB
	);
	
	// Store the Private key to file.
	int ret = PEM_write_RSAPrivateKey(
		file,					// FILE struct to write to
		rsa,					// RSA key struct
		EVP_aes_128_cbc(),		// default EVP_CIPHER for encrypting the key on disk
		(uint8_t *)passphrase,	// passphrase for encrypting the key on disk
		strlen(passphrase),		// length of the passphrase string
		NULL,					// callback for requesting a password // pem_password_cb
		NULL					// user data to pass to the callback
	);

	RSA_free(rsa);
	// EVP_PKEY_free(pkey);	// The RSA structure will be automatically freed.
	BN_free(bn);
	fclose(file);
}

void SavePrivateKey(EVP_PKEY * pkey, const char * filename, const char * passphrase)
{
	FILE * file = fopen(filename, "wb");

	//// #include "openssl/err.h"
	// OpenSSL_add_all_algorithms();
	// OpenSSL_add_all_ciphers();
	// ERR_load_crypto_strings();

	// A generic structure to hold diverse types of asymmetric keys or "key pairs".
	// EVP_PKEY * pkey = EVP_PKEY_new();
	// EVP_PKEY_assign_RSA(pkey, rsa);

	int ret = PEM_write_PrivateKey(
		file,					// FILE struct to write to
		pkey,					// EVP_PKEY struct
		EVP_aes_128_cbc(),		// default EVP_CIPHER for encrypting the key on disk
		(uint8_t *)passphrase,	// passphrase for encrypting the key on disk
		strlen(passphrase),		// length of the passphrase string
		NULL,					// callback for requesting a password // pem_password_cb
		NULL					// user data to pass to the callback
	);

	// EVP_PKEY_free(pkey);	// The RSA structure will be automatically freed.
	fclose(file);
}

EVP_PKEY * GetPrivateKey(const char * filename)
{
	EVP_PKEY * pkey = EVP_PKEY_new();
	FILE * file = fopen(filename, "rb");
	PEM_read_PrivateKey(file, &pkey, NULL, NULL);
	fclose(file);
	return pkey;
}

}