#include "iostream"
#include "iomanip"

#include "stdio.h"
#include "string.h"
#include "stdint.h"

#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"

#include "openssh_test.h"

int main()
{
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();

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
	
	// A generic structure to hold diverse types of asymmetric keys or "key pairs".
	EVP_PKEY * pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, rsa);

	print(pkey->pkey.rsa->d);
	print(pkey->pkey.rsa->e);

	FILE * file = fopen("../private.pem", "wb");
	const char passphrase[] = "Himanshu";
	int ret = PEM_write_PrivateKey(
		file,					// FILE struct to write to
		pkey,					// EVP_PKEY struct
		EVP_aes_128_cbc(),		// default EVP_CIPHER for encrypting the key on disk
		(uint8_t *)passphrase,	// passphrase for encrypting the key on disk
		strlen(passphrase),		// length of the passphrase string
		NULL,					// callback for requesting a password // pem_password_cb
		NULL					// user data to pass to the callback
	);
	fclose(file);

	EVP_PKEY_free(pkey);	// The RSA structure will be automatically freed.
	BN_free(bn);
}