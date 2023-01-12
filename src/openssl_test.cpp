#include "openssl/err.h"

#include "openssl_test.h"
#include "encode.h"
#include "key.h"
#include "encrypt.h"

using namespace LibOpenSSL;

int main()
{
	const char * filename = "../private.pem";
	const char * passphrase = "Himanshu";

	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();
	
	BIO * bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	BIO_printf(bio_out, "Hello World\n");

	Base64(bio_out, (uint8_t *)"Hello World\n");

	// GenRSAPrivateKey(filename, passphrase);
	// EVP_PKEY * pkey = GetPrivateKey(filename);
	// printKey(pkey->pkey.rsa);
	// EVP_PKEY_print_private(bio_out, pkey, 0, NULL);

	AES_CBC_256();

	// EVP_PKEY_free(pkey);
	BIO_free(bio_out);
	return 0;
}