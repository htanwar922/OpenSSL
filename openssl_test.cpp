#include "openssl_test.h"

#include "openssl/bio.h"

int main()
{
	const char * filename = "../private.pem";
	const char * passphrase = "Himanshu";
	
	BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	BIO_printf(bio_out, "Hello World\n");

	GenRSAPrivateKey(filename, passphrase);
	EVP_PKEY * pkey = GetPrivateKey(filename, passphrase);
	printKey(pkey->pkey.rsa);
	EVP_PKEY_print_private(bio_out, pkey, 0, NULL);
	EVP_PKEY_free(pkey);
}