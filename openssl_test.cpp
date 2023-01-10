#include "openssl_test.h"

#include "openssl/bio.h"

int main()
{
	const char * filename = "../private.pem";
	const char * passphrase = "Himanshu";

	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();
	
	BIO * bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	BIO_printf(bio_out, "Hello World\n");

	// BIO_f_base64 filter
	// - encodes the data written through it.
	// - decodes the data read through it.
	BIO * bio_base64 = BIO_new(BIO_f_base64());
	BIO_push(bio_base64, bio_out);
	int bio_outBytes = BIO_write(bio_base64, "Hello World\n", strlen("Hello World\n"));
	BIO_flush(bio_base64);	// BIO_flush() normally writes out any internally buffered data; in some cases it is used to signal EOF and that no more data will be written.
	BIO_printf(bio_base64->next_bio, "Out Bytes: %d\n", bio_outBytes);
	BIO_free(bio_base64);	// Alternatively, BIO_free_all(bio_base64);

	// GenRSAPrivateKey(filename, passphrase);
	EVP_PKEY * pkey = GetPrivateKey(filename);
	printKey(pkey->pkey.rsa);
	EVP_PKEY_print_private(bio_out, pkey, 0, NULL);
	EVP_PKEY_free(pkey);
	BIO_free(bio_out);
	return 0;
}