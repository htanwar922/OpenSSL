#include "openssl/err.h"

#include "openssl_test.h"
#include "encode.h"
#include "key.h"
#include "encrypt.h"
#include "digest.h"

using namespace LibOpenSSL;

int main(int argc, char ** argv)
{
	const char * filename = "../private.pem";
	const char * passphrase = "Himanshu";

	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();
	
	BIO * bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	BIO_printf(bio_out, "Hello World\n");

	Base64(bio_out, (uint8_t *)"Hello World\n");

	// GenRSAPrivateKey(filename, passphrase);
	// EVP_PKEY * pkey = GetPrivateKey(filename);
	// printKey(pkey->pkey.rsa);
	// EVP_PKEY_print_private(bio_out, pkey, 0, NULL);

	uint8_t * plaintext = (uint8_t *)"Hello World! How is it?\n";
	uint8_t ciphertext[1024] = {0};

	AES_CBC_256 encodeObject = AES_CBC_256();
	int ciphertext_len = encodeObject.Encrypt(plaintext, strlen((char *)plaintext), ciphertext);

	BIO_printf(bio_out, "Key is:\n");
	BIO_dump(bio_out, (const char *)encodeObject.GetKey(), 32);
	BIO_printf(bio_out, "IV is:\n");
	BIO_dump(bio_out, (const char *)encodeObject.GetIV(), AES_BLOCK_SIZE);
	BIO_printf(bio_out, "Ciphertext is:\n");
	encodeObject.PrintCiphertext(ciphertext, ciphertext_len);

	uint32_t digest_len = 0;
	uint8_t * digest = MessageDigest(ciphertext, ciphertext_len, &digest_len, "sha256");
	BIO_printf(bio_out, "Digest is:\n");
	BIO_dump(bio_out, (const char *)digest, digest_len);
	
	// EVP_PKEY_free(pkey);
	BIO_free(bio_out);
	return 0;
}