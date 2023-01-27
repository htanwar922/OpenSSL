#include "openssl/err.h"

#include "openssl_test.h"
#include "encode.h"
#include "key.h"
#include "encrypt.h"
#include "digest.h"

using namespace LibOpenSSL;

int main(int argc, char ** argv)
{
	printf("Source dir : %s\n", SOURCE_DIR);
	const char * filename = SOURCE_DIR"/private.pem";
	const char * passphrase = "Himanshu";

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	// OPENSSL_config(NULL); // Load default configuration (e.g. openssl.conf)
	// OPENSSL_init_ssl(0, NULL);
	
	BIO * bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	BIO_printf(bio_out, "Hello World\n");

	Base64(bio_out, (uint8_t *)"Hello World\n");

	// GenRSAPrivateKey(filename, passphrase);
	// EVP_PKEY * pkey = GetPrivateKey(filename);
	// printKey(pkey->pkey.rsa);
	// EVP_PKEY_print_private(bio_out, pkey, 0, NULL);
	// EVP_PKEY_free(pkey);

	uint8_t * plaintext = (uint8_t *)"Hello World! How is it?\n";
	uint8_t * ciphertext = new uint8_t[1024];

	AES_CBC_256 encodeObject = AES_CBC_256();
	size_t ciphertext_len = encodeObject.Encrypt(plaintext, strlen((char *)plaintext), ciphertext);

	BIO_printf(bio_out, "AES-256-CBC Key is:\n");
	BIO_dump(bio_out, (const char *)encodeObject.GetKey(), 32);
	BIO_printf(bio_out, "IV is:\n");
	BIO_dump(bio_out, (const char *)encodeObject.GetIV(), AES_BLOCK_SIZE);
	BIO_printf(bio_out, "Ciphertext is:\n");
	encodeObject.PrintCiphertext(ciphertext, ciphertext_len);

	uint32_t digest_len = 0;
	uint8_t * digest = MessageDigest(ciphertext, ciphertext_len, &digest_len, "sha256");
	BIO_printf(bio_out, "Digest is:\n");
	BIO_dump(bio_out, (const char *)digest, digest_len);

	delete[] ciphertext;
	delete[] digest;

	PKey pkey;
	// pkey.GenPrivateKey(EVP_PKEY_RSA, 2048);
	// pkey.SaveKey(SOURCE_DIR"/private.pem", "private", "Himanshu");
	// pkey.SaveKey(SOURCE_DIR"/public.pem", "public");

	// pkey.GetKey(SOURCE_DIR"/private.pem", "private");
	// pkey.PrintKey("private");

	pkey.GetKey(SOURCE_DIR"/public.pem", "public");
	// pkey.PrintKey("public");
	ciphertext_len = pkey.Encrypt((const uint8_t *)"Hello", 5U, ciphertext);
	BIO_printf(bio_out, "Ciphertext is: %lu\n", ciphertext_len);
	BIO_dump(bio_out, (const char *)ciphertext, ciphertext_len);
	
	pkey.GetKey("../private.pem", "private");
	// pkey.PrintKey("public");
	uint8_t * text = NULL;
	int plaintext_len = pkey.Decrypt(ciphertext, ciphertext_len, text);
	BIO_printf(bio_out, "Plaintext is:\n");
	BIO_dump(bio_out, (const char *)plaintext, plaintext_len);


	delete[] ciphertext;

	BIO_free(bio_out);

	// CONF_modules_unload(1);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	// ERR_remove_state(pid);
	ERR_free_strings();

	return 0;
}