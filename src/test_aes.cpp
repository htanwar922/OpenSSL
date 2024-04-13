#include "utils.h"
#include "digest.h"
#include "encode.h"
#include "key.h"

#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/aes.h"
#include "openssl/rand.h"

#include "encrypt.h"

using namespace LibOpenSSL;

#define ALGORITHM "AES-128-GCM"

// uint8_t plaintext[] = "Hello World! How is it?\n";

uint8_t plaintext[] = {
	0x01, 0x01, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44,
	0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
	0xdd, 0xee, 0xff, 0x00, 0x00, 0x06, 0x5f, 0x1f,
	0x04, 0x00, 0x00, 0x7e, 0x1f, 0x04, 0xb0, 
};

uint8_t aad[] = {
	0x30, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
	0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde,
	0xdf
};

const uint8_t key[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

const uint8_t iv[12] = {
	0x4d, 0x4d, 0x4d, 0x00, 0x00, 0xbc, 0x61, 0x4e,
	0x01, 0x23, 0x45, 0x67
};

int main(int argc, char ** argv)
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	// OPENSSL_config(NULL); // Load default configuration (e.g. openssl.conf)
	// OPENSSL_init_ssl(0, NULL);
	
	// uint8_t * plaintext = (uint8_t *)"Hello World! How is it?\n";
	// size_t plaintext_len = strlen((char *)plaintext);

	size_t plaintext_len = sizeof(plaintext);

	BIO * bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	uint8_t * ciphertext = new uint8_t[1024];
	uint8_t * decodedtext = new uint8_t[1024] {0};
	uint8_t tag[AES_BLOCK_SIZE] = {0};

	AES aes(ALGORITHM, key, sizeof(key), iv, sizeof(iv), sizeof(tag));
	size_t ciphertext_len = aes.Encrypt(plaintext, plaintext_len, ciphertext, tag, aad, sizeof(aad));
	size_t decodedtext_len = aes.Decrypt(ciphertext, ciphertext_len, decodedtext, tag, aad, sizeof(aad));

	BIO_printf(bio_out, "Plaintext is:\n");
	BIO_dump_fp(stdout, (const char *)plaintext, plaintext_len);
	BIO_printf(bio_out, ALGORITHM" Key is:\n");
	BIO_dump(bio_out, (const char *)key, sizeof(key));
	BIO_printf(bio_out, "IV is:\n");
	BIO_dump(bio_out, (const char *)iv, sizeof(key));
	BIO_printf(bio_out, "Ciphertext is:\n");
	BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
	BIO_printf(bio_out, "Tag is:\n");
	BIO_dump(bio_out, (const char *)tag, sizeof(tag));
	BIO_printf(bio_out, "Decodedtext is:\n");
	BIO_dump_fp(stdout, (const char *)decodedtext, decodedtext_len);

	delete[] ciphertext;
	delete[] decodedtext;

	BIO_free(bio_out);

	// CONF_modules_unload(1);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	// ERR_remove_state(pid);
	ERR_free_strings();

	return 0;
}