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

// uint8_t ctos[] = {
// 	// 'K', '5', '6', 'i', 'V', 'a', 'g', 'Y'
// };

uint8_t aad[] = {
	0x00,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf
};

const uint8_t key[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

uint8_t iv[12] = {
	// 0x4d, 0x4d, 0x4d, 0x00, 0x00, 0xbc, 0x61, 0x4e,
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
	0x00, 0x00, 0x00, 0x00
};

struct Array {
	uint8_t * data = nullptr;
	size_t len = 0;
};

Array hex_stream_to_array(const char * stream)
{
	Array array;
	array.len = strlen(stream) / 2;
	array.data = new uint8_t[array.len];
	for(size_t i = 0; i < array.len; i++)
		sscanf(stream + 2 * i, "%02hhx", array.data + i);
	return array;
}

uint32_t htonl(uint32_t hostlong)
{
	return ((hostlong & 0xff000000) >> 24) |
		((hostlong & 0x00ff0000) >> 8) |
		((hostlong & 0x0000ff00) << 8) |
		((hostlong & 0x000000ff) << 24);
}

int main(int argc, char ** argv)
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	// OPENSSL_config(NULL); // Load default configuration (e.g. openssl.conf)
	// OPENSSL_init_ssl(0, NULL);

	*(uint32_t *)((uint8_t *)iv + 8) = htonl(0x00000014);
	aad[0] = 0x30;

	size_t plaintext_len = sizeof(plaintext);
	size_t tag_len = 12;	// or AES_BLOCK_SIZE???

	BIO * bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	uint8_t * ciphertext = new uint8_t[1024];
	uint8_t * decodedtext = new uint8_t[1024] {0};
	uint8_t tag[tag_len] = {0};
	size_t ciphertext_len = 0;
	size_t decodedtext_len = 0;

	// AES aes(ALGORITHM, key, sizeof(key), iv, sizeof(iv), sizeof(tag));
	// ciphertext_len = aes.Encrypt(plaintext, plaintext_len, ciphertext, tag, aad, sizeof(aad));
	// decodedtext_len = aes.Decrypt(ciphertext, ciphertext_len, decodedtext, tag, aad, sizeof(aad));

	// BIO_printf(bio_out, "Plaintext is:\n");
	// BIO_dump_fp(stdout, (const char *)plaintext, plaintext_len);
	// BIO_printf(bio_out, ALGORITHM" Key is:\n");
	// BIO_dump(bio_out, (const char *)key, sizeof(key));
	// BIO_printf(bio_out, "IV is:\n");
	// BIO_dump(bio_out, (const char *)iv, sizeof(iv));
	// BIO_printf(bio_out, "Ciphertext is:\n");
	// BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
	// BIO_printf(bio_out, "Tag is:\n");
	// BIO_dump(bio_out, (const char *)tag, sizeof(tag));
	// BIO_printf(bio_out, "Decodedtext is:\n");
	// BIO_dump_fp(stdout, (const char *)decodedtext, decodedtext_len);

	delete[] ciphertext; ciphertext = nullptr;
	delete[] decodedtext; decodedtext = nullptr;

	Array ctos = hex_stream_to_array("03dc7ea945ace7bab4b5463ef0035970");
	// Array expected_tag = hex_stream_to_array("cf0525308eb7c504dfd1dca6c5501633");
	// Array ctos = hex_stream_to_array("e7d4c23c572ae376036ddfa5799c3341");
	Array expected_tag;
	aad[0] = 0x30;
	int challenge_len = sizeof(aad) + ctos.len;
	uint8_t * challenge = new uint8_t[challenge_len];
	memcpy(challenge, aad, sizeof(aad));
	memcpy(challenge + sizeof(aad), ctos.data, ctos.len);
	BIO_printf(bio_out, "Challenge is:\n");
	BIO_dump(bio_out, (const char *)challenge, challenge_len);

	uint32_t start = 0x00000000;
	uint32_t end   = 0x0000ffff;
	start = end = 0xcf052530;
	for (uint32_t ic = start; ic <= end; ic++) {
		*(uint32_t *)((uint8_t *)iv + 8) = htonl(ic);

		AES aes(ALGORITHM, key, sizeof(key), iv, sizeof(iv), sizeof(tag));
		ciphertext_len = aes.Encrypt(challenge, challenge_len, ciphertext, tag, nullptr, 0);

		bool is_equal = true;
		for (size_t i = 0; i < expected_tag.len; i++) {
			if (tag[i] != expected_tag.data[i]) {
				is_equal = false;
				break;
			}
		}
		if (is_equal) {
			BIO_printf(bio_out, "Tag is:\n");
			BIO_dump(bio_out, (const char *)tag, sizeof(tag));
			BIO_printf(bio_out, "Ciphertext Length: %ld\n", ciphertext_len);
		}
	}

	BIO_free(bio_out);

	// CONF_modules_unload(1);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	// ERR_remove_state(pid);
	ERR_free_strings();

	return 0;
}