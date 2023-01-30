#pragma once

#include "cstring"
#include "stdint.h"

#include "openssl/rsa.h"
#include "openssl/pem.h"

#include "digest.h"
#include "openssl_test.h"

// openssl genrsa -des3 -out private.pem 2048
// openssl rsa -in private.pem -pubout | openssl rsa -pubin -text -noout
// openssl rsa -in private.pem -out public.pem -pubout
// openssl rsa -in private.pem -inform PEM -text -noout
// openssl rsa -in public.pem -inform PEM -text -noout -pubin

namespace LibOpenSSL {

class PKey
{
private:
	EVP_PKEY * pkey = NULL;
public:
	PKey()
	{
	}
	
	EVP_PKEY * GenPrivateKey(int algorithm_id = EVP_PKEY_RSA, uint32_t bits = 2048)
	{
		EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new_id(algorithm_id, NULL);
		EVP_PKEY_keygen_init(ctx);
		switch (algorithm_id)
		{
		case EVP_PKEY_RSA:
			EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
			break;
		case EVP_PKEY_DSA:
		case EVP_PKEY_EC:
		case EVP_PKEY_HMAC:
		case EVP_PKEY_CMAC:
		case EVP_PKEY_DH:
		case EVP_PKEY_NONE:
		default:
			break;
		}
		EVP_PKEY_keygen(ctx, &pkey);
		EVP_PKEY_CTX_free(ctx);
		return pkey;
	}

	size_t Encrypt(const uint8_t * plaintext, size_t len, uint8_t * &ciphertext)
	{
		EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if(ERR_LIB_NONE != EVP_PKEY_encrypt_init(ctx)) {
			ERROR("EVP_PKEY_encrypt_init error");
			return -1;
		}
		size_t retLength = 0;
		if(ERR_LIB_NONE != EVP_PKEY_encrypt(ctx, NULL, &retLength, plaintext, len)) {
			ERROR("EVP_PKEY_encrypt error");
			return -1;
		}
		ciphertext = (uint8_t *)OPENSSL_malloc(retLength);
		if(ERR_LIB_NONE != EVP_PKEY_encrypt(ctx, ciphertext, &retLength, plaintext, len)) {
			ERROR("EVP_PKEY_encrypt error");
			return -1;
		}
		EVP_PKEY_CTX_free(ctx);
		return retLength;
	}

	size_t Decrypt(const uint8_t * ciphertext, size_t len, uint8_t * &plaintext)
	{
		EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if(ERR_LIB_NONE != EVP_PKEY_decrypt_init(ctx)) {
			ERROR("EVP_PKEY_decrypt_init error");
			return -1;
		}
		size_t retLength = 0;
		if(ERR_LIB_NONE != EVP_PKEY_decrypt(ctx, NULL, &retLength, ciphertext, len)) {
			ERROR("EVP_PKEY_decrypt error");
			return -1;
		}
		plaintext = (uint8_t *)OPENSSL_malloc(retLength);
		if(ERR_LIB_NONE != EVP_PKEY_decrypt(ctx, plaintext, &retLength, ciphertext, len)) {
			ERROR("EVP_PKEY_decrypt error");
			return -1;
		}
		EVP_PKEY_CTX_free(ctx);
		return retLength;
	}

	uint8_t * Sign(const uint8_t data[], size_t len, size_t * signLength, const char * algorithm)
	{
		uint32_t digestLen = 0;
		uint8_t * digest = MessageDigest(data, (uint32_t)len, &digestLen, algorithm);
		EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if(ERR_LIB_NONE != EVP_PKEY_sign_init(ctx)) {
			ERROR("EVP_PKEY_sign_init error");
			return NULL;
		}
		if(ERR_LIB_NONE != EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING)) {
			ERROR("EVP_PKEY_CTX_set_rsa_padding error");
			return NULL;
		}
		if(ERR_LIB_NONE != EVP_PKEY_CTX_set_signature_md(ctx, EVP_get_digestbyname(algorithm))) {
			ERROR("EVP_PKEY_CTX_set_signature_md error");
			return NULL;
		}
		if(ERR_LIB_NONE != EVP_PKEY_sign(ctx, NULL, signLength, digest, digestLen)) {
			ERROR("EVP_PKEY_sign error 1");
			return NULL;
		}
		printf("sign len : %lu\n", *signLength);
		uint8_t * signature = new uint8_t[*signLength]{0};
		if(ERR_LIB_NONE != EVP_PKEY_sign(ctx, signature, signLength, digest, digestLen)) {
			ERROR("EVP_PKEY_sign error 2");
			return NULL;
		}
		EVP_PKEY_CTX_free(ctx);
		delete[] digest;
		return signature;
	}

	bool Verify(const uint8_t data[], size_t len, const uint8_t signature[], size_t signLength, const char * algorithm)
	{
		uint32_t digestLen = 0;
		uint8_t * digest = MessageDigest(data, (uint32_t)len, &digestLen, algorithm);
		EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if(ERR_LIB_NONE != EVP_PKEY_verify_init(ctx)) {
			ERROR("EVP_PKEY_verify_init error");
			return false;
		}
		if(ERR_LIB_NONE != EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING)) {
			ERROR("EVP_PKEY_CTX_set_rsa_padding error");
			return false;
		}
		if(ERR_LIB_NONE != EVP_PKEY_CTX_set_signature_md(ctx, EVP_get_digestbyname(algorithm))) {
			ERROR("EVP_PKEY_CTX_set_signature_md error");
			return false;
		}
		if(ERR_LIB_NONE != EVP_PKEY_verify(ctx, signature, signLength, digest, digestLen)) {
			ERROR("EVP_PKEY_sign error");
			return false;
		}
		EVP_PKEY_CTX_free(ctx);
		delete[] digest;
		return true;
	}

	void SaveKey(const char * filename = SOURCE_DIR"/private.pem", const char * key_type = "private", const char * passphrase = "Himanshu")
	{
		FILE * file = fopen(filename, "wb");
		int ret = -1;
		if(strcmp("private", key_type) == 0)
			switch (EVP_PKEY_type(EVP_PKEY_base_id(pkey)))
			{
			case EVP_PKEY_RSA:
				ret = PEM_write_RSAPrivateKey(
					file,					// FILE struct to write to
					pkey->pkey.rsa,					// EVP_PKEY struct
					EVP_aes_128_cbc(),		// default EVP_CIPHER for encrypting the key on disk
					(uint8_t *)passphrase,	// passphrase for encrypting the key on disk
					strlen(passphrase),		// length of the passphrase string
					NULL,					// callback for requesting a password // pem_password_cb
					NULL					// user data to pass to the callback
				);
				break;
			case EVP_PKEY_DSA:
				break;
			case EVP_PKEY_EC:
				break;
			case EVP_PKEY_HMAC:
				break;
			case EVP_PKEY_CMAC:
				break;
			case EVP_PKEY_DH:
				break;
			default:
				break;
			}
		else
			ret = PEM_write_PUBKEY(file, pkey);
		fclose(file);
	}

	EVP_PKEY * GetKey(const char * filename, const char * key_type = "private")
	{
		if(pkey) EVP_PKEY_free(pkey);
		pkey = EVP_PKEY_new();
		FILE * file = fopen(filename, "rb");
		if(strcmp("private", key_type) == 0)
			PEM_read_PrivateKey(file, &pkey, NULL, NULL);
		else
			PEM_read_PUBKEY(file, &pkey, NULL, NULL);
		fclose(file);
		return pkey;
	}

	const char * GetType()
	{
		const char * algorithm;
		int algorithm_id = EVP_PKEY_base_id(pkey);
		switch (EVP_PKEY_type(algorithm_id))
		{
		case EVP_PKEY_RSA:
			algorithm = "EVP_PKEY_RSA";
			break;
		case EVP_PKEY_DSA:
			algorithm = "EVP_PKEY_DSA";
			break;
		case EVP_PKEY_EC:
			algorithm = "EVP_PKEY_EC";
			break;
		case EVP_PKEY_HMAC:
			algorithm = "EVP_PKEY_HMAC";
			break;
		case EVP_PKEY_CMAC:
			algorithm = "EVP_PKEY_CMAC";
			break;
		case EVP_PKEY_DH:
			algorithm = "EVP_PKEY_DH";
			break;
		default:
			algorithm = "EVP_PKEY_NONE";
			break;
		}
		return algorithm;
	}

	void PrintKey(const char * key_type = "public")
	{
		BIO * bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
		if(strcmp("private", key_type) == 0)
			EVP_PKEY_print_private(bio_out, pkey, 0, NULL);
		else
			EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
		BIO_free(bio_out);
	}

	~PKey()
	{
		if(pkey) EVP_PKEY_free(pkey);
	}
};

void GenRSAPrivateKey(const char * filename = SOURCE_DIR"/private.pem", const char * passphrase = "Himanshu")
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

	// EVP_PKEY * pkey = EVP_PKEY_new();
	// EVP_PKEY_assign_RSA(pkey, rsa);
	// SavePrivateKey(pkey, filename, passphrase);
	// EVP_PKEY_free(pkey);	// The RSA structure will be automatically freed.

	RSA_free(rsa);
	BN_free(bn);
	fclose(file);
}

void SavePrivateKey(EVP_PKEY * pkey, const char * filename, const char * passphrase)
{
	FILE * file = fopen(filename, "wb");
	// BIO * file = BIO_new_file(filename, "wb");

	//// #include "openssl/err.h"
	// OpenSSL_add_all_algorithms();
	// OpenSSL_add_all_ciphers();
	// ERR_load_crypto_strings();

	// A generic structure to hold diverse types of asymmetric keys or "key pairs".
	// EVP_PKEY * pkey = EVP_PKEY_new();
	// EVP_PKEY_assign_RSA(pkey, rsa);

	int ret = PEM_write_PKCS8PrivateKey(
		file,					// FILE struct to write to
		pkey,					// EVP_PKEY struct
		EVP_aes_128_cbc(),		// default EVP_CIPHER for encrypting the key on disk
		(char *)passphrase,		// passphrase for encrypting the key on disk
		strlen(passphrase),		// length of the passphrase string
		NULL,					// callback for requesting a password // pem_password_cb
		NULL					// user data to pass to the callback
	);

	// EVP_PKEY_free(pkey);	// The RSA structure will be automatically freed.
	fclose(file);
	// BIO_free(file);
}

EVP_PKEY * GetPrivateKey(const char * filename)
{
	EVP_PKEY * pkey = EVP_PKEY_new();
	FILE * file = fopen(filename, "rb");
	PEM_read_PrivateKey(file, &pkey, NULL, NULL);
	fclose(file);
	return pkey;
}

} // namespace LibOpenSSL
