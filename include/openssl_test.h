#include "iostream"
#include "iomanip"
#include "stdio.h"
#include "string.h"
#include "stdint.h"
#include "string"

#include "openssl/md5.h"
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"

void print(BIGNUM * bn, const char * sep = ":")
{
	std::cout << bn->dmax << std::endl;
	std::cout << std::hex;
	int i=bn->dmax;
	while(!bn->d[i-1]) i--;
	while(i--)
	{
		std::cout << std::setw(sizeof(unsigned long) << 1) << std::setfill('0') << bn->d[i] << sep;
		if(!(i % 2)) std::cout << std::endl;
	}
	std::cout << std::endl << std::endl;
}

void printKey(RSA * rsa)
{
	std::cout << "Modulus: ";
	print(rsa->n);
	std::cout << "Public Exponent: ";
	print(rsa->e);
	std::cout << "Private Exponent: ";
	print(rsa->d);
}

void GenRSAPrivateKey(const char * filename = "../private.pem", const char * passphrase = "Himanshu")
{
	FILE * file = fopen(filename, "wb");

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

void SavePrivateKey(EVP_PKEY * pkey, const char * filename = "../private.pem", const char * passphrase = "Himanshu")
{
	FILE * file = fopen(filename, "wb");

	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();

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

EVP_PKEY * GetPrivateKey(const char * filename = "../private.pem", const char * passphrase = "Himanshu")
{
	EVP_PKEY * pkey = EVP_PKEY_new();
	FILE * file = fopen(filename, "rb");
	PEM_read_PrivateKey(file, &pkey, NULL, NULL);
	fclose(file);
	return pkey;
}

std::string GenerateMD5(const uint8_t data[])
{
	uint8_t digest[MD5_DIGEST_LENGTH];
	MD5(data, strlen((char *)data), digest);		// use strlen, not sizeof. (sizeof = strlen + 1)

	char messageDigestString[MD5_DIGEST_LENGTH << 1 + 1];
	for(int i=0; i<MD5_DIGEST_LENGTH; i++)
		sprintf(messageDigestString + i*2, "%02x", digest[i]);
	
	printf("Message Digest:\n%s\n", messageDigestString);
	return messageDigestString;
}

std::string GenerateSHA1(const uint8_t data[])
{
	uint8_t hash[SHA_DIGEST_LENGTH];
	SHA1(data, strlen((char *)data), hash);		// use strlen, not sizeof. (sizeof = strlen + 1)

	char messageDigestString[SHA_DIGEST_LENGTH << 1 + 1];
	for(int i=0; i<SHA_DIGEST_LENGTH; i++)
		sprintf(messageDigestString + i*2, "%02x", hash[i]);
	
	printf("Message Digest:\n%s\n", messageDigestString);
	return messageDigestString;
}