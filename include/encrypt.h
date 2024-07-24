#pragma once

#include "stdint.h"

#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/aes.h"
#include "openssl/rand.h"

#include "utils.h"

// For encryption/decryption, we need four components:
// - algorithm	: Ciphers - AES, DES, 3DES, RC2, RC4, RC5, etc.
// - mode		: CBC, GCM, GCM, CCM, CFB, ECB, etc.
// - key		: the key to be used by the cipher.
// - iv			: the initialization vector - a hex number.

// openssl enc -aes-256-cbc -k <passphrase> -P/p =====> salt, key, iv
// openssl enc -nosalt -aes-256-cbc -in message.txt -out message.txt.enc -base64 -K <key> -iv <iv>
// openssl enc -nosalt -aes-256-cbc -d -in message.txt.enc -base64 -K <key> -iv <iv>
// echo -en "Hello World" | openssl enc -nosalt -aes-256-cbc -k <key> -iv <iv> | hexdump -C # (or xxd)
// echo -en "Hello World" | openssl enc -nosalt -aes-256-cbc -k <key> -iv <iv> | openssl enc -d -nosalt -aes-256-cbc -k <key> -iv <iv>
namespace LibOpenSSL {

class AES
{
protected:
	const char * ciphername = NULL;
	const char algo[4] = "AES";
	const int bitsize = 128;
	const char mode[4] = "GCM";

	const uint8_t * key = NULL, * iv = NULL;
	int key_len = 0, iv_len = 0, tag_len = 0;
public:
	AES(const char * ciphername, const uint8_t * key, int key_len, const uint8_t * iv, int iv_len, int tag_len = 0)
	: ciphername(ciphername)
	, key_len(key_len)
	, iv_len(iv_len)
	, tag_len(tag_len)
	{
		this->key = new uint8_t[key_len];
		this->iv = new uint8_t[iv_len];
		if (key)
			memcpy((void *)this->key, (void *)key, key_len);
		if (iv)
			memcpy((void *)this->iv, (void *)iv, iv_len);
		sscanf(ciphername, "%[^-]-%d-%s", (char *)algo, (int *)&bitsize, (char *)mode);
	}

	int Encrypt(const uint8_t * plaintext, int len, uint8_t * &ciphertext, uint8_t * tag = NULL, uint8_t * aad = NULL, int aad_len = 0)
	{
		EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
		if(ERR_LIB_NONE != EVP_EncryptInit_ex(ctx, EVP_get_cipherbyname(ciphername), NULL, NULL, NULL)) {
			ERROR("EVP_EncryptInit error\n");
			return -1;
		}
		if (0 == strcmp(mode, "GCM")) {
			if (ERR_LIB_NONE != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
				ERROR("EVP_CIPHER_CTX_ctrl error in setting the IV Length\n");
				return -1;
			}
		}
		if(ERR_LIB_NONE != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
			ERROR("EVP_EncryptInit error\n");
			return -1;
		}

		if (aad_len and aad) {
			if (ERR_LIB_NONE != EVP_EncryptUpdate(ctx, NULL, &aad_len, aad, aad_len)) {
				ERROR("EVP_EncryptUpdate error in setting the AAD\n");
				return -1;
			}
		}

		int retLength1 = 0;
		// Repeat for more plaintext blocks before finishing.
		if(ERR_LIB_NONE != EVP_EncryptUpdate(ctx, ciphertext, &retLength1, plaintext, len)) {
			ERROR("EVP_EncryptUpdate error\n");
			return -1;
		}
		int retLength2 = 0;
		if(ERR_LIB_NONE != EVP_EncryptFinal_ex(ctx, ciphertext + retLength1, &retLength2)) {
			ERROR("EVP_EncryptFinal error\n");
			return -1;
		}

		if (0 == strcmp(mode, "GCM")) {
			if (tag_len and tag) {
				if (ERR_LIB_NONE != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
					ERROR("EVP_CIPHER_CTX_ctrl error in getting the tag\n");
					return -1;
				}
			}
			else {
				ERROR("Tag length is zero or tag is NULL\n");
			}
		}

		EVP_CIPHER_CTX_free(ctx);
		return retLength1 + retLength2;
	}

	int GetGMAC(const uint8_t * plaintext, int len, uint8_t * tag, uint8_t * aad = NULL, int aad_len = 0)
	{
		EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
		if(ERR_LIB_NONE != EVP_EncryptInit_ex(ctx, EVP_get_cipherbyname(ciphername), NULL, NULL, NULL)) {
			ERROR("EVP_EncryptInit error\n");
			return -1;
		}
		if (0 == strcmp(mode, "GCM")) {
			if (ERR_LIB_NONE != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
				ERROR("EVP_CIPHER_CTX_ctrl error in setting the IV Length\n");
				return -1;
			}
		}
		if(ERR_LIB_NONE != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
			ERROR("EVP_EncryptInit error\n");
			return -1;
		}

		if (aad_len and aad) {
			if (ERR_LIB_NONE != EVP_EncryptUpdate(ctx, NULL, &aad_len, aad, aad_len)) {
				ERROR("EVP_EncryptUpdate error in setting the AAD\n");
				return -1;
			}
		}

		int retLength1 = 0;
		// Repeat for more plaintext blocks before finishing.
		if(ERR_LIB_NONE != EVP_EncryptUpdate(ctx, NULL, &retLength1, plaintext, len)) {
			ERROR("EVP_EncryptUpdate error\n");
			return -1;
		}
		int retLength2 = 0;
		if(ERR_LIB_NONE != EVP_EncryptFinal_ex(ctx, NULL, &retLength2)) {
			ERROR("EVP_EncryptFinal error\n");
			return -1;
		}

		if (0 == strcmp(mode, "GCM")) {
			if (tag_len and tag) {
				if (ERR_LIB_NONE != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
					ERROR("EVP_CIPHER_CTX_ctrl error in getting the tag\n");
					return -1;
				}
			}
			else {
				ERROR("Tag length is zero or tag is NULL\n");
			}
		}

		EVP_CIPHER_CTX_free(ctx);
		return retLength1 + retLength2;
	}

	int Decrypt(const uint8_t * ciphertext, int len, uint8_t * &plaintext, uint8_t * tag = NULL, uint8_t * aad = NULL, int aad_len = 0)
	{
		EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
		if(ERR_LIB_NONE != EVP_DecryptInit_ex(ctx, EVP_get_cipherbyname(ciphername), NULL, NULL, NULL)) {
			ERROR("EVP_DecryptInit error\n");
			return -1;
		}

		if (0 == strcmp(mode, "GCM")) {
			if (ERR_LIB_NONE != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
				ERROR("EVP_CIPHER_CTX_ctrl error in setting the IV Length\n");
				return -1;
			}
			if (tag_len and tag) {
				if (ERR_LIB_NONE != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag)) {
					ERROR("EVP_CIPHER_CTX_ctrl error in setting the tag\n");
					return -1;
				}
			}
			else {
				ERROR("Tag length is zero or tag is NULL\n");
			}
		}

		if(ERR_LIB_NONE != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
			ERROR("EVP_DecryptInit error\n");
			return -1;
		}

		if (aad_len and aad) {
			if (ERR_LIB_NONE != EVP_DecryptUpdate(ctx, NULL, &aad_len, aad, aad_len)) {
				ERROR("EVP_DecryptUpdate error in setting the AAD\n");
				return -1;
			}
		}

		int retLength1 = 0;
		// Repeat for more ciphertext blocks before finishing.
		if(ERR_LIB_NONE != EVP_DecryptUpdate(ctx, plaintext, &retLength1, ciphertext, len)) {
			ERROR("EVP_DecryptUpdate error\n");
			return -1;
		}
		int retLength2 = 0;
		if(ERR_LIB_NONE != EVP_DecryptFinal_ex(ctx, plaintext + retLength1, &retLength2)) {
			ERROR("EVP_DecryptFinal error\n");
			return -1;
		}

		EVP_CIPHER_CTX_free(ctx);
		return retLength1 + retLength2;
	}

	void PrintCiphertext(const uint8_t * ciphertext, int len)
	{
		BIO_dump_fp(stdout, (const char *)ciphertext, len);
	}

	const uint8_t * GetKey()
	{
		return key;
	}

	const uint8_t * GetIV()
	{
		return iv;
	}

	~AES()
	{
		if(key)	delete[] key;
		if(iv) delete[] iv;
	}
};

// AES CBC 256-bit encryption class
// AES - Advanced Encryption Standard
// CBC - Cipher Block Chain mode
//
class AES_CBC_256 : public AES
{
public:
	AES_CBC_256() : AES("AES-256-CBC", NULL, 32, NULL, AES_BLOCK_SIZE)
	{
		// key = new uint8_t[32];
		// iv = new uint8_t[AES_BLOCK_SIZE];
		// RAND_bytes((uint8_t *)key, 32);
		// RAND_bytes((uint8_t *)iv, AES_BLOCK_SIZE);

		// echo -en "Hello World How art thou?\r\n" | openssl enc -nosalt -aes-256-cbc -K f71d24280a6bb77e18f9fd2ff22a72dfad72d8f44a9b71181358234553357913 -iv 62bd8545506afca8d6e71f066ba3e7a0 | hexdump -C
		key = new uint8_t[32]{0xf7, 0x1d, 0x24, 0x28, 0x0a, 0x6b, 0xb7, 0x7e, 0x18, 0xf9, 0xfd, 0x2f, 0xf2, 0x2a, 0x72, 0xdf, 0xad, 0x72, 0xd8, 0xf4, 0x4a, 0x9b, 0x71, 0x18, 0x13, 0x58, 0x23, 0x45, 0x53, 0x35, 0x79, 0x13};
		iv = new uint8_t[AES_BLOCK_SIZE]{0x62, 0xbd, 0x85, 0x45, 0x50, 0x6a, 0xfc, 0xa8, 0xd6, 0xe7, 0x1f, 0x06, 0x6b, 0xa3, 0xe7, 0xa0};
	}
};

} // namespace LibOpenSSL

/** LOW LEVEL ENCRYPTION DIRECTLY USING AES FUNCTIONS

// Setup the AES Key structure required for use in the OpenSSL APIs
AES_KEY* AesKey = new AES_KEY();
AES_set_encrypt_key(key, 256, AesKey);

// Make a copy of the IV to IVd as it seems to get destroyed when used
uint8_t IVd[AES_BLOCK_SIZE];
for(int i=0; i < AES_BLOCK_SIZE; i++){
    IVd[i] = IV[i];
}

// take an input string and pad it so it fits into 16 bytes (AES Block Size)
std::string txt("this is a test");
const int UserDataSize = (const int)txt.length();   // Get the length pre-padding
int RequiredPadding = (AES_BLOCK_SIZE - (txt.length() % AES_BLOCK_SIZE));   // Calculate required padding
std::vector<unsigned char> PaddedTxt(txt.begin(), txt.end());   // Easier to Pad as a vector
for(int i=0; i < RequiredPadding; i++){
    PaddedTxt.push_back(0); //  Increase the size of the string by
}                           //  how much padding is necessary

unsigned char * UserData = &PaddedTxt[0];// Get the padded text as an unsigned char array
const int UserDataSizePadded = (const int)PaddedTxt.size();// and the length (OpenSSl is a C-API)

// Peform the encryption
unsigned char EncryptedData[512] = {0}; // Hard-coded Array for OpenSSL (C++ can't dynamic arrays)
AES_cbc_encrypt(UserData, EncryptedData, UserDataSizePadded, (const AES_KEY*)AesKey, IV, AES_ENCRYPT);

// Setup an AES Key structure for the decrypt operation
AES_KEY* AesDecryptKey = new AES_KEY(); // AES Key to be used for Decryption
AES_set_decrypt_key(Key, 256, AesDecryptKey);   // We Initialize this so we can use the OpenSSL Encryption API

// Decrypt the data. Note that we use the same function call. Only change is the last parameter
unsigned char DecryptedData[512] = {0}; // Hard-coded as C++ doesn't allow for dynamic arrays and OpenSSL requires an array
AES_cbc_encrypt(EncryptedData, DecryptedData, UserDataSizePadded, (const AES_KEY*)AesDecryptKey, IVd, AES_DECRYPT);
*/