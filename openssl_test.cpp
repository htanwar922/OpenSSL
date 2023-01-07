#include "openssl_test.h"

int main()
{
	const char * filename = "../private.pem";
	const char * passphrase = "Himanshu";

	GenRSAPrivateKey(filename, passphrase);
	// EVP_PKEY * pkey = 
	GetPrivateKey(filename, passphrase);

	FILE *f;
EVP_PKEY *pkey;
f = fopen(filename, "rb");
PEM_read_PrivateKey(
    f,     /* use the FILE* that was opened */
    &pkey, /* pointer to EVP_PKEY structure */
    NULL,  /* password callback - can be NULL */
    NULL   /* parameter passed to callback or password if callback is NULL */
);
printKey(pkey->pkey.rsa);
fclose(f);
}