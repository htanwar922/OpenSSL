#pragma once

#include "string.h"
#include "stdint.h"

#include "openssl/bio.h"
#include "openssl/evp.h"

namespace LibOpenSSL {

// BIO_f_base64 filter
// - encodes the data written through it.
// - decodes the data read through it.
void Base64(BIO * bio_out, const uint8_t * str, int len = 0)
{
	BIO * bio_base64 = BIO_new(BIO_f_base64());
	BIO_push(bio_base64, bio_out);
	int bio_outBytes = BIO_write(bio_base64, str, len ? len : strlen((const char *)str));
	BIO_flush(bio_base64);	// BIO_flush() normally writes out any internally buffered data; in some cases it is used to signal EOF and that no more data will be written.
	BIO_printf(bio_base64->next_bio, "Out Bytes: %d\n", bio_outBytes);
	BIO_free(bio_base64);	// Alternatively, BIO_free_all(bio_base64);
}

}