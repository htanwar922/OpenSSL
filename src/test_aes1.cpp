
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/aes.h"
#include "openssl/rand.h"

#include "utils.h"
#include "test_aes1.h"

using namespace LibOpenSSL;

#define ALGORITHM "AES-128-GCM"

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
	Array data = hex_stream_to_array("b3124dc843bb8ba61f035a7d0938251f");
	Array secret = "Gurux";
	Array reply;

	Array s;
	size_t len = data.GetSize();
	if (len % 16 != 0)
	{
		len += (16 - (data.GetSize() % 16));
	}
	if (secret.GetSize() > data.GetSize())
	{
		len = secret.GetSize();
		if (len % 16 != 0)
		{
			len += (16 - (secret.GetSize() % 16));
		}
	}
	s.Set(&secret);
	s.Zero(s.GetSize(), len - s.GetSize());
	reply.Set(&data);
	reply.Zero(reply.GetSize(), len - reply.GetSize());

	BIO * bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	BIO_printf(bio_out, "Data is:\n");
	BIO_dump_fp(stdout, (const char *)data.data, data.len);
	BIO_printf(bio_out, "Secret is:\n");
	BIO_dump_fp(stdout, (const char *)s.data, s.len);

	// AES1Encrypt block
	for (size_t pos = 0; pos < len / 16; ++pos)
	{
		Aes1Encrypt(reply, pos * 16, s);
	}
	BIO_printf(bio_out, "Encrypted data is:\n");
	BIO_dump_fp(stdout, (const char *)reply.data, reply.len);

	s.Set(&secret);
	s.Zero(s.GetSize(), len - s.GetSize());
	reply = hex_stream_to_array("cf0525308eb7c504dfd1dca6c5501633");
	// reply = hex_stream_to_array("e2935690cdec0b1ec0f17cf071ca5f61");

	// AES1Decrypt block
	Aes1Decrypt(reply, s);
	BIO_printf(bio_out, "Decrypted data is:\n");
	BIO_dump_fp(stdout, (const char *)reply.data, reply.len);

	return 0;
}
