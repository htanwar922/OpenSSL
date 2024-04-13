#pragma once

#include "utils.h"
#include "digest.h"
#include "encode.h"
#include "key.h"
#include "encrypt.h"

namespace LibOpenSSL {

void print(const BIGNUM * bn, const char * sep = ":")
{
	int dmax = BN_num_bytes(bn);					// bn->dmax;
	unsigned char* d = new unsigned char[dmax];		// bn->d;
    BN_bn2binpad(bn, d, dmax);

	std::cout << dmax << std::endl;
	std::cout << std::hex;
	int i = dmax;
	while(!d[i-1] && --i);
	while(i--)
	{
		std::cout << std::setw(sizeof(unsigned long) << 1) << std::setfill('0') << d[i] << sep;
		if(!(i % 2)) std::cout << std::endl;
	}
	std::cout << std::endl << std::endl;
}

void printKey(RSA * rsa)
{
	std::cout << "Modulus: ";
	print(RSA_get0_n(rsa));
	std::cout << "Public Exponent: ";
	print(RSA_get0_e(rsa));
	std::cout << "Private Exponent: ";
	print(RSA_get0_d(rsa));
}

} // namespace LibOpenSSL