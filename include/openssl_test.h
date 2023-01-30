#pragma once

#include "utils.h"
#include "digest.h"
#include "encode.h"
#include "key.h"
#include "encrypt.h"

namespace LibOpenSSL {

void print(BIGNUM * bn, const char * sep = ":")
{
	std::cout << bn->dmax << std::endl;
	std::cout << std::hex;
	int i=bn->dmax;
	while(!bn->d[i-1] && --i);
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

} // namespace LibOpenSSL