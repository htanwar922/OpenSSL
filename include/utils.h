#pragma once

#include "iostream"
#include "iomanip"

#include "openssl/rsa.h"

namespace LibOpenSSL {

#define ERROR(str) {\
	fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, str);	\
	ERR_print_errors_fp(stderr);	\
}
	

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

}