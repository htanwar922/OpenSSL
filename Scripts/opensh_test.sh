#!/bin/bash

# key.h
## generate and store key pair
openssl genrsa -des3 -out private.pem 2048
openssl rsa -in private.pem -pubout | openssl rsa -pubin -text -noout
openssl rsa -in private.pem -out public.pem -pubout
openssl rsa -in private.pem -inform PEM -text -noout
openssl rsa -in public.pem -inform PEM -text -noout -pubin
## encrypt and decrypt
echo 'Hey babe! Come here I need you!'					\
	| openssl rsautl -encrypt -pubin -inkey ../public.pem	\
	| openssl rsautl -decrypt -inkey ../private.pem
## sign and verify using key pair
echo -en "Hello World" | openssl dgst -sha256 -sign ../private.pem -out signature.dat
echo -en "Hello World" | openssl dgst -sha256 -verify ../public.pem -signature signature.dat

## Self Note
# -text probably prints in little-endian format of 8 Bytes:-
#	least significant set of 8 Bytes is printed in first row.
#	most significant set of 8 Bytes is printed in last row.

# encode.h
echo -en "AA" | openssl enc -base64	# -n in echo ensures an extra newline isn't appended
openssl enc -base64 -in text.plain -out text.base64
openssl enc -d -base64 -in text.base64 -out text.plain

# encrypt.h
openssl enc -aes-256-cbc -k <passphrase> -P/p =====> salt, key, iv
openssl enc -nosalt -aes-256-cbc -in message.txt -out message.txt.enc -base64 -K <key> -iv <iv>
openssl enc -nosalt -aes-256-cbc -d -in message.txt.enc -base64 -K <key> -iv <iv>
echo -en "Hello World" | openssl enc -nosalt -aes-256-cbc -k <key> -iv <iv> | hexdump -C # (or xxd)
echo -en "Hello World" | openssl enc -nosalt -aes-256-cbc -k <key> -iv <iv> | openssl enc -d -nosalt -aes-256-cbc -k <key> -iv <iv>

# digest.h
echo -en "Hello World" | openssl dgst -sha256 | hexdump -C
echo -en "Hello World" | openssl sha256 | hexdump -C