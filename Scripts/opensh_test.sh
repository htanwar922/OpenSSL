openssl genrsa -des3 -out private.pem 2048
openssl rsa -in private.pem -pubout | openssl rsa -pubin -text -noout
openssl rsa -in private.pem -out public.pem -pubout
openssl rsa -in private.pem -inform PEM -text -noout
openssl rsa -in public.pem -inform PEM -text -noout -pubin

## Self Note
# -text probably prints in little-endian format of 8 Bytes:-
#	least significant set of 8 Bytes is printed in first row.
#	most significant set of 8 Bytes is printed in last row.

echo -en "AA" | openssl enc -base64	# -n in echo ensures an extra newline isn't appended
openssl enc -base64 -in text.plain -out text.base64
openssl enc -d -base64 -in text.base64 -out text.plain
