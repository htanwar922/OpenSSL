openssl genrsa -des3 -out private.pem 2048
openssl rsa -in private.pem -pubout | openssl rsa -pubin -text -noout
openssl rsa -in private.pem -out public.pem -pubout
openssl rsa -in private.pem -inform PEM -text -noout
openssl rsa -in public.pem -inform PEM -text -noout -pubin