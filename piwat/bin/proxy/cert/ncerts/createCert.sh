#!/bin/sh
openssl req -config openssl.cnf -days 365 -nodes -new -keyout $1.key -out $1.csr
openssl ca -batch -notext -config openssl.cnf -out $1.crt -infiles $1.csr 
cat $1.crt $1.key > $1.pem
