#!/bin/sh
openssl req -config openssl.cnf -extensions v3_ca -days 3650 -new -x509 -keyout proxpy.key -out proxpyca.crt -nodes
