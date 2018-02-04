#!/bin/bash
openssl req -x509 -newkey rsa -keyout ca.key -out ca.crt -days 3650 -nodes -subj '/C=XX/O=Test CA Issuer/CN=Root CA'
openssl req -newkey rsa -keyout internim.key -out internim.csr -days 3650 -nodes -subj '/C=XX/O=Test CA Issuer/CN=Internim CA'
echo -n '00' >ca.srl
openssl x509 -req -CA ca.crt -CAkey ca.key -in internim.csr -out internim.crt -days 3650 -extfile <(echo "basicConstraints=CA:TRUE")
openssl req -newkey rsa -keyout server.key -out server.csr -days 3650 -nodes -subj '/C=XX/O=Test Server/CN=localhost'
echo -n '00' >internim.srl
openssl x509 -req -CA internim.crt -CAkey internim.key -in server.csr -out server.crt -days 3650 -extfile <(printf "subjectAltName=DNS:localhost")
openssl x509 -in server.crt -outform DER -out server.der
cat server.crt internim.crt >server-bundle.crt
openssl pkcs12 -export -in server-bundle.crt -inkey server.key -out server-bundle.p12
