#!/bin/bash
openssl req -new -sha256 -nodes -out example.test.csr -newkey rsa:2048 -keyout example.test.key -config <(
cat <<-EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
#C=US
#ST=New York
#L=Rochester
#O=End Point
#OU=Testing Domain
#emailAddress=your-administrative-address@your-awesome-existing-domain.com
CN = example.test

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = example.test
DNS.2 = www.example.test
EOF
)

