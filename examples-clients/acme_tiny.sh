#!/bin/sh

# create a csr with gen-csr.sh first!

export http_proxy=
export https_proxy=

mkdir -p /tmp/well-known/.well-known/acme-challenge
sudo true || exit 99 # warm up sudo, since next call is backgrounded
( cd /tmp/well-known && sudo python3 -m http.server 80; ) &
httpd=$?

cd $(dirname $(realpath $0))
cd acme-tiny-master/
python3 ./acme_tiny.py \
	--directory-url https://localhost:8443/directory \
	--acme-dir /tmp/well-known/.well-known/acme-challenge/ \
	--account-key ../altcert/example.test.key \
	--csr ../altcert/example.test.csr \
	#--contact certmaster@example.test test@example.org

sudo kill $httpd
