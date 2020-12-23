#!/bin/sh

# this acme client isn't great :/

export http_proxy=
export https_proxy=

sudo true || exit 99 # warm up sudo, since next call is backgrounded
sudo python3 -m http.server 80 &
httpd=$?

cd $(dirname $(realpath $0))
./acme.sh/acme.sh --issue -d example.test -d www.example.test -w .  --server https://localhost:8443/directory --insecure --force # force to dont wait for expiry

sudo kill $httpd
