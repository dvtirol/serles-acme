#!/bin/sh

sudo certbot certonly \
	--standalone \
	--server https://localhost:8443/directory `#URL of your ACMEByProxy server` \
	--pre-hook 'rm -rf /etc/letsencrypt/accounts' `#certbot tries to reuse account keys, but we don't store them` \
	--register-unsafely-without-email --agree-tos \
	--keep-until-expiring `#or for testing: --force-renewal` \
	-d example.test \
	--no-verify-ssl # XXX: very bad, no good idea!
