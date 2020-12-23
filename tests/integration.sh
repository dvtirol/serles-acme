#!/bin/sh

if ! test $UID -eq 0; then
	echo "run test as root"
	exit 1
fi

if ! test -x ./acme_tiny.py; then
	echo "acme_tiny.py absent or not executable"
	exit 1
fi

cd $(dirname $(realpath $0))

export PYTHONPATH=.:..
export CONFIG="$(mktemp)"

logfile="$(mktemp)"

cat > "$CONFIG" <<'EOF'
[serles]
database = sqlite:///:memory:
backend = tests.MockBackend:Backend
allowedServerIpRanges =
	::1/128
	127.0.0.1/32
excludeServerIpRanges = 127.0.0.2/32
verifyPTR = false
subjectNameTemplate = CN={SAN[0]}
EOF

python3 -m serles >>$logfile 2>>$logfile &
#python3 -c 'import serles; serles.create_app().run(host="::0", port=8443, ssl_context="adhoc")' >>$logfile 2>>$logfile &
acme=$!
sleep 1 # wait for flask to get ready

mkdir -p /tmp/well-known/.well-known/acme-challenge
( cd /tmp/well-known && python3 -m http.server 80 >>$logfile 2>>$logfile; ) &
httpd=$!

accountkey=/tmp/privkey.pem  #misusing privkey for this
csr=/tmp/acmetest.csr
openssl req -newkey rsa:2048 -keyout $accountkey -out $csr -nodes -subj "/CN=example.test" >>$logfile 2>>$logfile

export http_proxy=
export https_proxy=
python3 ./acme_tiny.py \
        --directory-url https://localhost:8443/directory \
        --acme-dir /tmp/well-known/.well-known/acme-challenge/ \
        --account-key $accountkey \
        --csr $csr  2>>$logfile |
	grep -v '^$' |
	diff -s - good.pemchain >>$logfile 2>>$logfile

if test "$?" -eq 0; then
	echo "test passed."
else
	echo "test failed."
	echo
	cat $logfile
fi

kill $httpd $acme 2>/dev/null

rm -f "$CONFIG" $accountkey $csr
