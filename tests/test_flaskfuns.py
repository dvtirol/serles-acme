import json
from werkzeug.exceptions import Forbidden
from werkzeug.datastructures import Headers
import flask
import unittest
from unittest.mock import Mock
import os, sys
import serles as main
import serles.flask_handlers as handlers
import base64
import jwcrypto.jwk, jwcrypto.jws, jwcrypto.common
import datetime

# from acme_tiny.py (0a9afb2)
# acme_tiny.py is Copyright 2015 Daniel Roesler and licensed under the MIT/X11 license. see https://raw.githubusercontent.com/diafygi/acme-tiny/master/LICENSE
def sign_json(nonce, url, account_key, payload):
    import base64, json, subprocess, re, binascii

    _b64 = lambda b: base64.urlsafe_b64encode(b).decode("utf8").replace("=", "")
    # parse account key:
    proc = subprocess.Popen(
        ["openssl", "rsa", "-in", account_key, "-noout", "-text"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = proc.communicate(None)
    pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(
        pub_pattern, out.decode("utf8"), re.MULTILINE | re.DOTALL
    ).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    jwk = {
        "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
        "kty": "RSA",
        "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
    }

    # _send_signed_request():
    payload64 = "" if payload is None else _b64(json.dumps(payload).encode("utf8"))
    protected = {"url": url, "alg": "RS256"}
    if nonce:
        protected.update({"nonce": nonce})
    protected.update({"jwk": jwk})
    protected64 = _b64(json.dumps(protected).encode("utf8"))
    protected_input = "{0}.{1}".format(protected64, payload64).encode("utf8")
    proc = subprocess.Popen(
        ["openssl", "dgst", "-sha256", "-sign", account_key],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = proc.communicate(protected_input)
    data = json.dumps(
        {"protected": protected64, "payload": payload64, "signature": _b64(out)}
    )
    return data


# endfrom


class FlaskFunctionTester(unittest.TestCase):
    def test_exception_handler_acmeexception(self):
        error = main.ACMEError("foo", 400, "bar")
        app = flask.Flask(__name__)
        with app.app_context():
            result = main.exception_handler(error)
        self.assertIsInstance(result, flask.Response)
        self.assertEqual(result.status_code, 400)
        result = json.loads(result.data)
        self.assertEqual(
            result, {"detail": "foo", "type": "urn:ietf:params:acme:error:bar"}
        )

    def test_exception_handler_httperror(self):
        error = Forbidden("baz")
        app = flask.Flask(__name__)
        with app.app_context():
            result = main.exception_handler(error)
        self.assertIsInstance(result, flask.Response)
        self.assertEqual(result.status_code, 403)
        result = json.loads(result.data)
        self.assertEqual(
            result, {"detail": "baz", "type": "urn:ietf:params:acme:error:malformed"}
        )

    def test_exception_handler_exception(self):
        error = Exception("qux")
        app = flask.Flask(__name__)
        with app.app_context():
            result = main.exception_handler(error)
        self.assertIsInstance(result, flask.Response)
        self.assertEqual(result.status_code, 500)
        result = json.loads(result.data)
        self.assertEqual(
            result,
            {"detail": "qux", "type": "urn:ietf:params:acme:error:serverInternal"},
        )

    def test_index_header(self):
        mock_response = Mock()
        mock_response.headers = Headers()
        with unittest.mock.patch.object(main.api, "url_for", lambda *x, **y: "/"):
            result = main.index_header(mock_response)
            self.assertIsNotNone(result.headers.get("Link"))

    def test_inject_nonce(self):
        mock_response = Mock()
        mock_response.headers = Headers()
        with unittest.mock.patch.object(main.Nonces, "new", lambda: "foo"):
            result = main.inject_nonce(mock_response)
            self.assertIsNotNone(result.headers.get("Replay-Nonce"))

    def test_parse_jws_get(self):
        app = flask.Flask(__name__)
        with app.test_request_context(method="GET"):
            main.parse_jws()  # should do nothing

    def test_parse_jws_mimetype(self):
        app = flask.Flask(__name__)
        with app.test_request_context(
            json={}, mimetype="application/json", method="POST"
        ):
            self.assertRaisesRegex(
                main.ACMEError, r"expected application/jose\+json", main.parse_jws
            )

    def test_parse_jws_noprotect(self):
        app = flask.Flask(__name__)
        key = jwcrypto.jwk.JWK.generate(kty="oct", size=256).export()
        with app.test_request_context(
            json={}, mimetype="application/jose+json", method="POST"
        ):
            self.assertRaisesRegex(
                main.ACMEError, r"no 'protected' field in request", main.parse_jws
            )

    def test_parse_jws_nokey(self):
        app = flask.Flask(__name__)
        key = jwcrypto.jwk.JWK.generate(kty="oct", size=256).export()
        with app.test_request_context(
            json={"protected": "e30="}, mimetype="application/jose+json", method="POST"
        ):
            self.assertRaisesRegex(
                main.ACMEError, r"no public key or key id", main.parse_jws
            )

    def test_parse_jws_kid_nonexisting(self):
        app = flask.Flask(__name__)
        key = jwcrypto.jwk.JWK.generate(kty="oct", size=256)
        with app.test_request_context(
            json={
                "protected": base64.urlsafe_b64encode(
                    json.dumps({"kid": "fakekeyid"}).encode()
                ).decode(),
                "payload": "Zm9v",  # "foo".b64e
                "signature": "",
            },
            mimetype="application/jose+json",
            method="POST",
        ):
            mockedAccountTbl = Mock()
            mockedAccountTbl.query.filter_by = lambda id: Mock(first=lambda: None)
            with unittest.mock.patch.object(handlers, "Account", mockedAccountTbl):
                self.assertRaisesRegex(
                    main.ACMEError, r"unknown key id", main.parse_jws
                )

    def test_parse_jws_kid(self):
        app = flask.Flask(__name__)
        key = jwcrypto.jwk.JWK.generate(kty="oct", size=256)
        with app.test_request_context(
            json={
                "protected": base64.urlsafe_b64encode(
                    json.dumps({"kid": "fakekeyid"}).encode()
                ).decode(),
                "payload": "Zm9v",  # "foo".b64e
                "signature": "",
            },
            mimetype="application/jose+json",
            method="POST",
        ):
            mockedAccountTbl = Mock()
            mockedAccountTbl.query.filter_by = lambda id: Mock(
                first=lambda: Mock(jwk=open("data_privkey.pem", "rb").read())
            )
            with unittest.mock.patch.object(handlers, "Account", mockedAccountTbl):
                self.assertRaisesRegex(
                    main.ACMEError, r"signed with invalid or wrong key", main.parse_jws
                )

    def test_parse_jws_nosig(self):
        app = flask.Flask(__name__)
        key = jwcrypto.jwk.JWK.generate(kty="oct", size=256)
        with app.test_request_context(
            json={
                "protected": base64.urlsafe_b64encode(
                    json.dumps({"jwk": json.loads(key.export())}).encode()
                ).decode(),
                "payload": "Zm9v",  # "foo".b64e
                "signature": "",
            },
            mimetype="application/jose+json",
            method="POST",
        ):
            self.assertRaisesRegex(
                main.ACMEError, r"signed with invalid or wrong key", main.parse_jws
            )

    def test_parse_jws_nononce(self):
        app = flask.Flask(__name__)
        key = jwcrypto.jwk.JWK.generate(kty="oct", size=256)
        with app.test_request_context(
            json=json.loads(
                sign_json(
                    nonce=None, url="", account_key="data_privkey.pem", payload="foo"
                )
            ),
            mimetype="application/jose+json",
            method="POST",
        ):
            self.assertRaisesRegex(main.ACMEError, r"nonce invalid", main.parse_jws)

    def test_parse_jws_nourl(self):
        app = flask.Flask(__name__)
        key = jwcrypto.jwk.JWK.generate(kty="oct", size=256)
        with app.test_request_context(
            json=json.loads(
                sign_json(
                    nonce="x", url="", account_key="data_privkey.pem", payload="foo"
                )
            ),
            mimetype="application/jose+json",
            method="POST",
        ), unittest.mock.patch.object(main.Nonces, "check", lambda x: True):
            self.assertRaisesRegex(main.ACMEError, r"url doesn't match", main.parse_jws)

    def test_parse_jws_good(self):
        app = flask.Flask(__name__)
        key = jwcrypto.jwk.JWK.generate(kty="oct", size=256)
        with app.test_request_context(
            json=json.loads(
                sign_json(
                    nonce="x",
                    url="http://localhost/",
                    account_key="data_privkey.pem",
                    payload="foo",
                )
            ),
            mimetype="application/jose+json",
            method="POST",
        ), unittest.mock.patch.object(main.Nonces, "check", lambda x: True):
            main.parse_jws()
            self.assertEqual(flask.g.payload, "foo")

    def test_nonces(self):
        app = flask.Flask(__name__)
        app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        main.db.init_app(app)
        with app.app_context():
            main.db.create_all()
            nonce1 = main.Nonces.new()
            nonce2 = main.Nonces.new()
            self.assertNotEqual(nonce1, nonce2)

            self.assertTrue(main.Nonces.check(nonce1))
            self.assertFalse(main.Nonces.check(nonce1))  # double use forbidden

            # force-expire nonce2:
            main.Nonces.query.filter(
                main.Nonces.value == nonce2
            ).first().expires = datetime.datetime.now(datetime.timezone.utc)
            main.db.session.commit()
            main.Nonces.purge_expired()
            self.assertFalse(main.Nonces.check(nonce2))
