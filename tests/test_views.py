import flask
import unittest
from unittest.mock import Mock
import jwcrypto.jwk
import json
import base64

import serles as main


class ViewTester(unittest.TestCase):
    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.config["PROPAGATE_EXCEPTIONS"] = True
        self.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        self.app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        main.api.init_app(self.app)
        main.db.init_app(self.app)
        with self.app.app_context():
            main.db.create_all()
        self.app.register_error_handler(Exception, main.exception_handler)

        self.payload = {}
        self.kid = "foo"
        self.jwk = json.loads(jwcrypto.jwk.JWK.generate(kty="RSA", size=2048).export())

        @self.app.before_request
        def parse_jws():
            from flask import g

            g.kid = self.kid
            g.jwk = self.jwk
            g.payload = self.payload

    def test_landing(self):
        c = self.app.test_client()
        r = c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, b'"Serles ACME Server is running."\n')

    def test_directory(self):
        c = self.app.test_client()
        r = c.get("/directory")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json["newNonce"], "http://localhost/newNonce")
        self.assertEqual(r.json["newAccount"], "http://localhost/newAccount")
        self.assertEqual(r.json["newOrder"], "http://localhost/newOrder")

    def test_nonce(self):
        c = self.app.test_client()
        r = c.get("/newNonce")
        self.assertEqual(r.status_code, 204)
        self.assertNotEqual(r.headers.get("Cache-Control"), None)
        r = c.head("/newNonce")
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r.headers.get("Cache-Control"), None)

    def test_newAccount_badmail(self):
        c = self.app.test_client()
        self.payload = {"contact": "nomailto@foo.test"}
        r = c.post("/newAccount")
        self.assertEqual(r.status_code, 400)

    def test_newAccount(self):
        c = self.app.test_client()
        # first, new key but onlyReturnExisting:
        self.payload = {"onlyReturnExisting": True}
        r = c.post("/newAccount")
        self.assertEqual(r.status_code, 400)
        # then, we run into nonexisting/new account key:
        self.payload = {}
        r = c.post("/newAccount")
        self.assertEqual(r.status_code, 201)
        # finally, we run into preexisting key:
        r = c.post("/newAccount")
        self.assertEqual(r.status_code, 200)

    def test_newOrder(self):
        c = self.app.test_client()
        # no identifiers:
        r = c.post("/newOrder")
        self.assertEqual(r.status_code, 400)
        # malformed:
        self.payload = {"identifiers": [{}]}
        r = c.post("/newOrder")
        self.assertEqual(r.status_code, 400)
        # non-dns identifier:
        self.payload = {"identifiers": [{"type": "foo", "value": "bar"}]}
        r = c.post("/newOrder")
        self.assertEqual(r.status_code, 400)
        # correct identifier, but no account:
        self.payload = {"identifiers": [{"type": "dns", "value": "example.test"}]}
        r = c.post("/newOrder")
        self.assertEqual(r.status_code, 400)
        # setup: create account
        r = c.post("/newAccount")
        _, _, account_id = r.headers.get("Location").rpartition("/")
        self.assertEqual(r.status_code, 201)
        # correct identifier and existing account:
        self.kid = account_id
        r = c.post("/newOrder")
        self.assertEqual(r.status_code, 201)
        order_url = r.headers.get("Location")
        self.assertEqual(order_url[:32], "http://localhost/order/urn:uuid:")
        # test order access
        r = c.post(order_url)
        self.assertEqual(r.status_code, 200)
        # test authz access
        r = c.post(r.json["authorizations"][0])
        self.assertEqual(r.status_code, 200)
        # test challenge access
        with unittest.mock.patch.object(
            main.challenge, "http_challenge", lambda x: (None, None)
        ):
            r = c.post(r.json["challenges"][0]["url"])
        self.assertEqual(r.status_code, 200)
        # test finalizing
        self.payload = {
            "csr": base64.b64encode(
                open("data_example.test.csr.bin", "rb").read()
            ).decode()
        }
        r = c.post(order_url + "/finalize")
        cert_url = r.json["certificate"]
        self.assertEqual(r.status_code, 200)
        # test cert dl
        r = c.post(cert_url)
        self.assertEqual(r.status_code, 200)
        # test cert 403
        self.kid = "whatever"
        r = c.post(cert_url)
        self.assertEqual(r.status_code, 403)

    def test_accountMain(self):
        c = self.app.test_client()
        # setup: create account
        self.payload = {"contact": ["mailto:foo@bar.baz"]}
        r = c.post("/newAccount")
        account_url = r.headers.get("Location")
        _, _, account_id = account_url.rpartition("/")
        self.assertEqual(r.status_code, 201)
        # nonexisting account
        self.kid = "foo"
        r = c.post("/account/foo")
        self.assertEqual(r.status_code, 400)
        # existing account, update email broken:
        self.kid = account_id
        self.payload = {"contact": ["foo@bar.baz"]}
        r = c.post("/account/" + account_id)
        self.assertEqual(r.status_code, 400)
        # existing account, update email ok:
        self.kid = account_id
        self.payload = {"contact": ["mailto:foo@bar.baz"]}
        r = c.post("/account/" + account_id)
        self.assertEqual(r.status_code, 200)
        # existing account, bad kid
        self.kid = "foo"
        r = c.post("/account/bar")
        self.assertEqual(r.status_code, 403)

    def test_notfound(self):
        c = self.app.test_client()
        # nonexisting order
        r = c.post("/order/foo")
        self.assertEqual(r.status_code, 404)
        # nonexisting authz
        r = c.post("/authorization/foo")
        self.assertEqual(r.status_code, 404)
        # nonexisting challenge
        r = c.post("/challenge/foo")
        self.assertEqual(r.status_code, 404)
        # nonexisting order/finalize
        self.payload = {
            "csr": base64.b64encode(
                open("data_example.test.csr.bin", "rb").read()
            ).decode()
        }
        r = c.post("/order/foo/finalize")
        self.assertEqual(r.status_code, 404)
        # nonexisting cert
        r = c.post("/cert/foo")
        self.assertEqual(r.status_code, 404)

    def test_order_badkey(self):
        c = self.app.test_client()
        # setup: create account
        r = c.post("/newAccount")
        _, _, account_id = r.headers.get("Location").rpartition("/")
        self.assertEqual(r.status_code, 201)
        # correct identifier and existing account:
        self.kid = account_id
        self.payload = {"identifiers": [{"type": "dns", "value": "example.test"}]}
        r = c.post("/newOrder")
        self.assertEqual(r.status_code, 201)
        order_url = r.headers.get("Location")
        self.assertEqual(order_url[:32], "http://localhost/order/urn:uuid:")
        # test order access
        order = c.post(order_url)
        self.assertEqual(order.status_code, 200)
        authz = c.post(order.json["authorizations"][0])
        self.assertEqual(authz.status_code, 200)
        # wrong account key
        self.kid = "foo"
        r = c.post(order_url)
        self.assertEqual(r.status_code, 403)
        # test authz access
        r = c.post(order.json["authorizations"][0])
        self.assertEqual(r.status_code, 403)
        # test challenge access
        with unittest.mock.patch.object(
            main.challenge, "http_challenge", lambda x: (None, None)
        ):
            r = c.post(authz.json["challenges"][0]["url"])
        self.assertEqual(r.status_code, 403)

    def test_ordernotready(self):
        c = self.app.test_client()
        with self.app.app_context():
            mock_order = Mock()
            mock_order.status = "x"
            mock_order.account_id = "foo"
            mock_order_q = Mock()
            mock_order_q.filter_by = lambda id: Mock(first=lambda: mock_order)
            with unittest.mock.patch.object(main.Order, "query", mock_order_q):
                # with unittest.mock.patch.object(main.Order.query, 'filter_by', lambda id: Mock(first=lambda: Mock(status=main.OrderStatus.pending))):
                self.payload = {"csr": base64.b64encode(b"foo").decode()}
                self.kid = "foo"
                r = c.post("/order/foo/finalize")
                self.assertEqual(r.status_code, 403)
                self.assertEqual(r.json["type"], "urn:ietf:params:acme:error:orderNotReady")
            with unittest.mock.patch.object(main.Order, "query", mock_order_q):
                # with unittest.mock.patch.object(main.Order.query, 'filter_by', lambda id: Mock(first=lambda: Mock(status=main.OrderStatus.pending))):
                self.payload = {"csr": base64.b64encode(b"foo").decode()}
                self.kid = "bar"
                r = c.post("/order/foo/finalize")
                self.assertEqual(r.status_code, 403)
                self.assertEqual(r.json["type"], "urn:ietf:params:acme:error:unauthorized")

    def test_notimplemented(self):
        c = self.app.test_client()
        with self.app.app_context():
            r = c.post("/newAuthz")
            self.assertEqual(r.status_code, 403)
            self.assertEqual(r.json["type"], "urn:ietf:params:acme:error:unauthorized")
            r = c.post("/revokeCert")
            self.assertEqual(r.status_code, 403)
            self.assertEqual(r.json["type"], "urn:ietf:params:acme:error:unauthorized")
            r = c.post("/keyChange")
            self.assertEqual(r.status_code, 403)
            self.assertEqual(r.json["type"], "urn:ietf:params:acme:error:unauthorized")
