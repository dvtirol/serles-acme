import os
import ipaddress
import requests
import datetime
import unittest
from unittest.mock import Mock
import mock
import pytest

import serles.challenge as main
import MockBackend
import dns.resolver


class MockedRequestsSession:
    def get(self, *args, **kwargs):
        mock_response = Mock()
        mock_response.raw.connection.sock.getpeername = lambda: ("", "")
        mock_response.text = "token.i9Qes9RMOIbciQjAy6pzYwcZw8IKjKxPP7UZ8fTetps"
        return mock_response


class MockedRequestsSessionPeerNameFallback:
    def get(self, *args, **kwargs):
        mock_response = Mock()
        mock_response.raw.connection.sock = None
        mock_response.text = "token.i9Qes9RMOIbciQjAy6pzYwcZw8IKjKxPP7UZ8fTetps"
        return mock_response


class MockedRequestsErrorSession:
    def get(self, *args, **kwargs):
        raise requests.ConnectionError()


class MockedRequestsResponseSession:
    def get(self, *args, **kwargs):
        mock_response = Mock()
        mock_response.raw.connection.sock.getpeername = lambda: ("10.0.0.1", "")
        mock_response.text = "something wrong"
        return mock_response


def mockedDNSResolve(qname, rdtype, search=False):
    rsp = {"1.0.0.10.in-addr.arpa.": "localhost."}.get(str(qname))
    if not rsp:
        raise dns.resolver.NXDOMAIN
    return [rsp]


# a challenge object, mocked just enought to pass the tests:
mock_authz = Mock(status=main.AuthzStatus.valid)
mock_challenge = Mock()
mock_challenge.authorization.identifier.value = "example.test"
mock_challenge.type = main.ChallengeTypes.http_01
mock_challenge.token = "token"
mock_challenge.authorization.expires = datetime.datetime.now(
    datetime.timezone.utc
) + datetime.timedelta(days=7)
mock_challenge.authorization.order.authorizations = [mock_authz]
mock_challenge.authorization.order.account.jwk = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl939KlZLTx1IXb6oAgNq
Fs/c0t17Gc834+pa/GdVDIkdsbObatNs4l6Qf7lhizANi0JCxID/copS+ZbeTIW5
/xJaWZ+Uw0dHzR4yC+28CaHv2MqHKZgAtFx9wFOavfiP89Sw63HpZxJI+EoAcdP+
LkroZ2tX47S0hyyzDEO/9h4lIA+LCEfjsNPIkuXCAEYrv+bT+L1ztjIlmAwoR0sP
pCslDx9PB3F55+fBaM6gtxEpJsgG14z7od65EZwDTzoFg4dKURTkTJZ7ZnwMe+zY
nB7cAzUtoA06AJ1DZTP74LcOaMj/rQhs5qLelTb6HwLR3At5ilHkP3K+XddUK/y2
BwIDAQAB
-----END PUBLIC KEY-----"""

orig_db = main.db


class ChallengeFunctionTester(unittest.TestCase):
    def setUp(self):
        main.backend = MockBackend.Backend([])
        main.config = {
            "allowedServerIpRanges": None,
            "excludeServerIpRanges": None,
            "verifyPTR": False,
            "forceTemplateDN": True,
            "subjectNameTemplate": "{SAN[0]}",
        }
        main.db = Mock()  # don't commit into the nonexisting database
        os.chdir(os.path.dirname(__file__))

    def tearDown(self):
        main.db = orig_db

    def test_verify_challenge_ok(self):
        with unittest.mock.patch.object(main, "http_challenge", lambda x: (None, None)):
            main.verify_challenge(mock_challenge)
            self.assertEqual(
                mock_challenge.authorization.order.status, main.OrderStatus.ready
            )

    def test_verify_challenge_err(self):
        with unittest.mock.patch.object(
            main, "http_challenge", lambda x: ("foo", "bar")
        ):
            self.assertRaisesRegex(
                main.ACMEError, "bar", main.verify_challenge, mock_challenge
            )

    def test_verify_challenge_expired(self):
        with unittest.mock.patch.object(
            mock_challenge.authorization,
            "expires",
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7),
        ):
            self.assertRaisesRegex(
                main.ACMEError,
                "challenge expired",
                main.verify_challenge,
                mock_challenge,
            )

    def test_verify_challenge_invalid(self):
        with unittest.mock.patch.object(
            main.requests, "Session", MockedRequestsSession
        ):
            old_authz = mock_challenge.authorization.order.authorizations
            mock_challenge.authorization.order.authorizations = [
                Mock(status=main.AuthzStatus.invalid)
            ]
            main.verify_challenge(mock_challenge)
            self.assertEqual(
                mock_challenge.authorization.order.status, main.OrderStatus.invalid
            )
            mock_challenge.authorization.order.authorizations = old_authz

    def test_verify_challenge_unsupported(self):
        with unittest.mock.patch.object(
            mock_challenge, "type", main.ChallengeTypes.dns_01
        ):
            self.assertRaisesRegex(
                main.ACMEError,
                "challenge type not supported",
                main.verify_challenge,
                mock_challenge,
            )

    def test_http_challenge(self):
        with unittest.mock.patch.object(
            main.requests, "Session", MockedRequestsSession
        ):
            result = main.http_challenge(mock_challenge)
            self.assertEqual(result, (None, None))

    def test_http_challenge_connection(self):
        with unittest.mock.patch.object(
            main.requests, "Session", MockedRequestsErrorSession
        ):
            result = main.http_challenge(mock_challenge)
            self.assertEqual(result[0], "connection")

    def test_http_challenge_response(self):
        with unittest.mock.patch.object(
            main.requests, "Session", MockedRequestsResponseSession
        ):
            result = main.http_challenge(mock_challenge)
            self.assertEqual(result[0], "incorrectResponse")

    def test_http_challenge_peername1(self):
        with unittest.mock.patch.object(
            main.requests, "Session", MockedRequestsResponseSession
        ), unittest.mock.patch.dict(
            main.config, {"allowedServerIpRanges": [ipaddress.ip_network("::1/128")]}
        ):
            result = main.http_challenge(mock_challenge)
            self.assertEqual(result[0], "rejectedIdentifier")

    def test_http_challenge_peername2(self):
        with unittest.mock.patch.object(
            main.requests, "Session", MockedRequestsResponseSession
        ), unittest.mock.patch.dict(
            main.config, {"excludeServerIpRanges": [ipaddress.ip_network("10.0.0.0/8")]}
        ):
            result = main.http_challenge(mock_challenge)
            self.assertEqual(result[0], "rejectedIdentifier")

    def test_http_challenge_peername3(self):
        with unittest.mock.patch.object(
            main.requests, "Session", MockedRequestsSessionPeerNameFallback
        ), unittest.mock.patch.object(
            main.socket, "fromfd", lambda a, b, c: Mock(getpeername=lambda: ("1::2", 0))
        ), unittest.mock.patch.dict(
            main.config, {"allowedServerIpRanges": [ipaddress.ip_network("::1/128")]}
        ):
            result = main.http_challenge(mock_challenge)
            self.assertEqual(result[0], "rejectedIdentifier")

    def test_http_challenge_ptr(self):
        with unittest.mock.patch.object(
            main.requests, "Session", MockedRequestsResponseSession
        ), unittest.mock.patch.dict(
            main.config, {"verifyPTR": True}
        ), unittest.mock.patch.object(
            dns.resolver, "query", mockedDNSResolve
        ), unittest.mock.patch.object(
            dns.resolver, "resolve", mockedDNSResolve
        ):
            result = main.http_challenge(mock_challenge)
            self.assertEqual(result[0], "rejectedIdentifier")

    def test_check_csr_and_return_cert(self):
        csr_input = open("data_example.test.csr.bin", "rb").read()
        mock_order = Mock()
        mock_order.account.contact = None
        example_inval = Mock()
        example_inval.value = "example.inval"
        example_test = Mock()
        example_test.value = "example.test"

        # additional identifiers in CSR:
        mock_order.identifiers = []
        self.assertRaisesRegex(
            main.ACMEError,
            r"set\(\)",
            main.check_csr_and_return_cert,
            csr_input,
            mock_order,
        )
        # identifiers missing in CSR:
        mock_order.identifiers = [example_inval, example_test]
        self.assertRaisesRegex(
            main.ACMEError,
            "example.inval",
            main.check_csr_and_return_cert,
            csr_input,
            mock_order,
        )
        mock_order.identifiers = [example_test]

        result = main.check_csr_and_return_cert(csr_input, mock_order)
        good = open("data_pkcs7.bin", "rb").read()
        self.assertEqual(result, good)

        with unittest.mock.patch.object(
            main.backend, "sign", lambda *x: ("a string, not bytes", None)
        ):
            result = main.check_csr_and_return_cert(csr_input, mock_order)
            self.assertEqual(result, b"a string, not bytes") # utf-8-encoded bytes

        with unittest.mock.patch.object(
            main.backend, "sign", lambda *x: (None, "error")
        ):
            self.assertRaisesRegex(
                main.ACMEError,
                "error",
                main.check_csr_and_return_cert,
                csr_input,
                mock_order,
            )

    def test_check_csr_and_return_cert_nocn(self):
        csr_input = open("data_nocn.csr", "rb").read()
        mock_order = Mock()
        mock_order.account.contact = None
        example_inval = Mock()
        example_inval.value = "example.inval"
        example_test = Mock()
        example_test.value = "example.test"

        # additional identifiers in CSR:
        mock_order.identifiers = []
        self.assertRaisesRegex(
            main.ACMEError,
            r"set\(\)",
            main.check_csr_and_return_cert,
            csr_input,
            mock_order,
        )
        # identifiers missing in CSR:
        mock_order.identifiers = [example_inval, example_test]
        self.assertRaisesRegex(
            main.ACMEError,
            "example.inval",
            main.check_csr_and_return_cert,
            csr_input,
            mock_order,
        )
        mock_order.identifiers = [example_test]

        result = main.check_csr_and_return_cert(csr_input, mock_order)
        good = open("data_pkcs7.bin", "rb").read()
        self.assertEqual(result, good)

        with unittest.mock.patch.object(
            main.backend, "sign", lambda *x: (None, "error")
        ):
            self.assertRaisesRegex(
                main.ACMEError,
                "error",
                main.check_csr_and_return_cert,
                csr_input,
                mock_order,
            )
