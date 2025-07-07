import os
import ipaddress
import requests
import datetime
import unittest
from unittest.mock import Mock
from unittest.mock import MagicMock
from unittest.mock import PropertyMock
import pytest
from copy import deepcopy

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


class MockedRequestAbortedChunk:
    def get(self, *args, **kwargs):
        mock_response = Mock()
        mock_response.raw.connection.sock.getpeername = lambda: ("", "")
        type(mock_response).text = PropertyMock(
            side_effect=requests.exceptions.ChunkedEncodingError
        )
        return mock_response


class MockedRequestsResponseSession:
    def get(self, *args, **kwargs):
        mock_response = Mock()
        host = args[0].split("/")[2]
        peer = {
            "example.test": "10.0.0.1",
            "example.invalid": "10.0.0.2",
        }
        mock_response.raw.connection.sock.getpeername = lambda: (peer[host], "")
        mock_response.text = "something wrong"
        return mock_response


class MockedSocket:
    def __init__(self, host):
        ...

    def __enter__(self):
        return self

    def __exit__(self, a, b, c):
        ...


class MockedSocketBadConnection(MockedSocket):
    def __enter__(self):
        raise ConnectionError("oops")


class MockedSSLContext:
    def wrap_socket(self, sock, server_hostname):
        return self

    def __enter__(self):
        return self

    def __exit__(self, a, b, c):
        ...

    def set_alpn_protocols(self, protos):
        assert protos == ["acme-tls/1"]

    # inside wrapped_socket context:
    def getpeername(self):
        return (None,)

    def getpeercert(self, binary_form):
        return open("data_alpn_cert.der", "rb").read()

    def version(self):
        return "TLSv1.2"

    def selected_alpn_protocol(self):
        return "acme-tls/1"


class MockedSSLContextBadTLS(MockedSSLContext):
    def version(self):
        return "TLSv1.1"


class MockedSSLContextBadALPN(MockedSSLContext):
    def selected_alpn_protocol(self):
        return "h2"


class MockedSSLContextBadCert(MockedSSLContext):
    def getpeercert(self, binary_form):
        return open("data_alpn_cert_bad.der", "rb").read()


def mockedDNSResolve(qname, rdtype, search=False):
    rsp = {"1.0.0.10.in-addr.arpa.": "localhost."}.get(str(qname))
    if not rsp:
        raise dns.resolver.NXDOMAIN
    return [rsp]

def MockedDNSResolveTXT(qname, rdtype, search=False):
    if "Answer" in qname:
        raise dns.resolver.NoAnswer
    elif "NXDOMAIN" in qname:
        raise dns.resolver.NXDOMAIN
    elif "NoNameservers" in qname:
        raise dns.resolver.NoNameservers
    elif "YXDOMAIN" in qname:
        raise dns.resolver.YXDOMAIN
    elif "LifetimeTimeout" in qname:
        raise dns.resolver.LifetimeTimeout
    elif "empty.example.test" in qname:
        response = MagicMock()
        response.strings = [b""]
        return [response]
    elif "multiple.example.test" in qname:
        response0 = MagicMock()
        response0.strings = [b"Ohter record"]
        response1 = MagicMock()
        response1.strings = [b"jakqACx_UydeDJUABUWWv40pxm0c1qFM-yGWatF09qw", b"nulled record"]
        response2 = MagicMock()
        response2.strings = [b"unused record"]
        return [response0,response1,response2]
    elif "bad.example.test" in qname:
        response = MagicMock()
        response.strings = [b"bad challenge response"]
        return [response]
    else:
        response = MagicMock()
        response.strings = [b"jakqACx_UydeDJUABUWWv40pxm0c1qFM-yGWatF09qw"]
        return [response]


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

mock_dns_challenge = deepcopy(mock_challenge)
mock_dns_challenge.type = main.ChallengeTypes.dns_01
mock_dns_challenge.authorization.wildcard = None
mock_dns_challenge.token = "Y04KQ2An8anfd4de3Cmbt0296uo4nbSdpKcx0sD29D8"  # .jVHQIxagaHz0ubj_zvLAyJsuvO-njTCIUxDiiV3Kxxg
mock_dns_challenge.authorization.order.account.jwk = b"""-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAqMgO7lNTAsB1FV6vwAvH
jAuNRAcW3qOUx3MQhPu/K1C1l1d22qrlDOz/kN8vgOP8pFNFgzMOBb9cxe6EzRzB
6jQavRTM2PRTsBCsc86oXJZQnA2YtAd+CpqJIWQA7mcC/6WCpCEr8/ABjHTJdByb
3p2frjlcgW7DP+lZGgX29oK9rZ/85McRO/CNiIpKgYOb/rtxR6AGO5U4V7YDgn/w
srZGzkNgZ7RzGnlcQ5QHSELZd+x7imLMrLd/m+6Fgi8lLpHWY9R80TPJcaCe2Bgt
UHHT6/jwIPodRfe5yhwuiQRtFbOOHrgg4x/a0d2Pzmp17ORtpzWyvemTiVi64kR8
q8XJ6esqCry0Zdzvn1ydnu1Io7R4OS6CIROjLx7EF6RfLt96lkZjrEzuIOryphM9
3mrRYu0F1EwlB5gPY/12Dh4PTkbyqJn45r5V+bXaeXAQVCOj9wYcEnuv+AVFinvT
DfhRQn/W5DAdM5PWQcCIrZn1Z4fKFZdl3Cm/PrRiRTmfAgMBAAE=
-----END PUBLIC KEY-----"""

mock_wildcard_challenge = deepcopy(mock_challenge)
mock_wildcard_challenge.type = main.ChallengeTypes.dns_01
mock_wildcard_challenge.token = "Y04KQ2An8anfd4de3Cmbt0296uo4nbSdpKcx0sD29D8"  # .jVHQIxagaHz0ubj_zvLAyJsuvO-njTCIUxDiiV3Kxxg
mock_wildcard_challenge.authorization.wildcard = True
mock_wildcard_challenge.authorization.order.account.jwk = b"""-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAqMgO7lNTAsB1FV6vwAvH
jAuNRAcW3qOUx3MQhPu/K1C1l1d22qrlDOz/kN8vgOP8pFNFgzMOBb9cxe6EzRzB
6jQavRTM2PRTsBCsc86oXJZQnA2YtAd+CpqJIWQA7mcC/6WCpCEr8/ABjHTJdByb
3p2frjlcgW7DP+lZGgX29oK9rZ/85McRO/CNiIpKgYOb/rtxR6AGO5U4V7YDgn/w
srZGzkNgZ7RzGnlcQ5QHSELZd+x7imLMrLd/m+6Fgi8lLpHWY9R80TPJcaCe2Bgt
UHHT6/jwIPodRfe5yhwuiQRtFbOOHrgg4x/a0d2Pzmp17ORtpzWyvemTiVi64kR8
q8XJ6esqCry0Zdzvn1ydnu1Io7R4OS6CIROjLx7EF6RfLt96lkZjrEzuIOryphM9
3mrRYu0F1EwlB5gPY/12Dh4PTkbyqJn45r5V+bXaeXAQVCOj9wYcEnuv+AVFinvT
DfhRQn/W5DAdM5PWQcCIrZn1Z4fKFZdl3Cm/PrRiRTmfAgMBAAE=
-----END PUBLIC KEY-----"""

mock_alpn_challenge = deepcopy(mock_challenge)
mock_alpn_challenge.type = main.ChallengeTypes.tls_alpn_01
mock_alpn_challenge.token = "Y04KQ2An8anfd4de3Cmbt0296uo4nbSdpKcx0sD29D8"  # .jVHQIxagaHz0ubj_zvLAyJsuvO-njTCIUxDiiV3Kxxg
mock_alpn_challenge.authorization.order.account.jwk = b"""-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAqMgO7lNTAsB1FV6vwAvH
jAuNRAcW3qOUx3MQhPu/K1C1l1d22qrlDOz/kN8vgOP8pFNFgzMOBb9cxe6EzRzB
6jQavRTM2PRTsBCsc86oXJZQnA2YtAd+CpqJIWQA7mcC/6WCpCEr8/ABjHTJdByb
3p2frjlcgW7DP+lZGgX29oK9rZ/85McRO/CNiIpKgYOb/rtxR6AGO5U4V7YDgn/w
srZGzkNgZ7RzGnlcQ5QHSELZd+x7imLMrLd/m+6Fgi8lLpHWY9R80TPJcaCe2Bgt
UHHT6/jwIPodRfe5yhwuiQRtFbOOHrgg4x/a0d2Pzmp17ORtpzWyvemTiVi64kR8
q8XJ6esqCry0Zdzvn1ydnu1Io7R4OS6CIROjLx7EF6RfLt96lkZjrEzuIOryphM9
3mrRYu0F1EwlB5gPY/12Dh4PTkbyqJn45r5V+bXaeXAQVCOj9wYcEnuv+AVFinvT
DfhRQn/W5DAdM5PWQcCIrZn1Z4fKFZdl3Cm/PrRiRTmfAgMBAAE=
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
            "allowWildcards": False,
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

    def test_verify_challenge_dns_ok(self):
        with unittest.mock.patch.object(main, "dns_challenge", lambda x: (None, None)):
            main.verify_challenge(mock_dns_challenge)
            self.assertEqual(
                mock_dns_challenge.authorization.order.status, main.OrderStatus.ready
            )

    def test_verify_challenge_alpn_ok(self):
        with unittest.mock.patch.object(main, "alpn_challenge", lambda x: (None, None)):
            main.verify_challenge(mock_alpn_challenge)
            self.assertEqual(
                mock_alpn_challenge.authorization.order.status, main.OrderStatus.ready
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
            mock_challenge, "type", None
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

    def test_http_challenge_abortedchunked(self):
        with unittest.mock.patch.object(
            main.requests, "Session", MockedRequestAbortedChunk
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

    def test_http_challenge_ptr_nxdomain(self):
        with unittest.mock.patch.object(
            main.requests, "Session", MockedRequestsResponseSession
        ), unittest.mock.patch.dict(
            main.config, {"verifyPTR": True}
        ), unittest.mock.patch.object(
            dns.resolver, "query", mockedDNSResolve
        ), unittest.mock.patch.object(
            dns.resolver, "resolve", mockedDNSResolve
        ):
            mock_challenge.authorization.identifier.value = "example.invalid"
            result = main.http_challenge(mock_challenge)
            self.assertEqual(result[0], "rejectedIdentifier")

    # DNS challenge unit testing
    def test_dns_challenge_ok(self):
        mock_dns_challenge.authorization.identifier.value = "example.test"
        with unittest.mock.patch.object(
            dns.resolver, "query", MockedDNSResolveTXT
        ), unittest.mock.patch.object(
            dns.resolver, "resolve", MockedDNSResolveTXT
        ):
            result = main.dns_challenge(mock_dns_challenge)
            self.assertEqual(result, (None, None))

    def test_dns_challenge_wildcardforbidden(self):
        mock_wildcard_challenge.authorization.identifier.value = "*.example.test"
        with unittest.mock.patch.object(
            dns.resolver, "query", MockedDNSResolveTXT
        ), unittest.mock.patch.object(
            dns.resolver, "resolve", MockedDNSResolveTXT
        ):
            result = main.dns_challenge(mock_wildcard_challenge)
            self.assertEqual(result[0], "rejectedIdentifier")

    def test_dns_challenge_wildcardallowed(self):
        mock_wildcard_challenge.authorization.identifier.value = "*.example.test"
        with unittest.mock.patch.object(
            dns.resolver, "query", MockedDNSResolveTXT
        ), unittest.mock.patch.object(
            dns.resolver, "resolve", MockedDNSResolveTXT
        ):
            main.config['allowWildcards'] = True
            result = main.dns_challenge(mock_wildcard_challenge)
            self.assertEqual(result, (None, None))
            main.config['allowWildcards'] = False

    def test_dns_challenge_multiple_txt_ok(self):
        mock_dns_challenge.authorization.identifier.value = "multiple.example.test"
        with unittest.mock.patch.object(
            dns.resolver, "query", MockedDNSResolveTXT
        ), unittest.mock.patch.object(
            dns.resolver, "resolve", MockedDNSResolveTXT
        ):
            result = main.dns_challenge(mock_dns_challenge)
            self.assertEqual(result, (None, None))

    def test_dns_challenge_txt_empty(self):
        mock_dns_challenge.authorization.identifier.value = "empty.example.test"
        with unittest.mock.patch.object(
            dns.resolver, "query", MockedDNSResolveTXT
        ), unittest.mock.patch.object(
            dns.resolver, "resolve", MockedDNSResolveTXT
        ):
            result = main.dns_challenge(mock_dns_challenge)
            self.assertEqual(result[0], "incorrectResponse")

    def test_dns_challenge_bad_txt(self):
        mock_dns_challenge.authorization.identifier.value = "bad.example.test"
        with unittest.mock.patch.object(
            dns.resolver, "query", MockedDNSResolveTXT
        ), unittest.mock.patch.object(
            dns.resolver, "resolve", MockedDNSResolveTXT
        ):
            result = main.dns_challenge(mock_dns_challenge)
            self.assertEqual(result[0], "incorrectResponse")

    def test_dns_challenge_no_answer(self):
        mock_dns_challenge.authorization.identifier.value = "NoAnswer"
        with unittest.mock.patch.object(
            dns.resolver, "query", MockedDNSResolveTXT
        ), unittest.mock.patch.object(
            dns.resolver, "resolve", MockedDNSResolveTXT
        ):
            result = main.dns_challenge(mock_dns_challenge)
            self.assertEqual(result, ("dns", f"no TXT record found for _acme-challenge.NoAnswer"))

    def test_dns_challenge_nxdomain(self):
        mock_dns_challenge.authorization.identifier.value = "NXDOMAIN"
        with unittest.mock.patch.object(
            dns.resolver, "query", MockedDNSResolveTXT
        ), unittest.mock.patch.object(
            dns.resolver, "resolve", MockedDNSResolveTXT
        ):
            result = main.dns_challenge(mock_dns_challenge)
            self.assertEqual(result, ("dns", "no TXT record found for _acme-challenge.NXDOMAIN"))

    def test_dns_challenge_nonameservers(self):
        mock_dns_challenge.authorization.identifier.value = "NoNameservers"
        with unittest.mock.patch.object(
            dns.resolver, "query", MockedDNSResolveTXT
        ), unittest.mock.patch.object(
            dns.resolver, "resolve", MockedDNSResolveTXT
        ):
            result = main.dns_challenge(mock_dns_challenge)
            self.assertEqual(result[0], "dnsNoNameServers")

    def test_dns_challenge_querytoolong(self):
        mock_dns_challenge.authorization.identifier.value = "YXDOMAIN"
        with unittest.mock.patch.object(
            dns.resolver, "query", MockedDNSResolveTXT
        ), unittest.mock.patch.object(
            dns.resolver, "resolve", MockedDNSResolveTXT
        ):
            result = main.dns_challenge(mock_dns_challenge)
            self.assertEqual(result[0], "dnsQueryTooLong")

    def test_dns_challenge_timeout(self):
        mock_dns_challenge.authorization.identifier.value = "LifetimeTimeout"
        with unittest.mock.patch.object(
            dns.resolver, "query", MockedDNSResolveTXT
        ), unittest.mock.patch.object(
            dns.resolver, "resolve", MockedDNSResolveTXT
        ):
            result = main.dns_challenge(mock_dns_challenge)
            self.assertEqual(result[0], "dnsTimeout")

    # ALPN challenge unit testing
    def test_alpn_challenge_ok(self):
        with unittest.mock.patch.object(
            main.socket, "create_connection", MockedSocket
        ), unittest.mock.patch.object(main.ssl, "SSLContext", MockedSSLContext):
            result = main.alpn_challenge(mock_alpn_challenge)
            self.assertEqual(result, (None, None))

    def test_alpn_challenge_badsan(self):
        with unittest.mock.patch.object(
            main.socket, "create_connection", MockedSocket
        ), unittest.mock.patch.object(main.ssl, "SSLContext", MockedSSLContext):
            mock_challenge2 = deepcopy(mock_alpn_challenge)
            mock_challenge2.authorization.identifier.value = "example.invalid"
            result = main.alpn_challenge(mock_challenge2)
            self.assertEqual(
                result,
                (
                    "rejectedIdentifier",
                    "san is ['example.test'], expected ['example.invalid']",
                ),
            )

    def test_alpn_challenge_badtoken(self):
        with unittest.mock.patch.object(
            main.socket, "create_connection", MockedSocket
        ), unittest.mock.patch.object(main.ssl, "SSLContext", MockedSSLContext):
            mock_challenge2 = deepcopy(mock_alpn_challenge)
            mock_challenge2.token = "token"
            result = main.alpn_challenge(mock_challenge2)
            self.assertEqual(
                result, ("incorrectResponse", "key authorization hashes don't match")
            )

    def test_alpn_challenge_rejectspecial(self):
        with unittest.mock.patch.object(
            main.socket, "create_connection", MockedSocket
        ), unittest.mock.patch.object(
            main.ssl, "SSLContext", MockedSSLContext
        ), unittest.mock.patch.object(
            main, "additional_ip_address_checks", lambda _, __: "rejectMsg"
        ):
            result = main.alpn_challenge(mock_alpn_challenge)
            self.assertEqual(result, ("rejectedIdentifier", "rejectMsg"))

    def test_alpn_challenge_tlsversion(self):
        with unittest.mock.patch.object(
            main.socket, "create_connection", MockedSocket
        ), unittest.mock.patch.object(main.ssl, "SSLContext", MockedSSLContextBadTLS):
            result = main.alpn_challenge(mock_alpn_challenge)
            self.assertEqual(
                result, ("unauthorized", "could not negotiate TLS 1.2 or higher")
            )

    def test_alpn_challenge_alpnproto(self):
        with unittest.mock.patch.object(
            main.socket, "create_connection", MockedSocket
        ), unittest.mock.patch.object(main.ssl, "SSLContext", MockedSSLContextBadALPN):
            result = main.alpn_challenge(mock_alpn_challenge)
            self.assertEqual(
                result, ("unauthorized", "could not negotiate 'acme-tls/1'")
            )

    def test_alpn_challenge_noacmeextension(self):
        with unittest.mock.patch.object(
            main.socket, "create_connection", MockedSocket
        ), unittest.mock.patch.object(main.ssl, "SSLContext", MockedSSLContextBadCert):
            result = main.alpn_challenge(mock_alpn_challenge)
            self.assertEqual(
                result,
                ("unauthorized", "certificate does not have expected extensions"),
            )

    def test_alpn_challenge_socketerror(self):
        with unittest.mock.patch.object(
            main.socket, "create_connection", MockedSocketBadConnection
        ), unittest.mock.patch.object(main.ssl, "SSLContext", MockedSSLContext):
            result = main.alpn_challenge(mock_alpn_challenge)
            self.assertEqual(result, ("connection", "oops"))

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
            self.assertEqual(result, b"a string, not bytes")  # utf-8-encoded bytes

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
