import datetime
import ipaddress
import unittest
from unittest.mock import Mock
import os, sys
import serles.utils as main
from serles import UTCDateTime

import dns.resolver


def mockedDNSResolve(qname, rdtype, search=False):
    rsp = {"localhost.": "127.0.0.1", "1.0.0.127.in-addr.arpa.": "localhost."}.get(
        str(qname)
    )
    if not rsp:
        raise dns.resolver.NXDOMAIN
    return [rsp]


class MockDNS1x:
    query = mockedDNSResolve


class HelperFunctionTester(unittest.TestCase):
    def test_base64d(self):
        result = main.base64d("Pz8_Pw")
        self.assertEqual(result, b"????")

    def test_query_and_ptr(self):
        with unittest.mock.patch.object(
            dns.resolver, "query", mockedDNSResolve
        ), unittest.mock.patch.object(dns.resolver, "resolve", mockedDNSResolve):
            fqdn = "localhost."
            ipaddr = str(main.query(fqdn, "A")[0])
            result = main.get_ptr(ipaddr)
            self.assertEqual(result, fqdn)
            self.assertEqual(main.query("example.invalid", "A"), [])

    def test_force_dnspython1x(self):
        with unittest.mock.patch.object(dns, "resolver", MockDNS1x):
            fqdn = "localhost."
            main.query(fqdn, "A")

    def test_ip_in_range(self):
        ranges = [ipaddress.ip_network("10.1.0.0/24")]
        self.assertTrue(main.ip_in_ranges("10.1.0.1", ranges))
        self.assertFalse(main.ip_in_ranges("10.2.0.1", ranges))

    def test_normalize(self):
        result = main.normalize("LOCALHOST.")
        self.assertEqual(result, "localhost")
        self.assertIsNone(main.normalize(None))

    def test_utcclass(self):
        udt = UTCDateTime()
        val = datetime.datetime.now()
        result1 = udt.process_bind_param(val, None)
        result2 = udt.process_result_value(val, None)
        self.assertEqual(result1.tzinfo, datetime.timezone.utc)
        self.assertEqual(result2.tzinfo, datetime.timezone.utc)

    def test_backgroundjob(self):
        mockTimer = Mock()
        mockTimer.setDaemon = lambda x: None
        mockTimer.start = lambda: None
        with unittest.mock.patch.object(main, "Timer", mockTimer):

            @main.background_job(1)
            def _test():
                return

            self.assertTrue(mockTimer.called)

    def test_berparser(self):
        # test non-OCTET_STRING value
        self.assertRaises(TypeError, main.ber_parse, b"\x00")

        # test with zero length
        self.assertRaises(ValueError, main.ber_parse, b"\x04\x00foo")

        # test with too short length
        self.assertRaises(ValueError, main.ber_parse, b"\x04\x01foo")

        # test with too long length
        self.assertRaises(ValueError, main.ber_parse, b"\x04\x04foo")

        # test with indeterminate length
        self.assertEqual(b"foo", main.ber_parse(b"\x04\x80foo"))

        # test with 1 byte length
        self.assertEqual(b"foo", main.ber_parse(b"\x04\x03foo"))

        # test with multi byte length
        self.assertEqual(b"foo", main.ber_parse(b"\x04\x81\x03foo"))

        # test zero length string with 1 byte length
        self.assertEqual(b"", main.ber_parse(b"\x04\x00"))

        # test zero length string with multi byte length
        self.assertEqual(b"", main.ber_parse(b"\x04\x81\x00"))
