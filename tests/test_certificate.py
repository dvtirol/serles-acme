import os
import unittest
from unittest.mock import Mock

import serles.certificate as main
from serles.models import Identifier, IdentifierTypes
import MockBackend


example_inval = Identifier(value="example.inval", type=IdentifierTypes.dns)
example_test = Identifier(value="example.test", type=IdentifierTypes.dns)
example_ip = Identifier(value="2001:DB8::1", type=IdentifierTypes.ip)


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
            "allowIpIdentifiers": False,
        }
        os.chdir(os.path.dirname(__file__))

    def test_check_csr_and_return_cert(self):
        csr_input = open("data_example.test.csr.bin", "rb").read()
        mock_order = Mock()
        mock_order.account.contact = None

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

    def test_check_csr_and_return_cert_ipcn(self):
        csr_input = open("data_csr_ipcn.der", "rb").read()
        mock_order = Mock()
        mock_order.account.contact = None
        mock_order.identifiers = [example_ip]

        result = main.check_csr_and_return_cert(csr_input, mock_order)
        good = open("data_pkcs7.bin", "rb").read()
        self.assertEqual(result, good)

    def test_check_csr_and_return_cert_nocnorsan(self):
        csr_input = open("data_csr_empty.der", "rb").read()
        mock_order = Mock()
        mock_order.account.contact = None

        mock_order.identifiers = []
        self.assertRaisesRegex(
            main.ACMEError,
            r"no identifiers in CSR",
            main.check_csr_and_return_cert,
            csr_input,
            mock_order,
        )
