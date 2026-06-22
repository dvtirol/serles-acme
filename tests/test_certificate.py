import os
import unittest
from unittest.mock import Mock

import serles.certificate as main
from serles.models import Identifier, IdentifierTypes
import MockBackend


example_inval = Identifier(value="example.inval", type=IdentifierTypes.dns)
example_test = Identifier(value="example.test", type=IdentifierTypes.dns)
example_ip = Identifier(value="2001:DB8::1", type=IdentifierTypes.ip)

def mock_config(sign_rv=None, cfg={}):
    def get_config():
        backend = MockBackend.Backend([])
        if sign_rv:
            backend.sign = lambda *_: sign_rv
        return {
            "allowedServerIpRanges": None,
            "excludeServerIpRanges": None,
            "verifyPTR": False,
            "forceTemplateDN": True,
            "subjectNameTemplate": "{SAN[0]}",
            "allowWildcards": False,
            "allowIpIdentifiers": False,
            "removeRootCAFromChain": False,
            **cfg,
        }, backend
    return get_config


class ChallengeFunctionTester(unittest.TestCase):
    def setUp(self):
        os.chdir(os.path.dirname(__file__))

    def test_check_csr_and_return_cert(self):
        csr_input = open("data_example.test.csr.bin", "rb").read()
        mock_order = Mock()
        mock_order.account.contact = None

        with unittest.mock.patch.object(main, "get_config", mock_config()):
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
            good = open("data_leaf.pem", "rb").read()
            self.assertEqual(result, good)

    def test_check_csr_and_return_cert_trimroot(self):
        csr_input = open("data_example.test.csr.bin", "rb").read()
        mock_order = Mock()
        mock_order.account.contact = None
        mock_order.identifiers = [example_test]

        with unittest.mock.patch.object(
            main, "get_config", mock_config(cfg={"removeRootCAFromChain": True})
        ):
            result = main.check_csr_and_return_cert(csr_input, mock_order)
            good = open("data_leaf.pem", "rb").read()
            self.assertEqual(result, good)

    def test_check_csr_and_return_cert_strconv(self):
        csr_input = open("data_example.test.csr.bin", "rb").read()
        mock_order = Mock()
        mock_order.account.contact = None
        mock_order.identifiers = [example_test]

        with unittest.mock.patch.object(
            main, "get_config", mock_config(("a string, not bytes", None))
        ):
            result = main.check_csr_and_return_cert(csr_input, mock_order)
            self.assertEqual(result, b"a string, not bytes")  # utf-8-encoded

    def test_check_csr_and_return_cert_error(self):
        csr_input = open("data_example.test.csr.bin", "rb").read()
        mock_order = Mock()
        mock_order.account.contact = None
        mock_order.identifiers = [example_test]

        with unittest.mock.patch.object(
            main, "get_config", mock_config((None, "error"))
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
        good = open("data_leaf.pem", "rb").read()
        self.assertEqual(result, good)

    def test_check_csr_and_return_cert_ipcn(self):
        csr_input = open("data_csr_ipcn.der", "rb").read()
        mock_order = Mock()
        mock_order.account.contact = None
        mock_order.identifiers = [example_ip]

        result = main.check_csr_and_return_cert(csr_input, mock_order)
        good = open("data_leaf.pem", "rb").read()
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

    def test_remove_root_ca(self):
        with open("data_cacert.pem", "rb") as f:
            ca = f.read()
        with open("data_xcacert.pem", "rb") as f:
            xca = f.read()
        with open("data_leaf.pem", "rb") as f:
            leaf = f.read()
        with open("data_xleaf.pem", "rb") as f:
            xleaf = f.read()

        # should not get modified:

        # single self signed cert
        self.assertEqual(main.remove_root_ca(ca), ca)
        # single cross-signed cert
        self.assertEqual(main.remove_root_ca(xca), xca)
        # chain ending in cross-signed cert
        self.assertEqual(main.remove_root_ca(xleaf+xca), xleaf+xca)

        # expect trimming to occur:

        # chain ending in self-signed cert
        self.assertEqual(main.remove_root_ca(leaf+ca), leaf)
