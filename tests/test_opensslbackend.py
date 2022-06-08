import os
import tempfile
import unittest
from serles.backends import openssl as OpenSSLBCABackend

tmp = tempfile.mkdtemp()

good_config = dict(
    openssl=dict(
        cacert=f"{tmp}/ca.crt",
        cakey=f"{tmp}/ca.key",
    )
)


class HelperFunctionTester(unittest.TestCase):
    def setUp(self):
        os.chdir(os.path.dirname(__file__))

    def test_backend_configerror(self):
        config = dict(openssl=dict())
        self.assertRaisesRegex(
            Exception, "cacert", OpenSSLBCABackend.Backend, config  # missing config key
        )

    def test_sign(self):
        backend = OpenSSLBCABackend.Backend(good_config)
        csr_input = open("data_example.test.csr.bin", "rb").read()
        chain, error = backend.sign(csr_input, "dn", "san", "email")
        self.assertEqual(error, None)
        # we generate a new self-signed CA with every test run, so we can't compare fully
        self.assertEqual(chain[:28], "-----BEGIN CERTIFICATE-----\n")
