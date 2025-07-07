import os
import base64
import unittest.mock
from unittest.mock import Mock
from serles.backends import ejbca as EJBCABackend
import zeep


class MockedClient:
    def __init__(self, apiUrl, transport):
        pass

    def get_type(self, name):
        class zeep_type:
            def __init__(self, **kwargs):
                pass

        return zeep_type

    class _service:
        def certificateRequest(self, userdata, csr, csrtype, none, certtype):
            bad_csr = open("data_nocn.csr", "rb").read()
            if csr == base64.b64encode(bad_csr):
                raise zeep.exceptions.Fault("org.foo:bar")
            pkcs7_out = open("data_pkcs7.bin", "rb").read()
            return Mock(data=base64.b64encode(pkcs7_out))

    service = _service()


good_config = dict(
    ejbca=dict(
        clientCertificate="",
        apiUrl="https://example.test:8443/foo?",
        caBundle="caBundle",
        caName="caName",
        endEntityProfileName="endEntityProfileName",
        certificateProfileName="certificateProfileName",
        entityUsernameScheme="entityUsernameScheme",
        entityPasswordScheme="entityPasswordScheme",
    )
)


class HelperFunctionTester(unittest.TestCase):
    def setUp(self):
        os.chdir(os.path.dirname(__file__))

    def test_backend_configerror(self):
        config = dict(backend=dict())
        self.assertRaisesRegex(
            Exception, "missing config key", EJBCABackend.EjbcaBackend, config
        )

    def test_dnerror(self):
        config = dict(
            ejbca=dict(
                clientCertificate="",
                apiUrl="https://example.test:8443/foo?",
                caBundle="caBundle",
                caName="caName",
                endEntityProfileName="endEntityProfileName",
                certificateProfileName="certificateProfileName",
                entityUsernameScheme="{fieldmissing}",
                entityPasswordScheme="{fieldmissing}",
            )
        )
        with unittest.mock.patch.object(EJBCABackend.zeep, "Client", MockedClient):
            backend = EJBCABackend.EjbcaBackend(config)
            csr_input = open("data_example.test.csr.pem", "rb").read()
            retval = backend.sign(csr_input, "dn", "san", "email")
            self.assertEqual(retval, (None, "DN is missing field 'fieldmissing'"))

    def test_sign(self):
        with unittest.mock.patch.object(EJBCABackend.zeep, "Client", MockedClient):
            backend = EJBCABackend.EjbcaBackend(good_config)
            csr_input = open("data_example.test.csr.pem", "rb").read()
            retval = backend.sign(csr_input, "dn", "san", "email")
            pemchain_out = open("data_pemchain.txt", "r").read()
            self.assertEqual(retval, (pemchain_out, None))

    def test_failure(self):
        with unittest.mock.patch.object(EJBCABackend.zeep, "Client", MockedClient):
            backend = EJBCABackend.EjbcaBackend(good_config)
            csr_input = open("data_nocn.csr.pem", "rb").read()
            retval = backend.sign(csr_input, "dn", "san", "email")
            self.assertEqual(retval, (None, "bar"))

    def test_pkcs7_to_pem_chain_crypto31(self):
        der_input = open("data_pkcs7.bin", "rb").read()
        pem_output = open("data_pemchain.txt", "r").read()
        result = EJBCABackend.pkcs7_to_pem_chain(der_input)
        self.assertEqual(result.replace("\n", ""), pem_output.replace("\n", ""))
