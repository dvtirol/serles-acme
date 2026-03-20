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
                self.attrs = kwargs

        return zeep_type

    class _service:
        def certificateRequest(self, userdata, csr, csrtype, none, certtype):
            bad_csr = open("data_nocn.csr", "rb").read()
            if csr == base64.b64encode(bad_csr):
                raise zeep.exceptions.Fault("org.foo:bar")
            pkcs7_out = open("data_pkcs7.bin", "rb").read()
            return Mock(data=base64.b64encode(pkcs7_out))

    service = _service()

class KeyTypeClient(MockedClient):
    class _service:
        def certificateRequest(self, userdata, csr, csrtype, none, certtype):
            raise zeep.exceptions.Fault(userdata.attrs["caName"])
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
        config_noca = {"ejbca": good_config["ejbca"].copy()}
        del config_noca["ejbca"]["caName"]
        self.assertRaisesRegex(
            Exception, "missing config key caName, caName_rsa or caName_ecdsa", EJBCABackend.EjbcaBackend, config_noca
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

    def test_badkeyalgo(self):
        # only RSA and ECDSA keys are allowed, so this check with a DSA CSR will fail.
        with unittest.mock.patch.object(EJBCABackend.zeep, "Client", MockedClient):
            backend = EJBCABackend.EjbcaBackend(good_config)
            csr_input = open("data_dsa.csr.pem", "rb").read()
            retval = backend.sign(csr_input, "dn", "san", "email")
            self.assertEqual(retval, (None, "unsupported key algorithm 1.2.840.10040.4.1"))

    def test_keyalgos(self):
        config = dict(
            ejbca=dict(
                clientCertificate="",
                apiUrl="https://example.test:8443/foo?",
                caBundle="caBundle",
                caName_rsa="rsa key detected",
                caName_ecdsa="ecdsa key detected",
                endEntityProfileName="endEntityProfileName",
                certificateProfileName="certificateProfileName",
                entityUsernameScheme="entityUsernameScheme",
                entityPasswordScheme="entityPasswordScheme",
            )
        )
        with unittest.mock.patch.object(EJBCABackend.zeep, "Client", KeyTypeClient):
            backend = EJBCABackend.EjbcaBackend(config)
            csr_input = open("data_example.test.csr.pem", "rb").read()
            retval = backend.sign(csr_input, "dn", "san", "email")
            self.assertEqual(retval, (None, "rsa key detected"))

            csr_input = open("data_ecdsa.csr.pem", "rb").read()
            retval = backend.sign(csr_input, "dn", "san", "email")
            self.assertEqual(retval, (None, "ecdsa key detected"))

    def test_pkcs7_to_pem_chain_crypto31(self):
        der_input = open("data_pkcs7.bin", "rb").read()
        pem_output = open("data_pemchain.txt", "r").read()
        result = EJBCABackend.pkcs7_to_pem_chain(der_input)
        self.assertEqual(result.replace("\n", ""), pem_output.replace("\n", ""))

    def test_typed_ident(self):
        self.assertEqual(EJBCABackend.typed_ident("192.0.2.1"), "IPAddress=192.0.2.1")
        self.assertEqual(EJBCABackend.typed_ident("2001:DB8::1"), "IPAddress=2001:db8::1")
        self.assertEqual(EJBCABackend.typed_ident("2001:DB8::0:01"), "IPAddress=2001:db8::1")
        self.assertEqual(EJBCABackend.typed_ident("example.test"), "DNSNAME=example.test")
        # subnet is not an address, fall back to DNSNAME:
        self.assertEqual(EJBCABackend.typed_ident("192.0.2.0/24"), "DNSNAME=192.0.2.0/24")
