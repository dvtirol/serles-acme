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
            if csr == base64.b64encode(b"fail"):
                raise zeep.exceptions.Fault("foo:bar")
            return Mock(data=base64.b64encode(b"certificate-data"))

    service = _service()


good_config = dict(
    backend=dict(
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
    def test_backend_configerror(self):
        config = dict(backend=dict())
        self.assertRaisesRegex(
            Exception, "missing config key", EJBCABackend.EjbcaBackend, config
        )

    def test_dnerror(self):
        config = dict(
            backend=dict(
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
            retval = backend.sign(b"csr", "dn", "san", "email")
            self.assertEqual(retval, (None, "DN is missing field 'fieldmissing'"))

    def test_sign(self):
        with unittest.mock.patch.object(EJBCABackend.zeep, "Client", MockedClient):
            backend = EJBCABackend.EjbcaBackend(good_config)
            retval = backend.sign(b"csr", "dn", "san", "email")
            self.assertEqual(retval, (b"certificate-data", None))

    def test_failure(self):
        with unittest.mock.patch.object(EJBCABackend.zeep, "Client", MockedClient):
            backend = EJBCABackend.EjbcaBackend(good_config)
            retval = backend.sign(b"fail", "dn", "san", "email")
            self.assertEqual(retval, (None, "bar"))
