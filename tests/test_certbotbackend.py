import os
import tempfile
import unittest
import unittest.mock
from unittest.mock import Mock
from serles.backends import certbot as CertbotBackend

tmp = tempfile.mkdtemp()

good_config = {
    "certbot": {
        "config": f"#",
    }
}

both_config = {
    "certbot": {
        "config": "# a config file",
        "config-file": "/whatever",
    }
}


def subprocess_run(cmd, **kwargs):
    fullchain_file = cmd[10]
    open(fullchain_file, "w").write("fake cert")
    return Mock(stdout=b"", returncode=0)


def subprocess_run_failed(cmd, **kwargs):
    fullchain_file = cmd[10]
    return Mock(stdout=b"the error", returncode=1)


class CertbotBackendTester(unittest.TestCase):
    def setUp(self):
        os.chdir(os.path.dirname(__file__))

    def test_backend_okconfig(self):
        with unittest.mock.patch.object(
            CertbotBackend.os.path, "exists", lambda _: True
        ), unittest.mock.patch.object(CertbotBackend.os, "access", lambda a, b: True):
            config = dict(certbot=dict(path="/usr/local/bin/certbot", config="x"))
            backend = CertbotBackend.Backend(config)
            self.assertNotEqual(backend, None)

    def test_backend_nocertbot(self):
        with unittest.mock.patch.object(
            CertbotBackend.os.path, "exists", lambda _: False
        ), unittest.mock.patch.object(CertbotBackend.os, "access", lambda a, b: False):
            self.assertRaisesRegex(
                Exception,
                "certbot not found at '/usr/bin/certbot', please specify correct path in certbot.path setting in config.ini",
                CertbotBackend.Backend,
                good_config,
            )

    def test_backend_noexec(self):
        with unittest.mock.patch.object(
            CertbotBackend.os.path, "exists", lambda _: True
        ), unittest.mock.patch.object(CertbotBackend.os, "access", lambda a, b: False):
            self.assertRaisesRegex(
                Exception,
                "certbot '/usr/bin/certbot' not executable",
                CertbotBackend.Backend,
                good_config,
            )

    def test_backend_noconfig(self):
        with unittest.mock.patch.object(
            CertbotBackend.os.path, "exists", lambda _: True
        ), unittest.mock.patch.object(CertbotBackend.os, "access", lambda a, b: True):
            config = dict(certbot=dict())
            self.assertRaisesRegex(
                Exception,
                "no config specified, need either certbot.config or certbot.config-file",
                CertbotBackend.Backend,
                config,  # missing config key
            )

    def test_backend_fullconfig(self):
        with unittest.mock.patch.object(
            CertbotBackend.os.path, "exists", lambda _: True
        ), unittest.mock.patch.object(CertbotBackend.os, "access", lambda a, b: True):
            self.assertRaisesRegex(
                Exception,
                "cannot specify both certbot.config and certbot.config-file in config.ini",
                CertbotBackend.Backend,
                both_config,
            )

    def test_sign(self):
        with unittest.mock.patch.object(
            CertbotBackend.os.path, "exists", lambda _: True
        ), unittest.mock.patch.object(
            CertbotBackend.os, "access", lambda a, b: True
        ), unittest.mock.patch.object(
            CertbotBackend.subprocess, "run", subprocess_run
        ):
            backend = CertbotBackend.Backend(good_config)
            csr_input = open("data_example.test.csr.bin", "rb").read()
            chain, error = backend.sign(csr_input, "dn", "san", "email")
            self.assertEqual(error, None)
            self.assertEqual(chain[:28], "fake cert")

    def test_sign_failed(self):
        with unittest.mock.patch.object(
            CertbotBackend.os.path, "exists", lambda _: True
        ), unittest.mock.patch.object(
            CertbotBackend.os, "access", lambda a, b: True
        ), unittest.mock.patch.object(
            CertbotBackend.subprocess, "run", subprocess_run_failed
        ):
            backend = CertbotBackend.Backend(good_config)
            csr_input = open("data_example.test.csr.bin", "rb").read()
            chain, error = backend.sign(csr_input, "dn", "san", "email")
            self.assertEqual(
                error, "certbot exited with error 1 and output:\nthe error"
            )
