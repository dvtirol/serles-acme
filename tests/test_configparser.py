import tempfile
import unittest
import os, sys
import MockBackend
import serles as main
from serles.configloader import ConfigError


class ConfigFunctionTester(unittest.TestCase):
    def setUp(self):
        os.chdir(os.path.dirname(__file__))

    def test_configparser_gardenpath(self):
        config, backend = main.configloader.load_config_and_backend("data_config.ini")
        self.assertIsNotNone(config["allowedServerIpRanges"])
        self.assertIsNotNone(config["excludeServerIpRanges"])
        self.assertEqual(config["subjectNameTemplate"], "CN={SAN[0]}")
        self.assertEqual(config["verifyPTR"], False)
        # self.assertIsInstance(backend, MockBackend.Backend)  #this doesn't work for some reason?

    def test_configparser_noconfig(self):
        self.assertRaises(
            ConfigError, main.configloader.load_config_and_backend, "/nonexisting-file"
        )

    def test_configparser_configerror(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"[serles]\n")
            f.flush()
            self.assertRaisesRegex(
                ConfigError,
                "define the backend",
                main.configloader.load_config_and_backend,
                f.name,
            )
            f.write(b"backend=MockBackend\n")
            f.flush()
            self.assertRaisesRegex(
                ConfigError,
                "no .serles.database= configured",
                main.configloader.load_config_and_backend,
                f.name,
            )
            f.write(b"database=sqlite:///:memory:\n")
            f.flush()
            self.assertRaisesRegex(
                ConfigError,
                "subjectNameTemplate",
                main.configloader.load_config_and_backend,
                f.name,
            )
            f.write(b"subjectNameTemplate=x")
            f.flush()

            config, backend = main.configloader.load_config_and_backend(f.name)

            self.assertEqual(config["allowedServerIpRanges"], None)
            self.assertEqual(config["excludeServerIpRanges"], None)
            self.assertEqual(config["verifyPTR"], False)

    def test_configparser_wrongvalue(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"[serles]\nbackend=nonexisting.module\n")
            f.flush()
            self.assertRaisesRegex(
                ConfigError,
                "backend class could not be loaded",
                main.configloader.load_config_and_backend,
                f.name,
            )
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"[serles]\nbackend=MockBackend:NotExisting\n")
            f.flush()
            self.assertRaisesRegex(
                ConfigError,
                r"backend does not define a NotExisting class \(wrong module loaded\?\)",
                main.configloader.load_config_and_backend,
                f.name,
            )
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"[serles]\nbackend=MockBackend:RaisingBackend\n")
            f.flush()
            self.assertRaisesRegex(
                ConfigError,
                "exception while initializing backend",
                main.configloader.load_config_and_backend,
                f.name,
            )
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"[serles]\nbackend=MockBackend:NotBackend\n")
            f.flush()
            self.assertRaisesRegex(
                ConfigError,
                "backend does not define a sign method",
                main.configloader.load_config_and_backend,
                f.name,
            )
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"[serles]\n")
            f.write(b"database=sqlite:///:memory:\n")
            f.write(b"backend=MockBackend\n")
            f.write(b"subjectNameTemplate=x\n")
            f.write(b"forceTemplateDN=x\n")
            f.flush()
            self.assertRaisesRegex(
                ConfigError,
                "forceTemplateDN",
                main.configloader.load_config_and_backend,
                f.name,
            )
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"[serles]\n")
            f.write(b"database=sqlite:///:memory:\n")
            f.write(b"backend=MockBackend\n")
            f.write(b"subjectNameTemplate=x\n")
            f.write(b"verifyPTR=x\n")
            f.flush()
            self.assertRaisesRegex(
                ConfigError,
                "verifyPTR",
                main.configloader.load_config_and_backend,
                f.name,
            )
