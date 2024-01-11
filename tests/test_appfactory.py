import tempfile
import datetime
import unittest
from unittest.mock import Mock
from unittest.mock import patch
import os

import serles


class AppFactoryTester(unittest.TestCase):
    def test_createapp(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"[serles]\n")
            f.write(b"backend=MockBackend\n")
            f.write(b"database = sqlite:///:memory:\n")
            f.write(b"subjectNameTemplate={SAN[0]}\n")
            f.flush()
            with patch("os.environ", {"CONFIG": f.name}), unittest.mock.patch.object(
                serles, "background_job", lambda n: lambda f: f()
            ), unittest.mock.patch.object(
                serles,
                "Order",
                Mock(
                    query=Mock(filter=lambda q: Mock(all=lambda: [None])),
                    expires=datetime.datetime.now(datetime.timezone.utc),
                ),
            ), unittest.mock.patch.object(
                serles.db.session, "delete", lambda x: None
            ):
                serles.create_app()
