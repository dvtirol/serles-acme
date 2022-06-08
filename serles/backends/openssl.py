import subprocess
from os.path import exists

class Backend:
    def __init__(self, config):
        self.cacert = config['openssl']['cacert']
        self.cakey = config['openssl']['cakey']
        if not exists(self.cakey):
            subprocess.run([
                "openssl", "genrsa",
                "-out", self.cakey,
                "4096",
            ])
        if not exists(self.cacert):
            subprocess.run([
                "openssl", "req",
                "-new", "-x509",
                "-nodes",
                "-days", "3650",
                "-subj", "/C=XX/O=Serles",
                "-key", self.cakey,
                "-out", self.cacert,
            ])

    def sign(self, csr, subjectDN, subjectAltNames, email):
        x509 = subprocess.run([
            "openssl", "x509", "-req",
            "-CA", self.cacert,
            "-CAkey", self.cakey,
            "-CAcreateserial",
        ], input=csr, stdout=subprocess.PIPE)
        chain = x509.stdout + open(self.cacert, "rb").read()
        return chain.decode("utf-8"), None
