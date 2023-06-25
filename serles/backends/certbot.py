import subprocess
import tempfile
import json

from subprocess import STDOUT, PIPE
from pathlib import Path

class Backend:
    """ Serles Backend for certbot

    Backend will pass the certificate signing request to an already configured certbot installation.

    Example use cases:

       1. Want actual trusted certs without using an internal CA (you want it to work in browsers/etc. out of the box)
       2. Don't want the services externally exposed (internal services/development only)
       3. Don't want the internal services having control over your external DNS (random developers/users)
       4. Have an intermediate server running serles that you are willing to grant external DNS update rights to.

    This allows any internal entity to transparently use serles ACME CA with http-01 validation, but the actual signing
    requests are delegated to external ACME CA.

    """

    def __init__(self, config):
        self.path = "/usr/bin/certbot"
        self.args = []

        if "certbot" in config:
            if "path" in config['certbot']:
                self.path = config['certbot']['path']
            if "args" in config['certbot']:
                self.args = json.loads(config['certbot']['args'])

    def sign(self, csr, subjectDN, subjectAltNames, email):
        with tempfile.TemporaryDirectory(prefix="serles-certbot") as tmpdir:
            csr_file = f"{tmpdir}/csr.pem"
            with open(csr_file, "w") as fh:
                fh.write(csr.decode('utf-8'))

            cert_file = f"{tmpdir}/cert.pem"
            fullchain_file = f"{tmpdir}/fullchain.pem"
            chain_file = f"{tmpdir}/chain.pem"

            cmd = [
                self.path,
                "certonly",
                "--non-interactive",
                "--force-renew",
                "--expand",
                "--csr", csr_file,
                "--cert-path", cert_file,
                "--fullchain-path", fullchain_file,
                "--chain-path", chain_file,
                *(self.args),
            ]

            for csr_san in subjectAltNames:
              cmd.extend(["-d", csr_san])

            res = subprocess.run(cmd, stdout=PIPE, stderr=STDOUT, check=False)
            output = res.stdout.decode('utf-8')

            if res.returncode:
                return None, f"certbot exited with error {res.returncode} and output:\n{output}"

            with open(fullchain_file, "r") as new_chain:
                return new_chain.read(), None
