import subprocess
import tempfile
import json
import os

from subprocess import STDOUT, PIPE


class Backend:
    """ Serles Backend for certbot

    Backend will pass the certificate signing request to an already configured
    certbot installation.

    Example use cases:
       1. Want actual trusted certs without using an internal CA (you want it
          to work in browsers/etc. out of the box)
       2. Don't want the services externally exposed (internal
          services/development only)
       3. Don't want the internal services having control over your external
          DNS (random developers/users)
       4. Have an intermediate server running serles that you are willing to
          grant external DNS update rights to.

    This allows any internal entity to transparently use serles ACME CA with
    http-01 validation, but the actual signing requests are delegated to
    external ACME CA.

    Contributed by Nathan Neulinger.
    """

    def __init__(self, config):
        self.path = "/usr/bin/certbot"
        self.config = None
        self.config_file = None

        if "certbot" in config:
            if "path" in config["certbot"]:
                self.path = config["certbot"]["path"]
            if "config" in config["certbot"]:
                self.config = config["certbot"]["config"]
            if "config-file" in config["certbot"]:
                self.config_file = config["certbot"]["config-file"]

        if self.config_file and self.config:
            raise Exception(
                "cannot specify both certbot.config and certbot.config-file in config.ini"
            )

        if not self.config_file and not self.config:
            # Ensure we load in our own config and do NOT fall back to system level certbot default config file
            raise Exception(
                "no config specified, need either certbot.config or certbot.config-file"
            )

        if not os.path.exists(self.path):
            raise Exception(
                f"certbot not found at '{self.path}', please specify correct path in certbot.path setting in config.ini"
            )

        if not os.access(self.path, os.X_OK):
            raise Exception(f"certbot '{self.path}' not executable")

    def sign(self, csr, subjectDN, subjectAltNames, email):
        with tempfile.TemporaryDirectory(prefix="serles-certbot") as tmpdir:

            # Write explicit configuration to temporary file if a config file is not provided
            certbot_config_arg = self.config_file
            if self.config:
                ini_file = f"{tmpdir}/certbot-cli.ini"
                with open(ini_file, "w") as fh:
                    fh.write(self.config)
                certbot_config_arg = ini_file

            csr_file = f"{tmpdir}/csr.pem"
            with open(csr_file, "wb") as fh:
                fh.write(csr)

            cert_file = f"{tmpdir}/cert.pem"
            fullchain_file = f"{tmpdir}/fullchain.pem"
            chain_file = f"{tmpdir}/chain.pem"

            cmd = [
                self.path,
                "certonly",
                "--config", certbot_config_arg,
                "--non-interactive",
                "--csr", csr_file,
                "--cert-path", cert_file,
                "--fullchain-path", fullchain_file,
                "--chain-path", chain_file
            ]

            for csr_san in subjectAltNames:
                cmd.extend(["-d", csr_san])

            res = subprocess.run(cmd, stdout=PIPE, stderr=STDOUT, check=False)
            output = res.stdout.decode("utf-8")

            if res.returncode:
                return (
                    None,
                    f"certbot exited with error {res.returncode} and output:\n{output}"
                )

            with open(fullchain_file, "r") as new_chain:
                return new_chain.read(), None
