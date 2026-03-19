import base64
import csv
import ipaddress
import requests
import secrets
import zeep  # fedora package: python3-zeep.noarch
from cryptography import x509  # python3-cryptography.x86_64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.backends import default_backend as x509_backend


class EjbcaBackend:
    """ Serles Backend for EJBCA (Community edition compatible)

    Uses the EJBCA SOAP API to request certificates. Recommended setup on the
    EJBCA side:

    - A Certificate Profile for ACME-issued certificates, e.g.
      "ACMEServerProfile". Must have an Extended Key Usage of "Server
      Authentication". Should have relatively short Validity duration.
    - An End Entity Profile, e.g. "ACMEEndIdentityProfile". Uses the
      Server Certificate Profile mentioned above and should allow for a number
      of DNS Name Subject Alternative Names.

    To connect to the API, the following setup is used:

    - A Certificate Profile for authenticating EjbcaBackend with EJBCA's SOAP
      API, e.g. "APIClientProfile". Must have an Extended Key Usage of "Client
      Authentication".
    - An End Entity Profile for client authentication, e.g.
      "APIClientIdentityProfile". Uses the Client Certificate Profile mentioned
      above.
    - A concrete End Entity for EjbcaBackend, e.g. "client01". Uses the Client
      Entity Profile mentioned above. Should have its common name same as its
      user name.
    - A certificate must be issued for this entity and its location stored in
      config.ini.
    - An Administrator Role for API clients, e.g. "ACMEUser". From advanced
      mode, requires access to the Rules (`<>` denote variables)

      - ``/administrator``
      - ``/ca_functionality/create_certificate``
      - ``/ra_functionality/create_end_entity``
      - ``/ra_functionality/edit_end_entity``
      - ``/ca/<NAME_OF_CA>`` (e.g. ``/ca/ACMECA``)
      - ``/endentityprofilesrules/<END_ENTITY_PROFILE>/create_end_entity``
        (e.g. ``/endentityprofilesrules/ACMEEndIdentityProfile/create_end_entity/``)
      - ``/endentityprofilesrules/<END_ENTITY_PROFILE>/edit_end_entity``
        (e.g. ``/endentityprofilesrules/ACMEEndIdentityProfile/edit_end_entity/``)
    - Ensure the client entity is in the correct Administrator Role (e.g. via CN).
    """

    def __init__(self, config):
        try:
            clientCertificate = config["ejbca"]["clientCertificate"]
            apiUrl = config["ejbca"]["apiUrl"]
            caBundle = config["ejbca"]["caBundle"]
            caBundle = dict(default=True, none=False).get(caBundle, caBundle)
            self.endEntityProfileName = config["ejbca"]["endEntityProfileName"]
            self.certificateProfileName = config["ejbca"]["certificateProfileName"]
            self.entityUsernameScheme = config["ejbca"]["entityUsernameScheme"]
            self.entityPasswordScheme = config["ejbca"]["entityPasswordScheme"]
        except KeyError as e:
            raise Exception(f"missing config key {e}")

        # 'caName' (if present) is the default, unless overridden by _rsa and/or _ecdsa:
        fallbackCA = config["ejbca"].get("caName")
        self.caName = {
            "rsa": config["ejbca"].get("caName_rsa", fallbackCA),
            "ecdsa": config["ejbca"].get("caName_ecdsa", fallbackCA),
        }
        if not any(self.caName.values()):
            raise Exception(f"missing config key caName, caName_rsa or caName_ecdsa")

        session = requests.Session()
        session.verify = caBundle
        session.cert = clientCertificate
        transport = zeep.transports.Transport(session=session)

        self.client = zeep.Client(apiUrl, transport=transport)
        self.userData = self.client.get_type("ns0:userDataVOWS")

    def sign(self, csr, subjectDN, subjectAltNames, email):
        subjectAltName = ",".join(typed_ident(name) for name in subjectAltNames)

        csr_obj = x509.load_pem_x509_csr(csr, x509_backend())
        csr_der = csr_obj.public_bytes(serialization.Encoding.DER)

        # find out which kind of public key the CSR is using, and select the
        # authority to sign the certificate with accordingly. there are more but
        # the CA/B Baseline Requirements §7.1.3.1 only allow these two OIDs.
        csr_algo = csr_obj.public_key_algorithm_oid.dotted_string
        ca_algo = {
            "1.2.840.113549.1.1.1": "rsa", # rsaEncryption as per RFC3279§2.3.1 & RFC4055§1.2
            "1.2.840.10045.2.1": "ecdsa", # ecPublicKey as per RFC3279§2.3.5 & RFC5480§2.1.1
        }.get(csr_algo)
        if not ca_algo:
            return None, f"unsupported key algorithm {csr_algo}"
        caName = self.caName[ca_algo]

        # NOTE: this is very hacky and not to spec/rfc4514, but should be
        # enough to extract the CN. Notably, we don't support "+" and "\<hex>".
        dn = next(csv.reader([subjectDN], escapechar="\\", doublequote=False))
        dn = {part.partition("=")[0]: part.partition("=")[2] for part in dn}

        try:
            random = secrets.token_hex(16)  # generates 32 characters
            username = self.entityUsernameScheme.format(random=random, **dn)
            password = self.entityPasswordScheme.format(random=random, **dn)
        except KeyError as e:
            return None, f"DN is missing field {e}"

        try:
            result = self.client.service.certificateRequest(
                self.userData(
                    username=username,
                    password=password,
                    clearPwd=False,
                    subjectDN=subjectDN,
                    caName=caName,
                    subjectAltName=subjectAltName,
                    email=email,
                    status=10,  # EndEntityConstants.STATUS_NEW = 10
                    tokenType="USERGENERATED",  # userDataVOWS.TOKEN_TYPE_USERGENERATED
                    endEntityProfileName=self.endEntityProfileName,
                    certificateProfileName=self.certificateProfileName,
                    keyRecoverable=False,
                    sendNotification=(email is not None),
                ),
                base64.b64encode(csr_der),
                0,  # CertificateHelper.CERT_REQ_TYPE_PKCS10
                None,
                "PKCS7WITHCHAIN",  # CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN
            )
            pkcs7data = base64.b64decode(result.data)
            return pkcs7_to_pem_chain(pkcs7data), None
        except zeep.exceptions.Fault as e:
            # remove exception class names from error, if present. observed these:
            # - org.cesecore.certificates.certificate.CertificateCreateException
            # - org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException
            message = e.message
            if message.startswith("org."):
                typestr, _, message = message.partition(":")
            return None, message


def typed_ident(ident):
    try:
        ip = ipaddress.ip_address(ident)
        return f"IPAddress={ip.compressed}"
    except ValueError:
        # assume dNSname
        return f"DNSNAME={ident}"


def pkcs7_to_pem_chain(pkcs7_input):
    """ Converts a PKCS#7 cert chain to PEM format.

    Args:
        pkcs7_input (bytes): the PKCS#7 chain as stored in the database.

    Returns:
        str: PEM encoded certificate chain as expected by ACME clients.
    """

    certs = pkcs7.load_der_pkcs7_certificates(pkcs7_input)
    return "\n".join(
        [
            cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
            for cert in certs
        ]
    )
