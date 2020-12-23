# to implement your own backend, create a class Backend with a method sign(self,DER_CSR,DN,[SAN],email) that returns (PKCS7_fullchain,error_or_None).
import base64
import csv
import requests
import secrets
import zeep  # fedora package: python3-zeep.noarch


class EjbcaBackend:
    """ ACMEByProxy Backend for EJBCA (Community edition compatible)

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
            clientCertificate = config["backend"]["clientCertificate"]
            apiUrl = config["backend"]["apiUrl"]
            caBundle = config["backend"]["caBundle"]
            caBundle = dict(default=True, none=False).get(caBundle, caBundle)
            self.caName = config["backend"]["caName"]
            self.endEntityProfileName = config["backend"]["endEntityProfileName"]
            self.certificateProfileName = config["backend"]["certificateProfileName"]
            self.entityUsernameScheme = config["backend"]["entityUsernameScheme"]
            self.entityPasswordScheme = config["backend"]["entityPasswordScheme"]
        except KeyError as e:
            raise Exception(f"missing config key {e}")

        session = requests.Session()
        session.verify = caBundle
        session.cert = clientCertificate
        transport = zeep.transports.Transport(session=session)

        self.client = zeep.Client(apiUrl, transport=transport)
        self.userData = self.client.get_type("ns0:userDataVOWS")

    def sign(self, csr, subjectDN, subjectAltNames, email):
        subjectAltName = ",".join(f"DNSNAME={name}" for name in subjectAltNames)

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
                    caName=self.caName,
                    subjectAltName=subjectAltName,
                    email=email,
                    status=10,  # EndEntityConstants.STATUS_NEW = 10
                    tokenType="USERGENERATED",  # userDataVOWS.TOKEN_TYPE_USERGENERATED
                    endEntityProfileName=self.endEntityProfileName,
                    certificateProfileName=self.certificateProfileName,
                    keyRecoverable=False,
                    sendNotification=(email is not None),
                ),
                base64.b64encode(csr),
                0,  # CertificateHelper.CERT_REQ_TYPE_PKCS10
                None,
                "PKCS7WITHCHAIN",  # CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN
            )
            return base64.b64decode(result.data), None
        except zeep.exceptions.Fault as e:
            # observed these exception types:
            # - org.cesecore.certificates.certificate.CertificateCreateException
            # - org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException
            typestr, _, message = e.message.partition(":")
            return None, message
