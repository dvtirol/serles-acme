import json
import socket
import requests
import jwcrypto.jwk  # fedora package: python3-jwcrypto.noarch
import jwcrypto.jws

from datetime import datetime, timezone

from cryptography import x509  # python3-cryptography.x86_64
from cryptography.hazmat.backends import default_backend as x509_backend
from cryptography.hazmat.primitives import serialization

from .utils import get_ptr, ip_in_ranges, normalize
from .configloader import get_config
from .models import *
from .exceptions import ACMEError

config = {}
backend = None


def init_config():
    global config, backend
    config, backend = get_config()


def verify_challenge(challenge):
    """ verify a challenge

    Args:
        challenge (Challenge): The challenge to verify.

    Returns:
        bool: True on success, False on error.

    Raises:
        ACMEError: Verification failed.
    """
    error = None

    # check that the challenge hasn't expired yet:
    if challenge.authorization.expires < datetime.now(timezone.utc):
        challenge.status = ChallengeStatus.invalid
        challenge.authorization.status = AuthzStatus.expired
        challenge.authorization.order.status = OrderStatus.invalid
        db.session.commit()
        raise ACMEError("challenge expired", 400, "malformed")  # better error code?

    if challenge.type == ChallengeTypes.http_01:
        error, info = http_challenge(challenge)
    else:
        challenge.status = ChallengeStatus.invalid
        db.session.commit()
        raise ACMEError("challenge type not supported", 501, "serverInternal")

    if error:
        # the challenge was not fulfilled, but hasn't expired yet either; we
        # may try again _only_after_ the client has sent a retry request
        # (RFC8555 §8.2)
        challenge.error = json.dumps(dict(type=f"urn:ietf:params:acme:error:{error}"))
        db.session.commit()
        raise ACMEError(info, 400, error)

    # if the challenge was sucessfully validated, propagate up:
    challenge.status = ChallengeStatus.valid
    challenge.validated = datetime.now(timezone.utc)
    # the authorization is valid if any challenge succeeded:
    challenge.authorization.status = AuthzStatus.valid
    # the order is only valid if _all_ authorizations are:
    for authz in challenge.authorization.order.authorizations:
        if authz.status != AuthzStatus.valid:
            break
    else:
        challenge.authorization.order.status = OrderStatus.ready
    # the challenge is now verified
    db.session.commit()


def http_challenge(challenge):  # RFC8555 §8.3
    """ verify a HTTP Challenge

    Args:
        challenge (Challenge): The HTTP challenge to verify.

    Returns:
        tuple(str,str): problem detail type of the error and  textual
            description, or (None,None).
    """
    host = challenge.authorization.identifier.value
    token = challenge.token
    prefix = ".well-known/acme-challenge"
    session = requests.Session()
    session.trust_env = False  # bypass proxy

    # follow redirect-to-https, but ignore self-signed certs:
    session.verify = False
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )

    # Setting stream=True lets us access the socket used to establish the
    # connection. We use this to get the IP address of the server we connect to
    # to verify it is in the range(s) of allowed addresses. Note that the
    # socket goes away once we read r.content or r.text.
    try:
        r = session.get(f"http://{host}/{prefix}/{token}", stream=True)
    except requests.ConnectionError as e:
        return "connection", str(e)  # also catches dns and tls errors

    try:  # this sometimes fails (sock is None)
        remote_ip, *_ = r.raw.connection.sock.getpeername()
    except AttributeError:
        sock = socket.fromfd(r.raw.fileno(), socket.AF_INET, socket.SOCK_STREAM)
        remote_ip, *_ = sock.getpeername()

    # additional checks that are useful in an enterprise setting, but not
    # required by spec:
    if config["allowedServerIpRanges"] and not ip_in_ranges(
        remote_ip, config["allowedServerIpRanges"]
    ):
        return "rejectedIdentifier", f"{remote_ip} not in allowed ranges"
    if config["excludeServerIpRanges"] and ip_in_ranges(
        remote_ip, config["excludeServerIpRanges"]
    ):
        return "rejectedIdentifier", f"{remote_ip} in excluded range"
    if config["verifyPTR"] and normalize(get_ptr(remote_ip)) != normalize(host):
        return "rejectedIdentifier", f"PTR does not match"

    thumbprint = jwcrypto.jwk.JWK.from_pem(
        challenge.authorization.order.account.jwk
    ).thumbprint()

    expect = f"{token}.{thumbprint}"
    if not r.ok or r.text != expect:
        return "incorrectResponse", f"expected {expect}, got {r.text}"

    return None, None  # no error occurred :)


def pkcs7_to_pem_chain(pkcs7_input):
    """ Converts a PKCS#7 cert chain to PEM format.

    Attempts to use python-cryptography 3.1 or falls back to using the
    openssl(1) tool.

    Args:
        pkcs7_input (bytes): the PKCS#7 chain as stored in the database.

    Returns:
        str: PEM encoded certificate chain as expected by ACME clients.
    """
    from cryptography import __version__ as crypto_version

    v = [int(s) if s.isdigit() else -1 for s in crypto_version.split(".")]

    if v[0] > 3 or (v[0] == 3 and v[1] >= 1):  # if cryptography 3.1 or higher:
        from cryptography.hazmat.primitives.serialization import pkcs7

        certs = serialization.pkcs7.load_der_pkcs7_certificates(pkcs7_input)
        return "\n".join(
            [
                cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
                for cert in certs
            ]
        )
    else:
        from subprocess import Popen, PIPE, DEVNULL

        proc = Popen(
            ["openssl", "pkcs7", "-print_certs", "-inform", "DER"],
            stdin=PIPE,
            stdout=PIPE,
            stderr=DEVNULL,
        )
        proc.stdin.write(pkcs7_input)
        proc.stdin.close()
        pem_cert = proc.stdout.read().decode("ascii")
        return "\n".join(
            [
                l
                for l in pem_cert.splitlines()
                if not l.startswith("subject=") and not l.startswith("issuer=")
            ]
        )


def check_csr_and_return_cert(csr_der, order):
    """ validate CSR and pass to backend

    Checks that the CSR only contains domains from previously validated
    challenges and get a signed certificate from the backend.

    Args:
        csr_der (bytes): client's CSR in DER encoding
        order (Order): the order object that the CSR belongs to

    Returns:
        bytes: the signed certificate and chain in PKCS#7 format (DER encoded)

    Raises:
        ACMEError: CSR was rejected (by us) or the backend refused to sign it.
    """
    csr = x509.load_der_x509_csr(csr_der, x509_backend())
    try:
        alt_names = csr.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value.get_values_for_type(x509.DNSName)
    except:
        alt_names = []
    try:
        common_name = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[
            0
        ].value
    except IndexError:
        # certbot does not set Subject Name, only SANs
        # https://github.com/certbot/certbot/issues/4922
        common_name = alt_names[0]

    if not common_name in alt_names:  # chrome ignores CN, so write CN to SAN
        alt_names.insert(0, common_name)

    # since we pass the CN and SANs to the backend, make sure the client only
    # specified those that we verified before:
    order_identifiers = {ident.value for ident in order.identifiers}
    csr_identifiers = {*alt_names}  # convert list to set
    if order_identifiers != csr_identifiers:
        raise ACMEError(f"{order_identifiers} != {csr_identifiers}", 400, "badCSR")

    csr_der = csr.public_bytes(serialization.Encoding.DER)
    email = order.account.contact
    subject_dn = csr.subject.rfc4514_string()
    if config["forceTemplateDN"] or not subject_dn:
        subject_dn = config["subjectNameTemplate"].format(SAN=alt_names, MAIL=email)

    certificate, error = backend.sign(csr_der, subject_dn, alt_names, email)

    if error:
        raise ACMEError(error, 400, "badCSR")

    return certificate
