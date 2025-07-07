import ssl
import json
import socket
import hashlib
import base64
import requests
import jwcrypto.jwk  # fedora package: python3-jwcrypto.noarch
import jwcrypto.jws
import dns.resolver

from datetime import datetime, timezone

from cryptography import x509  # python3-cryptography.x86_64
from cryptography.hazmat.backends import default_backend as x509_backend
from cryptography.hazmat.primitives import serialization

from .utils import get_ptr, ip_in_ranges, normalize, ber_parse
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
    elif challenge.type == ChallengeTypes.dns_01:
        error, info = dns_challenge(challenge)
    elif challenge.type == ChallengeTypes.tls_alpn_01:
        error, info = alpn_challenge(challenge)
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
        r = session.get(f"http://{host}/{prefix}/{token}", stream=True, timeout=10)
    except (requests.ConnectionError, requests.ReadTimeout) as e:
        return "connection", str(e)  # also catches dns and tls errors

    try:  # this sometimes fails (sock is None)
        remote_ip, *_ = r.raw.connection.sock.getpeername()
    except AttributeError:
        sock = socket.fromfd(r.raw.fileno(), socket.AF_INET, socket.SOCK_STREAM)
        remote_ip, *_ = sock.getpeername()

    reject = additional_ip_address_checks(remote_ip, host)
    if reject:
        return "rejectedIdentifier", reject

    # consume the response body (and close connection)
    try:
        found = r.text
    except (requests.exceptions.ChunkedEncodingError, requests.ReadTimeout) as e:
        return "connection", f"server did not send a proper response"

    expect = key_authorization(challenge)
    if not r.ok or found != expect:
        return "incorrectResponse", f"expected {expect}, got {r.text}"

    return None, None  # no error occurred :)


def dns_challenge(challenge):  # RFC8555 §8.4
    """ verify a DNS-01 Challenge

    Args:
        challenge (Challenge): The DNS-01 challenge to verify.

    Returns:
        tuple(str,str): problem detail type of the error and  textual
        description, or (None,None).
    """
    host = challenge.authorization.identifier.value

    if challenge.authorization.wildcard:
        host = host.removeprefix("*.")
        if not config["allowWildcards"]:
            return "rejectedIdentifier", f"wildcard certificate issuance disallowed"

    # Try to resolve the _acme-challenge record
    try:
        answers = dns.resolver.resolve(f"_acme-challenge.{host}", "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "dns", f"no TXT record found for _acme-challenge.{host}"
    except dns.resolver.NoNameservers as e:
        return "dnsNoNameServers", str(e)
    except dns.resolver.YXDOMAIN as e:
        return "dnsQueryTooLong", str(e)
    except dns.resolver.LifetimeTimeout as e:
        return "dnsTimeout", str(e)

    # Verify the expected challenge is present
    sha256_digest = hashlib.sha256(key_authorization(challenge).encode('utf-8')).digest()
    expect = base64.urlsafe_b64encode(sha256_digest).rstrip(b"=")
    for answer in answers:
        if expect == answer.strings[0]:
            break
    else:
        return "incorrectResponse", f"no token found in TXT record {expect}"

    return None, None  # no error occurred :)


def alpn_challenge(challenge):  # RFC 8737 §3
    """ verify a TLS-ALPN-01 Challenge

    Args:
        challenge (Challenge): The TLS-ALPN-01 challenge to verify.

    Returns:
        tuple(str,str): problem detail type of the error and  textual
        description, or (None,None).
    """
    ALPN_PROTOCOL = "acme-tls/1"

    host = challenge.authorization.identifier.value

    context = ssl.SSLContext()  # server may return self-signed cert here
    context.set_alpn_protocols([ALPN_PROTOCOL])
    try:
        with socket.create_connection((host, 443)) as sock, context.wrap_socket(
            sock, server_hostname=host
        ) as ssock:
            remote_ip, *_ = ssock.getpeername()

            reject = additional_ip_address_checks(remote_ip, host)
            if reject:
                return "rejectedIdentifier", reject

            if ssock.version() not in ("TLSv1.2", "TLSv1.3"):
                return "unauthorized", f"could not negotiate TLS 1.2 or higher"

            if ssock.selected_alpn_protocol() != ALPN_PROTOCOL:
                return "unauthorized", f"could not negotiate {ALPN_PROTOCOL!r}"

            cert = x509.load_der_x509_certificate(
                ssock.getpeercert(binary_form=True), x509_backend()
            )
    except (socket.error, ssl.SSLError, ValueError) as e:
        return "connection", str(e)

    try:
        san = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        if len(san) != 1 or san[0].value != host:
            san_list = [e.value for e in san]
            return "rejectedIdentifier", f"san is {san_list!r}, expected {[host]!r}"

        acmeIdentifier = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.31")  # RFC 8737 §6.1
        authorization = ber_parse(
            cert.extensions.get_extension_for_oid(acmeIdentifier).value.value
        )
        # Note: spec expects us to check criticality, but cryptography does not expose that.
    except (x509.extensions.ExtensionNotFound, AttributeError, ValueError) as e:
        return "unauthorized", "certificate does not have expected extensions"

    expect = hashlib.sha256(key_authorization(challenge).encode()).digest()
    if authorization != expect:
        return "incorrectResponse", "key authorization hashes don't match"

    return None, None  # no error occurred :)


def check_csr_and_return_cert(csr_der, order):
    """ validate CSR and pass to backend

    Checks that the CSR only contains domains from previously validated
    challenges and get a signed certificate from the backend.

    Args:
        csr_der (bytes): client's CSR in DER encoding
        order (Order): the order object that the CSR belongs to

    Returns:
        bytes: the signed certificate and chain in PEM format.

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

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    email = order.account.contact
    subject_dn = csr.subject.rfc4514_string()
    if config["forceTemplateDN"] or not subject_dn:
        subject_dn = config["subjectNameTemplate"].format(SAN=alt_names, MAIL=email)

    certificate, error = backend.sign(csr_pem, subject_dn, alt_names, email)

    if error:
        raise ACMEError(error, 400, "badCSR")

    if type(certificate) == str:
        certificate = certificate.encode("utf-8")

    return certificate


def key_authorization(challenge):
    """ build key authorization string from challenge

    Args:
        challenge (models.Challenge): a challenge object

    Returns:
        str: key authorization string
    """
    token = challenge.token
    thumbprint = jwcrypto.jwk.JWK.from_pem(
        challenge.authorization.order.account.jwk
    ).thumbprint()
    return f"{token}.{thumbprint}"


def additional_ip_address_checks(remote_ip, host):
    """ perform additional checks on the remote IP address

    These are useful in an enterprise setting, but not required by spec.

    Args:
        remote_ip (str): the IP address which we connected to for challenge
            verification
        host (str): dNSname which we resolved to get `remote_ip`

    Returns:
        Optional[str]: An error, if one occured, or None.
    """
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
