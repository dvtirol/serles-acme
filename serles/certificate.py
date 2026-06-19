import ipaddress

from cryptography import x509  # python3-cryptography.x86_64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .configloader import get_config
from .models import IdentifierTypes
from .exceptions import ACMEError


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
    config, backend = get_config()

    csr = x509.load_der_x509_csr(csr_der)
    try:
        san = csr.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        san_dns = san.get_values_for_type(x509.DNSName)
        san_ips = san.get_values_for_type(x509.IPAddress)
        alt_names = san_dns + san_ips
    except x509.extensions.ExtensionNotFound as e:
        san_dns = []
        san_ips = []
        alt_names = []

    try:
        common_name = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[
            0
        ].value
    except IndexError:
        if not alt_names:
            raise ACMEError("no identifiers in CSR", 400, "badCSR")
        common_name = alt_names[0]

    if not common_name in alt_names:  # chrome ignores CN, so write CN to SAN
        alt_names.insert(0, common_name)
        try:
            ip = ipaddress.ip_address(common_name)
            san_ips.insert(0, ip)
        except ValueError:
            san_dns.insert(0, common_name)

    # since we pass the CN and SANs to the backend, make sure the client only
    # specified those that we verified before (and that types match):
    order_identifiers = {(unstringify_ip(ident), ident.type) for ident in order.identifiers}
    csr_identifiers = {
        *((ident, IdentifierTypes.dns) for ident in san_dns),
        *((ident, IdentifierTypes.ip) for ident in san_ips),
    }

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

    if config["removeRootCAFromChain"]:
        certificate = remove_root_ca(certificate)

    return certificate


def unstringify_ip(ident):
    """ convert IP address identifiers to `ipaddress` objects

    cryptography.x509.SubjectAlternativeName.get_values_for_type returns IP
    addresses as IPv4Address/IPv6Address objects, not strings. This allows us
    to compare Order identifiers to them.

    Args:
        ident (Identifier): the identifier to convert based on its type

    Returns:
        str | IPv4Address | IPv6Address: converted value
    """

    if ident.type == IdentifierTypes.ip:
        return ipaddress.ip_address(ident.value)
    return ident.value


def remove_root_ca(pem_chain):
    """ Removes Root CA Certificate from PEM-Chain

    Some CAs return the full certificate chain, including the root certificate.
    RFC5246 §7.4.2 (c.f. 'certificate_list') explicitly allows omitting the
    final (self-signed) CA certificate. So we snip it off if requested.

    Args:
        pem_chain (bytes): concatenated PEM encoded certificates

    Returns:
        bytes: same certificates, but excluding the optional self-signed Root
    """

    certs = x509.load_pem_x509_certificates(pem_chain)

    if len(certs) > 1 and is_self_signed(certs[-1]):
        certs.pop(-1)

    return b"".join([
        cert.public_bytes(serialization.Encoding.PEM) for cert in certs
    ])


def is_self_signed(cert):
    """ Checks whether a certificate is self-signed.

    Args:
        cert (cryptography.x509.Certificate): certificate to test.

    Returns:
        bool: True iff the certificate is self-signed.
    """

    # Note: OpenSSL validates that cert.subject == cert.issuer && SKID == AKID,
    # but AKID is often absent on root certificates.

    try:
        cert.verify_directly_issued_by(cert)
    except (ValueError, TypeError, InvalidSignature):
        return False
    else:
        return True
