import base64
import ipaddress
import dns.resolver  # fedora package: python3-dns.noarch
import dns.reversename
from threading import Timer


def background_job(interval):
    """ executes the decorated function in an interval

    A very simple "cron" replacement: decorate a function to call it in its own
    thread in a given interval.

    Args:
        interval (int): number of seconds between executions.
    """

    def wrapper(f):
        f()
        t = Timer(interval, wrapper, args=(f,))
        t.setDaemon(True)
        t.start()

    return wrapper


def base64d(s):
    """ padding-ignoring base64-decoder

    ACME uses url-safe base64, but does not add padding. Python's base64 lib
    throws an exception on wrong padding, so we add it for it.

    Args:
        s (str): input to decode.

    Returns:
        bytes: decoded input.
    """

    return base64.urlsafe_b64decode(s + "===")


def query(qname, rdtype):
    """ Query DNS records without raising an exception.

    Args:
        qname (str): query name.
        rdtype (str): query type.

    Returns:
        list: results, or the empty list on error.
    """
    try:
        if hasattr(dns.resolver, "resolve"):  # dnspython 2.x
            return dns.resolver.resolve(qname, rdtype, search=True)
        else:  # dnspython 1.x
            return dns.resolver.query(qname, rdtype)
    except dns.resolver.NXDOMAIN:
        return []


def get_ptr(ipaddr):
    """ resolve an IP address to a domain name.

    Args:
        ipaddr (str): query.

    Returns:
        str: FQDN, or None.

    """
    ptr = query(dns.reversename.from_address(ipaddr), "PTR")
    return str(ptr[0]) if ptr else None


def ip_in_ranges(ipaddr, ranges):
    """ check whether the given IP is in any of the given subnets.

    Args:
        ipaddr (str): IP to check.
        ranges (list): list of ipaddress.IPv4Network or ipaddress.IPv6Network.

    Returns:
        bool: True if it is, False if it isn't.
    """
    for ipRange in ranges:
        if ipaddress.ip_address(ipaddr) in ipRange:
            return True
    return False


def normalize(domain):
    """ don't differentiate between FQDN and PartiallyQDN, ignore case

    Args:
        domain (str): domain name to normalize.

    Returns:
        str: normalized domain name.
    """
    return domain.rstrip(".").lower() if domain else None
