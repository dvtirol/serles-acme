Serles: A Tiny and Extensible ACME Server/Proxy
===============================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:
   :hidden:

   installation
   ejbca-configuration

   api
   genindex

Serles is a tiny ACME-CA implementation to enhance your existing Certificate
Authority infrastructure. Initially developed to support ACME with the Open
Source version of PrimeKey's EJBCA's (ACME support is only available in the
Enterprise version), the software is designed for easy adaptation to other PKI
software/CAs which provide an API to issue certificates.

We sometimes call it a proxy, as it delegates certificate issuance to your
existing PKI. From a user point of view serles-acme in combination with an EJBCA
instance can be compared to be something like your own private letsencrypt.

If you want to use another PKI project, feel free to implement your own
backends. Contributions are heavily welcome.

For whom is this project?

- You want to build up you own PKI, either for company or home usage
- You want to automate the issuing process for all your devices
- You already using another PKI Software and want to use certbot with it

Architecture
------------

Serles is intended to automate certificate issuance from your existing CA. It
will verify the legitimacy of certificate requests, and (if they are), pass
them on to a plugin/backend.

.. code-block:: text

  +--------+                            +---------+                        +---------+
  |        | (1) ---{authentication}--> |         |                        | Backend |
  |  Web   | (2) ---{order cert}------> | Serles  |                        |  (e.g.  |
  | Server | <-----{validation}-----(3) |  ACME   |                        |  EJBCA) |
  |        | (4) ---{CSR}-------------> |         | (5) ---{CSR}---------> |         |
  +--------+ <-----{certificate}--- (7) +---------+ <--{certificate}-- (6) +---------+

The threat model is *execution inside a (trusted) enterprise network*. Yet, care
has been taken when accepting any user data. While there is no user
authentication (i.e. anyone who can access Serles is allowed to ask for
certificates), one may specify to which IP subnets requested domains must
resolve to in order to be granted a certificate.

Installation
------------

See :ref:`installation`.

Configuration
-------------

The configuration file can be set using the ``CONFIG`` environment variable. If it
is absent, it is loaded from ``/etc/serles.ini``. An extensively commented
example configuration file is included as ``config.ini.example``. You may copy
(and rename) it to the beforementioned location. Serles is compatible with any
WSGI server; please consult your server's manual for its configuration.

Backends
--------

The software ships with one predefined backend, but it is easy to write others.
If you do, please send patches!

A backend is simply a class (no inheritance required) and has the following methods:

- a constructor taking the parsed config (``ConfigParser`` object; ``dict``-like)
- a method ``sign(self, csr, subjectDN, subjectAltNames, email)``:  
    Parameters:  

    - ``csr``: the CSR as coming from the client (in DER-encoded PKCS#10 format)
    - ``subjectDN``: The CSR's Distinguished Name as a string or, if absent, one
      created from the template string in the config file.
    - ``subjectAltNames``: a list of domain names (as strings) that are to be
      written in the certificate's SAN extension attributes.
    - ``email``: the email stored in the requesting account (or None).
      Intended to be passed on to the backend for notification of the client.
    
    Returns:  

    - on success, the tuple ``(chain_pkcs7_der, None)`` where ``chain_pkcs7_der``
      is the full DER-encoded PKCS#7 certificate chain.
    - on error, the tuple ``(None, error_msg)``, where ``error_msg`` is a string
      (possibly forwarded from the backend) that describes why the CSR has been
      rejected. This is forwarded to the client in a ``badCSR`` problem document.

.. code-block:: python

  class SomeBackend:
      def __init__(self, config):
          self.config = config
      def sign(self, csr, subjectDN, subjectAltNames, email):
          return None, "not implemented"

Optionally, one can also inherit from the abstract ``serles.backends.base``:

.. code-block:: python

  class SomeBackend(serles.backends.base):
      def sign(self, csr, subjectDN, subjectAltNames, email):
          return None, "not implemented"

EJBCA SOAP Backend
~~~~~~~~~~~~~~~~~~

All you need is a user that has permission_ to issue certificates. Set up a
Certificate Authority (e.g. testca), an End Entity Profile (e.g. acmeendentity)
and a Certificate Profile (e.g. acmeserverprofile). Set up and enroll a user
with a client certificate which will be used to talk to the API.

When issuing certificates, the Username and Enrollment Code will be generated
from a template. This template can be configured in the config; you can use
parameters from the Distinguished Name (from CSR) by wrapping them in curly
brackets.

If the client sets a contact email, we will pass it on to EJBCA when forwarding
the CSR. EJBCA can then be configured to send notifications for the
EndEntityProfile.

.. _permission: https://download.primekey.se/docs/EJBCA-Enterprise/latest/ws/org/ejbca/core/protocol/ws/client/gen/EjbcaWS.html#certificateRequest(org.ejbca.core.protocol.ws.client.gen.UserDataVOWS,java.lang.String,int,java.lang.String,java.lang.String)

Dependencies
------------

Dependencies are stated in ``setup.py``. If the available python-cryptography
version is less than 3.1, the openssl command line utility (somewhere in
``$PATH``) is required.

Notes on threads and databases
------------------------------

The database is used to hold the state between requests, but once an order has
been fulfilled (or rejected), all data relating to it is no longer used (and
actually deleted when the order expires, 7 days after its creation). It is
therefore sufficient to store this database in-memory. However, this in-memory
database is not thread safe. Depending on your requirements, either set
``database`` in ``config.ini`` to a on-disk DB, or (when using gunicorn) limit
the number of worker processes and threads to 1.

Note that certbot tries to re-use account IDs, so when using an in-memory DB
pass ``--pre-hook 'rm -rf /etc/letsencrypt/accounts'`` to it, to avoid this
behaviour.

Note that when using the EJBCA backend, you should only allow a single
connection at a time (i.e. single-threading), since there are concurrency
problems in the EJBCA software.
