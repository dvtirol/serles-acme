.. |ejbca-host| replace:: localhost:9443

.. _ejbca-configuration:

EJBCA Dev Environment Quickstart
================================

This document describes the steps necessary to install and setup a minimal
EJBCA instance for testing Serles.

Installing EJBCA Community
-----------------------

.. code-block:: shell

    docker pull primekey/ejbca-ce
    docker run -it -p 9980:8080 -p 9443:8443 -h ejbca-test -e TLS_SETUP_ENABLED="simple" primekey/ejbca-ce

These commands expose the Web UI on Port 9443 using a self-signed certificate
(Note that the SOAP-API cannot be accessed over plain text). Port 8443 is the
default port of Serles, so we will use 9443 for EJBCA.

Configuring EJBCA for use with Serles
-----------------------------------

1. Create a Certificate Authority

    :ejbca:`Certification Authorities <adminweb/ca/editcas/editcas.jsp>`

    suggested name: *ACMECA*

2. Create a Certification Profile

    :ejbca:`Certificate Profiles <adminweb/ca/editcertificateprofiles/editcertificateprofiles.jsf>`

    suggested name: *ACMEServerProfile*

    Notes: Set *Extended Key Usage* to *Server Authentication*.

3. Create End Entity Profile

    :ejbca:`End Entity Profiles <adminweb/ra/editendentityprofiles/editendentityprofiles.jsp>`

    suggested name: *ACMEEndEntityProfile*

    Notes: Add a few *DNS Name* entries to the allowed *Subject Alternative
    Name* *Other subject attributes* and under *Main certificate data* set the
    CA to the one from Step 1, and the Certificate Profile to the one from Step 2.

4. Create a Certificate Profile for the API client:

    :ejbca:`Certificate Profiles <adminweb/ca/editcertificateprofiles/editcertificateprofiles.jsf>`

    suggested name: *APIClientProfile*

    Notes: Set *Extended Key Usage* to *Client Authentication*. The CA should
    be the *ManagementCA*.

5. Create a End Entity Profile for the client certificate:

    :ejbca:`End Entity Profiles <adminweb/ra/editendentityprofiles/editendentityprofiles.jsp>`

    suggested name: *APIClientEntityProfile*

    Notes: Under *Main certificate data* set it to use *APIClientProfile* and
    *ManagementCA*.

6. Create a user for the API:

    :ejbca:`Add End Entity <adminweb/ra/addendentity.jsp>`

    suggested name: *client01*

    Notes: Use the *End Entity Profile* from Step 5 and set Common Name to same
    as username.

7. Create user role for acme-client-cert:

    :ejbca:`Administrator Roles <adminweb/administratorprivileges/roles.xhtml>`

    suggested name: *ACMEUser*

    Notes: Set *Access Rules* using *Advanced Mode* to allow the following_:

	 - ``/administrator``
	 - ``/ca_functionality/create_certificate``
	 - ``/ra_functionality/create_end_entity``
	 - ``/ra_functionality/edit_end_entity``
	 - ``/ca/<CA_OF_USER>`` (using CA from Step 1)
	 - ``/endentityprofilesrules/<END_ENTITY_PROFILE_OF_USER>/create_end_entity``
	 - ``/endentityprofilesrules/<END_ENTITY_PROFILE_OF_USER>/edit_end_entity``
           (using End Entity Profile from Step 3)

.. _following: https://download.primekey.se/docs/EJBCA-Enterprise/latest/ws/org/ejbca/core/protocol/ws/client/gen/EjbcaWS.html#certificateRequest(org.ejbca.core.protocol.ws.client.gen.UserDataVOWS,java.lang.String,int,java.lang.String,java.lang.String)

8. Add ACMEUser to the new usergroup/role:

    :ejbca:`Administrator Roles <adminweb/administratorprivileges/roles.xhtml>`

    Notes: Set the *Members* of the Administrator Role from Step 7 to match
    (e.g. on CN and CA) the client entity from Step 6.

9. Issue a certificate for the user

    :ejbca:`Create Certificate from CSR <enrol/server.jsp>` or :ejbca:`EJBCA RA-Request new certificate <https://localhost:9443/ejbca/ra/enrollmakenewrequest.xhtml>`

    Notes:

      - ``openssl req -newkey rsa:2048 -keyout client01.key -out client01.csr -nodes -subj /CN=client01``
      - upload CSR, then download certificate (``client01.pem``)
      - ``cat client01.key client01.pem > client01-privpub.pem``
