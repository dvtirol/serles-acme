import jwcrypto.jwk  # fedora package: python3-jwcrypto.noarch
import jwcrypto.jws

from flask import g, make_response
from flask_restful import Resource, Api

from .utils import base64d
from .models import *
from .challenge import (
    init_config as c_init_config,
    verify_challenge,
    pkcs7_to_pem_chain,
    check_csr_and_return_cert,
)
from .exceptions import ACMEError

api = Api()


def init_config():
    c_init_config()


@api.resource("/")
class LandingPage(Resource):
    def get(self):
        """ return a 200 OK message on / so Users know what this is. """
        return "Serles ACME Server is running."


@api.resource("/directory")
class Directory(Resource):
    def get(self):
        """
        Displays the URLs for accessing certain functions, and some metadata.
        """
        return {
            "newNonce": api.url_for(NewNonce, _external=True),
            "newAccount": api.url_for(NewAccount, _external=True),
            "newOrder": api.url_for(NewOrder, _external=True),
            # "newAuthz": MUST be absent if pre-authorization not supported
            # "revokeCert": not offered
            # optional: meta:{termsOfService"",website"",caaIdentities[""],externalAccountRequired?}
        }


@api.resource("/newNonce")  # RFC8555 §7.2
class NewNonce(Resource):
    """ Lets the client fetch a nonce, if they ran out of 'em. """

    # Note: the replay-nonce header is injected in a @after_request handler.
    def head(self):
        return "", 200, {"Cache-Control": "no-store"}

    def get(self):
        return "", 204, {"Cache-Control": "no-store"}


@api.resource("/newAccount")  # RFC8555 §7.3
class NewAccount(Resource):
    def post(self):
        """
        Request a new Account or get the Key ID associated with a JSON Web Key.
        """
        contact = g.payload.get("contact", [])
        contact = contact[0] if len(contact) > 0 else None  # only 1 email!
        if contact and not contact.startswith("mailto:"):
            raise ACMEError("only (one) email supported", 400, "unsupportedContact")
        if contact:
            contact = contact.replace("mailto:", "")
        termsOfServiceAgreed = g.payload.get("termsOfServiceAgreed", False)
        onlyReturnExisting = g.payload.get("onlyReturnExisting", False)

        # Note: we don't require clients to accept our terms of service.

        # To store the key in the database, and to compare a new key with
        # existing ones, we need to serialize it in a stable way. For this, we
        # arbitrarily chose the PEM format, as jwcrypto has support for it.
        jwk_pem = jwcrypto.jwk.JWK(**g.jwk).export_to_pem()

        account = Account.query.filter_by(jwk=jwk_pem).first()
        if account:  # this jwk is already registered; RFC8555 §7.3.1
            # Note: we don't handle account key rollover, since accounts aren't
            # persistent (§7.3.5/.6).
            preexisting = True
        elif onlyReturnExisting:
            raise ACMEError("", 400, "accountDoesNotExist")
        else:  # At this point, the user has no account, but wants one
            account = Account(jwk=jwk_pem, contact=contact)
            db.session.add(account)
            db.session.commit()  # note: accessing `account` after the commit requires setting expire_on_commit=False
            preexisting = False

        return (
            account.serialized,
            200 if preexisting else 201,
            {"Location": account.url},
        )


@api.resource("/newOrder")  # RFC8555 §7.4
class NewOrder(Resource):
    def post(self):
        """
        Submit a new Order. The request will include a list of Identifers
        (domain names) the client wants on the certificate.
        """
        notBefore = g.payload.get("notBefore")  # optional, we ignore it for now
        notAfter = g.payload.get("notAfter")  # optional, we ignore it for now
        identifiers = g.payload.get("identifiers")
        if not identifiers:
            raise ACMEError("no identifiers", 400, "malformed")

        # we check all the identifiers (i.e. domain names the client wants a
        # certificate for) and add them to the Order we store. If any
        # identifiers are not accepted, the whole order will be aborted.
        requested_identifiers = []
        required_authorizations = []
        for identifier in identifiers:
            if not "type" in identifier or not "value" in identifier:
                raise ACMEError("identifier not valid", 400, "malformed")
            type_ = identifier.get("type")
            value = identifier.get("value")
            if type_ != "dns":
                raise ACMEError(
                    "can only do 'dns' type identifiers", 400, "rejectedIdentifier"
                )

            identifier = Identifier(type=IdentifierTypes(type_), value=value)
            db.session.add(identifier)
            challenges = [Challenge(type=ChallengeTypes.http_01)]
            for c in challenges:
                db.session.add(c)
            authz = Authorization(identifier=identifier, challenges=challenges)
            db.session.add(authz)
            requested_identifiers.append(identifier)
            required_authorizations.append(authz)

        account = Account.query.filter_by(id=g.kid).first()
        if not account:
            raise ACMEError("", 400, "accountDoesNotExist")
        order = Order(
            account=account,
            identifiers=requested_identifiers,
            authorizations=required_authorizations,
            notBefore=notBefore,
            notAfter=notAfter,
        )

        db.session.add(order)
        db.session.commit()  # note: accessing `order` after the commit requires setting expire_on_commit=False
        return (
            order.serialized,
            201,
            {"Location": api.url_for(OrderMain, orderid=order.id)},
        )


@api.resource("/newAuthz")  # RFC8555 §7.4.1 (Pre-authorization, not offered)
class NewAuthz(Resource):
    "not offered."
    pass


@api.resource("/revokeCert")  # RFC8555 §7.6 (Certificate Revocation, not offered)
class RevokeCert(Resource):
    "not offered."
    pass


@api.resource("/account/<kid>")  # RFC8555 §7.3.2 (Account Management)
class AccountMain(Resource):
    def post(self, kid):
        """
        View or update the specified Account object.

        Args:
            kid: JSON Web Key ID that identifies the account

        Returns:
            JSON-serialized Account object (post-update).
        """
        if kid != g.kid:
            raise ACMEError(f"{kid}, {g.kid}Unexpected Account ID", 403, "unauthorized")
        account = Account.query.filter_by(id=kid).first()
        if not account:
            raise ACMEError("", 400, "accountDoesNotExist")

        # this endpoint is also used to update the account information. E.g,
        # acme_tiny uses it to set (even for new accounts) the contact email.
        contact = g.payload.get("contact", None)
        if contact is not None:
            contact = contact[0] if len(contact) > 0 else None  # only 1 email!
            if contact and not contact.startswith("mailto:"):
                raise ACMEError("only (one) email supported", 400, "unsupportedContact")
            if contact:
                contact = contact.replace("mailto:", "")
            account.contact = contact
            db.session.commit()  # note: accessing `account` after the commit requires setting expire_on_commit=False

        return account.serialized


# Note: since we send the orders list with all account objects anyways, there's
# no need for a separate route implementation.
@api.resource("/account/<kid>/orders")  # RFC8555 §7.1.2.1 (Orders List)
class AccountOrders(AccountMain):
    "see `AccountMain`."
    pass


@api.resource("/order/<orderid>")
class OrderMain(Resource):
    def post(self, orderid):
        """
        View the specified Order object.
        Args:
            orderid:

        Returns:
            JSON-serialized Order object.
        """
        order = Order.query.filter_by(id=orderid).first()
        if not order:
            raise ACMEError("Order does not exist", 404, "malformed")
        if not order.account_id == g.kid:
            raise ACMEError("Unexpected Account ID", 403, "unauthorized")
        return order.serialized


@api.resource("/order/<orderid>/finalize")  # RFC8555 page 47
class OrderFinalize(Resource):
    def post(self, orderid):
        """
        Upload CSR and (if order is ready) start issuance process.

        Returns:
            JSON-serialized Order object, now including a certificate id.
        """
        csr = base64d(g.payload.get("csr"))
        order = Order.query.filter_by(id=orderid).first()
        if not order:
            raise ACMEError("Order does not exist", 404, "malformed")
        if not order.account_id == g.kid:
            raise ACMEError("Unexpected Account ID", 403, "unauthorized")
        if order.status != OrderStatus.ready:
            raise ACMEError("", 403, "orderNotReady")

        certificate = check_csr_and_return_cert(csr, order)

        cert = Certificate(certificate=certificate)
        db.session.add(cert)
        order.status = OrderStatus.valid
        order.certificate = cert
        db.session.commit()  # note: accessing `cert` (as we do indirectly from order.serialized) after the commit requires setting expire_on_commit=False

        return order.serialized


@api.resource("/authorization/<authid>")  # RFC8555 §7.5
class AuthorizationMain(Resource):
    def post(self, authid):
        """
        View the specified Authorization object that contains challenges.

        Args:
            authid:

        Returns:
            JSON-serialized Authorization object.
        """
        authz = Authorization.query.filter_by(id=authid).first()
        if not authz:
            raise ACMEError("Authorization does not exist", 404, "malformed")
        if not authz.order.account_id == g.kid:
            raise ACMEError("Unexpected Account ID", 403, "unauthorized")
        return authz.serialized


@api.resource("/challenge/<challid>")  # RFC8555 §7.5.1
class ChallengeMain(Resource):
    """
    Once the client calls this endpoint, we can start verifying the challenge.
    """

    def post(self, challid):
        challenge = Challenge.query.filter_by(id=challid).first()
        if not challenge:
            raise ACMEError("Challenge does not exist", 404, "malformed")
        if not challenge.authorization.order.account_id == g.kid:
            raise ACMEError("Unexpected Account ID", 403, "unauthorized")
        challenge.status = ChallengeStatus.processing

        verify_challenge(challenge)  # sets challenge.status, raises on error

        authid = challenge.authz_id
        return (
            challenge.serialized,
            200,
            {"Link": f"<{api.url_for(AuthorizationMain, authid=authid)}>;rel=up"},
        )


@api.resource("/cert/<certid>")
class CertificateMain(Resource):
    def post(self, certid):
        """
        Download the specified certificate. Only the client who requested the
        order may access it.

        Args:
            certid:

        Returns:
            PEM encoded certificate chain.
        """
        cert = Certificate.query.filter_by(id=certid).first()
        if not cert:
            raise ACMEError("Certificate does not exist", 404, "malformed")

        if not cert.order.account.id == g.kid:
            raise ACMEError(
                "certificate was not generated for this user", 403, "unauthorized"
            )

        cert = cert.serialized

        pem_cert = pkcs7_to_pem_chain(cert)

        return make_response(
            pem_cert, 200, {"Content-Type": "application/pem-certificate-chain"}
        )
