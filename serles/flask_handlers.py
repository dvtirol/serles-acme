import json
import jwcrypto.jwk  # fedora package: python3-jwcrypto.noarch
import jwcrypto.jws

from flask import g, request, jsonify, make_response, current_app
from werkzeug.exceptions import HTTPException

from .utils import base64d
from .views import *  # Note: import views before models!
from .models import *
from .exceptions import ACMEError


def parse_jws():  # RFC8555 §6.2
    """
    Verify that the signature is as specified by the RFC, and make the payload
    available to all POST views using Flask's "g" object. Note that we aren't
    fully checking every detail, just the security relevant ones.
    Note also that we don't support key rollover (as required by spec).

    This function is registered as a before_request handler and augments the
    ``g`` object with the following attributes:
    - ``g.payload``: the actually interesting request data, JSON-decoded
    - ``g.kid``: the JWK key id (in our case a uuid) of the user, if known
    - ``g.jwk``: the JWK public key, when a user tries to register

    Raises:
        ACMEError: The request was not understood or not authorized.
    """

    if request.method != "POST":
        return

    if request.mimetype != "application/jose+json":
        raise ACMEError("expected application/jose+json", 405, "malformed")

    if not "protected" in request.json:
        raise ACMEError("no 'protected' field in request", 400, "malformed")

    protected = json.loads(base64d(request.json.get("protected")))
    if "kid" in protected:  # existing user
        (_, _, kid) = protected["kid"].rpartition("/")
        account = Account.query.filter_by(id=kid).first()
        if not account:
            raise ACMEError("unknown key id", 400, "accountDoesNotExist")
        key = jwcrypto.jwk.JWK.from_pem(account.jwk)
        g.kid = kid
    elif "jwk" in protected:  # new user trying to access /newAccount
        jwk = protected["jwk"]
        key = jwcrypto.jwk.JWK(**jwk)
        g.jwk = jwk
    else:
        raise ACMEError("no public key or key id", 400, "unauthorized")

    jws = jwcrypto.jws.JWS()
    assert "none" not in jws.allowed_algs

    try:
        jws.deserialize(request.data, key)
    except jwcrypto.jws.InvalidJWSSignature as e:
        raise ACMEError("signed with invalid or wrong key", 403, "unauthorized")

    if not "nonce" in jws.jose_header or not Nonces.check(jws.jose_header["nonce"]):
        raise ACMEError("nonce invalid", 400, "badNonce")
    if not "url" in jws.jose_header or jws.jose_header["url"] != request.url:
        raise ACMEError("url doesn't match", 400, "unauthorized")

    # make available to view function:
    g.payload = json.loads(jws.payload) if jws.payload else {}


def inject_nonce(response):
    response.headers.extend({"Replay-Nonce": Nonces.new()})
    return response


def index_header(response):  # RFC 8555 §7.1
    response.headers.extend(
        {"Link": f"<{api.url_for(Directory, _external=True)}>;rel=index"}
    )
    return response


def exception_handler(error):
    """
    This function is called by Flask when an exception is raised. We use the
    our ACMEError to return errors for failed API requests. Other exceptions
    are caught and transformed into an Internal Server Error and we log the
    exception for later review.
    Responses are in Problem Details format (RFC7807), albeit only with minimal
    content.
    """
    if isinstance(error, ACMEError):
        status = error.status
        error_type = error.error_type
        error_details = str(error)
    elif isinstance(error, HTTPException):
        status = error.code
        error_type = "malformed"  # there isn't really anything well-fitting.
        error_details = error.description
    else:
        status = 500
        error_type = "serverInternal"
        error_details = str(error)

    current_app.logger.error(f"{error_type} ({status}): {error_details}")

    if status >= 500:
        import traceback

        current_app.logger.error(traceback.format_exc())

    # wrapping into make_response, or flask-restful will overwrite content-type:
    return make_response(
        jsonify(
            {
                "type": f"urn:ietf:params:acme:error:{error_type}",
                "detail": error_details,
            }
        ),
        status,
        {"Content-Type": "application/problem+json"},
    )
