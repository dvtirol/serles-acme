import uuid
import json
import secrets

from enum import Enum
from datetime import datetime, timezone, timedelta

from flask_sqlalchemy import SQLAlchemy  # python3-flask-sqlalchemy.noarch
from sqlalchemy.ext.hybrid import hybrid_property

from . import views

db = SQLAlchemy(session_options={"expire_on_commit": False})

# Note: .serialized provides a dict() that gets jsonified by flask_restful.
class UTCDateTime(db.TypeDecorator):
    """
    SQLite stores datetimes without TZ info, and SQLAlchemy then returns
    TZ-naive datetimes. This breaks calculating timedeltas. So this wrapper
    converts incoming timestamps to UTC before storing and adds the TZ (utc)
    back on retrieval.
    """

    impl = db.DateTime

    def process_bind_param(self, val, _):
        return val.astimezone(timezone.utc) if val else None

    def process_result_value(self, val, _):
        return val.replace(tzinfo=timezone.utc) if val else None


class OrderStatus(Enum):
    """ `RFC 8555 § 7.1.6 (Fig.3) <https://tools.ietf.org/html/rfc8555#page-33>`_ """

    pending = "pending"
    ready = "ready"
    processing = "processing"
    valid = "valid"
    invalid = "invalid"


class Order(db.Model):  # RFC8555 §7.1.3
    """
    In ACME lingo, an Order identifies a client's request for a certificate. It
    keeps a list of Identifiers (domain names) requested from the client, a
    list of Authorizations (see below), and (once we decided to issue one) the
    certificate.
    """

    id = db.Column(db.String(45), primary_key=True, default=lambda: uuid.uuid4().urn)
    status = db.Column(db.Enum(OrderStatus), default=OrderStatus.pending)
    expires = db.Column(
        UTCDateTime, default=lambda: datetime.now(timezone.utc) + timedelta(days=7)
    )
    identifiers = db.relationship(
        "Identifier", backref=db.backref("order"), cascade="all, delete"
    )
    notBefore = db.Column(db.DateTime)
    notAfter = db.Column(db.DateTime)
    error = db.Column(db.Text)
    authorizations = db.relationship(
        "Authorization", backref=db.backref("order"), cascade="all, delete"
    )
    certificate = db.relationship(
        "Certificate", backref=db.backref("order"), cascade="all, delete", uselist=False
    )
    account_id = db.Column(db.String(45), db.ForeignKey("account.id"))

    @hybrid_property
    def finalize(self):
        return views.api.url_for(views.OrderFinalize, orderid=self.id, _external=True)

    @property
    def serialized(self):
        # fmt: off
        return {k:v for k,v in {
            "status": self.status.value, # required
            "expires": self.expires.isoformat() if self.expires else None, # required
            "identifiers": [ident.serialized for ident in self.identifiers], # required
            "notBefore": self.notBefore.isoformat() if self.notBefore else None,  # optional
            "notAfter": self.notAfter.isoformat() if self.notAfter else None,  # optional
            "error": json.loads(self.error) if self.error else None, # optional
            "authorizations": [authz.url for authz in self.authorizations], # required
            "finalize": self.finalize,  # required
            "certificate": self.certificate.url if self.certificate else None,  # optional
        }.items() if v is not None}
        # fmt: on


class IdentifierTypes(Enum):
    dns = "dns"


class Identifier(db.Model):
    """
    An Identifier is essentially a domain name and some metadata.
    """

    id = db.Column(db.String(45), primary_key=True, default=lambda: uuid.uuid4().urn)
    type = db.Column(db.Enum(IdentifierTypes), default=IdentifierTypes.dns)
    value = db.Column(db.Text, nullable=False)
    order_id = db.Column(db.String(45), db.ForeignKey("order.id"))
    authz_id = db.Column(db.String(45), db.ForeignKey("authorization.id"))

    @property
    def serialized(self):
        # fmt: off
        return {
            "type": self.type.value,
            "value": self.value,
        }
        # fmt: on


class AuthzStatus(Enum):
    """ `RFC 8555 § 7.1.6 (Fig.2) <https://tools.ietf.org/html/rfc8555#page-32>`_ """

    pending = "pending"
    valid = "valid"
    invalid = "invalid"
    deactivated = "deactivated"
    expired = "expired"
    revoked = "revoked"


class Authorization(db.Model):  # RFC8555 §7.1.4
    """
    For each Identifier (domain name) the client requested in an Order, there
    is a Authorization. To obtain a certificate, the client must satisfy all of
    them. To satisfy an Authorization, the client can solve any one of the
    Challenges within (i.e., only 1 Challenge per Authorization is required).
    """

    id = db.Column(db.String(45), primary_key=True, default=lambda: uuid.uuid4().urn)
    identifier = db.relationship(
        "Identifier",
        backref=db.backref("authorization"),
        cascade="all, delete",
        uselist=False,
    )
    status = db.Column(db.Enum(AuthzStatus), default=AuthzStatus.pending)
    expires = db.Column(
        UTCDateTime, default=lambda: datetime.now(timezone.utc) + timedelta(days=7)
    )
    challenges = db.relationship(
        "Challenge", backref=db.backref("authorization"), cascade="all, delete"
    )
    wildcard = db.Column(db.Boolean, default=False)
    order_id = db.Column(db.String(45), db.ForeignKey("order.id"))

    @hybrid_property
    def url(self):
        return views.api.url_for(
            views.AuthorizationMain, authid=self.id, _external=True
        )

    @property
    def serialized(self):
        # fmt: off
        return {k:v for k,v in {
            "identifier": self.identifier.serialized, # required
            "status": self.status.value, # required
            "expires": self.expires.isoformat() if self.expires else None,  # required
            "challenges": [chall.serialized for chall in self.challenges], # required
            "wildcard": self.wildcard, # optional
        }.items() if v is not None}
        # fmt: on


class ChallengeTypes(Enum):
    http_01 = "http-01"
    dns_01 = "dns-01"


class ChallengeStatus(Enum):
    """ `RFC 8555 § 7.1.6 (Fig.1) <https://tools.ietf.org/html/rfc8555#page-31>`_ """

    pending = "pending"
    processing = "processing"
    valid = "valid"
    invalid = "invalid"


class Challenge(db.Model):  # RFC8555 §7.1.5
    """
    A completed Challenge satisfies an Authorization. We support the HTTP-01
    challenge type, which requires the client to temporarily serve a short text
    string on a location we decide.
    """

    id = db.Column(db.String(45), primary_key=True, default=lambda: uuid.uuid4().urn)
    type = db.Column(db.Enum(ChallengeTypes), nullable=False)
    status = db.Column(db.Enum(ChallengeStatus), default=ChallengeStatus.pending)
    validated = db.Column(UTCDateTime)
    error = db.Column(db.Text)
    # http-01, dns-01
    token = db.Column(
        db.Text, nullable=False, default=lambda: secrets.token_urlsafe(32)
    )

    @hybrid_property
    def url(self):
        return views.api.url_for(views.ChallengeMain, challid=self.id, _external=True)

    authz_id = db.Column(db.String(45), db.ForeignKey("authorization.id"))

    @property
    def serialized(self):
        # fmt: off
        return {k:v for k,v in {
            "type": self.type.value, # required
            "url": self.url, # required
            "status": self.status.value,  # required
            "validated": self.validated.isoformat() \
                    if self.status == ChallengeStatus.valid else None,  # required if valid
            "error": json.loads(self.error) if self.error else None, # optional
            "token": self.token,
        }.items() if v is not None}
        # fmt: on


class Certificate(db.Model):
    """
    Pretty much what it says on the tin. Stored in the database for the short
    time between the client requesting finalization of their order and them
    fetching the cert from us.
    """

    id = db.Column(db.String(45), primary_key=True, default=lambda: uuid.uuid4().urn)
    certificate = db.Column(db.LargeBinary)

    @hybrid_property
    def url(self):
        return views.api.url_for(views.CertificateMain, certid=self.id, _external=True)

    order_id = db.Column(db.String(45), db.ForeignKey("order.id"))

    @property
    def serialized(self):
        # fmt: off
        return self.certificate
        # fmt: on


class AccountStatus(Enum):
    """ `RFC 8555 § 7.1.6 <https://tools.ietf.org/html/rfc8555#page-33>`_ """

    valid = "valid"
    deactivated = "deactivated"
    revoked = "revoked"


class Account(db.Model):  # RFC8555 §7.1.2
    """
    To avoid having to send the large public key for each request, a client
    registers an Account and identifies themselves using the key id. On
    letsencrypt, accounts persist over a long time, and some clients will try
    to keep using it. Certbot is especially bad at this, as it fails when the
    account it expects doesn't exist. This object also stores an optional
    contact email address, which we pass to the backend (e.g. for notifications
    regarding certificate expiry).
    """

    id = db.Column(db.String(45), primary_key=True, default=lambda: uuid.uuid4().urn)
    jwk = db.Column(db.LargeBinary)  # PEM encoded public key
    status = db.Column(db.Enum(AccountStatus), default=AccountStatus.valid)
    orders = db.relationship(
        "Order", backref=db.backref("account"), cascade="all, delete"
    )
    contact = db.Column(db.Text)
    # termsOfServiceAgreed = db.Column(db.Boolean)
    # externalAccountBinding # object
    @hybrid_property
    def url(self):
        return views.api.url_for(views.AccountMain, kid=self.id, _external=True)

    @hybrid_property
    def orders_url(self):
        return views.api.url_for(views.AccountOrders, kid=self.id, _external=True)

    @property
    def serialized(self):
        # fmt: off
        return {k:v for k,v in {
            "status": self.status.value, # required
            "contact": [self.contact], # we only support 1 email
            "orders": self.orders_url, # required
            #termsOfServiceAgreed # optional
            #externalAccountBinding # optional
        }.items() if v is not None}
        # fmt: on


class Nonces(db.Model):
    """
    To avoid replay attacks, each HTTP POST request must come with a nonce we
    issued.
    """

    value = db.Column(
        db.String(22), primary_key=True, default=lambda: secrets.token_urlsafe(16)
    )
    expires = db.Column(
        UTCDateTime, default=lambda: datetime.now(timezone.utc) + timedelta(hours=1)
    )

    @classmethod
    def new(cls):
        nonce = cls()
        db.session.add(nonce)
        db.session.commit()
        return nonce.value

    @classmethod
    def check(cls, value):
        """ returns True iff the nonce is valid (not yet used) """
        nonce = cls.query.filter(cls.value == value)
        if nonce.count():
            nonce.delete()
            db.session.commit()
            return True
        return False

    @classmethod
    def purge_expired(cls):
        cls.query.filter(cls.expires < datetime.now(timezone.utc)).delete()
        db.session.commit()
