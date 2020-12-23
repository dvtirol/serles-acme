from datetime import datetime, timezone
from flask import Flask

from .utils import background_job, base64d, query, get_ptr, ip_in_ranges, normalize
from .configloader import get_config
from .views import *  # Note: import views before models!
from .models import *
from .exceptions import ACMEError
from .flask_handlers import parse_jws, inject_nonce, index_header, exception_handler


def create_app():
    """ initialize web app

    This function should be passed to the WSGI server.
    """
    config, _ = get_config()

    app = Flask(__name__)
    app.config["PROPAGATE_EXCEPTIONS"] = True  # makes @app.errorhandler handle events
    app.config["SQLALCHEMY_DATABASE_URI"] = config["database"]
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    init_config()  # views.init_config()
    api.init_app(app)
    db.init_app(app)
    db.create_all(app=app)  # Note: model classes must be defined at this point

    app.register_error_handler(Exception, exception_handler)
    app.before_request(parse_jws)
    app.after_request(inject_nonce)
    app.after_request(index_header)

    @background_job(60)  # purge unused nonces every minute (keeps database small)
    def purge_nonces():
        with app.app_context():
            Nonces.purge_expired()

    @background_job(24 * 60 * 60)  # once daily, remove expired Orders
    def purge_orders():
        with app.app_context():
            for order in Order.query.filter(
                Order.expires < datetime.now(timezone.utc)
            ).all():
                db.session.delete(order)
            db.session.commit()

    return app
