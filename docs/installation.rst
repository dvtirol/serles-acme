.. |ejbca-host| replace:: localhost:9443

.. _installation:

Setting up Serles with Gunicorn
===============================

In this document we will describe a production-ready setup of Serles using
Gunicorn.

Installation
------------

.. code-block:: shell

    python3 -m venv /opt/serles_venv
    . /opt/serles_venv/bin/activate
    python3 -m pip install serles-acme

In order to run Serles in production, you will need a WSGI HTTP(s) server. We
have chosen gunicorn for this example, which ships with Serles. You do not have
to use a virtual environment; all dependencies should also be packaged by your
distribution.

Configuration
-------------

Copy the (fully commented) sample configuration file ``config.ini.example`` to
``/etc/serles/config.ini`` and modify it to suit your environment.

The included ``/bin/serles`` executable will load gunicorn configuration from
``/etc/serles/gunicorn_config.py``.

For gunicorn, the ``APP_MODULE`` string is ``serles:create_app()``.
Please see the `gunicorn configuration documentation
<https://docs.gunicorn.org/en/stable/settings.html>`_ for TLS and port binding.

Below is an example systemd unit file, that uses its own gunicorn from a
virtual environment:

.. code-block:: none

    [Unit]
    Description=gunicorn daemon for Serles
    After=network.target
    
    [Service]
    PIDFile=/run/acmeproxy/pid
    RuntimeDirectory=acmeproxy
    Environment="PATH=/opt/serles_venv/bin:/usr/bin"
    ExecStart=/opt/serles_venv/bin/gunicorn -c /etc/serles/gunicorn_config.py "serles:create_app()"
    ExecReload=/bin/kill -HUP $MAINPID
    PrivateTmp=true
    
    [Install]
    WantedBy=multi-user.target

Note that the selected backend will have to be configured as well; for the
included EJBCA backend see for example :ref:`ejbca-configuration`.

Database
--------

Serles requires a relational database for storing registered accounts and for
holding the state of orders between HTTP requests. Some clients (notably
certbot) assume that after they registered with an ACME server once, their
public key will be known to that service in perpetuity - and get very upset
when Serles forgets about them. For this reason, this database must be
persistent, and the ``Account`` table may not get truncated. All other data can
be ephemeral, and is in fact purged by Serles automatically on a regular
schedule.

For most deployments, an SQLite database is sufficient. If you are expecting
multiple simultaneous requests to occur regularly, you should consider
configuring Serles to use a client-server database like MySQL/MariaDB instead.

In principle, all `databases supported by SQLAlchemy
<https://docs.sqlalchemy.org/en/stable/dialects/>`_ should be supported.
