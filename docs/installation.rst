.. |ejbca-host| replace:: localhost:9443

Setting up Serles with Gunicorn
===============================

In this document we will describe a production-ready setup of Serles using
Gunicorn.

1. Installation
---------------

.. code-block:: shell

    python3 -m venv /opt/serles_venv
    . /opt/serles_venv/bin/activate
    python3 setup.py install  #inside serles/

In order to run Serles in production, you will need a WSGI HTTP(s) server. We
chose gunicorn for this example, which ships with Serles. You do not have to
use a virtual environment; all dependencies should also be packaged by your
distribution.

2. Configuration
----------------

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
