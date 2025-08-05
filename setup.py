import re
from setuptools import setup, find_packages

# read README (actually docs/index.rst):
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()
    long_description = re.sub(r":ref:`(.*?)`", r"\1 `<https://serles-acme.readthedocs.io/en/latest/\1.html>`_", long_description)

setup(
    name="serles-acme",
    version="1.2.0",
    packages=find_packages(),
    python_requires=">=3.9",
    scripts=["bin/serles"],
    install_requires=[
        "flask",
        "Flask-RESTful",
        "Flask-SQLAlchemy",
        "requests",
        "jwcrypto",
        "cryptography >= 3.1",
        "dnspython",
        # for EJBCABackend:
        "requests",
        "zeep",
        # for docs:
        "docutils",
        # for bin/serles:
        "gunicorn",
    ],
    # metadata to display on PyPI
    author="Daten-Verarbeitung-Tirol GmbH",
    author_email="project.serles-acme@tirol.gv.at",
    description="""
        A tiny ACME (Automatic Certificate Management Environment) Server that
        passes actual issuance off to an existing PKI Certificate Authority.
        Extensible with plug-ins. Ships with an EJBCA Community backend.
    """,
    long_description=long_description,
    long_description_content_type='text/x-rst',
    keywords="pki ejbca acme server certbot",
    url="https://github.com/dvtirol/serles-acme",
    project_urls={
        "Bug Tracker": "https://github.com/dvtirol/serles-acme/issues",
        "Documentation": "https://serles-acme.readthedocs.io/",
        "Source Code": "https://github.com/dvtirol/serles-acme",
    },
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.12",
    ],
)
