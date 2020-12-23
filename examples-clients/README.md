# Examples using different ACME clients

This directory contains a few scripts that ask the Serles ACME Server for a certificate. Some require a CSR; see `gen-csr.sh`.

These scripts will not run out of the box, but are supposed to be taken as
inspiration.

- [certbot]
- [ansible]
- [acme-tiny]
- [acme.sh]

[acme-tiny]: https://github.com/diafygi/acme-tiny
[acme.sh]: https://github.com/acmesh-official/acme.sh
[certbot]: https://certbot.eff.org/docs/using.html
[ansible]: https://docs.ansible.com/ansible/latest/modules/acme_certificate_module.html
