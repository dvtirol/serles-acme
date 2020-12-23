#!/usr/bin/env python3

from serles import create_app

if __name__ == "__main__":
    create_app().run(host="::0", port=8443, ssl_context="adhoc")
