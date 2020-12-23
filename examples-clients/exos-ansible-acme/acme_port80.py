# challenge verification server. to be temporarily started by ansible.
# workflow:
# 1. use "configure ssl csr ..." to create a csr
# 2. using a python script, copy the privkey to /config/
# 3. download the csr to the ansible host
# 4. use ansible_acme to fetch challenge data
# 5. upload challenge data to
# create process acme_port80 python-module acme_port80 start auto

import cherrypy
import sys
import urlparse

sys.path.append("/config")
import acme_tokens

tokens = {t.split(".")[0]: t for t in acme_tokens.tokens}


def httpd_service(environ, start_response):
    _, _, path, _, _, _ = urlparse.urlparse(environ.get("REQUEST_URI", "/"))

    if path == "/":
        start_response("200 OK", [])
        return "OK"

    parts = path.split("/")
    assert parts[0] == ""
    assert parts[1] == ".well-known"
    assert parts[2] == "acme-challenge"
    token = parts[3]

    start_response("200 OK", [])
    return tokens.get(token, "")


from cherrypy._cpserver import Server

cherrypy.server.unsubscribe()  # don't start default http server that listens on some socket
cherrypy.config.update({"/": {}})

server = Server(exos_vr="ALL")
server._socket_host = "::"
server.socket_port = 80

server.thread_pool = 7
server.subscribe()

cherrypy.tree.graft(httpd_service, "/")

cherrypy.engine.start()
server.start()
cherrypy.engine.block()
