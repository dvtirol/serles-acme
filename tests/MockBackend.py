import base64


class Backend:
    def __init__(self, config):
        pass

    def sign(self, csr, subjectDN, subjectAltNames, email):
        assert csr is not None
        assert subjectDN is not None
        assert type(subjectAltNames) == list
        assert email is None or "@" in email

        with open("data_leaf.pem") as f:
            return f.read(), None


class NotBackend:
    def __init__(self, config):
        pass


class RaisingBackend:
    def __init__(self, config):
        raise Exception("foo")
