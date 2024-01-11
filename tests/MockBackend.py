import base64


class Backend:
    def __init__(self, config):
        pass

    def sign(self, csr, subjectDN, subjectAltNames, email):
        assert csr is not None
        assert subjectDN is not None
        assert type(subjectAltNames) == list
        assert email is None or "@" in email

        # returning valid pkcs7 data (but bogus/self-signed cert)
        return (
            base64.b64decode(
                """
        MIIFQAYJKoZIhvcNAQcCoIIFMTCCBS0CAQExADALBgkqhkiG9w0BBwGgggUTMIIFDzCCAvegAwIB
        AgIUceeK5RaBgSsJ+peeahvMhUUV5pMwDQYJKoZIhvcNAQELBQAwFzEVMBMGA1UEAwwMZXhhbXBs
        ZS50ZXN0MB4XDTIwMDgxNzEzMTcyNloXDTIxMDgxNzEzMTcyNlowFzEVMBMGA1UEAwwMZXhhbXBs
        ZS50ZXN0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAny+AX0yR8Kc7NrEEfYoYKrq/
        ltkSzjrzsIsTYLDpxasE5iCEZejVirqFFMHkeBSfKeoUl6AMXKzpF5fAH7UCxy3qh0Efwa7JhuQz
        XFiCMSbqCfLeaSMVCgiB8MY9oWWP7GCJfOEI9vGFBU5jWdO6U/nlw4Y8cxf0OSkINbjzOakD5c19
        VIeNp4pTXqzhKH2S4KHDW3Eqc7K4uZmo+a0l/DHH/yQ1TPV5xaWNlC7ozGZ0ykc8nCoxQ8ASgeQ5
        u5lgRSIPGthRAXR5NIi/RuWKAwhSWOdSm7DTn5WM9HFqTPg/hlWW1670sTJ2R9sp6hZhljZ58Y0k
        jR0+unL4aZga/pSGgMYKoh1DUOTvfDLbtRVknzpMkZttyCKIrzhOOQxqPAjzRN0PItAQaP5cgbp/
        eJTk9s11Nqg7gC8Wufd7saYAof26Cxd+AeTgxiqX4qA7VNd2PZGXuDwhUW60T/mo72C17Cw/6UIy
        P7DkwFC/I/6AfnCViGjl7F1hpHkTJyU/OWgGwmRDv7bKxlAKp+UuFD+hd5fT3ko7Rw7om1UH10Wz
        VIVR1SD3Ti7iADyjaZGApvK4FZ6GmE/W4DvM34q+a4XdpviLCL/oVRgXBRilxJIS0os05M/Ggh3W
        FcEQvwcxEqcmh6rq3S6mjN1Clq6jBNaw1Jhaw9cxj3QZT6n19i0CAwEAAaNTMFEwHQYDVR0OBBYE
        FNTwKBK0n+u51/ua7jPyGz9XYnMWMB8GA1UdIwQYMBaAFNTwKBK0n+u51/ua7jPyGz9XYnMWMA8G
        A1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAIodMgF6EFwHAPJWdS86R3sZ+lD4Z39B
        /eWLugvWzAXMJu6Nhuy47cSkNUrA6pxI8VA6qHe9Y2WWtiKomRDXZVX3qVAZv7SLWrKI1w4QVMQN
        UYdG1rMmQJUlPyKC8J9f8GZiOCq1JAZ8giF3jhJcpnAe0XocjnV0zxQi1/y3UV8C31v2LbLCuo4S
        +R3jtOhR9MfSdszTeKKca+YEFJF88y0CNcRGuN5VEmgGuda93LBBhhuq4HzHrON0UVGSlPSKeQ9+
        MFVobnfwJvubklDmJeXlexbB58DrkMTcZUQ41UfHL9+K0LzwNlQ91rD7bU0dg8Ueee6nBG8+SPZb
        hUBibLbORSmQd7SvHz7MNEcAeCIeL7iVBAVeKORJHfu5FTrS5tvB4XKkLerJ+UTjpjzVK3DKAcgR
        yl2l2WFFzqDVyTPCuRqgX/iGnVh5ToRrTNl5d0haHRvvWGCQjzVHe9O+Fo/GlSgd5+XGxt6C+Iej
        b0T6CvU8uFy4yvNNt5ji1ckUIfOgUyLeDT/POdiw3X5Pbi/aHf5OH5sdZ5sgOkfHe8DiTYHkVnA0
        KMCbuiAZBsZfKJKQfF88aCiaTTSu+tqOwqQHC3Gc269MPcafAxZUTjWG9dEmjegqj6mjwYAaeEhd
        H8MnxhYRdADuww5g0GZIQOh78dPu7i4gbELgPrMzl3E7oQAxAA=="""
            ),
            None,
        )


class NotBackend:
    def __init__(self, config):
        pass


class RaisingBackend:
    def __init__(self, config):
        raise Exception("foo")
